"""Read-only recount of the completed A/B pilot from episodes and raw captures.

No model calls, scans or edits to existing results. Prints JSON for the append-only
command journal. Repeats are retained and paired within each case, never counted
as independent cases for an inferential test.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def leaves(node, prefix=''):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from leaves(value, f'{prefix}.{key}' if prefix else key)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from leaves(value, f'{prefix}[{i}]')
    elif isinstance(node, str):
        yield prefix, node


def main():
    allocation_path = AUDIT / 'AB_Pilot_Allocation_20261012_v1/allocation.json'
    allocation = read(allocation_path)
    input_changes = [name for name, digest in allocation['input_sha256'].items()
                     if sha(ROOT / name) != digest]
    assert not input_changes, input_changes
    per_run, paired, groups, errors, reviewed = [], defaultdict(dict), defaultdict(Counter), [], {}
    previous_start = None
    for planned in allocation['runs']:
        folder = ROOT / planned['output']
        env, selection, summary = [read(folder / name) for name in ['environment.json', 'selection.json', 'summary.json']]
        ids = selection['case_ids']
        model, condition, repeat = planned['model'], planned['condition'], planned['repeat']
        assert env['model'] == model and env['acceptance_policy'] == 'corrected'
        assert env['construction_mode'] == ('original_prompt' if condition == 'A' else 'typed_json')
        assert env['prompt_policy'] == ('historical_autogrep_default_unchanged' if condition == 'A' else 'CONDITION_B_TYPED_JSON')
        assert env['semgrep_version'] == '1.177.0' and env['max_attempts'] == 3
        assert env['temperature'] == 0 and env['max_tokens'] == 2048
        original_selection = ROOT / planned['argv'][planned['argv'].index('--selection') + 1]
        assert env['selection_sha256'] == sha(original_selection) == sha(folder / 'selection.json')
        assert set(ids) == set(read(original_selection)['case_ids']) and len(ids) == 24
        for name, digest in {**env['code_sha256'], **env['annotation_sha256']}.items():
            assert digest == allocation['input_sha256'][name] == sha(ROOT / name), name
        assert previous_start is None or env['created_utc'] > previous_start
        previous_start = env['created_utc']
        paths = sorted(folder.glob('CASE-*/episode.json'))
        assert len(paths) == 24
        count = Counter()
        for path in paths:
            episode = read(path)
            cid = episode['case_id']
            assert cid in ids
            attempts = episode['attempts']
            captures = [folder / 'raw/diagnostic' / (cid + '.json')]
            captures += sorted((folder / 'raw_retries/diagnostic').glob(cid + '_attempt*.json'))
            assert len(attempts) == episode['calls_recorded'] == len(captures)
            assert 1 <= len(captures) <= 3
            payloads = [read(p) for p in captures]
            for i, capture in enumerate(payloads, 1):
                assert capture['case_id'] == cid and capture['attempt_index'] == i
                assert capture['request']['model'] == model
                assert capture['request']['max_tokens'] == 2048 and capture['request']['temperature'] == 0
            for key in ['input_tokens', 'output_tokens', 'generation_seconds']:
                assert all(p[key] is not None for p in payloads), (path, key)
                assert abs(sum(p[key] for p in payloads) - episode[key]) < 1e-6
                count[key] += episode[key]
            count['calls'] += len(captures)
            accepted = episode['final_rule_path'] is not None
            count['accepted'] += accepted
            assert not any(a['visible_evaluation'] and a['visible_evaluation']['visible_correct'] for a in attempts[:-1])
            if accepted:
                assert attempts[-1]['visible_evaluation']['visible_correct']
                assert sha(Path(episode['final_rule_path'])) == episode['final_rule_sha256']
            else:
                assert len(attempts) == 3 and episode['iterative'] is None
                assert not attempts[-1]['visible_evaluation'] or not attempts[-1]['visible_evaluation']['visible_correct']
            first = attempts[0]
            count['first_unparsed'] += not first['parsed']
            visible = first['visible_evaluation']
            count['first_visible_scan_errors'] += bool(visible and not visible['scan_ok'])
            count['first_parsed_and_scan_ok'] += bool(first['parsed'] and visible and visible['scan_ok'])
            if not first['parsed']:
                errors.append({'model': model, 'condition': condition, 'repeat': repeat, 'case_id': cid,
                               'stage': 'response_decoder_or_schema', 'feedback': first['feedback']})
            elif visible and not visible['scan_ok']:
                rule = yaml.safe_load(Path(first['rule_path']).read_text())['rules'][0]
                for error in visible['errors']:
                    if error.get('type') == 'Rule parse error':
                        message = error['message']
                        fragment = re.search(r'----- pattern -----\n(.*?)\n----- end pattern -----', message, re.S)
                        text = fragment.group(1).strip() if fragment else None
                        locations = [p for p, value in leaves(rule) if text is not None and value.strip() == text]
                        errors.append({'model': model, 'condition': condition, 'repeat': repeat, 'case_id': cid,
                                       'stage': 'semgrep_rule_parse', 'pattern_paths': locations,
                                       'pattern_text': text, 'message': message})
            for stage in ['raw', 'iterative']:
                evaluation = episode[stage]
                count[stage + '_evaluated'] += evaluation is not None
                count[stage + '_scan_errors'] += bool(evaluation and not evaluation['scan_ok'])
                success = bool(evaluation and evaluation['complete_success'])
                count[stage + '_complete_success'] += success
                if evaluation:
                    assert success == bool(evaluation['scan_ok'] and all(s['outcome'] in {'TP', 'TN'} for s in evaluation['samples']))
                    for sample in evaluation['samples']:
                        assert sha(ROOT / sample['sample_path']) == sample['sample_sha256']
                if stage == 'iterative':
                    paired[(model, cid)].setdefault(condition, {})[repeat] = int(success)
            reviewed[str(path.relative_to(ROOT))] = sha(path)
            for p in captures:
                reviewed[str(p.relative_to(ROOT))] = sha(p)
        assert summary['requested_cases'] == summary['completed_cases'] == 24
        for stage in ['raw', 'iterative']:
            for field in ['evaluated', 'scan_errors', 'complete_success']:
                assert summary['conditions'][stage][field] == count[stage + '_' + field]
        assert count['accepted'] == summary['conditions']['iterative']['accepted'] == summary['conditions']['iterative']['visible_correct']
        count['unaccepted'] = 24 - count['accepted']
        per_run.append({'model': model, 'condition': condition, 'repeat': repeat, **count})
        groups[(model, condition)].update(count)
        for name in ['environment.json', 'selection.json', 'summary.json']:
            p = folder / name
            reviewed[str(p.relative_to(ROOT))] = sha(p)
    changes, all_case_rates = [], []
    for (model, cid), results in sorted(paired.items()):
        a, b = [results[k] for k in ['A', 'B']]
        assert set(a) == set(b) == {1, 2, 3}
        a_total, b_total = sum(a.values()), sum(b.values())
        row = {'model': model, 'case_id': cid, 'a_successes_of_3': a_total, 'b_successes_of_3': b_total,
               'a_by_repeat': a, 'b_by_repeat': b, 'mean_rate_delta': (b_total - a_total) / 3}
        all_case_rates.append(row)
        if a_total != b_total:
            changes.append(row)
    assert sum(c['calls'] for c in groups.values()) == 486
    assert sum(len(v) for v in paired.values()) == 96
    for p in [allocation_path, AUDIT / 'Bounded_Investigation_Tracking.md', ROOT / 'Research_Log/Correction_Log.md', Path(__file__)]:
        reviewed[str(p.relative_to(ROOT))] = sha(p)
    result = {'verified_utc': datetime.now(timezone.utc).isoformat(), 'per_run': per_run,
              'group_totals': [{'model': m, 'condition': c, **counts} for (m, c), counts in groups.items()],
              'paired_changes': changes, 'all_case_rates': all_case_rates, 'first_attempt_errors': errors,
              'total_calls': 486, 'episodes_verified': 288, 'allocation_inputs_unchanged': True,
              'recorded_run_start_order_matches_allocation': True, 'reviewed_sha256': reviewed,
              'limitations': 'Retained evidence audit; deleted stale-directory contents and remote execution histories cannot be independently reconstructed.',
              'new_model_calls': 0, 'new_semgrep_scans': 0}
    target = AUDIT / 'AB_Pilot_Verification_20261013.json'
    with target.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps({k: v for k, v in result.items() if k not in {'reviewed_sha256', 'all_case_rates', 'first_attempt_errors'}}, indent=2))
    print('Full evidence:', target.relative_to(ROOT))


if __name__ == '__main__':
    main()

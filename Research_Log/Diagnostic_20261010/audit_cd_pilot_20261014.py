"""Offline evidence checks and descriptive summaries of the allocated C/D pilot.

Never performs model calls or scans and never changes historical run files.
Use --run N for a completed-run checkpoint; omit it after all twelve complete.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALLOCATION = ROOT / 'Research_Log/Diagnostic_20261010/CD_Pilot_Allocation_20261014_v1/allocation.json'


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_run(run, allocation):
    folder = ROOT / run['output']
    env, selection, summary = [read(folder / name) for name in ['environment.json', 'selection.json', 'summary.json']]
    ids = selection['case_ids']
    assert ids == read(ROOT / 'benchmark/diagnostic_20261010/selection.json')['case_ids']
    assert len(ids) == len(set(ids)) == 24
    assert env['model'] == run['model'] and env['condition'] == run['condition']
    assert env['construction_mode'] == ('original_prompt' if run['condition'] == 'C' else 'typed_json')
    assert env['acceptance_policy'] == 'corrected' and env['semgrep_version'] == '1.177.0'
    assert env['temperature'] == 0 and env['max_tokens'] == 2048 and env['max_attempts'] == 3
    assert env['selection_sha256'] == sha(folder / 'selection.json')
    assert env['probe_manifest_sha256'] == sha(ROOT / 'benchmark/diagnostic_20261010/dev_probe_manifest_v1.json')
    for name, digest in {**env['code_sha256'], **env['annotation_sha256']}.items():
        assert digest == sha(ROOT / name), name
    counts = Counter()
    cases, probe_trajectories, reviewed = [], [], {}
    assert len(list(folder.glob('CASE-*/episode.json'))) == 24
    for cid in ids:
        path = folder / cid / 'episode.json'
        episode = read(path)
        assert episode['case_id'] == cid and episode['condition'] == run['condition']
        attempts = episode['attempts']
        captures = [folder / 'raw/diagnostic' / f'{cid}.json']
        captures += sorted((folder / 'raw_retries/diagnostic').glob(f'{cid}_attempt*.json'))
        assert 1 <= len(captures) == len(attempts) == episode['calls_recorded'] <= 3
        payloads = [read(p) for p in captures]
        for i, payload in enumerate(payloads, 1):
            assert payload['case_id'] == cid and payload['attempt_index'] == i
            assert payload['request']['model'] == run['model']
            assert payload['request']['temperature'] == 0 and payload['request']['max_tokens'] == 2048
            assert payload.get('error') is None, f'Provider failure in {cid}, attempt {i}: inspect capture'
        for key in ['input_tokens', 'output_tokens', 'generation_seconds']:
            values = [p.get(key) for p in payloads]
            if all(v is not None for v in values):
                assert episode[key] is not None and abs(sum(values) - episode[key]) < 1e-6
                counts[key] += episode[key]
            else:
                assert episode[key] is None
                counts[key + '_missing_episodes'] += 1
        counts['generation_calls'] += len(captures)
        counts['repair_calls'] += len(captures) - 1
        counts['eligible'] += episode['probe_eligible']
        counts['fallback_accepted'] += episode['probe_fallback_used']
        visible_scans = probe_scans = 0
        for i, attempt in enumerate(attempts, 1):
            assert attempt['attempt'] == i
            visible = attempt['visible_evaluation']
            probe = attempt['probe_evaluation']
            gate = attempt['gate_decision']
            assert bool(visible is not None) == attempt['parsed']
            visible_scans += visible is not None
            probe_scans += probe is not None
            counts['visible_scan_errors'] += bool(visible and not visible['scan_ok'])
            counts['probe_scan_errors'] += bool(probe and not probe['scan_ok'])
            if i == 1:
                counts['first_unparsed'] += not attempt['parsed']
                counts['first_visible_scan_errors'] += bool(visible and not visible['scan_ok'])
            if probe:
                assert episode['probe_eligible'] and visible['visible_correct']
                if probe.get('error', '').startswith('probe snapshot integrity'):
                    raise AssertionError(f'Probe integrity failure: {cid}')
                failed = not probe['scan_ok'] or not probe['vulnerable_detected'] or probe['patched_detected']
                if failed:
                    counts['probe_failed_attempts'] += 1
                    probe_trajectories.append({'case_id': cid, 'attempt': i, 'reason': gate['reason'],
                                              'repair_call_followed': i < len(attempts),
                                              'first_candidate_complete_success': bool(episode['raw'] and episode['raw']['complete_success']),
                                              'later_accepted': episode['final_rule_path'] is not None,
                                              'final_complete_success': bool(episode['iterative'] and episode['iterative']['complete_success'])})
            if gate and gate['accept']:
                assert i == len(attempts) and visible['visible_correct']
                if episode['probe_eligible']:
                    assert probe and probe['scan_ok'] and probe['vulnerable_detected'] and not probe['patched_detected']
                    assert not gate['is_fallback']
                else:
                    assert gate['is_fallback'] and probe is None
        resources = episode['resource_accounting']
        assert resources == {'generation_calls': len(attempts), 'visible_scans': visible_scans,
                             'probe_scans': probe_scans, 'repair_calls': len(attempts) - 1}, resources
        counts['visible_scans'] += visible_scans
        counts['probe_scans'] += probe_scans
        accepted = episode['final_rule_path'] is not None
        counts['accepted'] += accepted
        if accepted:
            assert attempts[-1]['gate_decision']['accept']
            assert sha(Path(episode['final_rule_path'])) == episode['final_rule_sha256']
        else:
            assert len(attempts) == 3 and episode['iterative'] is None
        for stage in ['raw', 'iterative']:
            evaluation = episode[stage]
            counts[stage + '_evaluated'] += evaluation is not None
            counts[stage + '_scan_errors'] += bool(evaluation and not evaluation['scan_ok'])
            success = bool(evaluation and evaluation['complete_success'])
            counts[stage + '_complete_success'] += success
            if evaluation and evaluation['scan_ok']:
                assert success == all(s['outcome'] in ['TP', 'TN'] for s in evaluation['samples'])
                for sample in evaluation['samples']:
                    assert sha(ROOT / sample['sample_path']) == sample['sample_sha256']
                    if sample['sample_type'].startswith('variant_vulnerable'):
                        counts[stage + '_hidden_positive_scanned'] += 1
                        counts[stage + '_hidden_tp'] += sample['outcome'] == 'TP'
                    if sample['sample_type'] in ['variant_safe', 'benign_lookalike']:
                        counts[stage + '_hidden_negative_scanned'] += 1
                        counts[stage + '_hidden_fp'] += sample['outcome'] == 'FP'
        cases.append({'case_id': cid, 'eligible': episode['probe_eligible'],
                      'success': int(bool(episode['iterative'] and episode['iterative']['complete_success'])),
                      'calls': len(attempts), 'accepted': accepted})
        for p in [path, *captures]:
            reviewed[str(p.relative_to(ROOT))] = sha(p)
    assert counts['generation_calls'] <= 72 and counts['eligible'] == 11
    assert summary['requested_cases'] == summary['completed_cases'] == 24
    for stage in ['raw', 'iterative']:
        for field in ['evaluated', 'scan_errors', 'complete_success']:
            assert summary['conditions'][stage][field] == counts[stage + '_' + field]
    dev = summary['development_probes']
    assert dev['eligible_cases_completed'] == 11 and dev['ineligible_cases_completed'] == 13
    assert dev['fallback_accepted'] == counts['fallback_accepted']
    assert dev['probe_scan_errors'] == counts['probe_scan_errors']
    for key in ['generation_calls', 'visible_scans', 'probe_scans', 'repair_calls']:
        assert dev['resources'][key] == counts[key]
    for name in ['environment.json', 'selection.json', 'summary.json']:
        p = folder / name
        reviewed[str(p.relative_to(ROOT))] = sha(p)
    return {'order': run['order'], 'model': run['model'], 'condition': run['condition'], 'repeat': run['repeat'],
            'output': run['output'], 'counts': dict(counts), 'cases': cases,
            'probe_failures': probe_trajectories, 'reviewed_sha256': reviewed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=int, choices=range(1, 13))
    args = parser.parse_args()
    allocation = read(ALLOCATION)
    assert all(sha(ROOT / name) == value for name, value in allocation['input_sha256'].items())
    runs = [r for r in allocation['runs'] if args.run is None or r['order'] == args.run]
    results = [check_run(run, allocation) for run in runs]
    report = {'verified_runs': len(results), 'runs': results, 'model_calls': sum(r['counts']['generation_calls'] for r in results)}
    if args.run is None:
        paired = []
        for model in allocation['models']:
            for condition in ['C', 'D']:
                chosen = [r for r in results if r['model'] == model and r['condition'] == condition]
                assert len(chosen) == 3
                rows = []
                identical_first_responses = 0
                for case in chosen[0]['cases']:
                    cid = case['case_id']
                    cd = [next(c['success'] for c in r['cases'] if c['case_id'] == cid) for r in chosen]
                    ab = []
                    for r in chosen:
                        planned = allocation['runs'][r['order'] - 1]
                        e = read(ROOT / planned['baseline_output'] / cid / 'episode.json')
                        ab.append(int(bool(e['iterative'] and e['iterative']['complete_success'])))
                        before = read(ROOT / planned['baseline_output'] / 'raw/diagnostic' / f'{cid}.json')
                        after = read(ROOT / planned['output'] / 'raw/diagnostic' / f'{cid}.json')
                        assert before['request']['messages'] == after['request']['messages']
                        identical_first_responses += before['raw_content'] == after['raw_content']
                    rows.append({'case_id': cid, 'eligible': case['eligible'], 'baseline_successes': sum(ab),
                                 'probe_condition_successes': sum(cd), 'difference_in_case_mean': (sum(cd) - sum(ab)) / 3})
                paired.append({'model': model, 'contrast': condition + '-' + {'C': 'A', 'D': 'B'}[condition],
                               'baseline_mean_success_rate': sum(r['baseline_successes'] for r in rows) / 72,
                               'probe_mean_success_rate': sum(r['probe_condition_successes'] for r in rows) / 72,
                               'difference_pp': sum(r['difference_in_case_mean'] for r in rows) / 24 * 100,
                               'identical_first_response_texts_out_of_72': identical_first_responses,
                               'eligible_case_count': sum(r['eligible'] for r in rows),
                               'eligible_baseline_rate': sum(r['baseline_successes'] for r in rows if r['eligible']) / 33,
                               'eligible_probe_rate': sum(r['probe_condition_successes'] for r in rows if r['eligible']) / 33,
                               'gained_cases': sum(r['difference_in_case_mean'] > 0 for r in rows),
                               'lost_cases': sum(r['difference_in_case_mean'] < 0 for r in rows), 'cases': rows})
        report['paired_descriptive_comparisons'] = paired
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()

"""Offline integration audit: real generation/decoder/runner/capture, mocked SDK and scanner.

No model or Semgrep calls. This complements, not replaces, the real-Semgrep tests.
Outputs are exclusive-created under the research audit directory, never benchmark results.
"""
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace as NS
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).parent
sys.path[:0] = [str(ROOT / 'pipeline'), str(ROOT / 'autogrep')]
import diagnostic_v2 as dv
from config import Config
from llm_client import LLMClient
from patch_processor import FileChange, PatchInfo
from raw_capture import RawCaptureRecorder, wrap_llm_client


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    out = AUDIT / ('Condition_B_Offline_Evidence_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(exist_ok=False)
    source = PatchInfo('review-owner', 'review-repo', 'deadbeef', [
        FileChange('app.py', '-foo(untrusted)\n+foo("safe")', 'python')])
    payload = {'id': 'review-rule', 'message': 'm', 'severity': 'ERROR',
               'languages': ['python'], 'pattern': 'foo($X)'}
    good = json.dumps(payload)
    yaml_good = yaml.safe_dump({'rules': [payload]})
    scenarios = [
        ('json_repair_then_accept', 'typed_json', ['invalid JSON', good], ['pass'], 2, True),
        ('json_budget_exhaustion', 'typed_json', ['invalid JSON'] * 3, [], 3, False),
        ('compiler_then_location_repair', 'typed_json', [good] * 3, ['compiler', 'location', 'pass'], 3, True),
        ('early_accept', 'typed_json', [good], ['pass'], 1, True),
        ('timeout_budget_exhaustion', 'typed_json', [TimeoutError('synthetic timeout')] * 3, [], 3, False),
        ('a_default_dispatch', 'original_prompt', [yaml_good], ['pass'], 1, True),
    ]
    results = []
    for name, mode, replies, visible_results, expected_calls, accepted in scenarios:
        folder = out / name
        folder.mkdir()
        config = Config(openrouter_api_key='offline-placeholder', construction_mode=mode,
                        rule_schema_policy='semgrep_search_taint_v2', max_output_tokens=2048,
                        generation_temperature=0, repos_cache_dir=folder / 'cache')
        llm = object.__new__(LLMClient)
        llm.config, llm.last_error = config, None
        requests, events = [], []
        responses = iter(replies)
        outcomes = iter(visible_results)

        def create(**kwargs):
            requests.append(kwargs)
            events.append('model_stub')
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return NS(choices=[NS(message=NS(content=response), finish_reason='stop')],
                      usage=NS(prompt_tokens=10, completion_tokens=20))

        llm.client = NS(chat=NS(completions=NS(create=create)))
        recorder = RawCaptureRecorder(folder, 'offline-review')
        wrap_llm_client(llm, recorder)

        def scan(rule_path, cid, manifest, annotations, scan_out, *, hidden):
            events.append('hidden_stub' if hidden else 'visible_stub')
            kind = 'pass' if hidden else next(outcomes)
            assert yaml.safe_load(rule_path.read_text())['rules'][0]['pattern'] == 'foo($X)'
            return {'scan_ok': kind != 'compiler', 'errors': ['synthetic compile failure'] if kind == 'compiler' else [],
                    'legacy_accepted': kind != 'compiler', 'visible_correct': kind == 'pass',
                    'complete_success': hidden, 'samples': [
                        {'sample_type': 'original_vulnerable', 'detected': True,
                         'finding_location_correct': kind == 'pass', 'finding_lines': [99 if kind == 'location' else 1],
                         'outcome': 'TP' if kind == 'pass' else 'FN'},
                        {'sample_type': 'original_patched', 'detected': False, 'outcome': 'TN'}]}

        with patch.object(dv, 'load_case', return_value=source), patch.object(dv, 'scan', side_effect=scan):
            episode = dv.run_model_case('CASE-REVIEW', llm, config, recorder,
                                        {'CASE-REVIEW': {'vulnerable_lines': [1, 1]}}, {}, folder,
                                        acceptance_policy='corrected')
        assert len(requests) == len(episode['attempts']) == episode['calls_recorded'] == expected_calls
        assert bool(episode['final_rule_path']) == accepted
        assert all(r['max_tokens'] == 2048 and r['temperature'] == 0 for r in requests)
        assert ('JSON object' in requests[0]['messages'][0]['content']) == (mode == 'typed_json')
        for i, request in enumerate(requests[1:]):
            assert episode['attempts'][i]['feedback'] in request['messages'][1]['content']
        if 'hidden_stub' in events:
            assert events.index('hidden_stub') > max(i for i, e in enumerate(events) if e == 'model_stub')
        capture_paths = [recorder.raw_dir / 'CASE-REVIEW.json'] + sorted(recorder.retries_dir.glob('*.json'))
        assert len(capture_paths) == expected_calls
        for i, path in enumerate(capture_paths):
            capture = json.loads(path.read_text())
            assert capture['request'] == requests[i]
            if isinstance(replies[i], Exception):
                assert capture['error']['type'] == 'TimeoutError' and capture['input_tokens'] is None
            else:
                assert capture['raw_content'] == replies[i]
                assert capture['input_tokens'] == 10 and capture['output_tokens'] == 20
        results.append({'scenario': name, 'construction_mode': mode, 'calls': expected_calls,
                        'accepted': accepted, 'events': events})

    llm.config.construction_mode = 'typed_json'
    prompt_a, prompt_b = llm._build_prompt_autogrep_default(source), llm._build_prompt_typed_json(source)
    prompt_a_path, prompt_b_path = out / 'prompt_a.txt', out / 'prompt_b.txt'
    prompt_a_path.write_text(prompt_a)
    prompt_b_path.write_text(prompt_b)
    assert 'EXAMPLES OF HIGH-QUALITY RULES' in prompt_a and 'pickle.loads' in prompt_a
    assert 'EXAMPLES OF HIGH-QUALITY RULES' not in prompt_b and 'pickle.loads' not in prompt_b
    assert source.file_changes[0].changes in prompt_a and source.file_changes[0].changes in prompt_b

    # Derive the metadata label from the literal expression the real CLI uses.
    tree = ast.parse((ROOT / 'pipeline/diagnostic_v2.py').read_text())
    env_expr = next(n.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'env' for t in n.targets)
                    and isinstance(n.value, ast.Dict)
                    and any(isinstance(k, ast.Constant) and k.value == 'prompt_policy' for k in n.value.keys))
    policy_expr = next(v for k, v in zip(env_expr.keys, env_expr.values)
                       if isinstance(k, ast.Constant) and k.value == 'prompt_policy')
    policy = eval(compile(ast.Expression(policy_expr), '<runner prompt policy>', 'eval'),
                  {'args': NS(prompt_variant='autogrep_default', construction_mode='typed_json')})
    assert policy == 'historical_autogrep_default_unchanged'

    # The source-hash tripwire fails on A. Distinguish prompt behavior from
    # whitespace-only source drift using the preserved pre-diagnostic snapshot.
    import llm_client as llm_module
    before_path = AUDIT / 'before/autogrep/llm_client.py'
    before_tree = ast.parse(before_path.read_text())
    current_tree = ast.parse((ROOT / 'autogrep/llm_client.py').read_text())
    def original_builder(tree):
        return next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                    and n.name == '_build_prompt_autogrep_default')
    before_fn, current_fn = original_builder(before_tree), original_builder(current_tree)
    assert ast.dump(before_fn, include_attributes=False) == ast.dump(current_fn, include_attributes=False)
    baseline_namespace = vars(llm_module).copy()
    exec(compile(ast.Module(body=[before_fn], type_ignores=[]), str(before_path), 'exec'), baseline_namespace)
    selection = json.loads((ROOT / 'results/diagnostic_20261010/qwen3_v3/selection.json').read_text())['case_ids']
    rendered_checks = 0
    for cid in selection:
        case = dv.load_case(cid, NS(benchmark_cases_dir=ROOT / 'benchmark/cases'))
        for feedback in [None, 'Synthetic repair feedback']:
            assert baseline_namespace['_build_prompt_autogrep_default'](llm, case, feedback) == llm._build_prompt_autogrep_default(case, feedback)
            rendered_checks += 1
    assert rendered_checks == 48

    files = [ROOT / n for n in ['autogrep/config.py', 'autogrep/llm_client.py', 'pipeline/gptlab_config.py',
                                'pipeline/diagnostic_v2.py', 'pipeline/typed_rule.py',
                                'pipeline/raw_capture.py', 'pipeline/tests/test_typed_json_construction.py']]
    files += [AUDIT / 'Controlled_2x2_Protocol_Draft_20261012.md',
              AUDIT / 'Bounded_Investigation_Tracking.md', ROOT / 'Research_Log/Correction_Log.md', Path(__file__)]
    result = {'evidence_directory': str(out.relative_to(ROOT)), 'scenarios': results,
              'prompt_a_chars': len(prompt_a), 'prompt_b_chars': len(prompt_b),
              'b_removes_a_worked_examples': True, 'typed_json_default_prompt_policy_label': policy,
              'a_builder_ast_matches_snapshot': True, 'a_rendered_prompts_equal_snapshot': rendered_checks,
              'reviewed_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
              'limitations': 'SDK and scanner are mocked; real Semgrep behavior is covered by the separate regression run.',
              'model_calls': 0, 'semgrep_scans': 0}
    with (out / 'verification.json').open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

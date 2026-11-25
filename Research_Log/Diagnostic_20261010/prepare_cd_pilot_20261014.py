"""Prepare and verify the C/D development allocation. Never executes inference.

Run from the repo root. Refuses to overwrite its allocation or any live-run target.
Requires the two separately recorded successful no-inference preflights.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex
import sys

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).parent
sys.path[:0] = [str(ROOT / 'pipeline'), str(ROOT / 'autogrep')]
from config import Config
from llm_client import LLMClient
from case_loader import load_case
from cd_experiment import DEFAULT_MANIFEST, validate_frozen_manifest


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def save(path, value):
    with path.open('x') as handle:
        json.dump(value, handle, indent=2)
        handle.write('\n')


def main():
    out = AUDIT / 'CD_Pilot_Allocation_20261014_v1'
    assert not out.exists(), f'Preserve existing allocation: {out}'
    baseline_path = AUDIT / 'AB_Pilot_Allocation_20261012_v1/allocation.json'
    baseline = read(baseline_path)
    manifest, _, manifest_bytes = validate_frozen_manifest(DEFAULT_MANIFEST)
    case_ids = manifest['case_ids']
    assert len(case_ids) == len(set(case_ids)) == 24
    changes = {name: {'baseline': old, 'current': sha(ROOT / name)}
               for name, old in baseline['input_sha256'].items() if sha(ROOT / name) != old}
    assert set(changes) == {'pipeline/diagnostic_v2.py'}, changes

    files = {ROOT / name for name in baseline['input_sha256']}
    files.update([baseline_path, Path(__file__), ROOT / 'benchmark/cwe_definitions.json',
                  DEFAULT_MANIFEST, ROOT / 'benchmark/diagnostic_20261010/selection.json',
                  ROOT / 'autogrep/requirements.txt'])
    files.update(ROOT / 'pipeline' / name for name in
                 ['cd_experiment.py', 'dev_probe.py', 'combined_gate.py', 'probe_cache.py',
                  'probe_coverage_check.py'])
    files.update(ROOT / 'benchmark/model_context' / f'{cid}.json' for cid in case_ids)
    prompt_checks, baseline_results = [], []
    for run in baseline['runs']:
        config = Config(construction_mode='original_prompt' if run['condition'] == 'A' else 'typed_json',
                        rule_schema_policy='semgrep_search_taint_v2', max_output_tokens=2048)
        client = object.__new__(LLMClient)  # No provider client or credentials needed.
        client.config = config
        run_dir = ROOT / run['output']
        selection_path = run_dir / 'selection.json'
        assert set(read(selection_path)['case_ids']) == set(case_ids)
        for cid in case_ids:
            raw_path = run_dir / 'raw/diagnostic' / f'{cid}.json'
            captured = read(raw_path)
            assert captured['attempt_index'] == 1
            patch = load_case(cid, config)
            if run['condition'] == 'A':
                system, user = client._system_message(), client._build_prompt(patch)
            else:
                system, user = client._system_message_typed_json(), client._build_prompt_typed_json(patch)
            messages = [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}]
            request = captured['request']
            assert messages == request['messages'], raw_path
            assert request['model'] == run['model']
            assert request['temperature'] == 0 and request['max_tokens'] == 2048
            prompt_checks.append({'raw': str(raw_path.relative_to(ROOT)), 'sha256': sha(raw_path),
                                  'first_call_messages_exact_match': True})
        summary_path, env_path = run_dir / 'summary.json', run_dir / 'environment.json'
        summary, env = read(summary_path), read(env_path)
        assert summary['requested_cases'] == summary['completed_cases'] == 24
        assert env['acceptance_policy'] == 'corrected' and env['semgrep_version'] == '1.177.0'
        assert env['construction_mode'] == config.construction_mode
        baseline_results.append({k: run[k] for k in ['model', 'repeat', 'condition', 'output']} |
                                {'complete_success': summary['conditions']['iterative']['complete_success']})
        files.update([selection_path, summary_path, env_path])
    assert len(prompt_checks) == 288

    preflights = {}
    for condition in ['C', 'D']:
        path = ROOT / f'results/diagnostic_20261010/_cd_pilot_preflight_20261014_v2_{condition.lower()}/environment.json'
        env = read(path)
        assert env['mode'] == 'preflight' and env['condition'] == condition
        assert env['semgrep_version'] == '1.177.0' and env['acceptance_policy'] == 'corrected'
        assert env['construction_mode'] == ('original_prompt' if condition == 'C' else 'typed_json')
        assert env['probe_coverage'] == {'requested_cases': 24, 'eligible_cases': 11, 'ineligible_cases': 13}
        assert env['probe_manifest_sha256'] == hashlib.sha256(manifest_bytes).hexdigest()
        assert all(sha(ROOT / name) == value for name, value in env['code_sha256'].items())
        preflights[condition] = {'environment': str(path.relative_to(ROOT)), 'sha256': sha(path)}
        files.add(path)

    runs = []
    for previous in baseline['runs']:
        condition = {'A': 'C', 'B': 'D'}[previous['condition']]
        slug = 'qwen3' if previous['model'] == 'qwen3-coder:30b' else 'gpt4o'
        label = f"cd_dev_20261014_v1_{slug}_r{previous['repeat']}_{condition.lower()}"
        target = ROOT / 'results/diagnostic_20261010' / label
        assert not target.exists(), target
        argv = ['.venv/bin/python', 'pipeline/diagnostic_audit.py', 'run', label, '--',
                '.venv/bin/python', 'pipeline/diagnostic_v2.py', 'model', '--model', previous['model'],
                '--condition', condition, '--selection', 'benchmark/diagnostic_20261010/selection.json',
                '--probe-manifest', 'benchmark/diagnostic_20261010/dev_probe_manifest_v1.json',
                '--output', str(target.relative_to(ROOT))]
        runs.append({'order': len(runs) + 1, 'model': previous['model'], 'repeat': previous['repeat'],
                     'condition': condition, 'case_count': 24, 'max_calls': 72,
                     'output': str(target.relative_to(ROOT)), 'baseline_output': previous['output'], 'argv': argv})
    assert len(runs) == 12 and sum(r['max_calls'] for r in runs) == 864
    plan = {'status': 'PREPARED_NOT_EXECUTED_INFERENCE_AUTHORIZATION_PENDING',
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'purpose': 'Descriptive C/D development pilot; no confirmation claims',
            'models': baseline['models'], 'repeats': 3, 'cases': 24, 'episodes': 288,
            'max_model_calls': 864, 'max_output_tokens_per_call': 2048,
            'max_total_output_tokens': 864 * 2048, 'temperature': 0,
            'max_attempts_per_episode': 3, 'sdk_retries': 0, 'semgrep_version': '1.177.0',
            'acceptance_policy': 'corrected', 'eligible_cases': 11, 'ineligible_cases': 13,
            'cost_caveat': 'Output-token ceiling excludes input tokens; no dollar estimate or monetary cap established.',
            'comparability_caveats': ['A/B shuffled case order by repeat; C/D uses the exact frozen canonical order.',
                                     'A/B and C/D run in different time batches; remote backend stability is unverified.',
                                     'Matching case/repeat labels do not imply shared random draws or seeds.',
                                     'Probe-eligible cases are a selected subset; report all 24 as the main denominator.'],
            'runs': runs, 'baseline_results': baseline_results,
            'input_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sorted(files)}}
    verification = {'model_calls': 0, 'baseline_files_checked': len(baseline['input_sha256']),
                    'baseline_changed_files': changes, 'first_call_prompt_checks': prompt_checks,
                    'preflights': preflights, 'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
                    'initial_sandbox_failure_preserved': 'results/diagnostic_20261010/_cd_pilot_preflight_20261014_v1_c/preflight_error.json'}
    commands = ['# C/D development pilot commands\n',
                'Prepared, not executed. Inference allocation: 12 runs, 288 episodes, at most 864 model calls. Live execution awaits the separate budget decision.\n',
                'Run from `/Users/nkabmo/Desktop/Tools/SS`, with the relevant provider credential available in your terminal. Never paste credentials into logs or chat.\n',
                'Execute one command at a time in the listed order (three C/D and three D/C blocks). Do not overwrite any output directory.\n',
                'After each run, verify exit=0; summary requested/completed=24; environment model/condition/construction mode and manifest hash; probe eligible/ineligible=11/13; generation_calls<=72 and each episode<=3 attempts. Reconcile actual raw requests, errors and usage with episode resource records. An exhausted or scan-error episode remains a measured failure, not a reason to rerun it.\n',
                'Pause on process/integrity/credential/infrastructure failure. Preserve partial raw calls, outputs and consumed budget; do not restart a used namespace or silently reset attempts. Diagnose and record recovery before proceeding. No automatic resume is implemented. Do not stop early merely because scores look good or bad.\n',
                'Final analysis: report all 24 cases, per model, averaging each case across its three repeats; compare C-A and D-B. Show eligible-subset results separately, probe repairs/failures, hidden TPs/FPs with scan-success denominators, scan errors and actual resources. These are descriptive development results, not confirmation evidence.\n',
                'Comparability: inputs and first-call prompts verified against A/B; C/D uses fixed case order and a later execution batch. See allocation.json and verification.json.\n']
    for run in runs:
        commands += [f"## {run['order']}. {run['model']} / repeat {run['repeat']} / condition {run['condition']}\n",
                     '```sh\n' + shlex.join(run['argv']) + '\n```\n']
    out.mkdir()
    save(out / 'allocation.json', plan)
    save(out / 'verification.json', verification)
    with (out / 'Commands.md').open('x') as handle:
        handle.write('\n'.join(commands))
    print(json.dumps({'allocation': str(out.relative_to(ROOT)), 'runs': len(runs),
                      'prompt_matches': len(prompt_checks), 'preflights': list(preflights), 'model_calls': 0}))


if __name__ == '__main__':
    main()

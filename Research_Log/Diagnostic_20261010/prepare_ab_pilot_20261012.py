"""Verify corrected B wiring and prepare a reviewable pilot allocation; NEVER run inference.

Credential checks use scrubbed environments and a mocked HTTP transport that stops
before output creation. All launch commands are saved as data, never executed.
"""
import ast
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import random
import re
import shlex
import sys
from types import SimpleNamespace as NS
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).parent
sys.path[:0] = [str(ROOT / 'pipeline'), str(ROOT / 'autogrep')]
import diagnostic_v2 as dv
import llm_client
from typed_rule import TypedRule


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


def main():
    out = AUDIT / 'AB_Pilot_Allocation_20261012_v1'
    out.mkdir(exist_ok=False)
    tree = ast.parse((ROOT / 'autogrep/llm_client.py').read_text())
    def literal_assignment(function, variable):
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == function)
        return ast.literal_eval(next(n.value for n in ast.walk(fn) if isinstance(n, ast.Assign)
                                     and any(isinstance(t, ast.Name) and t.id == variable for t in n.targets)))
    examples_a = literal_assignment('_build_prompt_autogrep_default', 'EXAMPLE_RULES')
    examples_b = literal_assignment('_build_prompt_typed_json', 'EXAMPLE_RULES_TYPED_JSON')
    example_ids = {}
    for language, rows in examples_b.items():
        ids = re.findall(r'- id: "([^"]+)"', examples_a[language])
        assert ids == [row['id'] for row in rows]
        for row in rows:
            TypedRule(**row).validate()
        example_ids[language] = ids
    assert sum(map(len, example_ids.values())) == 6
    assert 'typescript' not in examples_a and 'typescript' not in examples_b

    runner_tree = ast.parse((ROOT / 'pipeline/diagnostic_v2.py').read_text())
    env_expr = next(n.value for n in ast.walk(runner_tree) if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'env' for t in n.targets)
                    and isinstance(n.value, ast.Dict)
                    and any(isinstance(k, ast.Constant) and k.value == 'prompt_policy' for k in n.value.keys))
    def field(name, args):
        expr = next(v for k, v in zip(env_expr.keys, env_expr.values)
                    if isinstance(k, ast.Constant) and k.value == name)
        return eval(compile(ast.Expression(expr), '<actual metadata expression>', 'eval'), {'args': args})
    policies = {}
    for mode, expected in [('original_prompt', 'historical_autogrep_default_unchanged'),
                           ('typed_json', 'CONDITION_B_TYPED_JSON')]:
        args = NS(construction_mode=mode, prompt_variant='autogrep_default')
        policies[mode] = field('prompt_policy', args)
        assert policies[mode] == expected
        assert field('prompt_variant_ignored', args) == (mode == 'typed_json')

    class StopBeforeNetwork(Exception):
        pass

    credential_checks = []
    for model, variables, expected_key in [
        ('gpt-4o', {}, 'OPENAI_API_KEY'),
        ('gpt-4o', {'OPENAI_API_KEY': 'offline-fake-key'}, None),
        ('qwen3-coder:30b', {}, 'GPTLAB_API_KEY'),
        ('qwen3-coder:30b', {'GPTLAB_API_KEY': 'offline-fake-key'}, None),
    ]:
        requested = []
        def get(url, **kwargs):
            assert kwargs['headers']['Authorization'] == 'Bearer offline-fake-key'
            requested.append(url)
            raise StopBeforeNetwork()
        destination = ROOT / 'results/diagnostic_20261010/_ab_review_never_created'
        assert not destination.exists()
        args = ['diagnostic_v2.py', 'model', '--model', model, '--output', str(destination),
                '--construction-mode', 'typed_json', '--acceptance-policy', 'corrected']
        with patch.dict(os.environ, variables, clear=True), patch.object(sys, 'argv', args), patch('requests.get', side_effect=get):
            try:
                dv.main()
            except SystemExit as error:
                assert expected_key is not None and expected_key in str(error)
                assert not requested
            except StopBeforeNetwork:
                assert expected_key is None and len(requested) == 1
                assert ('api.openai.com' in requested[0]) == (model == 'gpt-4o')
            else:
                raise AssertionError('Credential probe unexpectedly continued')
        assert not destination.exists()
        credential_checks.append({'model': model, 'key_present': bool(variables),
                                  'result': 'provider_resolved_transport_mocked' if requested else 'correct_missing_key_error'})

    selection_path = ROOT / 'results/diagnostic_20261010/qwen3_v3/selection.json'
    selection = json.loads(selection_path.read_text())
    case_ids = selection['case_ids']
    assert len(case_ids) == len(set(case_ids)) == 24
    runs, selections = [], []
    for repeat in range(1, 4):
        ordered = list(case_ids)
        random.Random(20261012 + repeat).shuffle(ordered)
        path = out / f'selection_repeat_{repeat}.json'
        write_json(path, {'status': 'proposed_development_pilot', 'case_ids': ordered,
                          'source_selection': str(selection_path.relative_to(ROOT)),
                          'source_sha256': sha(selection_path), 'order_seed': 20261012 + repeat})
        selections.append(path)
        # Six paired model/repeat blocks: three AB and three BA. Each case
        # receives both conditions with identical order within that block.
        model_order = [('qwen3-coder:30b', 'qwen3'), ('gpt-4o', 'gpt4o')]
        if repeat == 2:
            model_order.reverse()
        for model, slug in model_order:
            conditions = ['A', 'B'] if ((repeat + (slug == 'gpt4o')) % 2 == 1) else ['B', 'A']
            for condition in conditions:
                mode = 'original_prompt' if condition == 'A' else 'typed_json'
                label = f'ab_dev_20261012_v1_{slug}_r{repeat}_{condition.lower()}'
                target = ROOT / 'results/diagnostic_20261010' / label
                assert not target.exists(), str(target)
                argv = ['.venv/bin/python', 'pipeline/diagnostic_audit.py', 'run', label, '--',
                        '.venv/bin/python', 'pipeline/diagnostic_v2.py', 'model',
                        '--model', model, '--construction-mode', mode,
                        '--prompt-variant', 'autogrep_default', '--acceptance-policy', 'corrected',
                        '--selection', str(path.relative_to(ROOT)), '--output', str(target.relative_to(ROOT))]
                runs.append({'order': len(runs) + 1, 'model': model, 'repeat': repeat,
                             'condition': condition, 'case_count': 24, 'max_calls': 72,
                             'output': str(target.relative_to(ROOT)), 'argv': argv})
    assert len(runs) == 12
    assert sum(r['case_count'] for r in runs) == 288
    assert sum(r['max_calls'] for r in runs) == 864
    files = [ROOT / name for name in ['autogrep/config.py', 'autogrep/llm_client.py',
             'pipeline/gptlab_config.py', 'pipeline/diagnostic_v2.py', 'pipeline/typed_rule.py',
             'pipeline/raw_capture.py', 'pipeline/case_loader.py', 'pipeline/eligible_cases.py',
             'autogrep/patch_processor.py', 'pipeline/diagnostic_audit.py',
             'benchmark/manifest_frozen_final.jsonl', 'benchmark/variant_vulnerable_lines.jsonl',
             'benchmark/variant_vulnerable_lines_v2_additions.jsonl']]
    files += selections + [selection_path]
    for cid in case_ids:
        files += sorted(p for p in (ROOT / 'benchmark/cases' / cid).iterdir() if p.is_file())
    plan = {'status': 'PROPOSED_NOT_APPROVED_NOT_EXECUTED', 'created_utc': datetime.now(timezone.utc).isoformat(),
            'purpose': 'Descriptive development A/B pilot; no confirmation claims',
            'models': ['qwen3-coder:30b', 'gpt-4o'], 'repeats': 3, 'cases': 24,
            'episodes': 288, 'max_model_calls': 864, 'max_output_tokens_per_call': 2048,
            'max_total_output_tokens': 864 * 2048, 'temperature': 0, 'max_attempts_per_episode': 3,
            'sdk_retries': 0, 'semgrep_version': '1.177.0', 'acceptance_policy': 'corrected',
            'input_tokens_and_monetary_cost': 'Not bounded by this output-token ceiling; actual provider usage must be reported.',
            'runs': runs, 'input_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files}}
    write_json(out / 'allocation.json', plan)
    commands = ['# Proposed A/B pilot commands\n',
                'Status: NOT APPROVED / NOT EXECUTED. Run from the repository root only after the live allocation is approved.\n',
                'Execute sequentially in this order. Stop on any nonzero exit. Do not overwrite or restart a used namespace; preserve consumed attempts on recovery.\n']
    for run in runs:
        commands += [f"\n## {run['order']}. {run['model']} / repeat {run['repeat']} / condition {run['condition']}\n",
                     '```sh\n' + shlex.join(run['argv']) + '\n```\n']
    with (out / 'Commands.md').open('x') as f:
        f.write('\n'.join(commands))
    verification = {'same_six_example_ids': example_ids, 'typed_examples_validate': 6,
                    'typescript_has_no_examples_in_either_condition': True, 'prompt_policies': policies,
                    'credential_scenarios': credential_checks, 'network_requests': 0, 'model_calls': 0,
                    'allocation': str((out / 'allocation.json').relative_to(ROOT)),
                    'reviewed_sha256': {str(p.relative_to(ROOT)): sha(p) for p in [
                        ROOT / 'autogrep/llm_client.py', ROOT / 'pipeline/diagnostic_v2.py',
                        AUDIT / 'Bounded_Investigation_Tracking.md', ROOT / 'Research_Log/Correction_Log.md',
                        AUDIT / 'Controlled_2x2_Protocol_Draft_20261012.md', Path(__file__)]}}
    write_json(out / 'verification.json', verification)
    print(json.dumps(verification, indent=2))


if __name__ == '__main__':
    main()

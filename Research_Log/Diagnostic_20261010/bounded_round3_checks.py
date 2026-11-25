"""Targeted, inference-free verification of the second follow-up fixes."""
import ast
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'pipeline'), str(ROOT / 'autogrep')]
import audit_failure_categories as audit
import diagnostic_v2 as dv
from typed_rule import TypedRule
import yaml


def main():
    paths = [ROOT / 'pipeline' / n for n in ['diagnostic_v2.py', 'audit_failure_categories.py',
        'typed_rule.py', 'verify_scan_integration.py', 'tests/test_diagnostic_regressions.py',
        'tests/test_typed_rule.py']]
    paths += [ROOT / 'Research_Log/Correction_Log.md', Path(__file__).parent / 'Bounded_Investigation_Tracking.md']
    result = {'model_calls': 0, 'reviewed_sha256': {str(p.relative_to(ROOT)): dv.sha(p) for p in paths}}
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        case = root / 'benchmark/cases/CASE-REVIEW'
        case.mkdir(parents=True)
        (case / 'metadata.json').write_text(json.dumps({'changed_file': 'x.tsx'}))
        for _, stem, _ in dv.SAMPLES:
            (case / (stem + '.ts')).write_text('const original = 1;\n')
        with patch.object(dv, 'ROOT', root):
            target = dv.resolve_target_path('CASE-REVIEW', 'vulnerable_source', 'typescript')
            target.write_text('const stale = 2;\n')
            result['same_process_stale_repaired'] = dv.resolve_target_path('CASE-REVIEW', 'vulnerable_source', 'typescript').read_bytes() == (case / 'vulnerable_source.ts').read_bytes()
            missing = target.parent / 'patched_source.tsx'
            missing.unlink()
            result['same_process_missing_repaired'] = dv.resolve_target_path('CASE-REVIEW', 'patched_source', 'typescript').read_bytes() == (case / 'patched_source.ts').read_bytes()
        (root / 'environment.json').write_text(json.dumps({'acceptance_policy': 'corrected'}))
        result['recorded_policy_field'] = audit.acceptance_field_for(root)
    common = dict(id='review', message='m', severity='ERROR', languages=('python',), pattern='foo($X)')
    result['tuple_languages_roundtrip'] = yaml.safe_load(TypedRule(**common).to_semgrep_yaml())['rules'][0]['languages']
    try:
        TypedRule(**common, metadata=['bad']).validate()
        result['invalid_metadata_rejected'] = False
    except ValueError:
        result['invalid_metadata_rejected'] = True
    ev = {'scan_ok': True, 'legacy_accepted': True, 'visible_correct': False, 'errors': [],
          'samples': [{'sample_type': 'original_vulnerable', 'detected': True, 'finding_location_correct': False},
                      {'sample_type': 'original_patched', 'detected': False}]}
    result['corrected_rejection_categories'] = sorted(audit.audit_visible_stage({'attempts': [{'parsed': True, 'visible_evaluation': ev}]}, 'visible_correct'))
    result['no_rule_categories'] = sorted(audit.audit_visible_stage({'attempts': [{'parsed': False, 'visible_evaluation': None}]}, 'legacy_accepted'))
    result['target_only_failure_categories'] = sorted(audit.audit_visible_stage({'attempts': [{'parsed': True, 'visible_evaluation': {
        'scan_ok': False, 'samples': [], 'errors': [{'path': 'target.ts', 'type': 'Parse error'}, {'message': 'Semgrep exited with status 2'}]}}]}, 'legacy_accepted'))
    run = ROOT / 'results/diagnostic_20261010/qwen3_mechanism_v1'
    episodes = [json.loads(p.read_text()) for p in run.glob('CASE-*/episode.json')]
    cats = [audit.audit_visible_stage(e, audit.acceptance_field_for(run)) for e in episodes]
    result['mechanism_v1'] = {'original_miss_clean': sum('original_miss_clean' in c for c in cats),
        'original_unevaluable': sum('original_unevaluable' in c for c in cats),
        'raw_scan_ok': sum(audit.categorize_hidden(e.get('raw')) is not None for e in episodes),
        'raw_accepted': sum(bool(e.get('raw') and e['raw']['legacy_accepted']) for e in episodes)}
    original = 'def probe(token):\n    return token\n'
    renamed = 'def probe(tok):\n    return tok\n'
    banned = {'locals', 'globals', 'getattr', 'setattr', 'vars', 'eval', 'exec'}
    result['keyword_example_has_banned_calls'] = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in banned for n in ast.walk(ast.parse(original)))
    outcomes = []
    for source in [original, renamed]:
        ns = {}
        exec(source, ns)
        try:
            outcomes.append(ns['probe'](token='unsafe'))
        except TypeError as error:
            outcomes.append({'exception': type(error).__name__, 'message': str(error)})
    result['keyword_call_before_after_arg_rename'] = outcomes
    summary_path = ROOT / 'results/diagnostic_20261010/_verify_scan_integration_20261011T221931377245Z/summary.json'
    result['retained_integration_summary'] = json.loads(summary_path.read_text())
    result['retained_integration_summary_sha256'] = dv.sha(summary_path)
    result['reviewed_files_unchanged'] = all(dv.sha(ROOT / p) == h for p, h in result['reviewed_sha256'].items())
    out = Path(__file__).parent / ('bounded_round3_findings_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.json')
    with out.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    assert result['same_process_stale_repaired'] and result['same_process_missing_repaired']
    assert result['invalid_metadata_rejected'] and result['tuple_languages_roundtrip'] == ['python']
    assert 'never_accepted' in result['corrected_rejection_categories']
    assert 'original_unevaluable' in result['no_rule_categories'] and 'original_miss_clean' not in result['no_rule_categories']
    print('Evidence:', out)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

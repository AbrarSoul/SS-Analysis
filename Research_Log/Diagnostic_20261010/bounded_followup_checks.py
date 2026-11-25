"""Review reproductions after the seven-finding fix pass; no inference or source edits.

Default: isolated fixtures and saved-output analysis. --engine additionally compares
the verifier's version-probe environment with the scanner's actual environment.
"""
import argparse
import ast
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
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
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', action='store_true')
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = Path(__file__).parent / ('bounded_followup_artifacts_' + stamp)
    out.mkdir()
    paths = [ROOT / 'pipeline' / n for n in ['diagnostic_v2.py', 'typed_rule.py',
        'audit_failure_categories.py', 'verify_scan_integration.py',
        'tests/test_diagnostic_regressions.py', 'tests/test_typed_rule.py']]
    paths += [ROOT / 'Research_Log/Correction_Log.md',
              Path(__file__).parent / 'Bounded_Investigation_Tracking.md']
    evidence = {'model_calls': 0, 'reviewed_sha256': {str(p.relative_to(ROOT)): dv.sha(p) for p in paths}}

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        case = root / 'benchmark/cases/CASE-REVIEW'
        case.mkdir(parents=True)
        (case / 'metadata.json').write_text(json.dumps({'changed_file': 'component.tsx'}))
        for _, stem, _ in dv.SAMPLES:
            (case / (stem + '.ts')).write_text('const original = 1;\n')
        staged = root / 'results/_diagnostic_tsx_stage/CASE-REVIEW'
        staged.mkdir(parents=True)
        (staged / 'vulnerable_source.tsx').write_text('const stale = 2;\n')
        with patch.object(dv, 'ROOT', root), patch.object(dv, '_TSX_STAGE_CACHE', {}):
            target = dv.resolve_target_path('CASE-REVIEW', 'vulnerable_source', 'typescript')
            evidence['first_call_repairs_stale_and_missing'] = all(
                (staged / (stem + '.tsx')).read_bytes() == (case / (stem + '.ts')).read_bytes()
                for _, stem, _ in dv.SAMPLES)
            target.write_text('const stale_again = 3;\n')
            evidence['second_call_serves_stale_bytes'] = dv.resolve_target_path(
                'CASE-REVIEW', 'vulnerable_source', 'typescript').read_bytes() != (case / 'vulnerable_source.ts').read_bytes()
            (staged / 'patched_source.tsx').unlink()
            evidence['second_call_leaves_missing_file'] = not dv.resolve_target_path(
                'CASE-REVIEW', 'patched_source', 'typescript').exists()

    no_rule = {'attempts': [{'parsed': False, 'visible_evaluation': None}], 'final_rule_path': None}
    evidence['no_rule_categories'] = sorted(audit.audit_visible_stage(no_rule))
    wrong_location = {'scan_ok': True, 'legacy_accepted': True, 'visible_correct': False,
        'errors': [], 'samples': [
            {'sample_type': 'original_vulnerable', 'detected': True, 'finding_location_correct': False},
            {'sample_type': 'original_patched', 'detected': False}]}
    evidence['corrected_rejected_episode_categories'] = sorted(audit.audit_visible_stage({
        'acceptance_policy': 'corrected', 'final_rule_path': None,
        'attempts': [{'parsed': True, 'visible_evaluation': wrong_location}]}))
    evidence['target_only_failure_categories'] = sorted(audit.audit_visible_stage({'attempts': [{
        'parsed': True, 'visible_evaluation': {'scan_ok': False, 'samples': [], 'errors': [
            {'type': 'Parse error', 'path': 'target.ts', 'message': 'Target parse failed'},
            {'message': 'Semgrep exited with status 2'}]}}]}))

    evidence['runs'] = {}
    runs = ROOT / 'results/diagnostic_20261010'
    for name in ['qwen3_v3'] + [f'qwen3_mechanism_v{i}' for i in range(1, 6)]:
        episodes = [json.loads(p.read_text()) for p in sorted((runs / name).glob('CASE-*/episode.json'))]
        cats = {e['case_id']: audit.audit_visible_stage(e) for e in episodes}
        misses = [e for e in episodes if 'original_miss' in cats[e['case_id']]]
        never_clean = [e['case_id'] for e in misses if not any(
            (a.get('visible_evaluation') or {}).get('scan_ok') for a in e['attempts'])]
        clean_raw = [e['raw'] for e in episodes if e.get('raw') and e['raw']['scan_ok']]
        evidence['runs'][name] = {
            'visible_categories': {c: sum(c in cats[e['case_id']] for e in episodes) for c in audit.VISIBLE_CATEGORIES},
            'original_miss_without_clean_scan': never_clean,
            'original_miss_with_clean_scan': len(misses) - len(never_clean),
            'raw_hidden_denominator_labeled_accepted': sum(audit.categorize_hidden(e.get('raw')) is not None for e in episodes),
            'actual_legacy_accepted_raw': sum(e['legacy_accepted'] for e in clean_raw),
            'actual_corrected_accepted_raw': sum(e['visible_correct'] for e in clean_raw),
            'raw_complete_success': sum(bool(e.get('raw') and e['raw']['complete_success']) for e in episodes),
            'iterative_complete_success': sum(bool(e.get('iterative') and e['iterative']['complete_success']) for e in episodes)}

    # Binding-consistent rename of the only local variable. No attributes/strings changed.
    original = 'def probe():\n    token = "unsafe"\n    return locals()["token"]\n'
    class Rename(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id == 'token':
                return ast.copy_location(ast.Name(id='renamed_token', ctx=node.ctx), node)
            return node
    tree = ast.parse(original)
    renamed = ast.fix_missing_locations(Rename().visit(ast.parse(original)))
    class Normalize(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in ('token', 'renamed_token'):
                return ast.copy_location(ast.Name(id='LOCAL_BINDING', ctx=node.ctx), node)
            return node
    normalized_equal = ast.dump(Normalize().visit(ast.parse(original))) == ast.dump(Normalize().visit(ast.parse(ast.unparse(renamed))))
    ns_before, ns_after = {}, {}
    exec(compile(tree, '<original>', 'exec'), ns_before)
    exec(compile(renamed, '<renamed>', 'exec'), ns_after)
    before = ns_before['probe']()
    try:
        after = ns_after['probe']()
    except Exception as e:
        after = {'exception': type(e).__name__, 'message': str(e)}
    evidence['ast_probe_counterexample'] = {'original': original, 'renamed': ast.unparse(renamed),
        'trees_equal_except_identifier': normalized_equal, 'original_result': before, 'renamed_result': after}

    common = dict(id='review', message='m', severity='ERROR', languages=['python'], pattern='foo($X)')
    evidence['invalid_metadata_still_accepted'] = TypedRule(**common, metadata=['not a mapping']).to_dict()
    tr = TypedRule(**{**common, 'languages': ('python',)})
    try:
        yaml.safe_load(tr.to_semgrep_yaml())
        tuple_result = 'safe-loaded'
    except yaml.YAMLError as e:
        tuple_result = type(e).__name__
    evidence['accepted_tuple_languages_yaml_roundtrip'] = tuple_result

    if args.engine:
        def version(env=None):
            p = subprocess.run([str(dv.SEMGREP), '--version'], env=env, text=True, capture_output=True, timeout=30)
            return {'returncode': p.returncode, 'stdout': p.stdout.strip(), 'stderr': p.stderr.strip()}
        evidence['verifier_version_probe'] = version()
        evidence['scan_environment_version_probe'] = version(dv.semgrep_env(out))
    evidence['reviewed_files_unchanged'] = all(dv.sha(ROOT / p) == h for p, h in evidence['reviewed_sha256'].items())
    (out / 'findings.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print('Evidence:', out / 'findings.json')
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    main()

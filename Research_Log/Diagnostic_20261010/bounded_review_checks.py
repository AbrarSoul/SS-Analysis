"""Reproduce review findings without inference or edits to implementation/benchmarks.

Run with --semgrep to include local compiler checks and replay the saved baseline.
Each invocation writes to a fresh review artifact directory. Temporary fixtures are
isolated; recorded historical rules and episodes are read only.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'pipeline'), str(ROOT / 'autogrep')]
import audit_failure_categories as audit
import diagnostic_v2 as dv
from eligible_cases import load_manifest
from raw_capture import RawCaptureRecorder
from typed_rule import TypedRule
import yaml


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--semgrep', action='store_true')
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = Path(__file__).parent / ('bounded_review_artifacts_' + stamp)
    out.mkdir()
    evidence = {'artifact_directory': str(out), 'model_calls': 0}
    files = [ROOT / 'pipeline' / name for name in (
        'diagnostic_v2.py', 'typed_rule.py', 'audit_failure_categories.py',
        'verify_scan_integration.py', 'tests/test_diagnostic_regressions.py')]
    files += [Path(__file__).parent / 'Bounded_Investigation_Tracking.md',
              ROOT / 'Research_Log/Correction_Log.md']
    evidence['reviewed_sha256'] = {str(p.relative_to(ROOT)): dv.sha(p) for p in files}
    common = dict(id='review-example', message='Synthetic review fixture',
                  severity='WARNING', languages=['python'])
    evidence['empty_either_serialized'] = TypedRule(**common, pattern_either=[]).to_dict()
    evidence['string_either_serialized'] = TypedRule(**common, pattern_either='foo()').to_dict()
    evidence['taint_exclusion_dropped'] = TypedRule(
        **common, taint_sources=['source()'], taint_sinks=['sink($X)'],
        pattern_not=['sink("safe")']).to_dict()

    with tempfile.TemporaryDirectory() as tmp:
        temp = Path(tmp)
        count = []
        def generate(*a, **kw):
            count.append(kw.get('error_feedback'))
            return {**common, 'pattern': 'foo($X)'}
        def fake_scan(*a, **kw):
            return {'legacy_accepted': True, 'visible_correct': False,
                    'scan_ok': True, 'errors': [], 'complete_success': False,
                    'samples': [{'sample_type': 'original_patched', 'detected': False}]}
        with patch.object(dv, 'load_case', return_value=NS()), patch.object(dv, 'scan', side_effect=fake_scan):
            ep = dv.run_model_case('CASE-REVIEW', NS(generate_rule=generate), NS(),
                                  RawCaptureRecorder(temp, 'review'), {}, {}, temp)
        evidence['wrong_location_gate'] = {'calls': len(count),
            'accepted_final_rule': ep['final_rule_path'] is not None, 'feedback': count}
        fixture = temp / 'staging_fixture'
        case = fixture / 'benchmark/cases/CASE-REVIEW'
        case.mkdir(parents=True)
        (case / 'metadata.json').write_text(json.dumps({'changed_file': 'component.tsx'}))
        for _, stem, _ in dv.SAMPLES:
            (case / (stem + '.ts')).write_text('const original = 1;\n')
        with patch.object(dv, 'ROOT', fixture), patch.object(dv, '_TSX_STAGE_CACHE', {}):
            target = dv.resolve_target_path('CASE-REVIEW', 'vulnerable_source', 'typescript')
            target.write_text('const stale = 2;\n')
            target2 = dv.resolve_target_path('CASE-REVIEW', 'vulnerable_source', 'typescript')
            evidence['stale_stage_reused'] = target2.read_bytes() != (case / 'vulnerable_source.ts').read_bytes()
            missing = target.parent / 'patched_source.tsx'
            missing.unlink()
            evidence['partial_stage_not_repaired'] = not dv.resolve_target_path(
                'CASE-REVIEW', 'patched_source', 'typescript').exists()

    evidence['runs'] = {}
    runs = ROOT / 'results/diagnostic_20261010'
    for name in ['qwen3_v3'] + [f'qwen3_mechanism_v{i}' for i in range(1, 6)]:
        episodes = [json.loads(p.read_text()) for p in sorted((runs / name).glob('CASE-*/episode.json'))]
        stats = {}
        for condition in ['raw', 'iterative']:
            evaluations = [e.get(condition) for e in episodes]
            cats = [audit.categorize(e) for e in evaluations]
            stats[condition] = {'requested': len(episodes),
                'missing_evaluation': sum(e is None for e in evaluations),
                'success': sum(bool(e and e['complete_success']) for e in evaluations),
                'categories': {k: sum(k in c for c in cats if c is not None) for k in audit.CATEGORIES}}
        evidence['runs'][name] = stats
    evidence['synthetic_original_miss_categories'] = sorted(audit.categorize({
        'scan_ok': True, 'samples': [{'sample_type': 'original_vulnerable',
                                    'detected': False, 'finding_location_correct': False, 'outcome': 'FN'}]}))

    if args.semgrep:
        env = dv.semgrep_env(out)
        version = subprocess.run([str(dv.SEMGREP), '--version'], env=env, text=True, capture_output=True, timeout=30)
        evidence['semgrep_version'] = version.stdout.strip()
        if version.returncode or version.stdout.strip() != '1.177.0':
            raise RuntimeError('Pinned Semgrep unavailable: ' + version.stderr)
        target = out / 'example.py'
        target.write_text('foo("unsafe")\nfoo("safe")\n')
        example_rules = {
            'serialized_single_exclusion': TypedRule(**common, pattern='foo($X)', pattern_not=['foo("safe")']).to_dict(),
            'nested_exclusion_control': {**common, 'patterns': [{'pattern': 'foo($X)'}, {'pattern-not': 'foo("safe")'}]},
            'empty_either': evidence['empty_either_serialized'],
        }
        evidence['compiler_probes'] = {}
        for name, rule in example_rules.items():
            rulefile = out / (name + '.yml')
            rulefile.write_text(yaml.safe_dump({'rules': [rule]}, sort_keys=False))
            proc = subprocess.run([str(dv.SEMGREP), '--config', str(rulefile), '--json',
                '--metrics=off', '--disable-version-check', '--no-git-ignore', '--jobs=1', str(target)],
                env=env, text=True, capture_output=True, timeout=60)
            (out / (name + '.stdout.json')).write_text(proc.stdout)
            (out / (name + '.stderr.txt')).write_text(proc.stderr)
            parsed = json.loads(proc.stdout)
            evidence['compiler_probes'][name] = {'exit_code': proc.returncode,
                'finding_lines': [r['start']['line'] for r in parsed.get('results', [])],
                'errors': parsed.get('errors', [])}
            print(name, json.dumps(evidence['compiler_probes'][name]), flush=True)
        baseline = runs / 'qwen3_v3'
        ids = json.loads((baseline / 'selection.json').read_text())['case_ids']
        manifest, ann = load_manifest(), dv.load_merged_ann()
        episodes = []
        protected = list(baseline.rglob('episode.json')) + list(baseline.rglob('rule.yml'))
        protected += list(baseline.rglob('final_rule.yml'))
        protected += [p for cid in ids for p in (ROOT / 'benchmark/cases' / cid).iterdir() if p.is_file()]
        before = {str(p): dv.sha(p) for p in protected}
        for cid in ids:
            old = json.loads((baseline / cid / 'episode.json').read_text())
            ep = {'case_id': cid}
            for condition, path in [('raw', baseline / cid / 'attempt_1/rule.yml'),
                                    ('iterative', Path(old['final_rule_path']) if old.get('final_rule_path') else None)]:
                ep[condition] = dv.scan(path, cid, manifest, ann, out / 'replay' / cid / condition, hidden=True) if path and path.exists() else None
            episodes.append(ep)
            print('replayed', cid, flush=True)
        evidence['replay_summary'] = dv.report(episodes, ids, 'model')
        evidence['replay_preserved_input_files'] = len(before)
        evidence['replay_inputs_unchanged'] = all(dv.sha(Path(p)) == h for p, h in before.items())
        assert evidence['replay_inputs_unchanged']
    evidence['reviewed_files_unchanged'] = all(dv.sha(ROOT / p) == h for p, h in evidence['reviewed_sha256'].items())
    (out / 'findings.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    main()

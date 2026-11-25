"""Audit retained ablation results and probe pattern-inside semantics. No inference."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'pipeline'), str(ROOT / 'autogrep')]
import diagnostic_v2 as dv
from typed_rule import TypedRule
import yaml


def main():
    out = Path(__file__).parent / ('exclusion_review_artifacts_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir()
    env = dv.semgrep_env(out)
    proc = subprocess.run([str(dv.SEMGREP), '--version'], env=env, text=True, capture_output=True, timeout=30)
    assert proc.returncode == 0 and proc.stdout.strip() == '1.177.0'
    paths = [ROOT / 'pipeline' / p for p in ['typed_rule.py', 'exclusion_composition_ablation.py',
        'diagnostic_v2.py', 'audit_failure_categories.py', 'tests/test_typed_rule.py', 'tests/test_diagnostic_regressions.py']]
    paths += [ROOT / 'Research_Log/Correction_Log.md', Path(__file__).parent / 'Bounded_Investigation_Tracking.md']
    evidence = {'model_calls': 0, 'semgrep_version': proc.stdout.strip(),
        'reviewed_sha256': {str(p.relative_to(ROOT)): dv.sha(p) for p in paths}}
    ablation = ROOT / 'results/diagnostic_20261010/_exclusion_ablation_20261011T225111285041Z'
    summary = json.loads((ablation / 'summary.json').read_text())
    rows, losses, exclusion_losses, scan_failures = [], [], [], []
    fp_removed = []
    for row in summary['per_instance']:
        folder = ablation / row['run'] / row['case_id']
        evals = [json.loads((folder / (label + '_hidden/evaluation.json')).read_text())
                 for label in ['original', 'isolated', 'rewritten']]
        for label,e in zip(['original','isolated','rewritten'],evals):
            if not e['scan_ok']:
                scan_failures.append({'run':row['run'],'case_id':row['case_id'],'arm':label,'errors':e['errors']})
        assert all(len(e['samples']) == 6 for e in evals)
        assert len({tuple((s['sample_type'], s['sample_sha256']) for s in e['samples']) for e in evals}) == 1
        source = ROOT / row['source_path']
        assert dv.sha(source) == row['source_sha256'] == dv.sha(folder / 'original_rule.yml')
        hist = json.loads((source.parent / 'episode.json').read_text())['iterative']
        assert [s['outcome'] for s in hist['samples']] == [s['outcome'] for s in evals[0]['samples']]
        a,b,c = [e['complete_success'] for e in evals]
        rows.append((a,b,c))
        if a and not c: losses.append((row['run'],row['case_id']))
        if a and b and not c:
            r = yaml.safe_load(source.read_text())['rules'][0]
            exclusion_losses.append({'run':row['run'],'case_id':row['case_id'],'rule_id':r['id'],
                'pattern':r['pattern'],'pattern_not':r['pattern-not'],
                'exact_text_equal':r['pattern'].strip()==r['pattern-not'].strip(),
                'semantic_pair_sha256':hashlib.sha256(json.dumps([r['pattern'],r['pattern-not']]).encode()).hexdigest()})
        for s,t in zip(evals[0]['samples'],evals[2]['samples']):
            if s['sample_type'] in ['variant_safe','benign_lookalike'] and s['outcome']=='FP' and t['outcome']=='TN':
                fp_removed.append((row['run'],row['case_id'],s['sample_type']))
    evidence['retained_ablation'] = {'instances':len(rows),'gained':sum(not a and c for a,b,c in rows),
        'lost':len(losses),'unchanged':sum(a==c for a,b,c in rows),'losses':losses,
        'original_to_isolated_success_losses':sum(a and not b for a,b,c in rows),
        'isolated_to_rewritten_success_losses':len(exclusion_losses),
        'exclusion_loss_patterns':exclusion_losses,'hidden_fp_removed':fp_removed,
        'scan_failures':scan_failures,'all_126_scans_clean':not scan_failures,'all_source_hashes_and_sample_hashes_verified':True,
        'full_original_outcome_vectors_match_historical':True}

    py_target = out / 'scope.py'
    py_target.write_text('def allowed():\n    foo("inside")\n\nfoo("outside")\n')
    common = {'id':'scope-review','message':'Scope review','severity':'WARNING','languages':['python']}
    tr = TypedRule(**common, pattern='foo($X)', pattern_inside='def allowed(...):\n    ...')
    rule_path = ROOT / 'results/diagnostic_20261010/qwen3_mechanism_v4/CASE-0063/final_rule.yml'
    real = yaml.safe_load(rule_path.read_text())['rules'][0]
    js_common = {k:v for k,v in real.items() if not k.startswith('pattern')}
    real_target = ROOT / 'benchmark/cases/CASE-0063/variant_vulnerable_01.js'
    patterns = [('python_current_serializer',tr.to_dict(),py_target),
        ('python_nested_control',{**common,'patterns':[{'pattern':'foo($X)'},{'pattern-inside':'def allowed(...):\n    ...'}]},py_target),
        ('real_bare',{**js_common,'pattern':real['pattern']},real_target),
        ('real_sibling_named',{**js_common,'pattern':real['pattern'],'pattern-inside':real['pattern-inside']},real_target),
        ('real_nested_named',{**js_common,'patterns':[{'pattern':real['pattern']},{'pattern-inside':real['pattern-inside']}]},real_target),
        ('real_nested_anonymous',{**js_common,'patterns':[{'pattern':real['pattern']},{'pattern-inside':'function(...) { ... }'}]},real_target),
        ('real_sibling_impossible',{**js_common,'pattern':real['pattern'],'pattern-inside':'function REVIEW_DOES_NOT_EXIST(...) { ... }'},real_target)]
    evidence['scope_probes'] = {}
    for name,rule,target in patterns:
        rp = out / (name + '.yml')
        rp.write_text(yaml.safe_dump({'rules':[rule]},sort_keys=False))
        p = subprocess.run([str(dv.SEMGREP),'--config',str(rp),'--json','--metrics=off',
            '--disable-version-check','--no-git-ignore','--jobs=1',str(target)],env=env,text=True,capture_output=True,timeout=60)
        (out / (name + '.stdout.json')).write_text(p.stdout)
        (out / (name + '.stderr.txt')).write_text(p.stderr)
        d=json.loads(p.stdout)
        assert p.returncode==0 and not d.get('errors')
        evidence['scope_probes'][name]={'lines':[r['start']['line'] for r in d['results']],
                                      'scan_ok':True,'target_sha256':dv.sha(target)}
        print(name,evidence['scope_probes'][name],flush=True)
    evidence['reviewed_files_unchanged']=all(dv.sha(ROOT/p)==h for p,h in evidence['reviewed_sha256'].items())
    assert evidence['reviewed_files_unchanged']
    (out/'findings.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print('Evidence:',out/'findings.json')
    print(json.dumps(evidence['retained_ablation'],indent=2))


if __name__=='__main__':
    main()

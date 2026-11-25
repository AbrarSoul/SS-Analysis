"""Read-only arithmetic/integrity verification of the corrected exclusion ablation."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).parent


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    runs = ROOT / 'results/diagnostic_20261010'
    run = runs / '_exclusion_ablation_20261011T234010189193Z'
    summary = json.loads((run / 'summary.json').read_text())
    counts = Counter()
    lost_cases = Counter()
    failed_pairs = []
    for row in summary['per_instance']:
        folder = run / row['run'] / row['case_id']
        a,b = [json.loads((folder / (label + '_hidden/evaluation.json')).read_text()) for label in ['original','rewritten']]
        assert row['evaluable'] == (a['scan_ok'] and b['scan_ok'])
        assert sha(ROOT / row['source_path']) == row['source_sha256'] == sha(folder / 'original_rule.yml')
        assert [(s['sample_type'],s['sample_sha256']) for s in a['samples']] == [(s['sample_type'],s['sample_sha256']) for s in b['samples']]
        old = json.loads((ROOT / row['source_path']).with_name('episode.json').read_text())['iterative']
        assert [s['outcome'] for s in a['samples']] == [s['outcome'] for s in old['samples']]
        gain = not a['complete_success'] and b['complete_success']
        loss = a['complete_success'] and not b['complete_success']
        counts['gained'] += gain
        counts['lost'] += loss
        counts['unchanged'] += a['complete_success'] == b['complete_success']
        if loss:
            lost_cases[row['case_id']] += 1
        if not row['evaluable']:
            assert row['outcome_changes'] == {}
            failed_pairs.append([row['run'],row['case_id']])
            continue
        counts['evaluable'] += 1
        for x,y in zip(a['samples'],b['samples']):
            if x['sample_type'].startswith('variant_vulnerable'):
                counts['tp_lost'] += x['outcome']=='TP' and y['outcome']=='FN'
                counts['tp_gained'] += x['outcome']=='FN' and y['outcome']=='TP'
            if x['sample_type'] in ['variant_safe','benign_lookalike']:
                counts['fp_lost'] += x['outcome']=='FP' and y['outcome']=='TN'
                counts['fp_gained'] += x['outcome']=='TN' and y['outcome']=='FP'
    assert dict(counts) == {'gained':0,'lost':9,'unchanged':33,'evaluable':41,'tp_lost':20,'tp_gained':0,'fp_lost':0,'fp_gained':0}
    assert failed_pairs == [['qwen3_v3','CASE-0184']]
    assert dict(lost_cases) == {'CASE-0220':4,'CASE-0323':4,'CASE-0063':1}
    for field,key in [('complete_success_gained','gained'),('complete_success_lost','lost'),
                      ('complete_success_unchanged','unchanged'),('hidden_variant_true_positives_lost','tp_lost'),
                      ('hidden_negative_false_positives_lost','fp_lost'),('hidden_negative_false_positives_gained','fp_gained')]:
        assert summary[field] == counts[key]
    old_runs = ['_exclusion_ablation_20261011T224534542491Z','_exclusion_ablation_20261011T225111285041Z',run.name]
    assert all((runs / name / 'summary.json').exists() for name in old_runs)
    files = [ROOT/'pipeline'/name for name in ['typed_rule.py','tests/test_typed_rule.py','exclusion_composition_ablation.py']]
    files += [ROOT/'Research_Log/Correction_Log.md',AUDIT/'Bounded_Investigation_Tracking.md']
    result={'verified_utc':datetime.now(timezone.utc).isoformat(),'counts':dict(counts),
            'complete_success_losses_by_case':dict(lost_cases),'unevaluable_pairs':failed_pairs,
            'preserved_run_summaries':{name:sha(runs/name/'summary.json') for name in old_runs},
            'reviewed_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'model_calls':0,
            'source_hashes_sample_hashes_and_original_outcome_vectors_verified':True}
    out=AUDIT/'Corrected_Ablation_Verification_20261012.json'
    with out.open('x') as f:
        json.dump(result,f,indent=2)
        f.write('\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()

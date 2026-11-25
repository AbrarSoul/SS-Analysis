"""Audit retained Item 3 scans and calculate a specified McNemar power scenario.

Reads existing research evidence; performs no inference or Semgrep scans. Prints
JSON to stdout so diagnostic_audit.py can retain the result without overwriting it.
The power calculation concerns ONE independent paired outcome per case, not the
draft's as-yet-unspecified repeated-trial or repository-clustered analysis.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import numpy as np
import scipy
from scipy.stats import binom

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def power_scenario(delta, q=0.25, alpha=0.05, max_n=1200):
    # D ~ Binomial(N,q); W | D ~ Binomial(D, (q+delta)/(2q)).
    # Under H0 the conditional win probability is 1/2.
    conditional = []
    for d in range(max_n + 1):
        k = np.arange(d + 1)
        reject = 2 * binom.cdf(np.minimum(k, d - k), d, 0.5) <= alpha
        conditional.append(float(binom.pmf(k, d, (q + delta) / (2 * q))[reject].sum()))

    def power(n):
        return float(np.dot(binom.pmf(np.arange(n + 1), n, q), conditional[:n + 1]))

    first = next(n for n in range(1, max_n + 1) if power(n) >= 0.8)
    return {
        "absolute_difference": delta, "discordance": q, "two_sided_alpha": alpha,
        "alternative_win_probability": (q + delta) / 2,
        "alternative_loss_probability": (q - delta) / 2,
        "first_n_with_at_least_80_percent_power": first,
        "power_by_n": {n: power(n) for n in sorted({80, 100, 200, first})},
    }


def main():
    folder = ROOT / 'results/diagnostic_20261010/_item3_reference_rule_check'
    summary = json.loads((folder / 'summary.json').read_text())
    assert len(summary) == 24
    counts, fp_cases, reviewed = Counter(), {}, {}
    for cid, row in sorted(summary.items()):
        ep, rawp = folder / cid / 'evaluation.json', folder / cid / 'stdout.json'
        evaluation, raw = json.loads(ep.read_text()), json.loads(rawp.read_text())
        assert evaluation['scan_ok'] and evaluation['returncode'] == 0
        assert evaluation['all_targets_scanned'] and not evaluation['errors']
        assert raw['version'] == '1.177.0' and not raw['errors']
        assert row['outcomes'] == {s['sample_type']: s['outcome'] for s in evaluation['samples']}
        assert len(evaluation['samples']) == 6
        assert row['complete_success'] == evaluation['complete_success']
        scanned = {str(Path(p).resolve()) for p in raw['paths']['scanned']}
        for sample in evaluation['samples']:
            path = ROOT / sample['sample_path']
            assert sha(path) == sample['sample_sha256']
            assert str(path.resolve()) in scanned
            lines = [r['start']['line'] for r in raw['results']
                     if Path(r['path']).resolve() == path.resolve()]
            assert lines == sample['finding_lines']
            assert bool(lines) == sample['detected']
            if sample['label'] == 'positive':
                assert sample['finding_location_correct'] and sample['outcome'] == 'TP'
            else:
                assert sample['outcome'] == ('FP' if lines else 'TN')
            counts[sample['outcome']] += 1
        assert evaluation['complete_success'] == all(
            s['outcome'] in {'TP', 'TN'} for s in evaluation['samples'])
        counts['complete_success'] += evaluation['complete_success']
        fps = [s['sample_type'] for s in evaluation['samples'] if s['outcome'] == 'FP']
        if fps:
            fp_cases[cid] = fps
        for p in [ep, rawp]:
            reviewed[str(p.relative_to(ROOT))] = sha(p)
    assert len(fp_cases) == 9
    for p in [folder / 'summary.json', AUDIT / 'Controlled_2x2_Protocol_Draft_20261012.md',
              AUDIT / 'Bounded_Investigation_Tracking.md', ROOT / 'Research_Log/Correction_Log.md',
              ROOT / 'pipeline/diagnostic_v2.py', ROOT / 'pipeline/typed_rule.py',
              ROOT / 'pipeline/tests/test_typed_rule.py', Path(__file__)]:
        reviewed[str(p.relative_to(ROOT))] = sha(p)
    print(json.dumps({
        'verified_utc': datetime.now(timezone.utc).isoformat(),
        'reference_cases': len(summary), 'sample_outcomes': dict(counts),
        'precision_gap_cases': fp_cases,
        'limitations': [
            'Location correctness checked against retained evaluation fields; annotations not independently adjudicated.',
            'Passing a reference rule does not establish transformation semantics.',
            'Power scenarios omit repeated-trial correlation, repository clustering and multiplicity.',
        ],
        'power_method': 'Two-sided exact conditional McNemar; unconditional power summed over discordance count.',
        'power_scenarios': [power_scenario(0.10), power_scenario(0.05)],
        'scipy_version': scipy.__version__, 'reviewed_sha256': reviewed,
        'model_calls': 0, 'new_semgrep_scans': 0,
    }, indent=2))


if __name__ == '__main__':
    main()

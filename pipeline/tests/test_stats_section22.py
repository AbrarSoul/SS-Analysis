"""
Known-answer verification for pipeline/stats_section22.py -- run BEFORE trusting these functions
on real Section 22 data, same discipline as every other piece of analysis code in this project.

Usage: PATH=.venv/bin:$PATH python pipeline/tests/test_stats_section22.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stats_section22 import mcnemar_exact, holm_correct, paired_case_bootstrap, friedman_on_matrix, wilcoxon_paired

FAILURES = []


def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


# 1. McNemar exact: classic textbook example (b=10, c=2) -- exact binomial two-sided p-value for
# this discordant split is a well-known reference value: 0.038574...
p = mcnemar_exact(10, 2)
check("mcnemar_exact(10,2) matches known textbook p-value", abs(p - 0.038574) < 1e-4, f"got {p}")

# 2. McNemar exact: b==c (no disagreement direction) must give p=1.0
p = mcnemar_exact(5, 5)
check("mcnemar_exact(5,5) == 1.0 (perfectly balanced discordance)", abs(p - 1.0) < 1e-9, f"got {p}")

# 3. McNemar exact: zero discordant pairs -> defined as p=1.0 (no evidence either way)
p = mcnemar_exact(0, 0)
check("mcnemar_exact(0,0) == 1.0 (no discordant pairs)", p == 1.0, f"got {p}")

# 4. Holm correction: classic example, raw p=[0.01, 0.02, 0.03, 0.04], m=4
# Holm: sorted ascending, multiply by (m - rank): 0.01*4=0.04, 0.02*3=0.06, 0.03*2=0.06, 0.04*1=0.04
# then enforce monotonicity (running max): 0.04, 0.06, 0.06, 0.06
raw = [0.01, 0.02, 0.03, 0.04]
adj = holm_correct(raw)
expected = [0.04, 0.06, 0.06, 0.06]
check("holm_correct basic 4-test example", all(abs(a - e) < 1e-9 for a, e in zip(adj, expected)),
      f"got {adj}, expected {expected}")

# 5. Holm correction: order-independence -- each hypothesis's adjusted p-value should depend only
# on its OWN raw p-value and its rank among the others, not on input order. raw2 is a permutation of
# raw=[0.01,0.02,0.03,0.04] (index0->0.04, index1->0.01, index2->0.03, index3->0.02); sorted ascending
# the processing order is index1(0.01,rank0)->adj 0.04, index3(0.02,rank1)->adj 0.06,
# index2(0.03,rank2)->adj 0.06, index0(0.04,rank3)->raw contribution 0.04*1=0.04 but monotonicity
# clamps it UP to the running max 0.06 (Holm-adjusted p-values must be non-decreasing in sorted
# rank) -- so index0 ends up at 0.06 here even though its RAW p-value alone would give 0.04; this
# is correct Holm behavior (verified against the standard algorithm), not a bug.
raw2 = [0.04, 0.01, 0.03, 0.02]
adj2 = holm_correct(raw2)
expected2 = [0.06, 0.04, 0.06, 0.06]
check("holm_correct order-independence", all(abs(a - e) < 1e-9 for a, e in zip(adj2, expected2)),
      f"got {adj2}, expected {expected2}")

# 6. Paired case bootstrap: a trivial case where A is always better by a fixed margin -- CI should
# be tight around the known difference and definitely exclude zero (p should be very small)
unit_ids = list(range(50))
VALUES_A = {i: 0.8 for i in unit_ids}
VALUES_B = {i: 0.5 for i in unit_ids}


def metric_a(ids):
    return sum(VALUES_A[i] for i in ids) / len(ids)


def metric_b(ids):
    return sum(VALUES_B[i] for i in ids) / len(ids)


diff, lo, hi, pval = paired_case_bootstrap(unit_ids, metric_a, metric_b, n_boot=2000)
check("paired_case_bootstrap: constant difference detected correctly",
      abs(diff - 0.3) < 1e-9 and lo > 0 and hi > 0 and pval < 0.01,
      f"diff={diff}, CI=({lo},{hi}), p={pval}")

# 7. Paired case bootstrap: no real difference (both conditions identical) -> CI should straddle
# zero, p should NOT be small
VALUES_A_null = {i: (i % 2) * 1.0 for i in unit_ids}
VALUES_B_null = dict(VALUES_A_null)


def metric_a_null(ids):
    return sum(VALUES_A_null[i] for i in ids) / len(ids)


def metric_b_null(ids):
    return sum(VALUES_B_null[i] for i in ids) / len(ids)


diff, lo, hi, pval = paired_case_bootstrap(unit_ids, metric_a_null, metric_b_null, n_boot=2000)
check("paired_case_bootstrap: null case (identical conditions) -> diff=0, p=1.0",
      diff == 0.0 and lo <= 0 <= hi and pval == 1.0,
      f"diff={diff}, CI=({lo},{hi}), p={pval}")

# 8. Friedman on matrix: a clear, strong pattern across 3 conditions should be significant
matrix = [[1, 0, 0], [1, 0, 0], [1, 1, 0], [1, 0, 0], [1, 1, 0], [1, 0, 1], [1, 0, 0], [1, 1, 0]] * 3
stat, p = friedman_on_matrix(matrix)
check("friedman_on_matrix: clear pattern is significant", stat is not None and p < 0.05, f"stat={stat}, p={p}")

# 9. Friedman on matrix: all-identical rows -> degenerate, handled gracefully (None, None)
matrix_degenerate = [[1, 1, 1]] * 10
stat, p = friedman_on_matrix(matrix_degenerate)
check("friedman_on_matrix: degenerate all-tied input handled without crashing", stat is None and p is None,
      f"stat={stat}, p={p}")

# 10. Wilcoxon paired: clear one-directional difference should be significant
a = [5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0]
b = [3.0, 3.5, 4.0, 4.5, 5.0, 5.5, 6.0, 6.5]
stat, p = wilcoxon_paired(a, b)
check("wilcoxon_paired: clear difference is significant", stat is not None and p < 0.05, f"stat={stat}, p={p}")

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All stats_section22 checks PASSED.")
    sys.exit(0)

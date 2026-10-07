"""
Statistical primitives for Section 22 (design doc) -- hand-rolled McNemar/Holm (no statsmodels
dependency, see Research_Log/Section22_Scope.md), plus a case-level paired bootstrap for pooled
metrics (MCC/VGR/FPR/PDS) where classic Wilcoxon doesn't directly apply (there is no natural
per-case MCC value -- see the scope doc's methodology section for why).

Every function here is verified against a known-answer example in
pipeline/tests/test_stats_section22.py before being trusted on real data.
"""
import random
from scipy.stats import binomtest, friedmanchisquare, wilcoxon


def mcnemar_exact(b: int, c: int) -> float:
    """Exact McNemar's test on the two discordant-pair counts (b = A-wins, c = B-wins among pairs
    where the two conditions disagree). Two-sided exact binomial test under p=0.5, the standard
    small-sample-exact form of McNemar's test (equivalent to the classic chi-square form in the
    large-sample limit, preferred here since discordant-pair counts in this study are often small)."""
    n = b + c
    if n == 0:
        return 1.0
    return binomtest(min(b, c), n=n, p=0.5, alternative="two-sided").pvalue


def holm_correct(pvalues: list) -> list:
    """Holm-Bonferroni step-down correction. Returns adjusted p-values in the SAME order as the
    input (not sorted), each already clamped to the running max for monotonicity."""
    m = len(pvalues)
    indexed = sorted(range(m), key=lambda i: pvalues[i])
    adjusted = [None] * m
    running_max = 0.0
    for rank, i in enumerate(indexed):
        adj = (m - rank) * pvalues[i]
        running_max = max(running_max, adj)
        adjusted[i] = min(running_max, 1.0)
    return adjusted


def paired_case_bootstrap(unit_ids: list, metric_fn_a, metric_fn_b, n_boot: int = 10000, seed: int = 42):
    """Case-level (or repo-level, if unit_ids are repo ids with cases pre-grouped into metric_fn's
    closures) paired bootstrap for a POOLED metric difference (metric_a - metric_b).

    metric_fn_a/metric_fn_b: callables taking a list of resampled unit_ids (with repetition) and
    returning the pooled metric value for that resample, for condition A and B respectively.

    Returns (observed_diff, ci_lo, ci_hi, p_value) -- p_value is the two-sided bootstrap p-value
    (2x the smaller tail proportion past zero, capped at 1.0).
    """
    rng = random.Random(seed)
    n = len(unit_ids)
    observed_diff = metric_fn_a(unit_ids) - metric_fn_b(unit_ids)

    diffs = []
    for _ in range(n_boot):
        resample = [unit_ids[rng.randrange(n)] for _ in range(n)]
        diffs.append(metric_fn_a(resample) - metric_fn_b(resample))
    diffs.sort()

    lo_idx = int(0.025 * n_boot)
    hi_idx = int(0.975 * n_boot) - 1
    ci_lo, ci_hi = diffs[lo_idx], diffs[hi_idx]

    n_le_zero = sum(1 for d in diffs if d <= 0)
    n_ge_zero = sum(1 for d in diffs if d >= 0)
    tail = min(n_le_zero, n_ge_zero) / n_boot
    p_value = min(1.0, 2 * tail)

    return observed_diff, ci_lo, ci_hi, p_value


def friedman_on_matrix(matrix: list) -> tuple:
    """matrix: list of rows, one per case, each row a list of per-condition values (same length,
    same condition order, for cases present in ALL conditions being compared). Returns
    (statistic, p_value) from scipy's friedmanchisquare, or (None, None) if degenerate -- either
    scipy raises ValueError (e.g. fewer than 3 conditions) or silently returns NaN (e.g. every row
    identical across conditions, zero rank variance -- confirmed this is scipy's real behavior here,
    not assumed, since it emits a RuntimeWarning rather than raising)."""
    columns = list(zip(*matrix))
    try:
        stat, p = friedmanchisquare(*columns)
    except ValueError:
        return None, None
    if stat != stat:  # NaN check without importing math/numpy just for this
        return None, None
    return stat, p


def wilcoxon_paired(a: list, b: list) -> tuple:
    """Thin wrapper over scipy's Wilcoxon signed-rank test for genuinely paired per-case scalars
    (latency, tokens, cost). Returns (statistic, p_value), or (None, None) if all differences are
    zero (scipy raises in that case rather than returning a degenerate p=1.0)."""
    try:
        stat, p = wilcoxon(a, b)
    except ValueError:
        return None, None
    return stat, p

"""
THE single, versioned source of truth for which cases are eligible for which analysis population.
Every analysis script must import from here rather than reading `semgrep_representability` off the
manifest directly -- this is Priority 3's explicit requirement ("one versioned manifest used by
every analysis script"), built in response to the 2026-10-06/07 and 2026-10-07 (round 2) audits.

Encodes, in one place, every correction made to case eligibility:
  - CASE-0166: excluded entirely (post-hoc audit exclusion, Correction_Log.md -- upstream patched
    revision does not compile, confirmed against the real GitHub commit).
  - CASE-0125/0140/0156/0174/0194: excluded from their respective representability population
    specifically (not from the dataset entirely) because the LABELED vulnerability's upstream fix
    is measurably still exploitable -- benchmark/ground_truth_exclusions.json has the full
    per-case reasoning.

Versioned: VERSION bumps whenever the eligibility logic itself changes (not when case data changes
for unrelated reasons), so every analysis output can cite exactly which version of the eligibility
rules produced it.
"""
import json
from pathlib import Path

VERSION = "2026-10-07.1"

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"

POST_HOC_DATASET_EXCLUSIONS = {"CASE-0166"}  # excluded from the dataset entirely


def _load_ground_truth_exclusions():
    data = json.loads((BENCH_DIR / "ground_truth_exclusions.json").read_text())
    return {r["case_id"] for r in data["excluded_cases"]}


GROUND_TRUTH_EXCLUSIONS = _load_ground_truth_exclusions()


def load_manifest():
    """Full manifest, with CASE-0166 removed (post-hoc dataset exclusion)."""
    rows = [json.loads(l) for l in (BENCH_DIR / "manifest_frozen_final.jsonl").read_text().splitlines()]
    return {r["case_id"]: r for r in rows if r["case_id"] not in POST_HOC_DATASET_EXCLUSIONS}


def case_counts(manifest=None):
    """Returns the current dataset's case counts by population, AFTER both corrections."""
    manifest = manifest or load_manifest()
    counts = {"total": len(manifest), "supported": 0, "partially_supported": 0, "unsupported": 0,
              "supported_ground_truth_excluded": 0, "partially_supported_ground_truth_excluded": 0}
    for cid, r in manifest.items():
        rep = r["semgrep_representability"]
        if cid in GROUND_TRUTH_EXCLUSIONS:
            counts[f"{rep}_ground_truth_excluded"] = counts.get(f"{rep}_ground_truth_excluded", 0) + 1
        else:
            counts[rep] = counts.get(rep, 0) + 1
    return counts


def eligible_supported_cases(manifest=None):
    """The primary comparison population: semgrep_representability == 'supported', minus the 3
    cases excluded for a measurably-unfixed labeled vulnerability (CASE-0140/0156/0194).
    This is the set every C2/C3/C4/primary-benchmark headline comparison should use going forward."""
    manifest = manifest or load_manifest()
    return {cid for cid, r in manifest.items()
            if r["semgrep_representability"] == "supported" and cid not in GROUND_TRUTH_EXCLUSIONS}


def eligible_partially_supported_cases(manifest=None):
    """The secondary (partially-supported) population, minus CASE-0125/0174."""
    manifest = manifest or load_manifest()
    return {cid for cid, r in manifest.items()
            if r["semgrep_representability"] == "partially_supported" and cid not in GROUND_TRUTH_EXCLUSIONS}


def excluded_supported_cases(manifest=None):
    """The 3 cases removed from the supported population specifically (for sensitivity analysis:
    compare results with vs. without them)."""
    manifest = manifest or load_manifest()
    return {cid for cid, r in manifest.items()
            if r["semgrep_representability"] == "supported" and cid in GROUND_TRUTH_EXCLUSIONS}


if __name__ == "__main__":
    m = load_manifest()
    c = case_counts(m)
    print(f"Eligibility module version {VERSION}")
    print(f"Total cases (post CASE-0166 exclusion): {c['total']}")
    print(f"  supported: {c['supported']} (+ {c.get('supported_ground_truth_excluded', 0)} ground-truth-excluded)")
    print(f"  partially_supported: {c['partially_supported']} (+ {c.get('partially_supported_ground_truth_excluded', 0)} ground-truth-excluded)")
    print(f"  unsupported: {c['unsupported']}")
    print(f"Eligible supported (primary population): {len(eligible_supported_cases(m))}")
    print(f"Eligible partially_supported: {len(eligible_partially_supported_cases(m))}")

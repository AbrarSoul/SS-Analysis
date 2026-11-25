"""
Research_Direction_20261011.md item 2: audit every saved output by failure category.

Rewritten 2026-10-12 after an independent review found the original version only ever looked at
`episode[condition]` (the hidden-stage evaluation, which is None for any case that was never
accepted) -- across the 6 real datasets, 57/144 requested episodes have no accepted-final
evaluation at all and so contributed to NONE of the original script's categories. This version uses
the RETAINED ATTEMPT RECORDS (`episode["attempts"]`, present for every one of the 24 requested cases
regardless of outcome) for the visible/construction-stage categories, so every requested episode is
actually accounted for.

Rewritten AGAIN, same day, after a follow-up review found three further issues in that rewrite,
each independently reproduced before fixing:
  1. The "raw" hidden-stage denominator was labeled "accepted" but only actually checked scan_ok --
     for mechanism_v1 it counted 19 "accepted" when only 6 passed real legacy_accepted (confirmed:
     19 vs 6, exact). Fixed: the raw condition's hidden categories are now explicitly labeled
     "scanned successfully" (what they actually measure -- attempt 1's rule, whatever its visible-
     acceptance status, run against all 6 samples), with the true legacy-accepted count reported
     alongside as a separate, explicitly distinct number, never conflated.
  2. `original_miss` conflated "clean scan, genuinely never detected" with "never got a clean scan
     to check at all" -- confirmed 10 + 2 = 12 for mechanism_v1's original count. Split into
     `original_miss_clean` and `original_unevaluable`.
  3. The acceptance gate was hardcoded to `legacy_accepted` regardless of which `--acceptance-policy`
     the run actually used. Fixed: reads `environment.json`'s `acceptance_policy` field and gates on
     the matching evaluation field (`legacy_accepted` or `visible_correct`) accordingly. No existing
     dataset is affected by this (all 6 real runs used the "legacy" default), but a future
     "corrected"-policy run would have been silently misattributed without this fix.

Rewritten a THIRD time, same day, after a round-3 review found `_is_target_error` was the only
classifier: "any error without a 'path' key" was treated as `rule_construction_error`. This folds
diagnostic_v2.py's own synthetic status-wrapper messages ("Semgrep exited with status N", "Semgrep
did not scan every requested sample", "Semgrep did not return JSON" -- none of which carry a "path"
and none of which are Semgrep's own report of a malformed rule) into the rule-construction count.
Reproduced the double-count with a synthetic fixture (a target-file syntax error plus a generic
exit-status message in the same errors list, labeled BOTH target_error and rule_construction_error).
Checked every real retained episode across all 6 datasets for this exact co-occurrence
(path-error + non-path-error in the same scan's errors list): it never happens -- whenever a
non-path error appears, it is always a genuine Semgrep-reported rule error (Rule parse error,
Invalid rule schema, invalid configuration file found), never only a status wrapper, and status
wrappers never appear alongside a path-based target error either. So no historical
rule_construction_error/target_error count changes. Fixed anyway, since the classifier was wrong in
general, not just unlucky to not yet have mattered: `_is_status_wrapper()` now recognizes
diagnostic_v2.py's own synthetic messages by content and excludes them from both real categories; a
new `unclassified_scan_error` category catches the (empirically never-occurring, but not silently
absorbed either) case of a scan_ok=False attempt whose errors are ONLY status wrappers.

Two separate analyses, not blended into one table:
  1. VISIBLE-STAGE, every requested episode (`audit_visible_stage`): never_parsed,
     rule_construction_error (a genuine Semgrep-reported RULE-level error -- Rule parse error /
     Invalid rule schema / invalid configuration file found, no "path" key and not a status
     wrapper), target_error (a TARGET-file-level error -- has a "path" key),
     unclassified_scan_error (scan failed but every error was a status wrapper -- never occurs in
     retained data, kept so a future run can't fall silently into rule_construction_error by
     default), original_miss_clean, original_unevaluable, wrong_location, patched_fp,
     never_accepted (per the run's own actual acceptance_policy). A case can hit more than one.
  2. HIDDEN-STAGE (`categorize_hidden`): renamed_miss / structural_miss / safe_benign_fp. For
     "iterative" this is genuinely conditional on acceptance (iterative's evaluation only exists for
     accepted cases at all). For "raw" this is conditional on attempt 1 having scanned successfully
     -- NOT on acceptance -- labeled accordingly so the denominator's meaning is never implied to be
     something it isn't.

Usage:
    python pipeline/audit_failure_categories.py <run_name>   # e.g. qwen3_v3
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

VISIBLE_CATEGORIES = ["never_parsed", "rule_construction_error", "target_error",
                       "unclassified_scan_error", "original_miss_clean", "original_unevaluable",
                       "wrong_location", "patched_fp", "never_accepted"]
HIDDEN_CATEGORIES = ["renamed_miss", "structural_miss", "safe_benign_fp"]

# diagnostic_v2.py's own synthetic wrapper messages (scan.py's scan(), not Semgrep's JSON output) --
# process/exit-status commentary about the scan run, never Semgrep's own report that the rule file
# itself is malformed. Matched by exact content since these are hardcoded string literals in
# diagnostic_v2.py, not a schema field.
_STATUS_WRAPPER_MESSAGES = {"Semgrep did not return JSON", "Semgrep did not scan every requested sample"}


def _is_status_wrapper(err: dict) -> bool:
    msg = err.get("message", "")
    return msg in _STATUS_WRAPPER_MESSAGES or msg.startswith("Semgrep exited with status ")


def _is_target_error(err: dict) -> bool:
    return "path" in err


def _is_rule_construction_error(err: dict) -> bool:
    return not _is_target_error(err) and not _is_status_wrapper(err)


def acceptance_field_for(run_dir: Path) -> str:
    """Reads the run's own recorded --acceptance-policy (added 2026-10-12) rather than assuming
    'legacy' -- a run using 'corrected' must be attributed against visible_correct, not
    legacy_accepted. Pre-2026-10-12 runs have no such field recorded; those were all generated under
    the only policy that existed then (legacy), so that's the correct default for them specifically,
    not a guess."""
    env_path = run_dir / "environment.json"
    if env_path.exists():
        policy = json.loads(env_path.read_text()).get("acceptance_policy", "legacy")
    else:
        policy = "legacy"
    return "visible_correct" if policy == "corrected" else "legacy_accepted"


def audit_visible_stage(episode: dict, accept_field: str) -> set:
    """Walks every retained attempt (not just the final accepted one) so every requested episode
    gets a real category, never silently excluded."""
    cats = set()
    attempts = episode.get("attempts", [])
    any_parsed = any(a["parsed"] for a in attempts)
    if not any_parsed:
        cats.add("never_parsed")

    ever_detected_vuln = False
    ever_correct_location = False
    ever_clean_scan = False
    any_accepted = False
    for a in attempts:
        ev = a.get("visible_evaluation")
        if ev is None:
            continue
        if not ev["scan_ok"]:
            errs = ev["errors"]
            if any(_is_target_error(e) for e in errs):
                cats.add("target_error")
            if any(_is_rule_construction_error(e) for e in errs):
                cats.add("rule_construction_error")
            if errs and all(_is_status_wrapper(e) for e in errs):
                cats.add("unclassified_scan_error")
            continue
        ever_clean_scan = True
        by_type = {s["sample_type"]: s for s in ev["samples"]}
        vuln = by_type.get("original_vulnerable")
        if vuln and vuln["detected"]:
            ever_detected_vuln = True
            if vuln["finding_location_correct"]:
                ever_correct_location = True
        patched = by_type.get("original_patched")
        if patched and patched["detected"]:
            cats.add("patched_fp")
        if ev.get(accept_field):
            any_accepted = True

    if not ever_detected_vuln:
        cats.add("original_miss_clean" if ever_clean_scan else "original_unevaluable")
    elif not ever_correct_location:
        cats.add("wrong_location")
    if not any_accepted:
        cats.add("never_accepted")
    return cats


def categorize_hidden(evaluation):
    """Only ever meaningful for cases where the evaluation exists AND scanned successfully.
    Returns None otherwise. Deliberately does NOT additionally gate on acceptance here -- for the
    'iterative' condition that's automatic (the evaluation itself only exists for accepted cases);
    for 'raw' it would shrink the denominator in a way that conflates two different questions (see
    module docstring) -- callers must report what this denominator actually means per condition."""
    if evaluation is None or not evaluation["scan_ok"]:
        return None
    cats = set()
    by_type = {s["sample_type"]: s for s in evaluation["samples"]}
    v1 = by_type.get("variant_vulnerable_1")
    if v1 and v1["outcome"] == "FN":
        cats.add("renamed_miss")
    v2 = by_type.get("variant_vulnerable_2")
    if v2 and v2["outcome"] == "FN":
        cats.add("structural_miss")
    for neg in ("variant_safe", "benign_lookalike"):
        s = by_type.get(neg)
        if s and s["detected"]:
            cats.add("safe_benign_fp")
    return cats


def main():
    run_name = sys.argv[1] if len(sys.argv) > 1 else "qwen3_v3"
    run_dir = ROOT / "results/diagnostic_20261010" / run_name
    selection = json.loads((run_dir / "selection.json").read_text())
    ids = selection["case_ids"]
    n_requested = len(ids)
    accept_field = acceptance_field_for(run_dir)
    print(f"(acceptance field used for this run: {accept_field})")

    print(f"\n{'='*90}\n{run_name} -- VISIBLE STAGE, all {n_requested} requested episodes\n{'='*90}")
    visible_cats = {}
    for cid in ids:
        ep = json.loads((run_dir / cid / "episode.json").read_text())
        cats = audit_visible_stage(ep, accept_field)
        visible_cats[cid] = cats
        print(f"  {cid:12s} {', '.join(sorted(cats)) if cats else 'none'}")
    print(f"\n  All-{n_requested}-requested denominator:")
    for cat in VISIBLE_CATEGORIES:
        count = sum(1 for c in visible_cats.values() if cat in c)
        print(f"    {cat:26s} {count:3d}/{n_requested}")

    for condition in ("raw", "iterative"):
        print(f"\n{'='*90}\n{run_name} -- HIDDEN STAGE, {condition} condition\n{'='*90}")
        hidden_cats = {}
        true_accepted = {}
        for cid in ids:
            ep = json.loads((run_dir / cid / "episode.json").read_text())
            ev = ep.get(condition)
            hidden_cats[cid] = categorize_hidden(ev)
            true_accepted[cid] = bool(ev and ev.get(accept_field))
        n_scanned = sum(1 for c in hidden_cats.values() if c is not None)
        n_true_accepted = sum(true_accepted.values())
        if condition == "raw":
            print(f"  n_scanned_successfully = {n_scanned}/{n_requested} -- NOT the same as accepted; "
                  f"of those, n_actually_accepted ({accept_field}) = {n_true_accepted}")
            print(f"  percentages below are of n_scanned_successfully ({n_scanned}), i.e. 'given attempt 1 "
                  f"produced a scannable rule' -- not conditional on acceptance")
        else:
            print(f"  n_accepted (reached this stage, {accept_field}) = {n_scanned}/{n_requested} "
                  f"-- percentages below are of THIS denominator, not {n_requested}")
            assert n_scanned == n_true_accepted, "iterative's evaluation existing should always imply accepted"
        for cat in HIDDEN_CATEGORIES:
            count = sum(1 for c in hidden_cats.values() if c is not None and cat in c)
            print(f"    {cat:26s} {count:3d}/{n_scanned}" if n_scanned else f"    {cat:26s} n/a")


if __name__ == "__main__":
    main()

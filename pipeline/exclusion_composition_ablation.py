"""
Exploratory deterministic composition ablation, per the round-3 review's recommended protocol
(Bounded_Investigation_Round3_Review_20261012.md, "Recommended next research step").

Context: `pipeline/typed_rule.py`'s own fix (Correction_Log.md, 2026-10-12) confirmed that a rule
with a top-level sibling `pattern` + `pattern-not` (optionally also `pattern-inside` /
`pattern-not-inside`) silently fails to exclude anything under real pinned Semgrep 1.177.0
execution, despite passing `semgrep --validate` cleanly. The frozen inventory
(`Research_Log/Diagnostic_20261010/bounded_followup_artifacts_20261011T215946041546Z/
historical_exclusion_inventory.json`) found 42 of the 87 historically-accepted rules across the 6
real diagnostic runs use exactly this form -- including all 19 of qwen3_v3's accepted rules. This
means some unknown fraction of those 42 rules may never have actually excluded anything via their
`pattern-not`, which would make their reported TP/FP/complete_success outcomes potentially wrong in
a way unrelated to any genuine model-capability limitation.

This script does NOT change any historical rule, result, or already-reported number. It:
  1. Loads the frozen inventory (not re-derived -- the set of 42 is fixed input, verified once).
  2. For each of the 42, builds a SEPARATE rewritten rule that changes ONLY composition -- the
     literal pattern strings, languages, message, severity, id, and metadata are byte-identical;
     `pattern`/`pattern-inside`/`pattern-not`/`pattern-not-inside` are moved from top-level siblings
     into one `patterns:` list, the composition form independently confirmed (by typed_rule.py's own
     test) to actually enforce exclusion/scope correctly. Any rule not matching the pre-specified
     {pattern, pattern-not, pattern-inside?, pattern-not-inside?} shape is rejected and reported
     separately, never given an improvised per-case edit.
  3. Scans BOTH the original and the rewritten rule against all 6 hidden samples, same pinned
     engine/TSX staging/annotations as every other scan in this project, under a fresh, isolated
     output directory -- never touching results/diagnostic_20261010/<run>/ itself.
  4. Reports per-instance outcome changes (gained AND lost true positives, not just reduced false
     positives) plus, per run, a recomputed complete_success out of the SAME 24-case denominator
     every historical number used (only the 42-rule subset's hidden evaluation is substituted; every
     other case in that run keeps its real historical evaluation untouched).

REWRITTEN 2026-10-12, same day, after a follow-up review found two real issues in the first version:

1. **The "nesting artifact" framing for CASE-0063 was a misdiagnosis, not a separate bug.** The
   first version treated wrapping `pattern`+`pattern-inside` in `patterns:` (with no exclusion
   present) as an unrelated Semgrep composition quirk, and added a three-way "isolated" rewrite to
   split this out from the real exclusion-composition question. Directly reproduced that this was
   wrong: a top-level SIBLING `pattern-inside` is silently IGNORED by Semgrep (confirmed with a
   probe a positive-only check can't catch -- a sibling `pattern-inside` naming a function that does
   not exist in the target file still matches); the NESTED form is Semgrep's own documented correct
   behavior, and it correctly returns 0 for CASE-0063's named-function scope constraint because the
   real vulnerable code sits inside an ANONYMOUS function, not a named one. So CASE-0063 belongs in
   exactly the same bucket as CASE-0220/CASE-0323 below -- a model-authored constraint
   (`pattern-inside` instead of `pattern-not`) that the historical composition bug rendered inert,
   not a new or different kind of artifact. The three-arm "isolated" split and its
   nesting_artifact_* fields are REMOVED; `typed_rule.py` was reverted to always compose
   `pattern_inside` via `patterns:` (see its own docstring for the full history of that reversal).
2. **Outcome comparisons didn't check whether either scan actually succeeded.** `scan()` always
   returns a `samples` record even when `scan_ok` is False (a rule-parse/target error) -- the
   "outcome" fields in that case are built from an empty `findings` list (the scan never ran), not
   from genuine behavior. Confirmed directly: CASE-0184's rewritten rule has `scan_ok=False` (a Java
   rule-parse error in its exclusion clause), and the prior version of this script counted its
   trivial FN/TN defaults as 2 real hidden-TP losses and 1 real hidden-FP improvement. Fixed: any
   instance where either side's scan did not succeed is marked `unevaluable_due_to_scan_failure` and
   excluded from every outcome tally, reported as its own separate count instead.

Explicitly out of scope (per the review's protocol point 4): 42 rule instances across repeated
development runs of the SAME underlying case are not 42 independent cases -- the per-instance table
below includes case_id and run together so this is never obscured. This is an ablation on ALREADY-
ACCEPTED rules only; it cannot estimate how many REJECTED rules might have been accepted under
correct composition, nor does it imply anything about a different repair-loop policy.

Usage:
    python pipeline/exclusion_composition_ablation.py
"""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))
import diagnostic_v2 as dv2
from eligible_cases import load_manifest

INVENTORY_PATH = (ROOT / "Research_Log/Diagnostic_20261010/"
                   "bounded_followup_artifacts_20261011T215946041546Z/historical_exclusion_inventory.json")

EXPECTED_KEY_SHAPE_ALLOWED = {"pattern", "pattern-not", "pattern-inside", "pattern-not-inside"}
EXPECTED_KEY_SHAPE_REQUIRED = {"pattern", "pattern-not"}
COMPOSITION_ORDER = ["pattern", "pattern-inside", "pattern-not", "pattern-not-inside"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _validate_shape(rule: dict):
    pattern_keys = {k for k in rule if k.startswith("pattern")}
    if pattern_keys - EXPECTED_KEY_SHAPE_ALLOWED:
        return None, f"unexpected pattern-family keys: {sorted(pattern_keys - EXPECTED_KEY_SHAPE_ALLOWED)}"
    if not EXPECTED_KEY_SHAPE_REQUIRED <= pattern_keys:
        return None, f"missing required keys {EXPECTED_KEY_SHAPE_REQUIRED}, got {sorted(pattern_keys)}"
    for k in pattern_keys:
        if not isinstance(rule[k], str):
            return None, f"{k} is not a plain string (got {type(rule[k]).__name__}) -- not the pre-specified shape"
    return pattern_keys, None


def rewrite_composition(rule: dict, pattern_keys: set):
    """Pure function: moves pattern/pattern-inside/pattern-not/pattern-not-inside from top-level
    siblings into one patterns: list, in the fixed order typed_rule.py itself uses. Everything else
    (id, languages, message, severity, metadata) is carried over UNCHANGED -- byte-identical values,
    not re-derived."""
    patterns_list = [{key: rule[key]} for key in COMPOSITION_ORDER if key in pattern_keys]
    new_rule = {"id": rule["id"], "patterns": patterns_list}
    for k, v in rule.items():
        if k in pattern_keys or k == "id":
            continue
        new_rule[k] = v
    return new_rule


def main():
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out = ROOT / "results/diagnostic_20261010" / f"_exclusion_ablation_{timestamp}"
    out.mkdir(parents=True, exist_ok=False)

    inventory = json.loads(INVENTORY_PATH.read_text())
    manifest = load_manifest()
    ann = dv2.load_merged_ann()

    instances = []
    for run, info in inventory.items():
        for rel_path in info["paths"]:
            case_id = Path(rel_path).parent.name
            instances.append((run, case_id, ROOT / rel_path))
    print(f"Loaded {len(instances)} sibling-exclusion rule instances from the frozen inventory "
          f"({INVENTORY_PATH.relative_to(ROOT)}, sha256={sha(INVENTORY_PATH)[:16]}...)")

    rejected = []
    per_instance = []
    for run, case_id, orig_path in instances:
        inst_dir = out / run / case_id
        inst_dir.mkdir(parents=True, exist_ok=True)
        orig_sha = sha(orig_path)
        orig_doc = yaml.safe_load(orig_path.read_text())
        orig_rule = orig_doc["rules"][0]
        pattern_keys, reject_reason = _validate_shape(orig_rule)
        if reject_reason:
            rejected.append({"run": run, "case_id": case_id, "path": str(orig_path.relative_to(ROOT)),
                              "source_sha256": orig_sha, "reason": reject_reason})
            continue
        new_rule = rewrite_composition(orig_rule, pattern_keys)

        rewritten_path = inst_dir / "rewritten_rule.yml"
        rewritten_path.write_text(yaml.dump({"rules": [new_rule]}, sort_keys=False, default_flow_style=False))
        (inst_dir / "original_rule.yml").write_bytes(orig_path.read_bytes())

        orig_eval = dv2.scan(orig_path, case_id, manifest, ann, inst_dir / "original_hidden", hidden=True)
        new_eval = dv2.scan(rewritten_path, case_id, manifest, ann, inst_dir / "rewritten_hidden", hidden=True)

        # Sanity cross-check: replaying the exact same rule file should reproduce the exact same
        # historical hidden evaluation already on disk, unless the location annotations themselves
        # were revised since that run (which did happen, in the Finding-1/v2-additions sense) -- a
        # mismatch here needs to be visible, not silently assumed away.
        historical_ep = json.loads((ROOT / "results/diagnostic_20261010" / run / case_id / "episode.json").read_text())
        historical_cs = bool(historical_ep.get("iterative") and historical_ep["iterative"]["complete_success"])
        replay_matches_historical = historical_cs == orig_eval["complete_success"]

        # Outcome comparisons only mean anything when BOTH scans actually succeeded -- scan() still
        # returns a samples record on a failed scan (findings=[] because the rule never ran), and
        # those trivial FN/TN defaults must never be read as real behavioral outcomes. Confirmed
        # directly: CASE-0184's rewritten rule has a Java rule-parse error in its exclusion clause
        # and scan_ok=False; without this gate its trivial defaults were previously counted as 2
        # hidden-TP losses and 1 hidden-FP improvement that never actually happened.
        evaluable = orig_eval["scan_ok"] and new_eval["scan_ok"]
        outcome_changes = {}
        if evaluable:
            orig_by_type = {s["sample_type"]: s for s in orig_eval["samples"]}
            new_by_type = {s["sample_type"]: s for s in new_eval["samples"]}
            outcome_changes = {t: {"from": orig_by_type[t]["outcome"], "to": new_by_type[t]["outcome"]}
                                for t in orig_by_type if orig_by_type[t]["outcome"] != new_by_type[t]["outcome"]}

        per_instance.append({
            "run": run, "case_id": case_id, "rule_id": orig_rule["id"],
            "source_path": str(orig_path.relative_to(ROOT)), "source_sha256": orig_sha,
            "has_pattern_inside": "pattern-inside" in pattern_keys,
            "has_pattern_not_inside": "pattern-not-inside" in pattern_keys,
            "replay_matches_historical_episode": replay_matches_historical,
            "evaluable": evaluable,
            "new_scan_error": None if evaluable else new_eval["errors"] if not new_eval["scan_ok"] else orig_eval["errors"],
            "orig_scan_ok": orig_eval["scan_ok"], "new_scan_ok": new_eval["scan_ok"],
            "orig_complete_success": orig_eval["complete_success"],
            "new_complete_success": new_eval["complete_success"],
            "complete_success_changed": orig_eval["complete_success"] != new_eval["complete_success"],
            "outcome_changes": outcome_changes,
        })

    distinct_case_ids = sorted({p["case_id"] for p in per_instance})
    n_replay_mismatches = sum(1 for p in per_instance if not p["replay_matches_historical_episode"])
    n_unevaluable = sum(1 for p in per_instance if not p["evaluable"])
    n_gained_cs = sum(1 for p in per_instance if not p["orig_complete_success"] and p["new_complete_success"])
    n_lost_cs = sum(1 for p in per_instance if p["orig_complete_success"] and not p["new_complete_success"])
    n_unchanged_cs = sum(1 for p in per_instance if not p["complete_success_changed"])

    tp_gained = tp_lost = fp_gained = fp_lost = 0
    for p in per_instance:
        for sample_type, chg in p["outcome_changes"].items():
            if sample_type.startswith("variant_vulnerable"):
                if chg["to"] == "TP" and chg["from"] == "FN":
                    tp_gained += 1
                elif chg["from"] == "TP" and chg["to"] == "FN":
                    tp_lost += 1
            if sample_type in ("variant_safe", "benign_lookalike"):
                if chg["to"] == "FP" and chg["from"] == "TN":
                    fp_gained += 1
                elif chg["from"] == "FP" and chg["to"] == "TN":
                    fp_lost += 1

    # Per-run recomputed complete_success out of the SAME 24-case denominator every historical
    # number used -- only the ablated subset's hidden evaluation is substituted.
    per_run_denominator = {}
    ablated_by_run_case = {(p["run"], p["case_id"]): p for p in per_instance}
    for run in inventory:
        run_dir = ROOT / "results/diagnostic_20261010" / run
        selection = json.loads((run_dir / "selection.json").read_text())
        ids = selection["case_ids"]
        orig_cs = new_cs = 0
        for cid in ids:
            ep = json.loads((run_dir / cid / "episode.json").read_text())
            it = ep.get("iterative")
            historical_cs = bool(it and it["complete_success"])
            orig_cs += historical_cs
            key = (run, cid)
            if key in ablated_by_run_case:
                new_cs += bool(ablated_by_run_case[key]["new_complete_success"])
            else:
                new_cs += historical_cs
        per_run_denominator[run] = {"requested": len(ids), "historical_complete_success": orig_cs,
                                     "ablated_complete_success": new_cs,
                                     "ablated_subset_size": inventory[run]["sibling_exclusion_rules"]}

    summary = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "label": "EXPLORATORY deterministic composition ablation -- not a new model generation "
                 "result, not proof of improvement on a fresh holdout. Applies only to the 42 "
                 "already-accepted rules in the frozen inventory; cannot estimate recovery of "
                 "rejected rules or a different repair-loop policy.",
        "inventory_sha256": sha(INVENTORY_PATH),
        "n_instances_total": len(instances),
        "n_instances_rejected": len(rejected),
        "rejected": rejected,
        "n_distinct_case_ids": len(distinct_case_ids),
        "distinct_case_ids": distinct_case_ids,
        "n_replay_mismatches_vs_historical_episode": n_replay_mismatches,
        "note_unit_of_analysis": f"{len(per_instance)} rule INSTANCES across repeated development "
                                  f"runs, covering only {len(distinct_case_ids)} distinct case ids "
                                  "-- not independent cases; see per_instance for the run+case_id "
                                  "pairing on every row.",
        "n_unevaluable_due_to_scan_failure": n_unevaluable,
        "note_unevaluable": "Instances where either the original or rewritten rule failed to scan "
                             "(scan_ok=False, e.g. a rule-parse error) are excluded from every "
                             "outcome tally below -- scan()'s trivial FN/TN defaults on a failed "
                             "scan are not real behavioral evidence. See per_instance's "
                             "new_scan_error field for which side failed and why.",
        "complete_success_gained": n_gained_cs,
        "complete_success_lost": n_lost_cs,
        "complete_success_unchanged": n_unchanged_cs,
        "hidden_variant_true_positives_gained": tp_gained,
        "hidden_variant_true_positives_lost": tp_lost,
        "hidden_negative_false_positives_gained": fp_gained,
        "hidden_negative_false_positives_lost": fp_lost,
        "per_run_24_case_denominator": per_run_denominator,
        "per_instance": per_instance,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2))

    print(f"\n{len(instances)} instances loaded, {len(rejected)} rejected (shape mismatch), "
          f"{len(per_instance)} scanned both ways, {n_unevaluable} unevaluable (a scan failed).")
    print(f"Distinct case ids covered: {len(distinct_case_ids)} (instances are NOT independent cases)")
    print(f"Replay-vs-historical mismatches: {n_replay_mismatches} (0 expected unless location "
          f"annotations changed since the original run)")
    print(f"\ncomplete_success: gained={n_gained_cs} lost={n_lost_cs} unchanged={n_unchanged_cs}")
    print(f"hidden variant TPs (evaluable pairs only): gained={tp_gained} lost={tp_lost}")
    print(f"hidden negative FPs (evaluable pairs only): gained={fp_gained} lost={fp_lost}")
    print(f"\nPer-run complete_success, same 24-case denominator as every historical report:")
    for run, d in per_run_denominator.items():
        print(f"  {run:22s} historical={d['historical_complete_success']:2d}/24  "
              f"ablated={d['ablated_complete_success']:2d}/24  (subset size {d['ablated_subset_size']})")
    if rejected:
        print(f"\nREJECTED instances (shape mismatch, not ablated):")
        for r in rejected:
            print(f"  {r['run']}/{r['case_id']}: {r['reason']}")
    unevaluable = [p for p in per_instance if not p["evaluable"]]
    if unevaluable:
        print(f"\nUNEVALUABLE instances (a scan failed, excluded from tallies):")
        for p in unevaluable:
            print(f"  {p['run']}/{p['case_id']}: orig_scan_ok={p['orig_scan_ok']} new_scan_ok={p['new_scan_ok']}")
    print(f"\nFull detail: {out / 'summary.json'}")


if __name__ == "__main__":
    main()

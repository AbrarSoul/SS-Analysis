"""
Research_Direction_20261011.md Item 5, step 3 of the post-pilot plan: "Measure coverage using
saved rules. Before spending inference budget, check how often these probes expose weaknesses in
existing candidates. This measures detection potential -- not whether model repairs will succeed."

No new model calls. Builds a probe pair (pipeline/dev_probe.py) for every development case where
one is possible, firewalled under results/diagnostic_20261010/_dev_probes/<case_id>/ (never written
into or read from benchmark/cases/), then re-scans every ALREADY-ACCEPTED final rule from the
just-completed A/B pilot (12 namespaces, results/diagnostic_20261010/ab_dev_20261012_v1_*/) against
those probe files with real, pinned Semgrep -- the same engine/semgrep_env() construction every
other scan in this project uses. This is new Semgrep execution (local, no inference), not new model
inference.

Usage:
    python pipeline/probe_coverage_check.py
"""
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))
sys.path.insert(0, str(ROOT / "autogrep"))
import diagnostic_v2 as dv2
from eligible_cases import load_manifest
from dev_probe import build_probe, ProbeResult, ProbeIneligible

EXT = {"python": "py", "java": "java", "javascript": "js", "typescript": "ts"}
SEMGREP = ROOT / ".venv/bin/semgrep"

PILOT_RUNS = [
    ("qwen3-coder:30b", "A", 1, "ab_dev_20261012_v1_qwen3_r1_a"),
    ("qwen3-coder:30b", "B", 1, "ab_dev_20261012_v1_qwen3_r1_b"),
    ("qwen3-coder:30b", "A", 2, "ab_dev_20261012_v1_qwen3_r2_a"),
    ("qwen3-coder:30b", "B", 2, "ab_dev_20261012_v1_qwen3_r2_b"),
    ("qwen3-coder:30b", "A", 3, "ab_dev_20261012_v1_qwen3_r3_a"),
    ("qwen3-coder:30b", "B", 3, "ab_dev_20261012_v1_qwen3_r3_b"),
    ("gpt-4o", "A", 1, "ab_dev_20261012_v1_gpt4o_r1_a"),
    ("gpt-4o", "B", 1, "ab_dev_20261012_v1_gpt4o_r1_b"),
    ("gpt-4o", "A", 2, "ab_dev_20261012_v1_gpt4o_r2_a"),
    ("gpt-4o", "B", 2, "ab_dev_20261012_v1_gpt4o_r2_b"),
    ("gpt-4o", "A", 3, "ab_dev_20261012_v1_gpt4o_r3_a"),
    ("gpt-4o", "B", 3, "ab_dev_20261012_v1_gpt4o_r3_b"),
]


def scan_probe(rule_path: Path, vulnerable_probe_path: Path, patched_probe_path: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=False)
    command = [str(SEMGREP), "--config", str(rule_path), "--json", "--metrics=off",
               "--disable-version-check", "--no-git-ignore", "--jobs=1",
               str(vulnerable_probe_path), str(patched_probe_path)]
    proc = subprocess.run(command, capture_output=True, text=True, env=dv2.semgrep_env(out_dir), timeout=120)
    (out_dir / "stdout.json").write_text(proc.stdout)
    (out_dir / "stderr.txt").write_text(proc.stderr)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"scan_ok": False, "error": "non-JSON output", "returncode": proc.returncode}
    errors = data.get("errors", [])
    if proc.returncode or errors:
        return {"scan_ok": False, "error": errors or f"exit {proc.returncode}", "returncode": proc.returncode}
    # Finding 4 (Dev_Probe_Implementation_Review_20261013.md): a malformed/mocked response with
    # zero scanned targets would otherwise satisfy the checks above and get silently treated as a
    # real "vulnerable_probe missed" result. Require both probe targets to actually appear in
    # Semgrep's own "paths.scanned" list before trusting any detection outcome.
    scanned = {str(Path(p).resolve()) for p in data.get("paths", {}).get("scanned", [])}
    missing = {p for p in (vulnerable_probe_path, patched_probe_path) if str(p.resolve()) not in scanned}
    if missing:
        return {"scan_ok": False,
                "error": f"target(s) not in paths.scanned: {[str(p) for p in missing]}",
                "returncode": proc.returncode}
    findings = data.get("results", [])
    vulnerable_hit = any(Path(r["path"]).resolve() == vulnerable_probe_path.resolve() for r in findings)
    patched_hit = any(Path(r["path"]).resolve() == patched_probe_path.resolve() for r in findings)
    return {"scan_ok": True, "vulnerable_detected": vulnerable_hit, "patched_detected": patched_hit}


def main():
    manifest = load_manifest()
    selection = json.loads((ROOT / "results/diagnostic_20261010/qwen3_v3/selection.json").read_text())
    ids = sorted(selection["case_ids"])

    # Finding 5 (Dev_Probe_Implementation_Review_20261013.md): the old shared
    # `_dev_probes/<case_id>/` path got overwritten by every run with no immutable snapshot or
    # per-run input hash, so an earlier run's exact probe source could never be reconstructed
    # once a later run rebuilt it. Probe sources are now written under this run's own timestamped
    # output directory instead, alongside a content hash recorded in eligibility.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    coverage_out = ROOT / "results/diagnostic_20261010" / f"_probe_coverage_{timestamp}"
    coverage_out.mkdir(parents=True, exist_ok=False)
    probe_root = coverage_out / "_probe_inputs"
    probe_root.mkdir(parents=True, exist_ok=True)

    eligibility = {}
    probe_paths = {}
    for cid in ids:
        language = manifest[cid]["language"]
        ctx = json.loads((ROOT / f"benchmark/model_context/{cid}.json").read_text())
        result = build_probe(cid, language, ctx["vulnerable_function"], ctx["patched_function"])
        if isinstance(result, ProbeIneligible):
            eligibility[cid] = {"eligible": False, "reason": result.reason, "language": language}
            continue
        case_dir = probe_root / cid
        case_dir.mkdir(parents=True, exist_ok=True)
        ext = EXT[language]
        vuln_path = case_dir / f"vulnerable_probe.{ext}"
        patched_path = case_dir / f"patched_probe.{ext}"
        vuln_path.write_text(result.vulnerable_probe)
        patched_path.write_text(result.patched_probe)
        eligibility[cid] = {"eligible": True, "language": language, "old_name": result.old_name,
                             "new_name": result.new_name, "patched_probe_renamed": result.patched_probe_renamed,
                             "vulnerable_probe_path": str(vuln_path.relative_to(ROOT)),
                             "patched_probe_path": str(patched_path.relative_to(ROOT)),
                             "vulnerable_probe_sha256": hashlib.sha256(result.vulnerable_probe.encode()).hexdigest(),
                             "patched_probe_sha256": hashlib.sha256(result.patched_probe.encode()).hexdigest()}
        probe_paths[cid] = (vuln_path, patched_path)

    n_eligible = sum(1 for v in eligibility.values() if v["eligible"])
    print(f"Probe eligibility: {n_eligible}/{len(ids)} cases")
    for cid, v in eligibility.items():
        if not v["eligible"]:
            print(f"  INELIGIBLE {cid} ({v['language']}): {v['reason']}")

    per_episode = []
    for model, cond, repeat, run_name in PILOT_RUNS:
        run_dir = ROOT / "results/diagnostic_20261010" / run_name
        for cid in ids:
            if cid not in probe_paths:
                continue
            final_rule_path_str = None
            episode_path = run_dir / cid / "episode.json"
            if not episode_path.exists():
                continue
            ep = json.loads(episode_path.read_text())
            final_rule_path_str = ep.get("final_rule_path")
            if not final_rule_path_str:
                continue  # never accepted in this episode -- nothing to probe
            rule_path = ROOT / final_rule_path_str if not Path(final_rule_path_str).is_absolute() else Path(final_rule_path_str)
            vuln_path, patched_path = probe_paths[cid]
            scan_dir = coverage_out / model.replace(":", "_") / cond / f"r{repeat}" / cid
            scan_result = scan_probe(rule_path, vuln_path, patched_path, scan_dir)
            per_episode.append({"model": model, "condition": cond, "repeat": repeat, "case_id": cid,
                                 "rule_path": final_rule_path_str, **scan_result})

    # Finding 4 (Dev_Probe_Implementation_Review_20261013.md): the old aggregate required
    # vulnerable_detected AND patched_detected for an "FP" count, which silently hid a patched-side
    # false positive whenever the same rule also missed the vulnerable probe. Count all four
    # (vulnerable_detected, patched_detected) outcomes explicitly instead of collapsing them.
    n_total = len(per_episode)
    n_scan_ok = sum(1 for e in per_episode if e["scan_ok"])
    ok_episodes = [e for e in per_episode if e["scan_ok"]]
    n_pass_clean = sum(1 for e in ok_episodes if e["vulnerable_detected"] and not e["patched_detected"])
    n_pass_with_patched_fp = sum(1 for e in ok_episodes if e["vulnerable_detected"] and e["patched_detected"])
    n_miss_clean = sum(1 for e in ok_episodes if not e["vulnerable_detected"] and not e["patched_detected"])
    n_miss_with_patched_fp = sum(1 for e in ok_episodes if not e["vulnerable_detected"] and e["patched_detected"])
    n_patched_fp_total = n_pass_with_patched_fp + n_miss_with_patched_fp  # independent of vulnerable outcome

    summary = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "label": "Research_Direction_20261011.md Item 5 step 3: coverage measurement using "
                 "already-saved accepted rules from the A/B pilot. No new model calls. Measures "
                 "detection potential, not whether a model would successfully repair when a probe "
                 "fails.",
        "eligibility": eligibility,
        "n_accepted_episodes_with_eligible_probe": n_total,
        "n_scan_ok": n_scan_ok,
        "n_probe_pass_clean": n_pass_clean,
        "n_probe_pass_with_patched_fp": n_pass_with_patched_fp,
        "n_probe_fail_miss_vulnerable_clean": n_miss_clean,
        "n_probe_fail_miss_vulnerable_with_patched_fp": n_miss_with_patched_fp,
        "n_patched_fp_total": n_patched_fp_total,
        "per_episode": per_episode,
    }
    (coverage_out / "summary.json").write_text(json.dumps(summary, indent=2))

    print(f"\nAccepted episodes with an eligible probe: {n_total} (across all 12 pilot runs)")
    print(f"  scan_ok: {n_scan_ok}")
    print(f"  probe PASS, clean (detects vulnerable, not patched): {n_pass_clean}")
    print(f"  probe PASS, but ALSO flags patched (fires on both): {n_pass_with_patched_fp}")
    print(f"  probe FAIL -- missed vulnerable_probe, clean otherwise: {n_miss_clean}")
    print(f"  probe FAIL -- missed vulnerable_probe AND flagged patched: {n_miss_with_patched_fp}")
    print(f"  patched_probe false positives, total (either vulnerable outcome): {n_patched_fp_total}")

    by_model_cond = {}
    for e in per_episode:
        key = (e["model"], e["condition"])
        by_model_cond.setdefault(key, {"total": 0, "pass_clean": 0, "pass_with_fp": 0,
                                         "miss_clean": 0, "miss_with_fp": 0, "scan_err": 0})
        d = by_model_cond[key]
        d["total"] += 1
        if not e["scan_ok"]:
            d["scan_err"] += 1
        elif e["vulnerable_detected"] and not e["patched_detected"]:
            d["pass_clean"] += 1
        elif e["vulnerable_detected"] and e["patched_detected"]:
            d["pass_with_fp"] += 1
        elif not e["vulnerable_detected"] and e["patched_detected"]:
            d["miss_with_fp"] += 1
        else:
            d["miss_clean"] += 1
    print("\nPer model/condition:")
    for (model, cond), d in by_model_cond.items():
        print(f"  {model:18s} {cond}: total={d['total']:3d} pass_clean={d['pass_clean']:3d} "
              f"pass_with_fp={d['pass_with_fp']:3d} miss_clean={d['miss_clean']:3d} "
              f"miss_with_fp={d['miss_with_fp']:3d} scan_err={d['scan_err']:3d}")

    print(f"\nFull detail: {coverage_out / 'summary.json'}")
    print(f"Probe files: {probe_root}")


if __name__ == "__main__":
    main()

"""Summarize frozen candidate results and probe one observed parser failure.

The TSX probe changes only copied file suffixes, never benchmark bytes or labels.
It is a post-hoc diagnostic, not a replacement score for the recorded run.
"""
import json
from pathlib import Path
import subprocess

from diagnostic_v2 import ROOT, SEMGREP, SAMPLES, EXT, save, sha, semgrep_env, report
from eligible_cases import load_manifest


def main():
    run = ROOT / "results/diagnostic_20261010/references_v1"
    out = ROOT / "results/diagnostic_20261010/failure_audit_v1"
    out.mkdir(parents=True, exist_ok=False)
    selection = json.loads((ROOT / "benchmark/diagnostic_20261010/selection.json").read_text())
    episodes = [json.loads((run / cid / "episode.json").read_text()) for cid in selection["case_ids"]]
    annotations = {(r["case_id"], r["variant"]): [r["start_line"], r["end_line"]] for r in
                   map(json.loads, (ROOT / "benchmark/variant_vulnerable_lines.jsonl").read_text().splitlines())}
    manifest = load_manifest()
    details = []
    for episode in episodes:
        cid, evaluation = episode["case_id"], episode["reference"]
        failures = []
        for sample in evaluation["samples"]:
            if sample["outcome"] not in {"FN", "FP"}:
                continue
            kind = sample["sample_type"]
            bounds = manifest[cid]["vulnerable_lines"] if kind == "original_vulnerable" else annotations.get((cid, kind))
            failures.append({"sample_type": kind, "outcome": sample["outcome"],
                "finding_lines": sample["finding_lines"], "accepted_location": bounds,
                "category": "scan_invalid" if not evaluation["scan_ok"] else
                    ("finding_outside_annotation" if sample["outcome"] == "FN" and sample["detected"] else
                     "miss" if sample["outcome"] == "FN" else "false_positive")})
        details.append({"case_id": cid, "scan_ok": evaluation["scan_ok"],
                        "complete_success": evaluation["complete_success"], "failures": failures})
    save(out / "case_diagnostics.json", {"source_run": str(run.relative_to(ROOT)), "cases": details})
    save(out / "summary.json", report(episodes, selection["case_ids"], "references"))

    # Hypothesis from the recorded errors: JSX stored with .ts suffix prevents
    # TypeScript parsing. Use byte-identical .tsx copies and the SAME frozen rule.
    probe = out / "case0298_tsx_probe"
    probe.mkdir()
    targets, evidence = [], []
    for kind, stem, positive in SAMPLES:
        source = ROOT / "benchmark/cases/CASE-0298" / (stem + ".ts")
        target = probe / (stem + ".tsx")
        target.write_bytes(source.read_bytes())
        targets.append(target)
        evidence.append({"sample_type": kind, "source": str(source.relative_to(ROOT)),
                         "copy": str(target.relative_to(ROOT)), "sha256": sha(source),
                         "identical_bytes": source.read_bytes() == target.read_bytes()})
    rule = run / "CASE-0298/rule.yml"
    command = [str(SEMGREP), "--config", str(rule), "--json", "--metrics=off",
               "--disable-version-check", "--no-git-ignore", "--jobs=1", *map(str, targets)]
    proc = subprocess.run(command, capture_output=True, text=True, env=semgrep_env(probe), timeout=120)
    (probe / "stdout.json").write_text(proc.stdout)
    (probe / "stderr.txt").write_text(proc.stderr)
    data = json.loads(proc.stdout)
    for row, target in zip(evidence, targets):
        row["finding_lines"] = [r["start"]["line"] for r in data.get("results", [])
                                if Path(r["path"]).resolve() == target.resolve()]
    save(probe / "probe.json", {"purpose": "post-hoc suffix sensitivity; not historical rescoring",
        "semgrep_version": "1.177.0", "command": command, "returncode": proc.returncode,
        "errors": data.get("errors", []), "samples": evidence, "rule_sha256": sha(rule)})
    print(json.dumps({"summary": report(episodes, selection["case_ids"], "references"),
                      "location_only_failures": [r for r in details if any(
                          f["category"] == "finding_outside_annotation" for f in r["failures"])],
                      "tsx_probe_errors": data.get("errors", []), "tsx_samples": evidence}, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Run a case harness (contract v1, see CONTRACT.md) against all six samples, each in its own
network-less container, and write <harness dir>/results.json plus a printed summary.

Usage (from the repo root):
  python3 review/harness_runner/run_harness.py CASE-0075 [--harness DIR] [--image gt-harness-runtime:1]

Default harness dir: review/cases_reviewed_r1/harness/<CASE>. Benchmark files are mounted read-only
and never modified.
"""
import argparse, hashlib, json, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLES = ["vulnerable_source", "patched_source", "variant_vulnerable_01", "variant_vulnerable_02", "variant_safe_01", "benign_lookalike"]
VULN = {"vulnerable_source", "variant_vulnerable_01", "variant_vulnerable_02"}
TIMEOUT = 120


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def tree_sha(d):
    h = hashlib.sha256()
    for f in sorted(p for p in Path(d).rglob("*") if p.is_file() and p.name != "results.json" and "__pycache__" not in p.parts):
        h.update(str(f.relative_to(d)).encode()); h.update(f.read_bytes())
    return h.hexdigest()


def judge(role, r):
    if r is None:
        return "no result", False
    if r.get("skipped"):
        return f"not testable: {r['skipped']}", False
    if not r.get("compiled"):
        return "did not compile / load", False
    hit = [k for k, v in (r.get("attacks") or {}).items() if v]
    if role in VULN:
        return (f"exploitable ({len(hit)} attack{'s' if len(hit) != 1 else ''} worked)", True) if hit else ("not exploited by any attack", False)
    if hit:
        return f"EXPLOITED by {', '.join(hit)}", False
    if r.get("control_ok") is False:
        return "blocked everything, including the benign control", False
    return "blocked every attack", True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("case")
    ap.add_argument("--harness")
    ap.add_argument("--image", default="gt-harness-runtime:1")
    a = ap.parse_args()
    case_dir = ROOT / "benchmark" / "cases" / a.case
    hdir = Path(a.harness).resolve() if a.harness else ROOT / "review" / "cases_reviewed_r1" / "harness" / a.case
    man = json.loads((hdir / "harness.json").read_text())
    assert man.get("contract") == 1 and man.get("case_id") == a.case, "harness.json: wrong contract or case_id"
    assert (hdir / "run.sh").is_file(), "harness has no run.sh"
    image_id = subprocess.run(["docker", "image", "inspect", "-f", "{{.Id}}", a.image], capture_output=True, text=True).stdout.strip()
    if not image_id:
        sys.exit(f"runtime image {a.image} missing: docker build -t {a.image} review/harness_runner/runtime")

    samples = {}
    for role in ROLES:
        f = next((p for p in case_dir.iterdir() if p.stem == role and p.suffix != ".pyc"), None)
        if not f:
            samples[role] = {"file": None, "verdict": "sample missing", "matches_label": False}
            continue
        cmd = ["docker", "run", "--rm", "--network", "none", "--memory", "1g", "--cpus", "2", "--pids-limit", "256",
               "--read-only", "--tmpfs", "/tmp:rw,exec,size=512m,mode=1777", "-e", "HOME=/tmp",
               "-v", f"{hdir}:/harness:ro", "-v", f"{f}:/case/{f.name}:ro", a.image, "bash", "-c",
               f"cp -r /harness /tmp/h && rm -f /tmp/h/results.json && cd /tmp/h && timeout {TIMEOUT} bash run.sh /case/{f.name} {role}"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT + 30)
            out, err, code = p.stdout, p.stderr, p.returncode
        except subprocess.TimeoutExpired:
            out, err, code = "", "runner timeout", -1
        line = next((l for l in reversed(out.splitlines()) if l.startswith("RESULT ")), None)
        try:
            r = json.loads(line[7:]) if line else None
        except json.JSONDecodeError:
            r = None
        verdict, match = judge(role, r)
        samples[role] = {"file": f.name, "sha256": sha(f), "label": "vulnerable" if role in VULN else "safe",
                         "result": r, "verdict": verdict, "matches_label": match, "exit_code": code,
                         "log_tail": (out[-3000:] + ("\n[stderr]\n" + err[-1500:] if err.strip() else "")).strip()}

    res = {"contract": 1, "case_id": a.case, "harness": {"title": man.get("title"), "built_by": man.get("built_by"),
           "sha256": tree_sha(hdir), "attacks": man.get("attacks"), "control": man.get("control"),
           "success_criterion": man.get("success_criterion")},
           "runtime_image": image_id, "run_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
           "isolation": "docker, --network none, read-only root, 1 GB, 2 CPUs, 120 s per sample", "samples": samples}
    (hdir / "results.json").write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n")

    print(f"{a.case} · {man.get('title')}")
    for role in ROLES:
        s = samples[role]
        mods = (s.get("result") or {}).get("modified") or []
        print(f"  {'OK ' if s['matches_label'] else '!! '} {role:<22} [{s.get('label', '?'):<10}] {s['verdict']}" + (f"   (modified copy: {'; '.join(mods)})" if mods else ""))
    print(f"-> {hdir / 'results.json'}")


if __name__ == "__main__":
    main()

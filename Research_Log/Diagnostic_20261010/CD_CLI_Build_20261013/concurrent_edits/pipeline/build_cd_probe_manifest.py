"""
Completion criterion 1 of the bounded C/D infrastructure task (per the user's explicit next-step
direction, 2026-10-13): freeze the probe manifest for the real 24-case development selection
against the reviewed builder/parser versions, using probe_cache.build_experiment_manifest_entry()
-- the exact same function already offline-tested in test_combined_gate.py's manifest tests.

No model calls, no real Semgrep scans -- build_probe() is pure and offline. This script only
calls it once per case and writes the frozen manifest JSON that pipeline/diagnostic_v2.py's CLI
adapter (once wired) and any C/D run must validate against via probe_cache.load_probe_for_experiment().

Usage:
    python pipeline/build_cd_probe_manifest.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))
from eligible_cases import load_manifest
from probe_cache import build_experiment_manifest_entry, dev_probe_sha256, parser_versions

OUT_PATH = ROOT / "Research_Log/Diagnostic_20261010/CD_Probe_Manifest_v1_20261013.json"


def main():
    manifest = load_manifest()
    selection = json.loads((ROOT / "results/diagnostic_20261010/qwen3_v3/selection.json").read_text())
    ids = sorted(selection["case_ids"])

    frozen = {}
    for cid in ids:
        language = manifest[cid]["language"]
        ctx = json.loads((ROOT / f"benchmark/model_context/{cid}.json").read_text())
        frozen[cid] = build_experiment_manifest_entry(cid, language, ctx["vulnerable_function"], ctx["patched_function"])

    n_eligible = sum(1 for e in frozen.values() if e["eligible"])
    payload = {
        "manifest_version": "cd_probe_manifest_v1_20261013",
        "source_selection": "results/diagnostic_20261010/qwen3_v3/selection.json",
        "n_cases": len(ids), "n_eligible": n_eligible,
        "dev_probe_sha256": dev_probe_sha256(), "parser_versions": parser_versions(),
        "entries": frozen,
    }
    OUT_PATH.write_text(json.dumps(payload, indent=2))
    print(f"Froze {len(ids)} cases ({n_eligible} eligible) to {OUT_PATH}")
    print(f"dev_probe_sha256: {payload['dev_probe_sha256']}")
    print(f"parser_versions: {payload['parser_versions']}")


if __name__ == "__main__":
    main()

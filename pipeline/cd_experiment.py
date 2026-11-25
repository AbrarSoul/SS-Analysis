"""Frozen development-only C/D inputs and offline preparation. No model or scanner calls.

The review pins below identify the already-reviewed selection and exact edit report. Freezing
replays the builder against those records; it cannot approve changed or additional source.
Imported only by explicitly selected C/D runs, never by the historical A/B path.
"""
import argparse
import hashlib
import json
from pathlib import Path

from dev_probe import ProbeResult
from probe_cache import (ExperimentManifestError, build_experiment_manifest_entry,
                         dev_probe_sha256, load_probe_for_experiment, parser_versions)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "benchmark/diagnostic_20261010/dev_probe_manifest_v1.json"
SELECTION = ROOT / "benchmark/diagnostic_20261010/selection.json"
REVIEW = ROOT / "Research_Log/Diagnostic_20261010/Dev_Probe_Binding_Audit_Decisions_20261013T090739177579Z.json"
SELECTION_SHA256 = "b473cb7b4d6737b5d2a822f8a01321e8e984f3cd314b947ee15cd29cd7e591b1"
REVIEW_SHA256 = "29f6a365e3fb106c858713a5ca6a9486ccf24dd1a9fcb5b89e6a40ad42355e33"
BUILDER_SHA256 = "d2d7364a77670e6d448da82bdf895a33aca785e9e08d1fe1941e5fae2af88114"
PARSERS = {"python": "3.14.4", "tree_sitter": "0.26.0", "tree_sitter_java": "0.23.5",
           "tree_sitter_javascript": "0.25.0", "tree_sitter_typescript": "0.23.2"}
FORMAT = "reviewed-development-probes-v1"
EXT = {"python": "py", "java": "java", "javascript": "js", "typescript": "ts"}


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise ExperimentManifestError(message)


def reviewed_inputs(selection_path=SELECTION):
    selection_bytes = Path(selection_path).read_bytes()
    require(sha_bytes(selection_bytes) == SELECTION_SHA256, "Selection differs from reviewed development selection")
    require(sha_bytes(REVIEW.read_bytes()) == REVIEW_SHA256, "Reviewed edit report changed")
    require(dev_probe_sha256() == BUILDER_SHA256, "Reviewed probe builder changed")
    require(parser_versions() == PARSERS, "Reviewed parser/runtime versions changed")
    ids = json.loads(selection_bytes)["case_ids"]
    rows = {r["case_id"]: r for r in json.loads(REVIEW.read_bytes())}
    require(len(ids) == len(set(ids)) == 24 and set(ids) == set(rows), "Reviewed case set mismatch")
    require(sum(r["eligible"] for r in rows.values()) == 11, "Reviewed eligibility mismatch")
    contexts, hashes = {}, {}
    for cid in ids:
        data = (ROOT / "benchmark/model_context" / f"{cid}.json").read_bytes()
        ctx = json.loads(data)
        row = rows[cid]
        require(ctx["case_id"] == cid and ctx["language"] == row["language"], f"{cid}: source identity changed")
        for field in ("vulnerable_function", "patched_function"):
            require(sha_bytes(ctx[field].encode()) == row[field + "_sha256"], f"{cid}: reviewed {field} changed")
        contexts[cid], hashes[cid] = ctx, sha_bytes(data)
    return ids, rows, contexts, hashes


def check_entry(entry, reviewed):
    fields = ["case_id", "language", "vulnerable_function_sha256", "patched_function_sha256", "eligible"]
    fields += (["old_name", "new_name", "vulnerable_probe_sha256", "patched_probe_sha256", "patched_probe_renamed"]
               if reviewed["eligible"] else ["reason"])
    for field in fields:
        require(entry.get(field) == reviewed[field], f"{reviewed['case_id']}: {field} differs from reviewed record")
    require(entry.get("dev_probe_sha256") == BUILDER_SHA256 and entry.get("parser_versions") == PARSERS,
            f"{reviewed['case_id']}: unreviewed builder/parser identity")


def build_frozen_manifest():
    ids, reviewed, contexts, context_hashes = reviewed_inputs()
    entries = {}
    for cid in ids:
        ctx = contexts[cid]
        entry = build_experiment_manifest_entry(cid, ctx["language"], ctx["vulnerable_function"], ctx["patched_function"])
        check_entry(entry, reviewed[cid])
        entries[cid] = entry
    return {"format": FORMAT, "purpose": "Fixed development subset; not a confirmation protocol freeze",
            "selection_sha256": SELECTION_SHA256, "reviewed_edit_report_sha256": REVIEW_SHA256,
            "case_ids": ids, "eligible_cases": 11, "ineligible_cases": 13,
            "context_sha256": context_hashes, "entries": entries}


def validate_frozen_manifest(path, selection_path=SELECTION):
    """Read/validate all 24 cases before credentials or inference; no cache/output writes."""
    data = Path(path).read_bytes()
    frozen = json.loads(data)
    ids, reviewed, contexts, context_hashes = reviewed_inputs(selection_path)
    require(frozen.get("format") == FORMAT, "Unsupported probe manifest format")
    require(frozen.get("selection_sha256") == SELECTION_SHA256 and
            frozen.get("reviewed_edit_report_sha256") == REVIEW_SHA256, "Manifest review provenance mismatch")
    require(frozen.get("case_ids") == ids and set(frozen["entries"]) == set(ids), "Manifest case set/order mismatch")
    require(frozen.get("eligible_cases") == 11 and frozen.get("ineligible_cases") == 13, "Manifest coverage mismatch")
    require(frozen.get("context_sha256") == context_hashes, "Full model-context bytes changed since freeze")
    for cid in ids:
        check_entry(frozen["entries"][cid], reviewed[cid])
    return frozen, contexts, data


def prepare_probes(frozen, contexts, manifest_bytes, out):
    """Strict loader -> role-specific materialization -> runner-owned snapshot at invocation.

    out is a fresh run directory. Only visible model-context snippets are builder inputs.
    Cache and materialized artifacts are local to this run; no previous run is overwritten.
    """
    prepared = {}
    manifest_sha = sha_bytes(manifest_bytes)
    for cid in frozen["case_ids"]:
        ctx = contexts[cid]
        result, status = load_probe_for_experiment(cid, ctx["language"], ctx["vulnerable_function"],
            ctx["patched_function"], out / "_probe_cache", frozen["entries"])
        require(result.case_id == cid and result.language == ctx["language"], f"{cid}: resolved probe identity mismatch")
        paths = None
        if isinstance(result, ProbeResult):
            require(result.patched_probe_renamed == frozen["entries"][cid]["patched_probe_renamed"],
                    f"{cid}: patched rename disposition mismatch")
            inputs = out / "_probe_inputs" / cid
            inputs.mkdir(parents=True, exist_ok=False)
            paths = (inputs / f"vulnerable_probe.{EXT[ctx['language']]}", inputs / f"patched_probe.{EXT[ctx['language']]}")
            for path, text in zip(paths, (result.vulnerable_probe, result.patched_probe)):
                with path.open("xb") as handle:
                    handle.write(text.encode())
        provenance = {"manifest_sha256": manifest_sha, "context_sha256": frozen["context_sha256"][cid],
                      "reviewed_entry": frozen["entries"][cid], "cache_status": status}
        prepared[cid] = (result, paths, provenance)
    return prepared


def summarize_cd(episodes, requested):
    """All-requested coverage and actual attempt resources, independent of success."""
    return {"requested_cases": len(requested), "completed_cases": len(episodes),
            "eligible_cases_completed": sum(e["probe_eligible"] for e in episodes),
            "ineligible_cases_completed": sum(not e["probe_eligible"] for e in episodes),
            "fallback_accepted": sum(e["probe_fallback_used"] for e in episodes),
            "probe_scan_errors": sum(bool(a["probe_evaluation"] and not a["probe_evaluation"]["scan_ok"])
                                     for e in episodes for a in e["attempts"]),
            "resources": {k: sum(e["resource_accounting"][k] for e in episodes)
                          for k in ("generation_calls", "visible_scans", "probe_scans", "repair_calls")}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["freeze", "verify"])
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    if args.action == "freeze":
        frozen = build_frozen_manifest()
        with args.manifest.open("x") as handle:
            json.dump(frozen, handle, indent=2)
            handle.write("\n")
    frozen, _, data = validate_frozen_manifest(args.manifest)
    print(json.dumps({"manifest": str(args.manifest), "sha256": sha_bytes(data),
                      "cases": len(frozen["case_ids"]), "eligible": 11, "ineligible": 13}))


if __name__ == "__main__":
    main()

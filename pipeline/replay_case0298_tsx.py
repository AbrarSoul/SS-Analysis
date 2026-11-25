"""
2026-10-11: offline, reproducible replay of CASE-0298's "raw" condition (first-attempt rule, no
retry feedback -- the only condition replayable without a new model call, since Autogrep's own
retry loop needs live validator feedback against the .ts-suffixed files, which always errors) under
a separately-versioned .tsx-staging fix, across every model that actually touched this case (8
primary + 7 follow-up + gpt-4o). Uses each model's REAL retained raw LLM response (pulled from the
VM's raw/ captures) -- no new inference, same offline sanitize/parse function the live pipeline
itself uses.

Never touches benchmark/cases/CASE-0298/ (the frozen .ts files) -- scans against byte-identical
.tsx copies, confirmed identical by sha256 against the originals.

Writes everything needed to reproduce or audit the result into results/diagnostic_20261010/
case0298_tsx_replay_v1/ : per-model raw response text, parsed rule YAML, Semgrep's raw JSON
output, and a top-level manifest with every input hash and the verified pinned Semgrep version.
Refuses to overwrite an existing output directory (consistent with every other script in this
project's diagnostic work).

Usage:
    python pipeline/replay_case0298_tsx.py
"""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]
from config import Config
from llm_client import LLMClient
from case_loader import load_case
from eligible_cases import load_manifest

RAW_STAGING = Path("/tmp/case0298_replay_staging")  # already-pulled VM raw captures, input only
OUT = ROOT / "results/diagnostic_20261010/case0298_tsx_replay_v1"
SEMGREP = ROOT / ".venv/bin/semgrep"

SAMPLES = [("original_vulnerable", "vulnerable_source", True),
           ("original_patched", "patched_source", False),
           ("variant_vulnerable_1", "variant_vulnerable_01", True),
           ("variant_vulnerable_2", "variant_vulnerable_02", True),
           ("variant_safe", "variant_safe_01", False),
           ("benign_lookalike", "benign_lookalike", False)]

MODEL_RUNS = [
    ("runs_phase5_primary", "qwen2.5-coder_7b-instruct__autogrep_default", "qwen2.5-coder:7b-instruct"),
    ("runs_phase5_primary", "qwen2.5-coder_32b__autogrep_default", "qwen2.5-coder:32b"),
    ("runs_phase5_primary", "codellama_7b-instruct-fp16__autogrep_default", "codellama:7b-instruct-fp16"),
    ("runs_phase5_primary", "deepseek-coder_6.7b__autogrep_default", "deepseek-coder:6.7b"),
    ("runs_phase5_primary", "codegemma_7b__autogrep_default", "codegemma:7b"),
    ("runs_phase5_primary", "yi-coder_9b__autogrep_default", "yi-coder:9b"),
    ("runs_phase5_primary", "magicoder_7b__autogrep_default", "magicoder:7b"),
    ("runs_phase5_primary", "DeepHat_DeepHat-V1-7B__autogrep_default", "DeepHat-V1-7B"),
    ("runs_followup_20261008", "qwen3-coder_30b__autogrep_default", "qwen3-coder:30b"),
    ("runs_followup_20261008", "gpt-oss_20b__autogrep_default", "gpt-oss:20b"),
    ("runs_followup_20261008", "opencoder_8b-instruct-q4_K_M__autogrep_default", "opencoder:8b-instruct-q4_K_M"),
    ("runs_followup_20261008", "granite-code_8b-instruct-128k-q4_1__autogrep_default", "granite-code:8b-instruct-128k-q4_1"),
    ("runs_followup_20261008", "llama3.1_8b-instruct-q4_K_M__autogrep_default", "llama3.1:8b-instruct-q4_K_M"),
    ("runs_followup_20261008", "hf.co_lmstudio-community_Mistral-Small-24B-Instruct-2501-GGUF_Q8_0__autogrep_default", "Mistral-Small-24B-Instruct-2501"),
    ("runs_followup_20261008", "phi4_14b-q4_K_M__autogrep_default", "phi4:14b-q4_K_M"),
    ("runs_openai_full_20261010", "gpt-4o__autogrep_default", "gpt-4o"),
]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def stage_tsx_samples(stage_dir: Path):
    """Byte-identical .tsx copies of CASE-0298's six frozen .ts samples. Records sha256 of both
    sides so byte-identity is provable, not just asserted."""
    stage_dir.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for _, stem, _ in SAMPLES:
        src = ROOT / "benchmark/cases/CASE-0298" / f"{stem}.ts"
        dst = stage_dir / f"{stem}.tsx"
        content = src.read_bytes()
        dst.write_bytes(content)
        h = sha(content)
        hashes[stem] = {"source_ts_sha256": h, "staged_tsx_sha256": sha(dst.read_bytes()), "identical": True}
        assert hashes[stem]["source_ts_sha256"] == hashes[stem]["staged_tsx_sha256"]
    return hashes


def find_raw_response(run_subdir, model_dir):
    """Attempt 1 only -- that's what the project's 'raw' condition means throughout. Returns
    (raw_content_text, source_path) or (None, None)."""
    base = RAW_STAGING / run_subdir / model_dir / "raw"
    if not base.exists():
        return None, None
    for run_dir in base.iterdir():
        f = run_dir / "CASE-0298.json"
        if f.exists():
            return json.loads(f.read_text())["raw_content"], str(f)
    return None, None


def run_semgrep(rule_path, tsx_stage, env):
    targets = [tsx_stage / f"{stem}.tsx" for _, stem, _ in SAMPLES]
    cmd = [str(SEMGREP), "--config", str(rule_path), "--json", "--metrics=off",
           "--disable-version-check", "--no-git-ignore", "--jobs=1", *[str(t) for t in targets]]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    return proc.stdout, proc.stderr, proc.returncode


def score(stdout, manifest, ann, tsx_stage):
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return None, ["Semgrep did not return JSON"]
    errors = data.get("errors", [])
    findings = data.get("results", [])
    records = {}
    for kind, stem, positive in SAMPLES:
        path = tsx_stage / f"{stem}.tsx"
        found = [r for r in findings if Path(r["path"]).resolve() == path.resolve()]
        lines = [r["start"]["line"] for r in found]
        location = None
        if positive:
            bounds = manifest["CASE-0298"]["vulnerable_lines"] if kind == "original_vulnerable" else ann.get(("CASE-0298", kind))
            location = bool(bounds and any(bounds[0] <= ln <= bounds[1] for ln in lines))
        outcome = ("TP" if location else "FN") if positive else ("FP" if found else "TN")
        records[kind] = {"detected": bool(found), "finding_lines": lines, "outcome": outcome}
    return records, errors


def main():
    if OUT.exists():
        sys.exit(f"{OUT} already exists -- refusing to overwrite. Remove it first or pick a new version.")
    OUT.mkdir(parents=True)

    semgrep_version = subprocess.run([str(SEMGREP), "--version"], capture_output=True, text=True).stdout.strip()

    manifest = load_manifest()
    ann = {(a["case_id"], a["variant"]): (a["start_line"], a["end_line"])
           for a in map(json.loads, (ROOT / "benchmark/variant_vulnerable_lines.jsonl").read_text().splitlines())}
    patch_info = load_case("CASE-0298", Config(openrouter_api_key="offline-replay"))

    tsx_stage = OUT / "tsx_staged_samples"
    staging_hashes = stage_tsx_samples(tsx_stage)

    import os
    env = os.environ.copy()
    env["PATH"] = str(ROOT / ".venv/bin") + os.pathsep + env.get("PATH", "")
    env.update(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")

    config = Config(openrouter_api_key="offline-replay")
    llm = object.__new__(LLMClient)
    llm.config = config
    llm.last_error = None

    results = {}
    for run_subdir, model_dir, label in MODEL_RUNS:
        model_dir_out = OUT / "models" / label.replace("/", "_").replace(":", "_")
        raw_content, source_path = find_raw_response(run_subdir, model_dir)
        if raw_content is None:
            results[label] = {"status": "no_raw_capture_found"}
            continue
        save_text(model_dir_out / "raw_response.txt", raw_content)
        record = {"source_raw_capture": source_path, "raw_response_sha256": sha(raw_content.encode())}

        rule = llm.parse_and_sanitize_response(raw_content, patch_info)
        if rule is None:
            record["status"] = "rule_never_parsed"
            results[label] = record
            save_json(model_dir_out / "result.json", record)
            continue

        rule_yaml = yaml.dump({"rules": [rule]})
        save_text(model_dir_out / "parsed_rule.yml", rule_yaml)
        record["parsed_rule_sha256"] = sha(rule_yaml.encode())

        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tf:
            tf.write(rule_yaml)
            rule_path = tf.name
        stdout, stderr, returncode = run_semgrep(rule_path, tsx_stage, env)
        save_text(model_dir_out / "semgrep_stdout.json", stdout)
        save_text(model_dir_out / "semgrep_stderr.txt", stderr)
        record["semgrep_returncode"] = returncode

        outcomes, errors = score(stdout, manifest, ann, tsx_stage)
        scan_ok = outcomes is not None and not errors and returncode == 0
        record["scan_ok"] = scan_ok
        record["errors"] = errors
        record["outcomes"] = outcomes
        record["status"] = "scanned" if scan_ok else "scan_error"
        results[label] = record
        save_json(model_dir_out / "result.json", record)

    manifest_out = {
        "created_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "purpose": "Offline replay of CASE-0298's raw-condition rule for all 16 headline models, under "
                   ".tsx target-file staging only (no prompt/workflow change). No new inference -- every "
                   "rule is reconstructed from a retained raw LLM response.",
        "semgrep_version_verified": semgrep_version,
        "pinned_semgrep_expected": "1.177.0",
        "tsx_staging_hashes": staging_hashes,
        "model_count": len(MODEL_RUNS),
        "results": results,
    }
    save_json(OUT / "manifest.json", manifest_out)
    print(f"Wrote {OUT}")
    print(json.dumps({k: v.get("status") for k, v in results.items()}, indent=2))


if __name__ == "__main__":
    main()

"""
Run v2, Part II cells C/D: build each case's development probe and write it into the run's own folder.

The probe is built by pipeline/dev_probe.py's deterministic builder from the VISIBLE functions only
(benchmark/model_context/<CASE>.json), never from hidden samples, and written outside benchmark/cases/.
On 2026-11-25 the builder could make a probe for 87 of the 150 eligible cases; for the 24 cases reviewed by hand
in October it gives the same 11 eligible cases as that review. All 174 probe files parse cleanly under pinned
Semgrep (bare Java methods included).
"""
import hashlib
import json
from pathlib import Path

from dev_probe import ProbeResult, build_probe

ROOT = Path(__file__).resolve().parent.parent
EXT = {"python": "py", "java": "java", "javascript": "js", "typescript": "ts"}


def build(case_id):
    ctx = json.loads((ROOT / "benchmark" / "model_context" / f"{case_id}.json").read_text())
    return build_probe(case_id, ctx["language"], ctx["vulnerable_function"], ctx["patched_function"]), ctx["language"]


def materialize(case_id, out_dir: Path):
    """Write the probe pair under out_dir/<CASE>/. Returns (paths or None, record). Refuses to overwrite."""
    result, language = build(case_id)
    if not isinstance(result, ProbeResult):
        return None, {"case_id": case_id, "eligible": False, "reason": result.reason}
    folder = Path(out_dir) / case_id
    folder.mkdir(parents=True, exist_ok=False)
    paths = (folder / f"vulnerable_probe.{EXT[language]}", folder / f"patched_probe.{EXT[language]}")
    record = {"case_id": case_id, "eligible": True}
    for path, text, role in zip(paths, (result.vulnerable_probe, result.patched_probe), ("vulnerable", "patched")):
        with path.open("xb") as fh:
            fh.write(text.encode())
        record[f"{role}_probe_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    return paths, record

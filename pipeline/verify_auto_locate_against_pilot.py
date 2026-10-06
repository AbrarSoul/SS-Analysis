"""
Verification harness (not part of the regular pipeline): re-derives each of
the 40 pilot cases' target function/class automatically via
auto_locate_target.py, and compares the result against the already
hand-verified extraction saved in benchmark/model_context/CASE-XXXX.json.

This is the trust-building step agreed before building the automated
targeting for the 300-case final set: if the automation independently
arrives at the same answer a human already painstakingly verified, that's
real evidence it's safe to use on new cases where there is no ground truth
to check against. Where it disagrees, that's exactly the case to look at
before trusting the automation further -- not something to average away.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from auto_locate_target import (
    all_hunk_targets, locate_python, locate_java, locate_js_ts, AutoLocateError,
)

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
EXT_BY_LANG = {"python": "py", "java": "java", "javascript": "js", "typescript": "ts"}
LOCATOR_BY_LANG = {
    "python": locate_python,
    "java": locate_java,
    "javascript": locate_js_ts,
    "typescript": locate_js_ts,
}


def normalize(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.strip().splitlines())


def main():
    case_dirs = sorted((BENCH_DIR / "cases").iterdir())
    results = {"match": [], "mismatch": [], "error": [], "skipped_no_context_file": []}

    for case_dir in case_dirs:
        case_id = case_dir.name
        context_file = BENCH_DIR / "model_context" / f"{case_id}.json"
        if not context_file.exists():
            results["skipped_no_context_file"].append(case_id)
            continue
        expected = json.loads(context_file.read_text())
        language = expected["language"]
        ext = EXT_BY_LANG[language]
        locator = LOCATOR_BY_LANG[language]

        diff_text = (case_dir / "patch.diff").read_text()
        vuln_src = (case_dir / f"vulnerable_source.{ext}").read_text()
        patched_src = (case_dir / f"patched_source.{ext}").read_text()

        try:
            hunks = all_hunk_targets(diff_text)
            vuln_text, vuln_class = locator(vuln_src, hunks, "old")
            patched_text, _ = locator(patched_src, hunks, "new")
        except AutoLocateError as e:
            results["error"].append((case_id, str(e)))
            continue
        except Exception as e:
            results["error"].append((case_id, f"{type(e).__name__}: {e}"))
            continue

        expected_vuln = normalize(expected["vulnerable_function"])
        got_vuln = normalize(vuln_text)
        truncated = expected.get("truncation_applied", False)

        if truncated:
            # truncation trims from the end -- a prefix match is the right
            # comparison here, not exact equality.
            ok = got_vuln.startswith(expected_vuln) or expected_vuln.startswith(got_vuln)
        else:
            ok = got_vuln == expected_vuln

        if ok:
            results["match"].append(case_id)
        else:
            results["mismatch"].append((case_id, expected_vuln[:150], got_vuln[:150]))

    print(f"MATCH: {len(results['match'])}")
    print(f"MISMATCH: {len(results['mismatch'])}")
    print(f"ERROR (auto-locate raised): {len(results['error'])}")
    print(f"SKIPPED (no saved context file): {len(results['skipped_no_context_file'])}")
    print()

    if results["mismatch"]:
        print("=== Mismatches ===")
        for case_id, exp, got in results["mismatch"]:
            print(f"\n{case_id}")
            print(f"  expected: {exp!r}")
            print(f"  got:      {got!r}")

    if results["error"]:
        print("\n=== Errors ===")
        for case_id, err in results["error"]:
            print(f"  {case_id}: {err}")


if __name__ == "__main__":
    main()

"""
Section 8 Step 6 for the 300-case FINAL dataset (Phase 4) -- mechanical
portion only.

Unlike the pilot's classify_difficulty.py, this does NOT fill in
pattern_or_taint, structural_or_context_heavy, or supported_status
(semgrep_representability). All three are genuine judgment calls that
require actually understanding each vulnerability's mechanism -- the
pilot's own script is explicit that its judgments came "from this
session's direct, hands-on construction of every case's Section 9
ground-truth bundle", not from anything mechanically derivable. For the
final set, that hands-on engagement (Section 9's test-bundle construction)
hasn't happened yet -- it comes after Step 7 in the design doc's own
ordering. Generating 305 of these judgments now, without that engagement,
would mean fabricating shallow classifications that could quietly corrupt
Phase 7's difficulty-stratified subgroup analysis -- decided with the user
to defer all three fields to Section 9 instead of guessing now, so the
deep per-case reading happens once, not twice.

Computes only what's genuinely mechanical:
- language, CWE ids (from Step 3/4 metadata, already verified)
- changed_files / lines_added / lines_removed (from patch.diff directly)
- function_size_chars / function_size_lines (from Step 5's extracted
  vulnerable_function)
- auto_locate_confidence (carried over from Step 5, itself a useful
  difficulty-adjacent signal: a low-confidence auto-located case is
  probably touching a more structurally ambiguous piece of code)
"""
import json
import re
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
STEP3_DIRS = {
    "final": BENCH_DIR / "step3_repo_states_final",
    "topup": BENCH_DIR / "step3_repo_states_topup",
    "topup2": BENCH_DIR / "step3_repo_states_topup2",
    "topup3": BENCH_DIR / "step3_repo_states_topup3",
    "topup4": BENCH_DIR / "step3_repo_states_topup4",
    "topup5": BENCH_DIR / "step3_repo_states_topup5",
    "topup6": BENCH_DIR / "step3_repo_states_topup6",
    "topup7": BENCH_DIR / "step3_repo_states_topup7",
    "topup8": BENCH_DIR / "step3_repo_states_topup8",
    "topup9": BENCH_DIR / "step3_repo_states_topup9",
    "topup10": BENCH_DIR / "step3_repo_states_topup10",
    "topup11": BENCH_DIR / "step3_repo_states_topup11",
    "topup12": BENCH_DIR / "step3_repo_states_topup12",
    "topup13": BENCH_DIR / "step3_repo_states_topup13",
    "topup14": BENCH_DIR / "step3_repo_states_topup14",
    "topup15": BENCH_DIR / "step3_repo_states_topup15",
    "topup16": BENCH_DIR / "step3_repo_states_topup16",
    "topup17": BENCH_DIR / "step3_repo_states_topup17",
    "topup18": BENCH_DIR / "step3_repo_states_topup18",
    "topup19": BENCH_DIR / "step3_repo_states_topup19",
    "topup20": BENCH_DIR / "step3_repo_states_topup20",
    "topup21": BENCH_DIR / "step3_repo_states_topup21",
    "topup22": BENCH_DIR / "step3_repo_states_topup22",
    "topup23": BENCH_DIR / "step3_repo_states_topup23",
    "topup24": BENCH_DIR / "step3_repo_states_topup24",
    "topup25": BENCH_DIR / "step3_repo_states_topup25",
    "topup26": BENCH_DIR / "step3_repo_states_topup26",
    "topup27": BENCH_DIR / "step3_repo_states_topup27",
    "topup28": BENCH_DIR / "step3_repo_states_topup28",
    "topup29": BENCH_DIR / "step3_repo_states_topup29",
    "topup30": BENCH_DIR / "step3_repo_states_topup30",
    "topup31": BENCH_DIR / "step3_repo_states_topup31",
    "topup32": BENCH_DIR / "step3_repo_states_topup32",
    "topup33": BENCH_DIR / "step3_repo_states_topup33",
    "topup34": BENCH_DIR / "step3_repo_states_topup34",
    "topup35": BENCH_DIR / "step3_repo_states_topup35",
    "topup36": BENCH_DIR / "step3_repo_states_topup36",
    "topup37": BENCH_DIR / "step3_repo_states_topup37",
    "topup38": BENCH_DIR / "step3_repo_states_topup38",
    "topup39": BENCH_DIR / "step3_repo_states_topup39",
    "topup40": BENCH_DIR / "step3_repo_states_topup40",
}
CONTEXT_DIRS = {
    "final": BENCH_DIR / "model_context_final",
    "topup": BENCH_DIR / "model_context_topup",
    "topup2": BENCH_DIR / "model_context_topup2",
    "topup3": BENCH_DIR / "model_context_topup3",
    "topup4": BENCH_DIR / "model_context_topup4",
    "topup5": BENCH_DIR / "model_context_topup5",
    "topup6": BENCH_DIR / "model_context_topup6",
    "topup7": BENCH_DIR / "model_context_topup7",
    "topup8": BENCH_DIR / "model_context_topup8",
    "topup9": BENCH_DIR / "model_context_topup9",
    "topup10": BENCH_DIR / "model_context_topup10",
    "topup11": BENCH_DIR / "model_context_topup11",
    "topup12": BENCH_DIR / "model_context_topup12",
    "topup13": BENCH_DIR / "model_context_topup13",
    "topup14": BENCH_DIR / "model_context_topup14",
    "topup15": BENCH_DIR / "model_context_topup15",
    "topup16": BENCH_DIR / "model_context_topup16",
    "topup17": BENCH_DIR / "model_context_topup17",
    "topup18": BENCH_DIR / "model_context_topup18",
    "topup19": BENCH_DIR / "model_context_topup19",
    "topup20": BENCH_DIR / "model_context_topup20",
    "topup21": BENCH_DIR / "model_context_topup21",
    "topup22": BENCH_DIR / "model_context_topup22",
    "topup23": BENCH_DIR / "model_context_topup23",
    "topup24": BENCH_DIR / "model_context_topup24",
    "topup25": BENCH_DIR / "model_context_topup25",
    "topup26": BENCH_DIR / "model_context_topup26",
    "topup27": BENCH_DIR / "model_context_topup27",
    "topup28": BENCH_DIR / "model_context_topup28",
    "topup29": BENCH_DIR / "model_context_topup29",
    "topup30": BENCH_DIR / "model_context_topup30",
    "topup31": BENCH_DIR / "model_context_topup31",
    "topup32": BENCH_DIR / "model_context_topup32",
    "topup33": BENCH_DIR / "model_context_topup33",
    "topup34": BENCH_DIR / "model_context_topup34",
    "topup35": BENCH_DIR / "model_context_topup35",
    "topup36": BENCH_DIR / "model_context_topup36",
    "topup37": BENCH_DIR / "model_context_topup37",
    "topup38": BENCH_DIR / "model_context_topup38",
    "topup39": BENCH_DIR / "model_context_topup39",
    "topup40": BENCH_DIR / "model_context_topup40",
}

OUT_DIR = BENCH_DIR / "difficulty_final"


def compute_diff_stats(diff_text: str) -> dict:
    files_changed = len(re.findall(r"^diff --git", diff_text, re.MULTILINE))
    added = len(re.findall(r"^\+(?!\+\+)", diff_text, re.MULTILINE))
    removed = len(re.findall(r"^-(?!--)", diff_text, re.MULTILINE))
    return {"changed_files": files_changed, "lines_added": added, "lines_removed": removed,
            "lines_changed_total": added + removed}


def main():
    out_dir = OUT_DIR
    # Clear stale output first -- same lesson as extract_context_final.py's
    # equivalent fix: a case excluded by a later Step 5 re-run (e.g. by its
    # size gate) shouldn't leave an orphaned difficulty record behind.
    if out_dir.exists():
        for f in out_dir.glob("*.json"):
            f.unlink()
    out_dir.mkdir(exist_ok=True)
    summary = []

    for batch_name, context_dir in CONTEXT_DIRS.items():
        step3_dir = STEP3_DIRS[batch_name]
        for context_file in sorted(context_dir.glob("*.json")):
            case_id = context_file.stem
            context = json.loads(context_file.read_text())
            metadata = json.loads((step3_dir / case_id / "metadata.json").read_text())
            diff_text = (step3_dir / case_id / "patch.diff").read_text()
            diff_stats = compute_diff_stats(diff_text)

            vuln_func_chars = len(context["vulnerable_function"])
            vuln_func_lines = context["vulnerable_function"].count("\n") + 1

            result = {
                "case_id": case_id,
                "batch": batch_name,
                "language": metadata["language"],
                "cwe_ids": metadata.get("cwe_ids", []),
                **diff_stats,
                "function_size_chars": vuln_func_chars,
                "function_size_lines": vuln_func_lines,
                "auto_locate_confidence": context.get("auto_locate_confidence"),
                "pattern_or_taint": None,
                "structural_or_context_heavy": None,
                "supported_status": None,
                "classification_pending_reason": (
                    "Deferred to Section 9 (test-bundle construction) -- these three "
                    "fields require genuine per-case understanding of the vulnerability "
                    "mechanism, not something mechanically derivable from the diff alone."
                ),
            }
            out_path = out_dir / f"{case_id}.json"
            out_path.write_text(json.dumps(result, indent=2) + "\n")
            summary.append(result)

    from collections import Counter
    print("Total cases:", len(summary))
    print("By language:", Counter(s["language"] for s in summary))
    print("By batch:", Counter(s["batch"] for s in summary))
    print("By auto_locate_confidence:", Counter(s["auto_locate_confidence"] for s in summary))
    print("Function size (lines) min/max/avg:",
          min(s["function_size_lines"] for s in summary),
          max(s["function_size_lines"] for s in summary),
          round(sum(s["function_size_lines"] for s in summary) / len(summary), 1))
    print("Changed lines (total) min/max/avg:",
          min(s["lines_changed_total"] for s in summary),
          max(s["lines_changed_total"] for s in summary),
          round(sum(s["lines_changed_total"] for s in summary) / len(summary), 1))

    (BENCH_DIR / "difficulty_final_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"\nWritten to {out_dir}")
    print(f"Summary: {BENCH_DIR / 'difficulty_final_summary.json'}")


if __name__ == "__main__":
    main()

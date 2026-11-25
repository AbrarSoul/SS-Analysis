"""
Ad hoc, one-off formal significance test: is gpt-4o's conditional-MCC edge over qwen3-coder:30b
(0.569 vs 0.553, pipeline/build_full_openai_comparison.py) real, or within repo-aware bootstrap
noise? Also tests the (already-tied, 11/150 each) end-to-end success rate difference.

Reuses the project's own audited repo-aware bootstrap machinery from
analyze_section22_corrected.py (repo_aware_bootstrap, paired_comparison_corrected,
_esr_from_samples) rather than re-deriving a parallel statistical method -- same ESR definition
(VGR/FPR threshold based), same repo-level resampling principle (cases from the same repo are not
independent, Section22_Scope.md), same 150-case eligible-supported population.

Usage:
    python pipeline/compare_gpt4o_vs_qwen3coder.py
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_phase5_primary import load_manifest, gated_samples
from analyze_section22 import _esr_from_samples
from analyze_section22_corrected import paired_comparison_corrected, print_comparison
from eligible_cases import eligible_supported_cases, VERSION as ELIGIBLE_VERSION

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
RESULTS_CORRECTED = ROOT / "results_corrected"


def load_corrected(run_subdir: str, model_dir_name: str, condition: str, case_filter=None):
    gen = [json.loads(l) for l in (RESULTS / run_subdir / model_dir_name / "generation_log.jsonl").read_text().splitlines()]
    smp = [json.loads(l) for l in (RESULTS_CORRECTED / run_subdir / model_dir_name / "sample_execution_log.jsonl").read_text().splitlines()]
    gen_c = {g["case_id"]: g for g in gen if g["condition"] == condition}
    smp_by_case = defaultdict(list)
    for s in smp:
        if s["condition"] == condition:
            smp_by_case[s["case_id"]].append(s)
    out = {}
    for cid, g in gen_c.items():
        if case_filter is not None and cid not in case_filter:
            continue
        executable = bool(g["yaml_valid"] and g["semgrep_valid"])
        case_samples = gated_samples(cid, executable, smp_by_case)
        out[cid] = {"esr": _esr_from_samples(case_samples, executable), "samples": case_samples}
    return out


def main():
    supported = eligible_supported_cases()
    manifest = load_manifest()
    case_to_repo = {cid: manifest[cid]["repository"] for cid in manifest}
    print(f"eligible_cases.py v{ELIGIBLE_VERSION}: {len(supported)} eligible supported cases. "
          f"Repo-aware bootstrap (n_boot=10000), Finding-1-corrected data throughout.\n")

    print("=" * 100)
    print("gpt-4o (full 300-case run, 2026-10-10)  vs  qwen3-coder:30b (follow-up campaign, 2026-10-08)")
    print("=" * 100)
    a = load_corrected("runs_openai_full_20261010", "gpt-4o__autogrep_default", "autogrep", supported)
    b = load_corrected("runs_followup_20261008", "qwen3-coder_30b__autogrep_default", "autogrep", supported)
    print_comparison(paired_comparison_corrected("gpt-4o", a, "qwen3-coder:30b", b, case_to_repo))


if __name__ == "__main__":
    main()

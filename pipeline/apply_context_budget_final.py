"""
Section 8 Step 5: enforce the shared maximum context limit (12,000
characters, confirmed with the user) over each case's extracted model
context, using one deterministic truncation policy applied in this fixed
order until the total fits:

  1. Truncate the unified diff from the end (keep the largest possible
     prefix, append a truncation marker noting how many characters were
     cut).
  2. If still over budget, truncate the patched function/method from the
     end (same marker convention).
  3. If still over budget, truncate the vulnerable function/method from
     the end (same marker convention).

Imports and the containing-class declaration are never truncated -- they
are always small and are required for the extracted function to be
minimally comprehensible/compilable in context.

Records whether truncation was applied and what was cut, for provenance
and for Step 6's difficulty classification (a truncated case is closer to
the "context-heavy" category).
"""
import json
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
CONTEXT_DIRS = [BENCH_DIR / "model_context_final", BENCH_DIR / "model_context_topup", BENCH_DIR / "model_context_topup2", BENCH_DIR / "model_context_topup3"]
BUDGET = 12000


def total_size(d: dict) -> int:
    return (
        len(d["vulnerable_function"])
        + len(d["patched_function"])
        + len(d["unified_diff"])
        + sum(len(x) for x in d["imports"])
        + len(d.get("containing_class_declaration") or "")
    )


def truncate_from_end(text: str, max_len: int, label: str) -> tuple[str, str | None]:
    if len(text) <= max_len:
        return text, None
    cut = len(text) - max_len
    marker = f"\n... [TRUNCATED: {cut} characters removed from the end of the {label} to stay within the {BUDGET}-character shared context budget] ...\n"
    keep = max_len - len(marker)
    if keep < 0:
        keep = 0
    return text[:keep] + marker, f"{label}: removed {cut} characters from the end"


def apply_budget(d: dict) -> dict:
    notes = []
    size = total_size(d)
    if size <= BUDGET:
        d["truncation_applied"] = False
        d["truncation_notes"] = []
        return d

    over = size - BUDGET

    # Step 1: truncate the diff
    diff_len = len(d["unified_diff"])
    if over > 0 and diff_len > 0:
        cut_here = min(over, diff_len)
        new_len = diff_len - cut_here
        d["unified_diff"], note = truncate_from_end(d["unified_diff"], new_len, "unified diff")
        if note:
            notes.append(note)
        over = total_size(d) - BUDGET

    # Step 2: truncate the patched function
    patched_len = len(d["patched_function"])
    if over > 0 and patched_len > 0:
        cut_here = min(over, patched_len)
        new_len = patched_len - cut_here
        d["patched_function"], note = truncate_from_end(d["patched_function"], new_len, "patched function")
        if note:
            notes.append(note)
        over = total_size(d) - BUDGET

    # Step 3: truncate the vulnerable function
    vuln_len = len(d["vulnerable_function"])
    if over > 0 and vuln_len > 0:
        cut_here = min(over, vuln_len)
        new_len = vuln_len - cut_here
        d["vulnerable_function"], note = truncate_from_end(d["vulnerable_function"], new_len, "vulnerable function")
        if note:
            notes.append(note)

    d["truncation_applied"] = True
    d["truncation_notes"] = notes
    return d


def main():
    truncated_cases = []
    for context_dir in CONTEXT_DIRS:
        for path in sorted(context_dir.glob("*.json")):
            d = json.loads(path.read_text())
            original_size = total_size(d)
            d = apply_budget(d)
            d["context_budget_chars"] = BUDGET
            d["context_size_chars_before_truncation"] = original_size
            d["context_size_chars_after_truncation"] = total_size(d)
            path.write_text(json.dumps(d, indent=2) + "\n")
            if d["truncation_applied"]:
                truncated_cases.append((d["case_id"], original_size, d["truncation_notes"]))

    print(f"Budget: {BUDGET} chars. Cases requiring truncation: {len(truncated_cases)}")
    for case_id, orig, notes in truncated_cases:
        print(f"  {case_id}: {orig} -> {BUDGET} chars")
        for n in notes:
            print(f"    - {n}")


if __name__ == "__main__":
    main()

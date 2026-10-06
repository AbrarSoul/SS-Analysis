"""
Correction (2026-10-06 audit, Finding 1): computes the missing per-variant line-range annotation
needed to retroactively check finding-location-correctness for variant_vulnerable_1/2 samples --
the two hidden, transformed samples VGR is computed from, for which no location check has EVER been
implemented (see Research_Log/Correction_Log.md).

No Semgrep or LLM execution is needed -- every sample record already stores the finding's actual
line numbers (`finding_lines`). What was missing is "where in THIS variant file does the vulnerable
construct actually sit" (the manifest's own `vulnerable_lines` field only describes the ORIGINAL,
untransformed file). This script infers that range for every case's two vulnerable variants,
without parsing each case's hand-written Section 9 build script (which vary too much in style to
parse generically) -- instead, directly comparing the two already-materialized files on disk.

Method: the variant files are built by replacing ONE localized block of the original file and
leaving everything else byte-identical (renaming, restructuring, etc., happens only within that
block). So:
  1. Take a few lines immediately before and after the ORIGINAL file's known vulnerable_lines range
     as "anchor" context.
  2. Find that exact anchor text in the variant file, preferring the occurrence closest to the
     expected position (guards against a spurious earlier match on a common anchor like a blank
     line or a repeated closing brace -- confirmed necessary by a real test failure, see
     Correction_Log.md).
  3. The modified range in the variant is everything strictly between the two anchors.
  4. Fall back to a buffered diff-opcode overlap (line-level SequenceMatcher, restricted to opcodes
     whose ORIGINAL-side range intersects a small buffer around vulnerable_lines) if an exact anchor
     match isn't found on either side.
  5. Flag low confidence (for manual review, not silently trusted) whenever the inferred span is
     less than 40% or more than 250% of the original span -- a real, calibrated sanity check, not
     an arbitrary one: verified against 5 diverse real cases during development, all of which came
     back within this range once the "nearest occurrence" fix was applied (described above).

Usage:
    python pipeline/compute_variant_vulnerable_lines.py
    -> writes benchmark/variant_vulnerable_lines.jsonl, one record per (case_id, variant_num):
       {"case_id": ..., "variant": "variant_vulnerable_1"|"variant_vulnerable_2",
        "start_line": int, "end_line": int, "method": str, "confidence": "high"|"LOW"}
"""
import difflib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = ROOT / "benchmark"
EXT_BY_LANGUAGE = {"python": "py", "java": "java", "javascript": "js", "typescript": "ts"}


def find_subseq_nearest(hay: list, needle: list, expected_idx: int):
    if not needle:
        return None
    candidates = [i for i in range(len(hay) - len(needle) + 1) if hay[i:i + len(needle)] == needle]
    if not candidates:
        return None
    return min(candidates, key=lambda i: abs(i - expected_idx))


def infer_variant_range(orig_lines: list, var_lines: list, vuln_start: int, vuln_end: int, anchor: int = 3):
    """vuln_start/vuln_end are 1-indexed, inclusive, describing the ORIGINAL file. Returns
    (start, end, method, confidence) for the VARIANT file, 1-indexed inclusive, or
    (None, None, 'failed', 'LOW') if no correspondence could be found at all."""
    pre_anchor = orig_lines[max(0, vuln_start - 1 - anchor):vuln_start - 1]
    post_anchor = orig_lines[vuln_end:vuln_end + anchor]

    pre_pos = find_subseq_nearest(var_lines, pre_anchor, vuln_start - 1 - anchor) if pre_anchor else None
    post_pos = find_subseq_nearest(var_lines, post_anchor, vuln_end) if post_anchor else None

    if pre_pos is not None and post_pos is not None and pre_pos + len(pre_anchor) <= post_pos:
        start, end, method = pre_pos + len(pre_anchor) + 1, post_pos, "anchor_exact"
    else:
        sm = difflib.SequenceMatcher(a=orig_lines, b=var_lines, autojunk=False)
        buf = 2
        lo, hi = vuln_start - 1 - buf, vuln_end + buf
        j_starts, j_ends = [], []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                continue
            if i2 > lo and i1 < hi:
                j_starts.append(j1)
                j_ends.append(j2)
        if not j_starts:
            return None, None, "failed", "LOW"
        start, end, method = min(j_starts) + 1, max(j_ends), "opcode_overlap_fallback"

    orig_span = vuln_end - vuln_start + 1
    inferred_span = end - start + 1
    ratio = (inferred_span / orig_span) if orig_span else 0
    confidence = "high" if 0.4 <= ratio <= 2.5 else "LOW"
    return start, end, method, confidence


def main():
    manifest = {}
    for path in (BENCH_DIR / "manifest_frozen_final.jsonl", BENCH_DIR / "manifest_frozen_pilot.jsonl"):
        if path.exists():
            for line in path.read_text().splitlines():
                r = json.loads(line)
                manifest[r["case_id"]] = r

    out_path = BENCH_DIR / "variant_vulnerable_lines.jsonl"
    records = []
    stats = {"high": 0, "LOW": 0, "no_case_dir": 0, "no_variant_file": 0}

    for case_id, row in sorted(manifest.items()):
        case_dir = BENCH_DIR / "cases" / case_id
        if not case_dir.exists():
            stats["no_case_dir"] += 1
            continue
        lang = row.get("language")
        ext = EXT_BY_LANGUAGE.get(lang)
        vuln_lines = row.get("vulnerable_lines")
        orig_file = case_dir / f"vulnerable_source.{ext}"
        if ext is None or not vuln_lines or not orig_file.exists():
            continue
        orig_lines = orig_file.read_text().splitlines()
        vs, ve = vuln_lines

        for num, variant_name in (("01", "variant_vulnerable_1"), ("02", "variant_vulnerable_2")):
            vf = case_dir / f"variant_vulnerable_{num}.{ext}"
            if not vf.exists():
                stats["no_variant_file"] += 1
                continue
            var_lines = vf.read_text().splitlines()
            start, end, method, confidence = infer_variant_range(orig_lines, var_lines, vs, ve)
            stats[confidence] = stats.get(confidence, 0) + 1
            records.append({
                "case_id": case_id, "variant": variant_name,
                "start_line": start, "end_line": end,
                "method": method, "confidence": confidence,
            })

    with open(out_path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"Wrote {len(records)} records to {out_path}")
    print(f"Confidence breakdown: {stats}")
    low = [r for r in records if r["confidence"] == "LOW"]
    if low:
        print(f"\n{len(low)} LOW-confidence record(s), flagged for manual review, NOT silently trusted:")
        for r in low:
            print(f"  {r['case_id']} {r['variant']}: [{r['start_line']}, {r['end_line']}] via {r['method']}")


if __name__ == "__main__":
    main()

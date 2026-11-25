"""
Run v2 (Issue 3): where the vulnerable construct is in each positive sample of a case.

Read from the benchmark at run time, so corrections made after the ground-truth review (applied to these
same files in one logged batch) are used automatically:
  - original_vulnerable:   benchmark/cases/<CASE>/metadata.json  "vulnerable_lines" [start, end]
  - variant_vulnerable_1/2: benchmark/variant_vulnerable_lines.jsonl (confidence "high" or "manual" only,
                            as in v1's rescoring), plus benchmark/variant_vulnerable_lines_v2_additions.jsonl,
                            which adds a second valid range where a restructured variant moved the construct.

A sample can therefore have more than one range; a finding is checked against all of them.
"""
import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Tuple

BENCH = Path(__file__).resolve().parent.parent / "benchmark"
TRUSTED_CONFIDENCE = ("high", "manual")
Range = Tuple[int, int]


@lru_cache(maxsize=None)
def _variant_ranges() -> Dict[Tuple[str, str], List[Range]]:
    out: Dict[Tuple[str, str], List[Range]] = {}
    for name in ("variant_vulnerable_lines.jsonl", "variant_vulnerable_lines_v2_additions.jsonl"):
        path = BENCH / name
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("confidence") not in TRUSTED_CONFIDENCE:
                continue
            rng = (int(r["start_line"]), int(r["end_line"]))
            out.setdefault((r["case_id"], r["variant"]), [])
            if rng not in out[(r["case_id"], r["variant"])]:
                out[(r["case_id"], r["variant"])].append(rng)
    return out


def load_location_ranges(case_id: str) -> Dict[str, List[Range]]:
    """{sample_type: [(start, end), ...]} for the positive samples that have an annotation."""
    ranges: Dict[str, List[Range]] = {}
    meta = json.loads((BENCH / "cases" / case_id / "metadata.json").read_text())
    vl = meta.get("vulnerable_lines")
    if vl:
        ranges["original_vulnerable"] = [(int(vl[0]), int(vl[1]))]
    for variant in ("variant_vulnerable_1", "variant_vulnerable_2"):
        found = _variant_ranges().get((case_id, variant))
        if found:
            ranges[variant] = list(found)
    return ranges


def missing_ranges(case_ids) -> List[Tuple[str, str]]:
    """(case_id, sample_type) pairs with no annotated range. Run v2 requires this to be empty at the freeze:
    a positive sample without a range would be scored without any location check."""
    out = []
    for cid in case_ids:
        have = load_location_ranges(cid)
        out += [(cid, st) for st in ("original_vulnerable", "variant_vulnerable_1", "variant_vulnerable_2")
                if st not in have]
    return out

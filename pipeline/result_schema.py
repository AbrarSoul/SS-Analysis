"""
Result-record schema for the benchmark.

Two record types, not one, because they answer different questions at
different granularities:

- GenerationRecord: one row per (case, model, condition, attempt) -- what
  the model produced and whether it was even executable. Steps 2-4's
  pipeline (raw_capture + Autogrep) naturally produces one of these per
  generation attempt.

- SampleExecutionRecord: one row per (case, model, condition, sample) --
  whether ONE labeled test-bundle sample (original vulnerable, original
  patched, a transformed variant, a safe rewrite, a benign look-alike) was
  flagged by the generated rule. A single generated rule is tested against
  every sample in its case's bundle (design doc Section 9), so confusion-
  matrix outcomes are inherently per-sample, not per-generation. Case-level
  metrics like PDS/VGR/FPR/MCC (design doc Section 21) are aggregates over
  several of these rows, computed downstream during analysis -- they are
  NOT fields you fill in on a single row, because a single generation event
  doesn't have one PDS/VGR value; the case it belongs to does, once all of
  its samples have been executed.

JSONL is used for both (one JSON object per line), matching the case-
manifest style already used in the design doc (Section 10).
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional


def make_run_id(model_tag: str) -> str:
    safe = model_tag.replace("/", "_").replace(":", "_")
    return f"{safe}__{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"


@dataclass
class GenerationRecord:
    run_id: str
    case_id: str
    model_tag: str
    host: str
    condition: str  # "raw" | "autogrep"
    attempt_index: int
    temperature: float
    max_retries: int
    prompt_hash: Optional[str] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    generation_seconds: Optional[float] = None
    yaml_valid: bool = False
    semgrep_valid: bool = False
    rule_id: Optional[str] = None
    rule_path: Optional[str] = None
    validation_error: Optional[str] = None
    timestamp: Optional[float] = None
    # Full per-attempt history for the "autogrep" condition -- e.g.
    # [{"attempt_index": 1, "yaml_valid": True, "semgrep_valid": False,
    # "error": "..."}, ...]. Autogrep's own retry loop discards everything
    # except the final outcome on total failure, so this is reconstructed
    # independently from raw-captured attempts (see pipeline/run_generation.py,
    # reconstruct_attempt_trail()). Left None for the "raw" condition, which
    # is just attempt 1 and is already fully described by this record's own
    # yaml_valid/semgrep_valid/validation_error fields.
    attempt_trail: Optional[List[dict]] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self))


# Sample types drawn directly from the design doc's six-sample test bundle
# (Section 9). "label" is ground truth; "detected"/"finding_location_correct"
# come from executing the generated rule against that sample with pinned Semgrep.
SAMPLE_TYPES = (
    "original_vulnerable",
    "original_patched",
    "variant_vulnerable_1",
    "variant_vulnerable_2",
    "variant_safe",
    "benign_lookalike",
)
POSITIVE_SAMPLE_TYPES = {"original_vulnerable", "variant_vulnerable_1", "variant_vulnerable_2"}
NEGATIVE_SAMPLE_TYPES = {"original_patched", "variant_safe", "benign_lookalike"}


@dataclass
class SampleExecutionRecord:
    run_id: str
    case_id: str
    model_tag: str
    condition: str  # "raw" | "autogrep"
    sample_type: str  # one of SAMPLE_TYPES
    label: str  # "positive" | "negative"
    detected: bool
    finding_location_correct: Optional[bool] = None  # meaningful only when label == "positive"
    finding_lines: Optional[List[int]] = None
    outcome: Optional[str] = None  # "TP" | "FP" | "FN" | "TN" -- derived if not given

    def __post_init__(self):
        if self.outcome is None:
            self.outcome = self._derive_outcome()

    def _derive_outcome(self) -> str:
        # Per design doc Section 9.3: a positive sample only counts as a true
        # positive if the finding is at the correct location, not merely
        # somewhere in the file.
        if self.label == "positive":
            true_hit = self.detected and (self.finding_location_correct is not False)
            return "TP" if true_hit else "FN"
        return "FP" if self.detected else "TN"

    def to_json(self) -> str:
        return json.dumps(asdict(self))


def append_jsonl(records, path: Path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        for r in records:
            f.write(r.to_json() + "\n")


def read_jsonl(path: Path, cls):
    path = Path(path)
    out = []
    if not path.exists():
        return out
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(cls(**json.loads(line)))
    return out


# ---------------------------------------------------------------------------
# Case-level aggregation helpers. These operate on one case's sample records
# and implement the Section 21 formulas exactly, so Phase 7's analysis can
# build macro/micro averages on top of them rather than re-deriving the logic.
# ---------------------------------------------------------------------------

def case_confusion_counts(sample_records: List[SampleExecutionRecord]) -> dict:
    counts = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for r in sample_records:
        counts[r.outcome] += 1
    return counts


def patch_discrimination_hit(sample_records: List[SampleExecutionRecord]) -> Optional[bool]:
    """PDS numerator condition (Section 21.10): the original vulnerable sample
    is detected AND the original patched sample is not -- for this one case."""
    by_type = {r.sample_type: r for r in sample_records}
    vuln = by_type.get("original_vulnerable")
    patched = by_type.get("original_patched")
    if vuln is None or patched is None:
        return None
    return vuln.outcome == "TP" and patched.outcome == "TN"


def vulnerability_generalization_recall(sample_records: List[SampleExecutionRecord]) -> Optional[float]:
    """VGR (Section 21.11) restricted to this one case's transformed variants."""
    variants = [r for r in sample_records if r.sample_type.startswith("variant_vulnerable")]
    if not variants:
        return None
    hits = sum(1 for r in variants if r.outcome == "TP")
    return hits / len(variants)


def false_positive_rate(counts: dict) -> Optional[float]:
    denom = counts["FP"] + counts["TN"]
    return (counts["FP"] / denom) if denom else None


def matthews_correlation_coefficient(counts: dict) -> float:
    tp, fp, fn, tn = counts["TP"], counts["FP"], counts["FN"], counts["TN"]
    numerator = tp * tn - fp * fn
    denom_terms = (tp + fp, tp + fn, tn + fp, tn + fn)
    if any(t == 0 for t in denom_terms):
        # Standard convention (matches scikit-learn's matthews_corrcoef):
        # MCC is undefined when any margin is zero -- return 0.0, not an error.
        return 0.0
    denominator = (denom_terms[0] * denom_terms[1] * denom_terms[2] * denom_terms[3]) ** 0.5
    return numerator / denominator

# Data Integrity Principles

Five concrete follow-ups raised before starting Phase 2 (the 30-case pilot). Two were code defects, now fixed and verified; three are standing policies for every phase from here on, recorded here so they survive past this conversation.

---

## 1. Per-retry error propagation — fixed

Autogrep's own `process_patch()` discarded all per-attempt diagnostic detail on total failure, returning a bare `None` with no record of what went wrong at each retry. `pipeline/run_generation.py` now independently reconstructs the full attempt trail from the raw-capture files (which already record every attempt, not just the first), producing an `attempt_trail` list on every `GenerationRecord` — one entry per attempt, each with its own `yaml_valid`/`semgrep_valid`/`error`.

**Verified:** re-ran `qwen2.5-coder:32b` (a total-failure case); the log now shows all 3 attempts' individual error text, not just a bare failure flag.

## 2. Regression tests for validator classification — added

`pipeline/tests/test_rule_validator_classification.py` (5 tests, run against the real pinned Semgrep binary, not mocked) locks in the deny-list error classification fixed earlier:

- A valid rule with a real match → results, no error.
- A valid rule with a genuine non-match → empty results, no error (the critical case that must **not** be confused with an invalid rule).
- An invalid rule (lowercase metavariables) → surfaced as an error, not silently treated as a clean miss.
- A target file with broken syntax → skipped safely (a file problem, not a rule problem).
- An explicit guard against the classifier reverting to an allow-list in the future.

All 5 pass. Run with `pytest pipeline/tests/`.

## 3. Report end-to-end and executable-rule-only performance separately — standing policy

Every `GenerationRecord` already carries both `yaml_valid` and `semgrep_valid` as independent booleans, specifically so downstream analysis (Phase 7) can compute two different views without conflating them:

- **End-to-end performance**: every requested generation counts in the denominator, including invalid/empty/malformed ones (an invalid rule counts as a miss on every positive sample it would have been tested against).
- **Executable-rule-only performance**: filtered to `semgrep_valid == True` rows only — answers "given that a model produced something that actually ran, how good was it?"

**Rule going forward:** never report only one of these as if it were the whole picture. A model with a high executable-rule-only score but a low raw compilation rate is a genuinely different result from a model that is merely mediocre throughout — the two views must be shown side by side, matching the design doc's own confusion-matrix guidance (Section 21.1: an invalid rule has no executable prediction and must not be credited for "correctly" ignoring negative samples it never actually ran against).

## 4. Preserve all raw failures without manual cleanup — fixed + standing policy

**Fixed a real violation of this, not just a hypothetical:** raw-capture files were previously written to a fixed path per case (`raw/{case_id}.json`), so re-running the same model against the same case — which happened repeatedly during this session's testing, and which the design's Section 13.4 stability experiment requires *deliberately* (5 runs per case) — silently overwrote the previous capture. Fixed by namespacing every raw-capture file under its `run_id` (`raw/{run_id}/{case_id}.json`), so no run's evidence is ever silently destroyed by a later one.

**Standing policy:** no raw output — malformed YAML, empty responses, nonsensical patterns — gets manually edited, deleted, or "tidied up" during curation or analysis. If a raw output is ugly, that ugliness is itself part of the data. The only place cleanup logic belongs is inside the pipeline itself (Autogrep's own `extract_response`/`clean_yaml_text`), applied identically and automatically to every model, never selectively by hand to individual cases.

## 5. Avoid ranking or removing models based on this single case — standing policy

Already stated in `Model_Failure_Root_Cause_Analysis.md` (Section 5), restated here as a durable rule since it's easy to forget once Phase 5 model selection is being discussed: the one aiohttp smoke-test case produced 6 failures out of 8 models, for five genuinely different reasons. That is **one hard case, run once**, and proves nothing about relative model quality. No model gets dropped, downgraded, or deprioritized in the Phase 5 primary model list on the basis of this result. Real ranking requires the actual 300-case dataset.

# Second-rater sheet (blinded sample of 45 cases)

Purpose: measure how stable the `semgrep_representability` (and the two other) labels are.
The labels were made by one rater (Claude Code). Please rate WITHOUT opening
`benchmark/labels_final.json`, `benchmark/manifest_frozen_final.jsonl`,
`benchmark/difficulty/*.json`, or `answer_key_DO_NOT_OPEN_UNTIL_RATED.json`.
Rows are shuffled; the sample is stratified by the original labels but that is not shown.

Fill the three YOUR_ columns in `sample_blinded.csv` for each row. Use the mechanism summary
plus `benchmark/cases/<CASE>/patch.diff` (and the vulnerable/patched source if needed).

**semgrep_representability** (design doc Section 7.3) -- can a Semgrep rule reasonably express the vulnerability?
- `supported`: the vulnerable code has a matchable shape inside the function itself (dangerous call/API,
  missing-check or missing-annotation idiom, tainted flow to a sink, hard-coded secret, missing entry in a literal security list).
- `partially_supported`: Semgrep sees part of the mechanism but important context is unavailable -- a locally matchable
  faulty expression/statement order whose wrongness is semantic (wrong operand/constant/argument, inverted comparison),
  or the source/sink/semantics lie outside the function, or framework/runtime behaviour decides the harm.
- `unsupported`: the vulnerable-vs-fixed difference is not a code-shape property (timing side channels, cryptographic
  parameter quality, data remanence, log volume, file-system/runtime behaviour, parser differentials, cross-function
  bookkeeping, business/authorization logic spread over several steps).

**pattern_or_taint**: `pattern` = a local syntactic/AST pattern flags it; `taint` = a value must be tracked from an untrusted source to a sink.

**structural_or_context_heavy**: `structural` = self-contained within a few lines; `context_heavy` = needs broader context (sibling code, framework/protocol semantics) to tell it from a look-alike.

When done, tell Claude; it will compute agreement (percent and Cohen's kappa) per field against the answer key.

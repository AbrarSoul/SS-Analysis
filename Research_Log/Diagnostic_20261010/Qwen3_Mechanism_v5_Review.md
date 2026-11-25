# Qwen3 mechanism run v5 review

Reviewed the supplied terminal output and retained artifacts for `qwen3_mechanism_v5`, which uses prompt `diagnostic_mechanism_v4`. Also inspected the intervening `qwen3_mechanism_v4` run (prompt `diagnostic_mechanism_v3`), which had not been covered by the previous review document. No inference or Semgrep executions were launched by this review.

## Results

| Iterative metric | Original prompt (`qwen3_v3`) | Mechanism run v3 | Mechanism run v4 | Latest mechanism run v5 |
|---|---:|---:|---:|---:|
| Complete successes | 6/24 (25.0%) | 5/24 (20.8%) | 6/24 (25.0%) | 3/24 (12.5%) |
| Legacy visible acceptance | 19 | 14 | 15 | 13 |
| Correct-location visible acceptance | 18 | 12 | 13 | 12 |
| Accepted hidden-positive hits / requested positives | 30/48 | 20/48 | 22/48 | 20/48 |
| Hidden false positives / evaluated accepted negatives | 8/38 | 4/28 | 6/30 | 7/26 |
| Model calls | 34 | 45 | 46 | 51 |

V5 passes CASE-0134, CASE-0136 and CASE-0323. Relative to mechanism run v4, it loses CASE-0063, CASE-0220 and CASE-0221 and gains none. Relative to the original-prompt diagnostic, it loses CASE-0220, CASE-0221 and CASE-0276 and gains none. This is a descriptive decline on the development subset, not a statistical or population-level causal claim.

First attempts yield only one complete success, CASE-0323. Retries recover CASE-0134 and CASE-0136, lifting E2E success from 1/24 to 3/24, and also recover visible acceptance for CASE-0193 without complete success. Thus retries help within this run, while the resulting workflow still underperforms both comparison runs above.

Ten cases use one call, one uses two calls and thirteen use three calls: 51 calls in total, including 27 calls beyond one per requested case. All recorded finish reasons are `stop`; no API exceptions are recorded. Usage totals are 82,620 input tokens and 12,146 output tokens. Provider-call elapsed time is approximately 140.69 seconds, excluding scan and orchestration overhead. No monetary cost or controlled speed comparison is inferred.

## New dominant failure

All 24 first attempts parse into a rule envelope, but seven first-attempt hidden evaluations report Semgrep errors:

- CASE-0134, CASE-0136, CASE-0220, CASE-0221 and CASE-0276 use scalar strings as `pattern-either` alternatives where Semgrep expects pattern mappings. Their errors are `InvalidRuleSchemaError`. For example, CASE-0221 emits `- new DefaultHttpHeaders(false)` rather than a mapping with a `pattern` key.
- CASE-0231 specifies mutually exclusive top-level `pattern-either` and `patterns` operators.
- CASE-0193 has a rule pattern parse error.

Additional repair attempts produce YAML errors in CASE-0220 and CASE-0339. The higher-level schema envelope accepting the first attempt is not proof that its nested Semgrep DSL is valid. The process exit code of zero means the experiment finished and recorded these failures.

The previously persistent CASE-0238 YAML failure is absent here: its first candidate parses and passes visible validation. It still flags both the transformed-safe and benign samples, so this formatting recovery does not become E2E success.

## Prompt change and interpretation

The retained CASE-0136 requests for mechanism runs v4 and v5 differ by an added guidance bullet about combining `pattern-either` and `pattern-not` under `patterns`. That bullet includes the shorthand `patterns: [{pattern-either: [...]}, {pattern-not: ...}]`, leaving the structure of individual alternatives implicit. The observed scalar-alternative errors make this guidance a concrete suspect to examine offline, but one changed-prompt run does not establish that the bullet caused every regression. Treat the language and structure of the guidance as an unproven intervention, not a guaranteed fix.

The model, 24-case selection, temperature 0, 2048-output-token cap, maximum three calls, schema policy and pinned Semgrep 1.177.0 match the diagnostic protocol. Prompt and source hashes identify the new condition. The diagnostic subset has already influenced repeated prompt changes, so a future selected workflow requires fresh held-out confirmation.

## Evaluation limitations still present

The runner still stops at `legacy_accepted`; CASE-0184 is accepted despite incorrect original localization. The TSX staging and additional-location policy are not integrated into this runner.

CASE-0298 reports no raw scan error in this particular run, but saved sample paths remain `.ts`. Its first rule scans without a reported error and misses the original; subsequent attempts have TypeScript rule-pattern parse errors. The absence of a target error for this candidate is not evidence that the suffix problem was fixed generally.

The iterative summary contains 13 accepted-rule evaluations and zero scan errors. Eleven cases have no accepted final rule and no iterative hidden scan; they remain failures in the denominator of 24. The conditional negative-sample denominator changes across runs, so false-positive counts alone should not be treated as an isolated specificity comparison.

## Decision

Do not promote v5 or launch another full development rerun with an unvalidated prompt change. Keep the original prompt and mechanism run v4 as recorded comparison conditions. First use saved invalid candidates and complete minimal examples to check nested `pattern-either`/`patterns` structure with the pinned compiler, without new inference. A runnable example should demonstrate every mapping level; an abbreviated ellipsis inside a schema example is insufficient guidance for this observed failure mode.

Complete and version the evaluator fixes before claiming a corrected-workflow comparison. After offline validation, use a small, prespecified smoke check before the full development subset. Hidden samples and their outcomes must stay out of generation, repair and candidate selection.

## Provenance and changes made by this review

- Output directory: `results/diagnostic_20261010/qwen3_mechanism_v5/`.
- Prompt identifier: `diagnostic_mechanism_v4`.
- Command log: `Research_Log/Diagnostic_20261010/commands/20261011T000407865385Z_qwen3_mechanism_v5.log`.
- Recorded start: 2026-10-11 00:04:09 UTC.
- Runner hash: `d5bae959f03e0986df604794e4879fdef228d1fe1f5381970425942f491d49ae`.
- LLM client hash: `479d3d4724851449a73d76e515dd01cbd18c4ea0bcbfe031f32ba60ee21d7dd0`.

Added this review, linked it from the audit README, and appended a milestone with document/source hashes to `events.jsonl`. Code, prompts, labels, run results and `Correction_Log.md` were not modified. No model calls or scans were launched. Earlier inventories remain snapshots of their recorded checkpoint time.

# Qwen3 diagnostic v3: completed run review

Reviewed after the user supplied terminal output for `qwen3_diagnostic_v3`. The local saved episodes, environment and selection were also inspected. This supersedes the earlier credential-blocked status for this particular run; the blocked preflight remains valid historical evidence.

## Evidence and configuration

- Run: `results/diagnostic_20261010/qwen3_v3/`.
- Command log: `Research_Log/Diagnostic_20261010/commands/20261010T204118903799Z_qwen3_diagnostic_v3.log`.
- Recorded start: 2026-10-10 20:41:20 UTC; process exit 0.
- Model: `qwen3-coder:30b`; temperature 0; maximum 2048 output tokens per call; up to three calls per case.
- Semgrep: 1.177.0. Schema: `semgrep_search_taint_v2`. Prompt: historical Autogrep prompt unchanged.
- Selection SHA-256: `b473cb7b4d6737b5d2a822f8a01321e8e984f3cd314b947ee15cd29cd7e591b1`.
- Runner SHA-256 recorded by the run: `fb094bbe93b5d8209f0539ac4adf2476baf662628f6563ed60771f89e0261ff0`.
- The directory suffix `v3` is a run identifier; recorded runner version is `diagnostic-v2.1`. It does not mean the location or TSX adjudication proposals were implemented.

## Results

| Metric | First attempt | Iterative condition |
|---|---:|---:|
| Requested cases | 24 | 24 |
| Hidden evaluations retained | 24 | 19 |
| Accepted by legacy visible gate | 19 | 19 |
| Correct original location and patched rejection | 18 | 18 |
| Complete success | 6/24 (25.0%) | 6/24 (25.0%) |
| Hidden positive hits from accepted rules | 30/48 (62.5%) | 30/48 (62.5%) |
| Hidden false positives among accepted rules | 8/38 (21.1%) | 8/38 (21.1%) |
| Hidden evaluations reporting scan errors | 2 | 0 |

The last row is not evidence that repair resolved both scanner failures: the iterative condition only evaluates accepted final rules. Five rejected cases have no iterative hidden evaluation. They remain failures in the 24-case denominator; success must not be reported as 6/19.

All six successful cases are unchanged from the historical Qwen3 outcomes stored in this exact frozen selection: CASE-0134, CASE-0136, CASE-0220, CASE-0221, CASE-0276 and CASE-0323. There are zero newly successful cases and zero lost successes. This is no observed E2E improvement on the selected subset, not proof that the schema change has no effect on every possible case.

The 25% subset result must not be compared directly with historical 11/150 (7.3%) as improvement: selection deliberately included six historical successes and six cases from each failure category. No new full-population rate has been measured.

## Attempts and failure mechanisms

Nineteen cases stopped after one call; five used three calls. Total: 34 model calls, including ten additional retry calls. None of those ten recovered an accepted rule or an E2E success. Recorded totals are 32,919 input tokens, 10,090 output tokens and approximately 256.50 seconds of provider-call elapsed time. That elapsed time excludes Semgrep and other run overhead; no monetary cost is inferred.

The 19 accepted rules divide into six complete successes and thirteen failures:

- Six cases selected for historical hidden-negative failure still fail hidden negatives: CASE-0340, CASE-0238, CASE-0193, CASE-0124, CASE-0063 and CASE-0184.
- Six selected for historical hidden-positive failure still miss the structural positive: CASE-0173, CASE-0222, CASE-0163, CASE-0171, CASE-0046 and CASE-0239. CASE-0163 also flags the safe transformation.
- CASE-0081 satisfies the legacy any-original-match gate but the original finding is at line 10, outside its accepted vulnerable range; both hidden positives are missed. Location-aware reporting exposes this, but the legacy gate still stops generation after one call.

For the six structural-positive misses above, the model rules produced **no findings** on those samples. They are not the outside-annotation findings previously observed with assistant reference rules. Applying those reference-driven location proposals would therefore not automatically recover these model detections.

The five rejected cases are CASE-0235, CASE-0298, CASE-0116, CASE-0231 and CASE-0339. CASE-0298's first attempt has target syntax errors in the `.ts` bundle, consistent with the prior byte-identical TSX probe. Its subsequent attempts have rule parse errors. CASE-0116 has a rule parse error on the first attempt, a patched false positive on the second, and an original miss on the third. An exit code of zero means the experiment finished and recorded these failures, not that every rule or scan succeeded.

The retry workflow provides feedback from the original pair and stops once its legacy gate passes. It consequently makes no repair calls for most hidden-generalization failures. This explains why visible acceptance and strict E2E success diverge in this run; it does not establish that supplying hidden answers to repair would be a valid experiment.

## Next experiment

Do not repeat all model runs with the unchanged configuration yet. First replay the retained CASE-0298 candidate on a separately versioned TSX adapter; this can be done without another model call. Review and freeze location policy separately. Keep all original results intact.

Then define a distinct candidate workflow: align the visible acceptance gate with original-location correctness, explicitly permit composite/taint forms in its prompt, and ask for vulnerability-mechanism reasoning that avoids dependence on local identifier names or a single code arrangement. Check it on the development subset using the same call/token budgets. Hidden samples and hidden outcomes must remain unavailable to repair; any prompt chosen using these diagnostic results needs fresh held-out confirmation.

Only after that small comparison should a full 150-case per-model rerun be considered for an updated benchmark table. This review makes no claim about C3/C4 and launches no model calls or scans.

## Files changed by this review

- Added this review document.
- Updated `Research_Log/Diagnostic_20261010/README.md` with a pointer to the completed live run.
- Appended a review milestone to `events.jsonl`, including document hashes and summary-file provenance.

Model outputs, source code, benchmark labels and `Correction_Log.md` were not modified by this review. Earlier file inventories remain snapshots of their recorded checkpoint time.

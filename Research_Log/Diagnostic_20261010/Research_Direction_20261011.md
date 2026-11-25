# Research direction after the mechanism-prompt diagnostics

Date: 2026-10-11. Status: proposed follow-up, not an adopted protocol or a revision of the original experimental design. This note responds to whether the study should keep trying to surpass `autogrep_default` and how to strengthen its contribution. No new inference or scans were launched. C3/C4 remain deferred.

## Recommendation and evidence

Continue analysis, but make understanding and improving rule generalization the objective. Beating one prompt is a comparison result, not a sufficient research contribution. A credible null result is preferable to selecting a favorable prompt from repeated trials on the same cases.

The original design already asks about syntactic validity, patch discrimination, generalization, over-generalization, pipeline contribution and efficiency. The proposed framing below consolidates these questions; it does not retrospectively replace their hypotheses or turn exploratory findings into prespecified tests.

On the outcome-selected 24-case development subset, the original-prompt diagnostic passes 6 cases. Mechanism runs v1 through v5 pass 4, 5, 5, 6 and 3 respectively. The latest run has seven first-attempt Semgrep errors, including five malformed `pattern-either` lists. The original-prompt diagnostic accepts 19 cases under the legacy gate, but only 18 have correct visible localization and only six pass the complete bundle. These observations motivate separating construction validity, visible acceptance and hidden generalization.

These are descriptive development results, not population estimates. A single case changes this subset's success rate by 4.17 percentage points. Repeatedly consulting its hidden outcomes makes it unsuitable for fresh confirmation. The comparison concerns this repository's prompt and diagnostic workflow, not a complete evaluation of the upstream Autogrep system.

The latest Correction_Log entry describes the composition-guidance bullet as a proven direct cause of the regression. Retained malformed outputs establish the immediate validation failure; the changed-prompt comparison makes the bullet a plausible cause, but does not establish its causal effect or magnitude without repeated controlled comparisons. Similarly, a single run reaching parity is not evidence of reliability. The existing log is preserved; this note records the interpretive qualification.

## Proposed research questions

1. How well does passing validation on an original vulnerable/patched pair predict generalization to unseen vulnerability-preserving and vulnerability-removing transformations?
2. Which failures arise from rule construction, vulnerability inference, available context, target parsing, or evaluation labels?
3. Under equal resource budgets, does structured rule construction and additional development-only behavioral feedback improve held-out complete success relative to the original prompt?

Multi-agent and heterogeneous-agent questions remain separate future work. Parameter count, architecture and security specialization are observational model characteristics unless the comparison controls their other differences.

## Bounded investigation before additional broad runs

1. Finish versioning the common evaluation environment: pinned actual Semgrep executable/version, correct file suffixes, reviewed localization policy, and explicit treatment of scan errors. Preserve historical scores and record a separate corrected protocol. Apply the same protocol to every newly compared condition.
2. Audit saved outputs without inference. Record construction errors, wrong original location, patched-code matches, renamed misses, structural misses, and safe/benign false positives separately. Record multiple behavioral failures when present; do not assume every miss reveals the model's reasoning. Show both the all-requested denominator and conditional metrics among accepted rules.
3. Independently review transformation semantics and a manageable set of reference rules. Existing assistant-authored references were constructed after viewing all six samples: they are diagnostic feasibility aids, not blind expert performance or a generalization ceiling. A reference rule passing six samples proves only sample-level fit. Cases outside the selected Semgrep engine's capabilities should remain documented in the primary cohort, with any narrower expressibility analysis reported separately.
4. Implement and validate one explicit hypothesis offline before inference: separating rule semantics from YAML/operator construction can reduce avoidable construction failures. A typed representation and deterministic serializer must preserve the intended supported DSL; if they restrict expressiveness, report the restriction. Compiling examples alone does not establish semantic correctness.
5. Study extra behavioral evidence as a separate factor. Development probes must be constructed only from permitted source/patch information, independently checked for their intended semantics, and available only to the designated conditions. Never copy final hidden samples, labels, or outcomes into feedback or candidate selection.

## Proposed controlled comparison

Use the same source context, engine, schema capabilities, visible-location policy, model settings and maximum resource allocation across these cells, except for the two named interventions:

| Condition | Rule construction | Behavioral feedback |
|---|---|---|
| A | Original-prompt direct output | Original vulnerable/patched pair |
| B | Typed representation plus deterministic serialization | Original pair |
| C | Original-prompt direct output | Original pair plus separate development probes |
| D | Typed representation plus deterministic serialization | Original pair plus separate development probes |

A versus B estimates the construction intervention; A versus C estimates additional behavioral feedback; D tests their combination and possible interaction. B and D necessarily change the output contract: do not describe their difference as a prompt-only improvement. All cells can receive the same compiler-error feedback. Different numbers of probes consume resources and must be accounted for, not treated as free evidence. Preserve an archived historical comparison separately if the common corrected runner changes acceptance or staging.

Start on development data with Qwen3 and one contrasting model selected for a stated reason, rather than rerunning all models. Prespecify a small fixed number of repeated trials per cell, retaining all trials; temperature zero alone does not establish repeatability. Match call and token ceilings and report actual token use, scans and elapsed time. More probes may increase scanning cost even with equal LLM budgets. Do not choose a winning replicate.

Define a minimum worthwhile E2E improvement and acceptable cost before confirmation. Select test-set size using that effect size and expected paired disagreement; 24 development cases are not adequate merely because they are convenient. If construction validity improves but hidden generalization does not, report precisely that result instead of continuing arbitrary prompt revisions.

## Confirmation and meaningful novelty

Freeze the method, metrics, candidate-selection policy and stopping rule before obtaining final test outcomes. Prefer newly collected, repository-disjoint cases with independent semantic review, and reserve transformation families not used during development. A split made after studying all cases cannot retroactively become an untouched test set. Deduplicate closely related patches and record any remaining contamination limitations.

Primary outcome: complete success over all requested cases, with rejected and invalid outputs retained as failures. Secondary outcomes: construction validity, correct-location visible discrimination, hidden-positive recall, hidden-negative specificity, and resource cost. Separate unevaluated outputs and scan errors from true negatives. Report paired differences with repository-aware uncertainty and the individual gained/lost cases. A small positive point estimate alone is not a demonstrated improvement.

Potential contributions, even without a winning method:

- A reproducible, independently audited benchmark of patch-derived rules under both vulnerability-preserving and vulnerability-removing transformations.
- Evidence quantifying how much original-pair acceptance overstates complete-bundle reliability, and which transformations expose the gap.
- Controlled evidence that distinguishes construction improvements from semantic generalization, including their resource tradeoffs and negative results.
- A boundary analysis of failures attributable to model output, context, engine capability and benchmark construction, supported by executable examples rather than conjecture.

These are candidate contributions, not established priority claims. A failed prompt alone is weak evidence; a controlled, sufficiently precise explanation of a recurring failure is stronger. Even a successful intervention only establishes performance within the tested scope, not general semantic correctness.

## Prior-art check and scope

The authors' [Autogrep description](https://lambdasec.github.io/AutoGrep-Automated-Generation-and-Filtering-of-Semgrep-Rules-from-Vulnerability-Patches/) already describes patch-to-Semgrep generation, validation and filtering. [RuleLLM (DSN 2025)](https://arxiv.org/abs/2504.17198) already studies LLM generation, refinement and alignment of YARA/Semgrep rules for malicious packages. The latter's task and metrics differ from this repository's patch-derived complete-success benchmark; its headline scores are not comparable baselines.

Consequently, neither “LLMs generate rules” nor “we add retries” is a defensible novelty claim by itself. The promising distinction is the controlled study of executable generalization and failure mechanisms. This targeted literature check is not a systematic review and cannot establish that the proposed combination is the first of its kind. A related-work comparison should explicitly cover task, inputs, validation exposure, held-out transformations, negative controls, executable localization, and budget matching.

## File accounting

This discussion adds `Research_Log/Diagnostic_20261010/Research_Direction_20261011.md`, adds a link to the audit `README.md`, and appends a timestamped event with document hashes to `events.jsonl`. It does not modify the original design, Correction_Log, implementation, prompts, labels, recorded outputs or historical scores. Proposed experiments have not been executed or adopted by writing this note.

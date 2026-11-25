# Closure of the semantic-qualification and probe-gate review

Date: 2026-10-12. Scope: verify the latest document changes and identify the next implementation
step. This review does not freeze the protocol, settle its six open decisions, implement condition
B, or launch model inference. C3/C4 and confirmation collection remain deferred.

## Findings closed at the documentation/design level

1. Tracking Item 3 and the appended Correction Log now describe CASE-0222 as conditional
   preservation, accounting for environment CA-bundle overrides. The CASE-0323 subobject,
   CASE-0136 call-site and CASE-0124 string-construction descriptions are corrected too.
   The prior network-free reproduction remains the supporting executable evidence; no repeat was
   necessary because the underlying sample and production-code hashes remain unchanged.
2. Protocol section 4 now explicitly distinguishes A/B visible acceptance from C/D's combined
   visible-plus-probe acceptance. It records the no-eligible-probe fallback, requires successful
   probe scans, prevents candidate scan errors from becoming eligibility fallbacks, and specifies
   failure after the last permitted attempt. The four required offline paths are listed. This
   closes the design contradiction; implementation and behavioral testing remain future work.
3. The draft qualifies 207/817 as illustrative scenarios, keeps pilot B-A descriptive, and preserves
   consumed attempts when interrupted episodes resume. These match the previous recommendations.

The CASE-0222 wording should be understood as an execution-environment assumption for the
vulnerability claim. Semgrep reads the source; its host environment does not itself execute that
sample's Requests call. Historical scan counts remain unchanged because the rule, source,
annotations and scoring have not changed, rather than because the scanner's environment proves
all relevant deployed environments have identical TLS behavior.

## One confirmation-only clarification remains

Section 6a, lines 293–295 in the reviewed revision, calls its candidate procedure a
"repository-cluster bootstrap" but then says "resample at the case level." Independently sampling
cases does not preserve dependence between different cases in the same repository.

The intended wording should be: sample repository clusters with replacement, retaining every case
and its full condition/model/repeat vector within each selected cluster; then recompute the
specified case-weighted statistic. If a repository is drawn twice, include its whole group twice.
Cross-repository CVE families still need an explicit grouping rule before confirmation. If there
is exactly one case per repository, case and repository resampling coincide, but that cannot be
assumed generally. The distinction is documented in the
[Stata bootstrap manual](https://www.stata.com/manuals/rbootstrap.pdf).

This is a precision correction within the proposed estimator, not a decision to adopt it or a
reason to delay an A/B development implementation. The user's draft was left unchanged in this
review so the remaining text issue is explicit rather than silently resolved.

## Concrete next implementation scope

The existing `pipeline/typed_rule.py` serializer is available, but the inspected live generation
path in `autogrep/llm_client.py` still extracts, cleans, parses and sanitizes YAML. Condition B
needs its own explicit output-contract route; running the current YAML route with a different
label would not implement B.

1. Add a separately named B construction mode with the typed-JSON prompt contract, strict JSON
   decoding, `TypedRule` construction/validation, deterministic serialization and actual Semgrep
   validation. Feed failed JSON/schema/compiler/visible checks into the shared bounded repair loop.
   Keep A's original prompt and existing historical routes available and identifiable.
2. Wire the mode into the diagnostic runner and record the exact prompts, raw outputs, JSON
   candidate, emitted rule, validation/feedback, acceptance policy, attempt usage and file hashes.
   Both A/B must use the corrected evaluator and matched call/output-token ceilings. Check
   provider-specific credential preflight before a two-model run: the current runner still requires
   `GPTLAB_API_KEY` before resolving the selected model's host.
3. Exercise the new workflow offline: valid JSON -> executable rule; invalid/unsupported output
   -> bounded repair; compiler/visible failures -> bounded repair; acceptance/exhaustion; capture
   completeness and hidden-data isolation. Include a behavioral composite-rule example so correct
   YAML alone cannot conceal a semantic composition failure. Existing 31 passing tests do not
   exercise a B path that has not yet been built.
4. After those checks, prepare a separate development-pilot execution manifest: the 24 case IDs,
   model identifiers, A/B conditions, trial allocation, order, ceilings and output namespaces.
   Run a fresh A baseline under the same corrected policy; the old legacy-policy 6/24 cannot
   substitute for that control. Report all-requested E2E, paired gains/losses, construction failure
   and cost. Do not select a winning replicate or treat development results as confirmation.

Implementation and offline preparation can proceed without settling confirmation effect size,
sample size, final contrast or sourcing. A live pilot still needs an explicit run allocation:
the six open decisions include pilot repeats and whether to start with A/B. A recorded
pilot-specific allocation can resolve the immediate execution scope without freezing the entire
confirmation protocol. The existing 288-episode/864-call figure remains a draft planning ceiling,
not evidence that those calls have been authorized or sent.

## Verification and changed files

Read the revised protocol, Tracking section, appended Correction Log and relevant generation/
runner code. Compared all source/sample hashes in the prior follow-up evidence with current files;
only the three intentionally revised research documents differ. No production code or benchmark
sample changes were found in that comparison. No regression suite was rerun; the reported 31/31
was not presented as a newly executed run. No new Semgrep or model calls were made.

Added: this closure note. Modified: `README.md` (link) and append-only `events.jsonl` (review,
input hashes, artifact hashes and changed-file accounting). No protocol, Tracking, Correction Log,
implementation, benchmark or historical result was modified by this review.

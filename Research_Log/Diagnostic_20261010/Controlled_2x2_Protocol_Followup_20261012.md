# Follow-up review of the corrected protocol and Item 3

Date: 2026-10-12. Status: methodological recommendations; no protocol freeze, confirmation
collection, or inference authorization is recorded by this review.

## Outcome

The revised draft addresses the previous numerical error, the model-parity inference, the
three-repeat justification, and most missing operational specifications. Item 3 now records
direct source review for all 24 restructured positives and explicitly preserves the self-review
limitation. That is a material improvement over substituting rule agreement for semantic review.

This review directly inspected the eleven newly reviewed source diffs. They support the intended
vulnerability-preservation reasoning in the ordinary execution setting, with one newly reproduced
environmental qualification for CASE-0222. The record can say 24/24 received direct self-review;
it should not claim unconditional semantic equivalence or independent expert adjudication.

The staged A/B development pilot remains the appropriate next experiment once the typed-output
path is implemented and exercised offline. The remaining C/D design issue below does not require
delaying A/B engineering. The reported 31 tests concern existing implementation, not proof that
the new experimental conditions have been implemented or validated.

## 1. CASE-0222: session-level TLS configuration is only conditionally equivalent

Tracking Item 3 calls `session.verify = False; session.post(...)` equivalent to the original
`requests.post(..., verify=False)`. With Requests 2.34.2 installed in this workspace, the former
can be overridden by `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE`, while explicit per-request
`verify=False` is retained. Requests merges environment settings before session defaults; see its
[primary source implementation](https://requests.readthedocs.io/en/latest/_modules/requests/sessions/).

`verify_protocol_followup.py` extracts the actual original request expression and transformed
`_post_login` helper from the retained benchmark files. It executes them with controlled dummy
inputs, mocking `Session.send` to capture the final settings without any network connection.
All assertions passed:

| Controlled environment | Original send `verify` | Restructured send `verify` |
|---|---|---|
| Neither CA-bundle variable set | `False` | `False` |
| `REQUESTS_CA_BUNDLE` set | `False` | CA-bundle path |
| `CURL_CA_BUNDLE` set | `False` | CA-bundle path |

The request URL, method and body agree in every scenario. The CA path is a dummy marker, not a
real certificate used for an outbound request. This reproduces a difference in effective
configuration, not an end-to-end TLS handshake. It does not establish that any historical model
score is wrong or that the variant is safe in ordinary environments.

Required wording correction: CASE-0222 preserves disabled verification when no environment CA
override applies; it is not equivalent under all environments. Record that precondition in the
semantic audit. If the study requires environment-independent transformation equivalence, handle
any stronger replacement through a versioned benchmark change and paired evaluation, rather than
silently editing this frozen sample. No sample or label was changed in this review.

Two lesser description corrections are visible in the retained diffs: CASE-0136 leaves
`File.createTempFile` at its original caller and extracts cleanup, rather than moving that sink
into the helper; CASE-0323 extracts the `allowedContent` subobject, not the entire widget config.
Neither observation undermines vulnerability preservation. CASE-0124 changes string construction,
not branch/control flow; CASE-0081 is the actual loop-to-reduce rewrite. Avoid a blanket
"byte-for-byte call preserved" characterization where the transformation intentionally changes
the call or moves only part of its surrounding code.

## 2. C/D acceptance is still ambiguous

Section 4's episode rule says accept and stop on `visible_correct`; section 5 says probe failure
must trigger repair after visible success. Those statements need one explicit combined gate.
Otherwise a literal implementation can stop before evaluating the probes and make C/D behave
like A/B regardless of the intended intervention.

Recommended gate:

```
A/B: visible_correct
C/D, eligible pair: visible_correct AND vulnerable_probe_correct AND patched_probe_correct
C/D, no eligible pair: visible_correct, with the coverage/fallback reason retained
```

Define `*_probe_correct` to require a successful scan as well as the correct detection outcome.
Freeze probe validity before model evaluation. Distinguish a case with no valid preconstructed
probe from a candidate's failure on an existing probe; candidate-specific scan errors must not
silently turn a probe-eligible case into an A/B fallback. A third-attempt probe failure exhausts
the budget and follows the declared unaccepted-episode failure policy.

Before C/D inference, exercise visible-pass/probe-fail -> repair, all-checks-pass -> stop,
budget-exhausted -> failure, and ineligible -> declared fallback. These are meaningful future
workflow checks, not additional tests run during this document review.

## Recommendations on the six decisions

| Decision | Recommended disposition |
|---|---|
| Pilot repeats | Adopt three, all retained. Revisit confirmation allocation using pilot variability and costs. |
| Primary contrast | For A/B development, report B-A descriptively. For a full factorial confirmation, designate the construction main effect `((B-A)+(D-C))/2` on Qwen3 as primary; feedback, interaction and GPT-4o replication/heterogeneity are secondary or exploratory. If both models must support confirmatory claims, explicitly plan multiplicity before testing. |
| Worthwhile effect | Retain 10 absolute percentage points as a provisional planning target, with five-point sensitivity and explicit cost reporting. Power against zero at a true ten-point effect does not prove that the improvement is at least ten points. |
| Confirmation size | Do not freeze N yet. 207 and 817 are specified single-pair binary scenarios, not universal requirements or lower bounds for averaged repeated trials. Replace the remaining "817 cases are a lower bound" wording in section 8. |
| C/D timing | Proceed toward an A/B pilot first; add C/D after the combined gate and probe validity are implemented and verified offline. |
| Fresh sourcing | Include a fresh confirmation set in the research plan. Define eligibility, exclusions, provenance and independent review now; defer a collection commitment until sourcing feasibility and the final budget are established. |

Section 6a is an improved analysis outline, not yet a fully executable analysis plan: it still
requires the specific interval/test, clustering rule and heterogeneity statistic. A concrete option
is paired repository-cluster bootstrap intervals, preserving every condition/model/repeat vector
for sampled cases and estimating the mean case-level difference. Freeze the resampling seed/count,
case weighting and treatment of CVE families crossing repositories; use the same paired draws for
cross-model differences. Simulate power for that estimator across plausible pilot-informed
correlation/variance scenarios before choosing confirmation N. This need not delay a descriptive
development pilot.

For interruption handling, preserve already-consumed attempts/call budgets on resume. A completed
three-error episode stays a failure; it is not a missing episode eligible for a fresh budget.
This is an implementation requirement implied by the new retry policy, not a claim that a new
resume implementation is already present.

## Evidence and file accounting

New reproducible check: `verify_protocol_followup.py`; retained successful output:
`commands/20261012T081326782706Z_protocol_followup_source_evidence.log`. The log includes the
eleven full source diffs, all three CASE-0222 scenarios, dependency version and SHA-256 hashes
of all inspected source pairs, the reviewed documents and relevant implementation files.
No credentials were printed; dummy request inputs and a mocked transport were used.

Added: this note, the verification script, and its command log.
Modified: `README.md` (follow-up link) and append-only `events.jsonl` (command and milestone records).
No implementation, sample, historical result, user-authored draft, Tracking document or Correction
Log was edited. Their reviewed hashes are checked before closing this review.

The prior passing regression result was not rerun for unchanged production code. This review
performed the targeted, network-free semantic reproduction instead. No new Semgrep scans or model
calls occurred. Source inspections preceded the journaled reproduction; no other mutations were
performed during that reconnaissance.

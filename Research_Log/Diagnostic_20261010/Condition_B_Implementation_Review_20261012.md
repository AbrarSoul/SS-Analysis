# Condition B implementation review

Date: 2026-10-12. Reviewed the typed-JSON construction mode, CLI/config wiring, output provenance,
new tests, and implementation claims. No model inference or A/B pilot was launched. Production
code, benchmark files and user-authored protocol/Tracking/Correction Log were not edited by this
review. All added evidence is under this research audit directory.

## Verification outcome

The new construction path is functional in offline checks. It delegates composition to
`TypedRule.to_dict()` and feeds the resulting rule mapping into the existing diagnostic runner.

- **44/44 pipeline tests passed**, excluding the separately executable
  `test_stats_section22.py` as in the reported run. The initial sandbox invocation had 34 passes
  and 10 failures from Semgrep certificate initialization (`ca-certs: empty trust anchors`). The
  authorized local rerun passed all 44 in 20.03 seconds. Both logs are preserved; no TLS
  verification was disabled. This was an environment limitation, not a reproduced code regression.
- Six additional **offline integration scenarios passed** through the real `generate_rule()`,
  typed decoder, `run_model_case()`, and raw-capture wrapper. Only provider responses and scanner
  outcomes were mocked. They cover invalid JSON -> repair -> acceptance, three invalid outputs ->
  exhaustion, compiler failure -> wrong-location failure -> acceptance, immediate acceptance,
  three timeouts -> exhaustion, and default-A dispatch. All captured requests, feedback handoffs,
  call limits and usage fields were checked; hidden evaluation follows all generation calls.
- The real-Semgrep composite-rule regression passes. The integration audit complements it; the
  mock scanner is not presented as another real Semgrep validation.
- A's rendered prompt matches the preserved snapshot on all 24 cases, both initially and with
  synthetic repair feedback: **48 exact string comparisons passed**. The function AST also
  matches. A source-whitespace hash mismatch remains, detailed below.

## Findings before live comparison

### 1. Research attribution: B removes worked examples as well as changing the output contract

`_build_prompt_autogrep_default()` includes language-specific worked rules for Python, Java and
JavaScript. `_build_prompt_typed_json()` includes field descriptions but no corresponding examples.
Both use the same case patch context, but this is not just translating the output representation.
For the retained synthetic Python patch, A is 3,399 characters and B is 2,035; these are character
counts, not token counts. The actual prompt texts are retained in the evidence directory.

Protocol section 3 promises the same surrounding instructions apart from the output contract.
Removing semantic worked examples introduces a separate change, with unknown direction of effect:
the old examples include known composition/formatting problems, so dropping them could help or
hurt. A later gain or loss cannot be attributed solely to deterministic composition or the schema.

Before the pilot, either translate the same example content into B's supported JSON representation
while retaining A unchanged, or explicitly define B as a bundled typed-construction **and
example-removal** intervention. The former better matches the current controlled-construction
question. The latter is a valid exploratory workflow comparison if described honestly. This
finding does not imply that B must outperform A or that a negative result would be invalid.

### 2. Provenance: typed-JSON runs are mislabeled as the historical prompt

In `diagnostic_v2.py`, `environment.json` derives `prompt_policy` solely from `prompt_variant`.
With the normal B flags (`construction_mode=typed_json`, default `prompt_variant=autogrep_default`),
it records `historical_autogrep_default_unchanged`, even though generation uses B's separate system
and user prompts. Selecting another prompt variant is also misleading because B ignores it.

The audit evaluates the real metadata expression and reproduces this incorrect label. Recording
`construction_mode` and full requests helps recover what happened, but contradictory metadata is
still unsuitable as the condition identifier. Derive an explicit, versioned effective prompt
policy from construction mode first; distinguish a requested-but-ignored prompt variant if it is
retained. Check the label through preflight before any live run.

### 3. Frozen source-hash check fails, although A's prompt behavior is unchanged

`pipeline/tests/verify_prompt_hashes.py` returns exit 1:

- `_build_prompt_autogrep_default`: expected `6e7d840e71782db4c9bd367d1e2a846f0f7b8707c9f2aacc6b040482c1613e42`,
  observed `ea6a4464b5589f8bce91a5fe71b14aff1e4cdf82ccf0b4555bbb5bc0c832e4df`.
- `_build_prompt_design_v1`: matches its pinned hash.

Comparison with `before/autogrep/llm_client.py` isolates whitespace outside prompt strings near
the final return of `_build_prompt_autogrep_default`. AST equivalence and the 48 rendered-string
comparisons establish that this is not an altered A prompt. Restore the original source whitespace
to make the existing tripwire pass; do not update the pinned hash merely to conceal this drift.
This is a reproducibility cleanup, not evidence that A's task behavior regressed.

### 4. Existing two-provider preflight limitation remains

The diagnostic runner still checks `GPTLAB_API_KEY` before resolving the selected model's host.
Thus an OpenAI-only environment with a valid `OPENAI_API_KEY` is rejected before the proper
provider credential is selected. This predates B and does not block a Qwen-only pilot, but should
be corrected before a two-model pilot. The credential-presence metadata should also use the
resolved provider. No credential values were inspected or recorded in this review.

## What the existing tests establish, and what they do not

The eight new tests mostly invoke `_parse_typed_json_response()` directly. Their names containing
"bounded repair" verify error-return shape, not actual bounded retries. The default-A test checks
prompt construction rather than generation dispatch. CLI `preflight` records configuration and
engine information; it does not exercise a model response through parsing, repair and capture.

The additional audit script now supplies that missing offline integration evidence, and all six
scenarios pass. Promoting those scenarios into permanent regression tests is advisable, but this
review does not claim a demonstrated retry bug. No live response-quality or E2E improvement claim
is possible yet. The parser also recovers fenced JSON and fills/coerces selected metadata defaults;
describe that actual decoder contract rather than implying strict raw-JSON rejection of every
nonconforming envelope.

The implementation file accounting must include `pipeline/diagnostic_v2.py`: it was changed for
the CLI, config forwarding and environment/hash recording, even though this research branch
tracks that whole file as untracked and `git diff --stat` does not display its changes.

## Recommended next action

Resolve the prompt-example scope, correct the effective prompt label, and restore the frozen
source hash. Fix provider preflight if GPT-4o is included. Then prepare the explicit pilot run
allocation and execute fresh A and B under the corrected acceptance policy in separate new output
namespaces. The implementation is ready for those focused adjustments; another broad semantic
audit or a confirmation-set run is not necessary before the development pilot.

## Retained evidence and file accounting

- `commands/20261012T092026429322Z_condition_b_review_tests.log`: initial sandbox failure.
- `commands/20261012T092110384900Z_condition_b_review_tests_local.log`: 44 passing tests.
- `commands/20261012T092302864726Z_condition_b_offline_workflow_review.log`: first successful six-scenario audit.
- `commands/20261012T092313358892Z_condition_b_frozen_prompt_hashes.log`: frozen-hash mismatch.
- `commands/20261012T092411234625Z_condition_b_offline_workflow_with_prompt_check.log`: expanded audit including 48 prompt comparisons.
- `verify_condition_b_workflow.py`: reproducible audit script; providers and scanners mocked.
- `Condition_B_Offline_Evidence_20261012T092303419272Z/`: preserved first audit artifacts.
- `Condition_B_Offline_Evidence_20261012T092411725871Z/`: final audit artifacts, raw requests and responses,
  attempts, serialized rules, episodes, A/B prompt texts and `verification.json` with input hashes.
  These are explicitly simulated review artifacts outside the historical-results tree.

Added: this note, the audit script, the five command logs and both simulated evidence directories.
Modified: `README.md` (review link) and append-only `events.jsonl` (command/milestone records).
The final milestone records exact artifact paths/hashes and confirms reviewed inputs remained
unchanged during this review. Test-generated temporary files/caches are not research source edits.
The first audit was expanded after the source-hash check exposed a new question, so both versions'
outputs remain available; neither was overwritten or deleted.

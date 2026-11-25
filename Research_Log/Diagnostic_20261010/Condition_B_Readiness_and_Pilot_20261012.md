# Condition B review closure and proposed development-pilot allocation

Date: 2026-10-12. Status: **reviewed implementation; pilot proposed, not approved or executed**.
No model inference, confirmation collection or C/D implementation occurred in this pass.

## Four prior findings closed for the inspected revision

1. B now includes the six worked examples corresponding to A's Python, JavaScript and Java examples.
   Reviewed their pattern, exclusion, scope and metadata content. An executable check confirms
   the same ordered example IDs and validates all six through `TypedRule`. Neither A nor B supplies
   TypeScript worked examples; the existing omission is shared, not silently fixed in one cell.
   The missing-example difference identified in the previous review is resolved.
2. Effective prompt provenance now checks construction mode first. The actual metadata expressions
   produce `CONDITION_B_TYPED_JSON` for B and `historical_autogrep_default_unchanged` for A;
   the requested variant and its ignored status are recorded separately.
3. The frozen-hash check passes for both original prompt builders. The original pinned hashes were
   preserved, rather than updated to accept drift.
4. Host resolution precedes credential selection. Four credential-scrubbed CLI probes pass:
   missing/present OpenAI credentials for GPT-4o and missing/present GPT-Lab credentials for Qwen3.
   HTTP transport is mocked and stops before network access or model/output initialization;
   the checks establish routing, not live credential validity or provider availability.

The full pipeline suite passes **44/44** (excluding the standalone `test_stats_section22.py`, as
previously documented). It ran outside the filesystem sandbox to permit Semgrep's macOS
certificate initialization. No model calls were made. The six additional workflow scenarios from
the preceding review remain the integration evidence; this pass changed prompt content and
preflight/provenance, not the generation/repair architecture.

Interpret the comparison as the effect of the whole typed-construction workflow: output contract,
supported grammar, serializer and corresponding instructions. Matched examples remove the specific
extra confound; they do not make this an isolated estimate of JSON versus YAML or serialization
alone. Runtime semantics of intentionally corrected example composition belong to that intervention.

## Concrete proposed allocation

The complete machine-readable allocation is in
`AB_Pilot_Allocation_20261012_v1/allocation.json`; the exact twelve launch commands are in
`AB_Pilot_Allocation_20261012_v1/Commands.md`. They are saved as text/data and have not been executed.

| Setting | Proposed value |
|---|---|
| Data | Existing 24 development cases, unchanged membership |
| Models | `qwen3-coder:30b`, `gpt-4o` |
| Conditions | A `original_prompt`; B `typed_json` |
| Repeats | Three per model/condition/case |
| Acceptance | `corrected` for both A and B |
| Engine | Actual Semgrep 1.177.0 required by the runner |
| Temperature | 0 |
| Attempts | At most three model calls per episode, SDK retries disabled |
| Output ceiling | 2,048 tokens per call |
| Total | 12 batch runs; 288 episodes; at most 864 model calls |
| Total output-token ceiling | 1,769,472 across both models; 884,736 per model |

Input tokens are additional and are not bounded by the output ceiling. No monetary cost estimate
is asserted; actual provider token usage and elapsed time must be reported. The call cap includes
failed requests/retries within an episode. The readiness review itself used zero inference calls.

Each repetition has a deterministic case permutation, shared by both models and both conditions.
The three selection files, seeds and hashes are recorded. The six paired model/repetition blocks
use three A-then-B and three B-then-A orders; model order also alternates. This reduces systematic
condition-order bias without adding calls, but does not eliminate all temporal/provider variation.
The planned result paths are fresh `results/diagnostic_20261010/ab_dev_20261012_v1_*` namespaces;
none existed when this allocation was prepared. A is newly generated under the corrected gate.

The allocation records source, annotation, selection and case-file hashes. Before executing any
approved run, verify those hashes and that its result namespace is unused. If implementation or
prompt content changes, issue a new versioned allocation instead of silently running the old one
against new code. Execute sequentially; stop on nonzero exit and retain every artifact. Do not
restart a consumed batch/episode with a fresh attempt budget. The current runner has no general
automatic resume facility; an interruption requires evidence-preserving recovery planning.

Report all-requested complete success per model and repeat, the mean per-case success rate,
paired B-A gains/losses, construction validity, visible discrimination, hidden errors and actual
cost. Keep all three repeats. Pilot results are descriptive development evidence, not confirmation
or a test of the draft ten-point worthwhile-effect threshold. Do not use hidden outcomes to
select candidates, discard runs or choose a winning replicate.

Approving this allocation would settle only the immediate pilot scope (A/B, these two models,
three repeats and the stated ceilings). The full 2×2 protocol and its confirmation sample size,
primary contrast, effect threshold, sourcing commitment and C/D engineering remain separate.
User approval for live inference has not been inferred from the completion report.

## Evidence and change accounting

- `commands/20261012T095359096245Z_condition_b_fixed_prompt_hashes.log`: both frozen hashes pass.
- `commands/20261012T095401452721Z_condition_b_fixed_tests.log`: 44 tests pass in 23.17 seconds.
- `commands/20261012T095606494220Z_condition_b_fixed_allocation_preparation.log`: six examples,
  effective metadata, four mocked credential routes and allocation preparation pass.
- `prepare_ab_pilot_20261012.py`: reproducible, preparation-only script; never executes the stored
  inference commands. Refuses to overwrite the allocation directory.
- `AB_Pilot_Allocation_20261012_v1/verification.json`: check results and reviewed-document hashes.

Added: this note, the preparation script, three command logs, and the allocation directory's six
files (allocation JSON, command document, three selection files and verification JSON).
Modified: `README.md` (readiness link) and append-only `events.jsonl` (commands and final milestone).
The milestone records exact files/hashes and checks that reviewed implementation/documents remain
unchanged during this pass. No implementation, protocol, Tracking, Correction Log, benchmark or
historical results were edited by this review/preparation task. Generated test caches are not
research source changes.

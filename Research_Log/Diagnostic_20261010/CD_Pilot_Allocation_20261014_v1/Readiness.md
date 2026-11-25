# C/D development pilot readiness — 2026-10-14 (Europe/Helsinki)

**Live execution started:** Credential setup succeeded. The authorized pilot is running; see `Execution_Status.json` and the command journal for current status. Prior missing-key notices below are historical.

**Execution update (2026-10-14):** The user authorized the full allocation. First launch stopped at the credential gate: `GPTLAB_API_KEY` is unavailable in this execution environment. Zero model calls and no live output directory were created. Authorization persists; execution can resume at command 1 after credential setup. See `Execution_Status.json`. Earlier preparation-time pending-approval statements below are historical.


The next experiment is prepared. No live model call was made during preparation, and no C/D performance result exists yet. The standing separate inference-budget decision remains pending. This entry supersedes the previous handoff's suggested paper-synthesis-first ordering in response to the user's request to proceed toward C/D runs; it does not freeze the confirmation protocol.

## Allocation and execution

Use [Commands.md](Commands.md) from the repository root, one run at a time. The first run is Qwen3, repeat 1, condition C. Inspect its recorded configuration, completion and resource accounting before the next command. The allocation contains both models (`qwen3-coder:30b`, `gpt-4o`), C and D, and three repeats: 12 runs, 288 requested episodes, at most 864 generation calls. Each run has 24 cases and at most 72 calls. All destinations were absent at preparation time.

C uses the original prompt with probe feedback; D uses typed JSON with probe feedback. Both use corrected visible acceptance, temperature 0, a 2,048-output-token call limit, three attempts per episode and no SDK retries. The output-token ceiling is 1,769,472; input tokens and monetary cost are not bounded by that figure. Actual calls, tokens, elapsed time and scanner invocations must be reported after execution.

Do not rerun low-scoring or exhausted episodes. Preserve partial calls and artifacts on interruption, pause for diagnosis, and record any recovery without resetting consumed budgets. Automatic resumption is not implemented. No confirmation cases are sourced or used.

## Verified evidence

- `cd_experiment.py verify` passes: frozen manifest hash `771400b84983a11b4edb97129e454ab860208b7727e7316a2c4b1689e093104f`, 24 cases, 11 probe-eligible and 13 explicitly ineligible.
- Real no-inference C and D preflights pass using Semgrep 1.177.0, the reviewed parser versions, correct construction-mode binding and matching manifest hashes. They prepare caches and probe files; episode snapshots are created later by the episode runner. These checks neither exercise a live provider nor establish credential availability.
- All 209 file hashes from the earlier A/B allocation were checked. 208 are unchanged; `pipeline/diagnostic_v2.py` is the one expected change from C/D integration. Its old/new hashes are preserved in `verification.json`.
- Current first-call system and user messages exactly match the captured requests for all 288 A/B episodes. Model names, temperature and token limit also match. This confirms initial prompt comparability; C/D repair feedback intentionally differs after a probe failure.
- All twelve historical A/B result directories contain 24 completed cases and corrected acceptance. Their per-run scores and paths are stored in `allocation.json`.
- The preparation script succeeds, produces twelve commands with unique unused outputs, and performs no inference. No implementation or test file changed this turn, so the previously recorded 156-test suite was not rerun.

Successful preflight outputs:

- `results/diagnostic_20261010/_cd_pilot_preflight_20261014_v2_c/`
- `results/diagnostic_20261010/_cd_pilot_preflight_20261014_v2_d/`

The first C preflight failed inside the sandbox because Semgrep could not initialize macOS certificate trust anchors. Its original output is retained in `_cd_pilot_preflight_20261014_v1_c/`; it was not overwritten. The two successful checks used fresh namespaces outside the sandbox. This was an environment-access issue, not a measured model failure.

Command logs (under `Research_Log/Diagnostic_20261010/commands/`):

- `20261013T225914749888Z_cd_pilot_preflight_c_20261014.log` — initial sandbox failure.
- `20261013T230122497246Z_cd_pilot_preflight_c_20261014_v2.log` — C passed.
- `20261013T230144793860Z_cd_pilot_preflight_d_20261014_v2.log` — D passed.

## Interpretation fixed before execution

Compare C−A and D−B separately within each model. Average each case's success over its three repeats before calculating paired gains/losses; repeats are not independent cases. Use all 24 requested cases as the main denominator, with the selected 11 eligible cases reported separately. Track whether probe-triggered repair changes hidden outcomes, including losses, and report scan failures separately from valid false-positive/false-negative outcomes.

There are two material comparability limits: A/B shuffled case order between repeats, whereas the reviewed C/D manifest requires canonical order; and C/D runs in a later time batch with unverified remote backend stability. Preserve the frozen manifest rather than changing it merely to reuse shuffled selections. Balanced C/D versus D/C blocks help within the new batch but do not remove the historical batch difference. Matching repeat labels do not establish shared randomness. These results will remain descriptive development evidence.

## File accounting

Created:

- `Research_Log/Diagnostic_20261010/prepare_cd_pilot_20261014.py` — reproducible offline verification and allocation writer; refuses overwrite.
- `CD_Pilot_Allocation_20261014_v1/allocation.json` — run order, caps, baseline mapping and current input hashes.
- `CD_Pilot_Allocation_20261014_v1/verification.json` — 288 prompt comparisons, baseline hash differences and preflight references.
- `CD_Pilot_Allocation_20261014_v1/Commands.md` — twelve launch commands and inspection/recovery guidance.
- This `Readiness.md`.

Updated existing documentation: `Research_Log/Diagnostic_20261010/README.md`, `Research_Log/Diagnostic_20261010/Bounded_Investigation_Tracking.md`, and `Research_Log/Correction_Log.md`. Audit events are appended to `Research_Log/Diagnostic_20261010/events.jsonl`; generated command/preflight artifacts are listed above. Existing unrelated working-tree changes remain in place. No historical result or benchmark input was changed, and no source/test implementation was modified.

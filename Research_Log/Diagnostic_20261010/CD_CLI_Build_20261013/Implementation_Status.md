# Bounded manifest / CLI implementation status

**Current status: COMPLETE, independently verified after consolidation (2026-10-13).** The concurrent-edit conflict and coordination question below are resolved. See [completion verification](Completion_Verification.md) for 86 executed passes, 156 collected tests, the unchanged reviewed manifest and final handoff. The earlier partial-work notes below are retained as historical context.

This task started from the user's “then what to do?” continuation of the agreed final bounded
manifest/CLI task. No model calls or real Semgrep scans have been made.

Completed independently in this task:

- Saved starting hashes and before-copies under `before/` and `starting_hashes.json`.
- Added `pipeline/cd_experiment.py`: pins the prior reviewed selection/edit-report/builder/parser
  identities; checks all source and probe fields against that review; freezes with overwrite
  refusal; provides strict preparation and all-requested resource/coverage aggregation.
- Created `benchmark/diagnostic_20261010/dev_probe_manifest_v1.json`, 24 cases, 11 eligible and
  13 explicit ineligible dispositions, SHA-256
  `771400b84983a11b4edb97129e454ab860208b7727e7316a2c4b1689e093104f`.
- Added `pipeline/tests/test_cd_cli.py`, including complete C/D CLI trajectories across all 24
  cases using real prompt construction, parsers, raw capture and snapshots with fake provider/
  scanner responses. These tests forbid real socket connections.
- Added a `--condition C|D` adapter, construction/acceptance validation, per-run manifest copy,
  provenance and interruption reporting to `pipeline/diagnostic_v2.py`.

Concurrent edit detected during integration testing:

A separate writer added `run_cd_case_from_manifest`, a `--use-probes` adapter, another
`--probe-manifest` option, `pipeline/build_cd_probe_manifest.py`, and
`pipeline/tests/test_run_cd_case_from_manifest.py` after the starting snapshot. Neither new
adapter existed in the saved starting runner. Both additions currently coexist in that shared
file and duplicate argparse registration prevents CLI execution. This is an integration conflict,
not a successful completed build. Test log preserves the failure:
`../commands/20261013T162512801628Z_cd_cli_tests_20261013.log` (10 failed, 76 passed).

Preserved the combined runner and the other newly observed implementation files under
`concurrent_edits/`, with hashes in `concurrent_edits.json`. Asked the user which implementation
to consolidate and to pause the other editor. Further changes to the shared runner are pending
that coordination; neither implementation nor the other writer's files have been discarded.

Next action after coordination: converge on one public CLI path, preserve compatible work/tests,
run the complete offline trajectories, and then publish the final file accounting and handoff.
The bounded task is not yet complete and no live C/D run is authorized by these edits.

The separately generated manifest at `../CD_Probe_Manifest_v1_20261013.json` was also inspected: its 24 `entries` are exactly equal to this task's frozen entries. The extra pins in `cd_experiment.py` bind those entries to the independently reviewed report and sources.

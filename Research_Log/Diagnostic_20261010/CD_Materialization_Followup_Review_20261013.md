# C/D materialization follow-up — 2026-10-13

Three findings are closed: unresolved probe state/identity, A/B import isolation, and probe timeout
handling. The pre-existing-file-mismatch reproduction is also fixed, but verification of actual
scan inputs remains partial: the runner checks once before generation, rather than at each use,
and hashes normalized text rather than file bytes. This is one remaining implementation finding,
not a new renamer audit. The real manifest and CLI adapter remain explicitly unimplemented.

## Verification

- **70 tests executed and passed in 6.27s**: `test_combined_gate.py`,
  `test_run_model_case_cd.py`, `test_diagnostic_regressions.py`.
- **140 tests collected**, not executed, across those three files plus `test_dev_probe.py`,
  `test_typed_json_construction.py`, `test_typed_rule.py`, `test_rule_validator_classification.py`.
  Collection confirms inventory, not passing behavior. This review does not independently claim
  140 executed passes. Collection log:
  `commands/20261013T112812970034Z_cd_full_collection_20261013.log`.
- Executable follow-up: pre-existing file mismatch raises before generation or scanning; `None`
  and wrong-language probe state raise before generation; three decode failures retain explicit
  ineligibility reason; three consecutive probe timeouts write all three attempt records and an
  unsuccessful episode, with three generation calls/three probe scans/two repairs.
- A fresh subprocess with all probe/tree-sitter imports actively prohibited can import the A/B
  diagnostic module successfully.

Evidence: `CD_Materialization_Followup_Evidence_20261013.json`, produced by
`audit_cd_materialization_followup_20261013.py`. Successful command log:
`commands/20261013T112746906351Z_cd_materialization_followup_20261013.log`.

## Remaining finding — Medium: startup verification does not establish the scanned-byte hashes

In `run_model_case_cd`, materialized files are read before `load_case`, generation and the retry
loop. Later each probe scan reopens the caller-supplied paths. The files are neither copied into
a protected per-run snapshot by this function nor rechecked when used. The docstring explicitly
says verification happens once. The future adapter that might enforce immutable ownership does
not exist yet.

Three bounded, temporary-file reproductions demonstrate the gap:

1. Start with matching files, change the vulnerable file during the mocked generation call.
   The probe scanner receives the changed bytes and its mocked passing response is accepted.
2. Start with matching files, let the first probe fail and replace the file between attempts.
   The next scan consumes different bytes and the second attempt accepts. The episode still
   records the initial hash as `verified_probe_hashes`.
3. Write the matching source using CRLF bytes. `Path.read_text()` normalizes line endings, so
   the startup comparison succeeds and `sha256(actual_text.encode())` records the LF hash.
   The scanner receives CRLF bytes with a different SHA-256. This is a provenance mismatch;
   no semantic change or Semgrep behavior difference from line endings is claimed.

The first two reproductions model a file changing during an episode; they do not claim that
such a change has occurred in historical results or that a model can edit these files. All scan
responses are mocked. The observed fact is that different bytes reach the scan boundary while
the saved record certifies the earlier text hash.

Required correction alongside the manifest/CLI work: materialize reviewed UTF-8 bytes into an
immutable, exclusively owned per-run location; compare `read_bytes()` with the expected bytes
before every probe invocation; and record the actual input hashes for that invocation. Keep the
startup check too, to reject existing mismatches before spending calls. Rechecking detects
changes during generation/retries; ownership of the snapshot is what prevents another writer
from changing it between verification and scanner access. Record any mid-episode integrity
failure and already-consumed calls, without converting it into reviewed ineligibility or giving
the episode a fresh budget. Add real-file tests covering between-attempt replacement and raw
byte hash agreement.

Once this boundary is enforced, proceed with the acknowledged next task: build the concrete
manifest by comparing all 24 source/disposition records and 11 eligible pairs with the existing
reviewed artifacts, then connect strict loading, per-run materialization, C/D construction-mode
binding and provenance through the CLI. These are offline steps; no inference approval is needed
to make them reviewable. A real C/D pilot remains a separate budget decision.

## Audit hiccups and file accounting

The first audit invocation attempted directory-wide pytest collection and exited 1 because its
child pytest collector exited 3 on the pre-existing `test_stats_section22.py` import-time
`sys.exit(0)`. That standalone script printed its ten successful checks; it is not a pytest
collection target. The failed wrapper log is preserved:
`commands/20261013T112714347043Z_cd_materialization_followup_20261013.log`.
After narrowing to the six diagnostic test files the audit completed with 135 collected; its
evidence retains that exact scope. Adding the five validator-classification tests in the separate
seven-file collection above confirms the reported 140. No earlier evidence was overwritten.

Added this review, audit script, evidence JSON and the three command logs above. Modified
Tracking, append-only Correction Log, README and events.jsonl. The final event hashes these
records and verifies reviewed implementation/test hashes remain unchanged. No implementation,
permanent regression tests, benchmark, dependency, saved outcome or existing probe was changed.
No actual model calls or real Semgrep scans; all counterexamples use temporary synthetic files.

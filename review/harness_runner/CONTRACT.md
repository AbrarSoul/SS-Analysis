# Harness contract v1

A harness is a small, case-specific test that attacks each of a case's six samples and reports, in a fixed format, whether each attack worked. The runner (`run_harness.py`) runs it in an isolated container with no network. It compares the results with each sample's label and writes `results.json`. The review server can later show those results and re-run them.

## Layout

```
<harness dir>/            usually review/cases_reviewed_r1/harness/<CASE>/
  harness.json            manifest (below)
  run.sh                  entry point: bash run.sh <sample file> <sample role>
  ...                     anything else the harness needs (stubs, attack generators)
  results.json            written by the runner, never by hand
```

The runner calls `run.sh` once per sample, each time in a fresh container:

- **Sample roles:** `vulnerable_source`, `patched_source`, `variant_vulnerable_01`, `variant_vulnerable_02`, `variant_safe_01`, `benign_lookalike`.
- **Inputs:** the sample is mounted read-only under `/case/`. The harness folder is copied to a writable `/tmp/h`, which is also the working directory.
- **Container:** Python 3, Node 18 + TypeScript, Java 17, and a few common Python libraries (Flask, Jinja2, PyYAML, lxml). There is no network, and the container is limited to 1 GB of memory, 2 CPUs and 120 s per sample.

## What `run.sh` must print

Exactly one line that starts with `RESULT `, followed by JSON:

```json
{"compiled": true,
 "attacks": {"1_plain_dotdot": true, "2_nested_dotdot": false},
 "control_ok": true,
 "modified": ["added missing import cz.…ExtractTaskListener"],
 "skipped": null,
 "notes": "free text"}
```

| Field | Meaning |
|---|---|
| `compiled` | The sample parsed or compiled and could be loaded. `false` means the attacks were not run. |
| `attacks` | For each attack id from `harness.json`: `true` = the attack worked (the real effect was observed). |
| `control_ok` | The benign control input still worked (`null` if there is no control). A "safe" sample that blocks everything, including the control, is broken rather than safe. |
| `modified` | Every change made to the copy of the sample before testing (added imports, stubs filled in). **Must be listed.** An empty list means the sample ran exactly as stored. |
| `skipped` | A reason string when the sample can't be tested at all (for example "no extraction code: body omitted"). That is itself a finding for checks H, I or J. |

Rules:
- **Detect real effects**, not log messages. Examples: a file appears outside the target folder, a command leaves a marker file, a query returns extra rows.
- Never change what a sample *does* about the bug. Only fill in what is missing so that it runs, and list it in `modified`.
- Always include one benign control input.

## `harness.json`

```json
{
  "contract": 1,
  "case_id": "CASE-0075",
  "title": "Zip slip: extract crafted archives and look for files written outside dest/",
  "built_by": "R1 (Claude Code session)",
  "date": "2026-11-24",
  "attacks": [{"id": "1_plain_dotdot", "input": "../ESCAPED_1.txt", "what": "plain parent-directory entry"}],
  "control": {"id": "6_benign_control", "input": "assets/minecraft/ok.txt"},
  "success_criterion": "An attack counts as exploited when its marker file exists anywhere outside dest/."
}
```

## How the runner reads the results

| Sample label | Matches label when |
|---|---|
| vulnerable (`vulnerable_source`, `variant_vulnerable_01/02`) | compiled and at least one attack worked |
| safe (`patched_source`, `variant_safe_01`, `benign_lookalike`) | compiled, no attack worked, and the control still works |

A skipped sample, or one that did not compile, is reported as such, never as a match. `results.json` also records the SHA-256 of the harness files and of each sample, the runtime image, and the time. A result can therefore always be traced to exactly what was run.

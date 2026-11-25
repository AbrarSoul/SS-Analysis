# Development-probe implementation review — 2026-10-13

The retained coverage totals are reproducible, but the builder is not yet safe to use as a repair
oracle. Executable counterexamples pass its structural checks while changing behavior. C/D's
combined gate also remains unimplemented, as the author's log explicitly acknowledges. Fix and
offline-test these issues before allocating C/D inference.

## Verified evidence and limits

Reviewed the builder, coverage script, 18 new tests, both logs, protocol, generated sources and
retained scans. The new test file passes: `18 passed in 0.05s`. I did not rerun the full 62-test
suite; that remains the author's reported result. No model calls or real Semgrep scans were made.

`audit_dev_probe_20261013.py` recounts the latest coverage run from all 116 raw `stdout.json`
files, checks both intended targets were scanned and every record reports Semgrep 1.177.0,
verifies accepted episode/rule hashes, regenerates all 24 eligibility decisions in memory and
compares the 30 current probe files byte-for-byte. All allocation input hashes still match.
Outputs and reviewed-file hashes are in `Dev_Probe_Review_Evidence_20261013.json`.

| Model / condition | Covered accepted episodes | Probe passes | Vulnerable misses | Patched findings |
|---|---:|---:|---:|---:|
| Qwen A | 33 | 33 | 0 | 0 |
| Qwen B | 29 | 26 | 3 | 0 |
| GPT-4o A | 27 | 24 | 3 | 0 |
| GPT-4o B | 27 | 27 | 0 | 0 |
| Total | 116 | 110 | 6 | 0 |

The latest namespace is `_probe_coverage_20261012T233737252844Z`. The earlier retained namespace
`_probe_coverage_20261012T233016021740Z` reports 98 passes and 18 misses, predating the Python
formatting correction. Both remain intact. There are 15 probe directories and 30 source files.

There are 195 accepted episodes across the 288 pilot episodes: 116 covered and 79 uncovered.
Thus 6/116 = 5.17% is conditional on **acceptance and probe eligibility**. The separate descriptive
yield is 6/195 = 3.08% of all accepted episodes flagged; uncovered episodes are unknown, not
passes. Case-level eligibility is 15/24.

The six misses are exactly Qwen B CASE-0171 repeats 1–3, GPT-4o A CASE-0136 repeats 2–3 and
GPT-4o A CASE-0173 repeat 3. Source diffs and saved rules support the reported literal-name
mechanism. This review has not demonstrated contamination of these six particular misses;
synthetic builder defects do not automatically invalidate their observed scan outcomes.

## 1. High: structural isomorphism accepts incorrect binding changes

`dev_probe.py:185` collects assignments across nested Python scopes. Its replacement walk
renames every same-spelled `Name` without resolving its declaration. The tree-sitter path also
lacks block-scope resolution. Store/Load contexts alone do not resolve Python bindings.

Reproductions retained in the evidence JSON:

- Python: inner `g()` assigns local `token`; outer `f()` reads global `token`. Both are renamed.
  Original `f()` returns 11 with global token=10; the probe raises `NameError`.
- JavaScript: `function f() { { let token = 1; } return token; }` returns global token=10 before
  transformation and raises `ReferenceError` afterward.
- JavaScript: `function f() { const cb = () => 7; return cb(); }` becomes
  `const cb_renamed = ...; return cb();`. The callee exclusion at line 408 skips the reference
  while renaming its declaration. Original returns 7; probe raises `ReferenceError`.
- Java: `int token() { int token = 1; return token; }` has its **method declaration name** changed
  to `token_renamed`, violating the local-only contract. This is source/CST inspection, not a
  claimed Java compilation/execution test.

All return successful `ProbeResult` objects. Isomorphism permits both old/new identifier
substitutions and unchanged identifiers; it cannot establish reference identity. Resolve each
chosen declaration and all and only its references, or reject the entire uncertain candidate.
Skipping a reference while renaming its declaration is unsafe. Add independent behavior tests.

## 2. High: patched-side eligibility and collision checks are missing

`_rename_patched_python` (line 291) and `_rename_patched_tree_sitter` (line 549) reuse the vulnerable
old/new names without independently checking local binding identity, parameters, reflection or
collisions against the patched source.

- A vulnerable local `token` and patched `def f(token): return token` produce
  `def f(token): return token_renamed`: 7 becomes `NameError`.
- Patched `token=1; token_renamed=2; return token+token_renamed` becomes two assignments to the same
  name: return value 3 becomes 4, while isomorphism passes.
- An invalid patched snippet `def f(:` is returned unchanged with `patched_probe_renamed=False`,
  yet the overall result remains eligible.

Validate both sources independently, choose collision-free names using both, and distinguish a
valid unchanged patched source from a parse/validation failure. Current CASE-0046/0184 pairs
have unchanged patched sides; report that explicitly and declare the intended pair policy.

## 3. High: whitespace bypasses the JavaScript reflection filter

The raw substring marker `eval(` misses `eval (text)`. A retained Node reproduction constructs
the string `token` via `String.fromCharCode`, avoiding the separate literal-name filter.
Before renaming, evaluation reads local token=7; afterward it reads global token=10. The builder
accepts this changed behavior. Use parsed call structure and conservative handling of unresolved
reflection mechanisms on both sources. Substring matching is not conservative for whitespace
or comments.

## 4. Medium: future scan results can be misclassified

`scan_probe` (coverage script line 64) checks exit/errors but not `paths.scanned`. A mocked
successful JSON response with zero scanned targets is marked `scan_ok=True` and a vulnerable
miss. Every current retained record does scan both targets, so current totals remain valid.
Require target coverage and separate infrastructure errors before wiring this into acceptance.

The FP aggregate requires `vulnerable_detected AND patched_detected`, hiding an FP when a rule
also misses the vulnerable source. Count patched findings independently, or use a four-way
confusion table. No current retained episode flags a patched source; verified zero FPs stands.

## 5. Medium: probe inputs are overwritten across evidence namespaces

The script writes shared `_dev_probes/<case>/` files before creating its timestamped output,
without immutable snapshots or per-run input hashes. Both retained summaries reference the same
paths although Python construction changed between runs. Preserving scan directories alone does
not preserve both input versions. This review hashes current inputs; it cannot reconstruct an
overwritten source from an absent snapshot.

Keep immutable per-run or content-addressed probe sources, input/rule/builder hashes and parser/
scanner versions. The builder has no persistent cache; the coverage script rebuilds and overwrites
files. Deterministic C/D caching therefore still needs implementation.

## 6. Medium: parser dependencies are installed but undeclared

Four packages are imported unconditionally, including by Python-only callers, but are absent from
`autogrep/requirements.txt` and no new project dependency manifest was supplied. A clean documented
installation does not reproduce this module. Reviewed versions: tree_sitter 0.26.0,
tree_sitter_java 0.23.5, tree_sitter_javascript 0.25.0, tree_sitter_typescript 0.23.2. Declare the
tested installation route and record versions for frozen experiments.

## Research interpretation and next step

The probe exposes a real, narrow defect. Of the eleven accepted Qwen B hidden-renaming misses
motivating Item 5, it flags only three CASE-0171 episodes. CASE-0163/0239/0238 lack eligible probes;
CASE-0173 repeat 2 has an eligible probe but passes it. One renamed local does not test every
incidental name. This comparison uses retained outcome metadata for analysis, never hidden source
or outcomes as builder input.

All six flagged episodes originally accepted after one call, leaving repair budget under the
three-call ceiling, but all six also miss the restructured positive. Passing a renaming probe
does not establish E2E success. Whether feedback fixes both weaknesses remains untested.

Next: correct the builder, add independent regressions, implement the combined C/D gate, cache,
resource and provenance accounting. Offline-test visible-pass/probe-fail repair, combined pass,
exhaustion, ineligible fallback and probe scan errors. Recompute coverage in a new immutable
namespace before allocating C/D inference. Preserve A/B and historical results.

## File accounting and verification

Added: this review, `audit_dev_probe_20261013.py`, `Dev_Probe_Review_Evidence_20261013.json`, and
`commands/20261012T235134157459Z_dev_probe_review_20261013.log`.
Modified: `README.md`, append-only `events.jsonl`, and appended review entries in
`Bounded_Investigation_Tracking.md` and `Research_Log/Correction_Log.md`.
No implementation, test, benchmark, existing probe or saved result files were modified.

Verification: the 18-test file via pytest; retained audit via `pipeline/diagnostic_audit.py run
dev_probe_review_20261013 -- .venv/bin/python Research_Log/Diagnostic_20261010/audit_dev_probe_20261013.py`
(exit 0). Exploratory source diffs and counterexamples preceded the retained audit. A broad
recursive manifest search was interrupted after printing source diffs; bounded `rg` replaced it.
One documentation patch failed context matching without changing files, then was corrected.
The retained audit asserts eight accepted-invalid transformation cases plus a mocked skipped-target
scanner case. It reproduces reviewed defects, not corrected implementation behavior.

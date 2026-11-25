# Follow-up review after the seven-finding fix pass

Reviewed 2026-10-12 Europe/Helsinki; command timestamps use UTC. This reviews the user's statement that all seven previous findings were fixed. It makes no implementation changes and launches no inference. C3/C4 remain deferred.

## Verdict and confirmed improvements

The important exclusion and model-stopping defects are fixed. However, “all seven fixed” remains too strong: the failure auditor still mislabels populations and outcomes, TSX verification still happens only on first access per process, and the revised probe validity criterion is insufficient. The verifier now asserts its outcomes but can record a different engine version from the engine that actually scans.

- Reran both regression files: **29 passed**, including three executable Semgrep behavior tests and two acceptance-policy tests. The scanner environment's engine was independently confirmed as 1.177.0.
- Single and alternative-pattern exclusions now compose inside `patterns`; the tests verify actual unsafe/safe match behavior, not only compilation.
- `--acceptance-policy corrected` reaches the generation loop and requires `visible_correct`. The retained legacy default still stops after one mocked wrong-location candidate; corrected mode uses three attempts and rejects it. The policy and annotation-file hashes are now recorded in model-run environment.json.
- Former string-as-list, empty-list and taint-exclusion examples are rejected by runtime checks. Two additional contract gaps are described below.
- First TSX access in a process now repairs stale and missing staged files; the broader every-call claim remains false.
- The integration verifier asserts the iterative success count, exact case set and both scan-error counts, and writes timestamped summaries. Two existing summaries record passing assertions, six iterative successes and engine 1.177.0. They were read, not rerun in this follow-up; the previous review independently replayed the baseline.
- Recomputed historical episode aggregates: iterative complete-success counts remain **6, 4, 5, 5, 6, 3** for the baseline and mechanism v1–v5. Fixing prototype code does not retroactively create new generated rules or new repair episodes.

## Remaining findings

### 1. High for research interpretation: failure populations are still mixed

Locations: `pipeline/audit_failure_categories.py:67–90` and `94–140`.

The rewrite does use all requested episodes, addressing the previous omission of 57/144 accepted-final evaluations. But its labels still support conclusions stronger than the observations:

**Raw hidden results are not conditional on acceptance.** `categorize_hidden()` checks only `scan_ok`, yet main labels the resulting denominator `n_accepted` and “CONDITIONAL ON ACCEPTANCE ONLY.” Raw candidates undergo hidden evaluation even if they fail the visible pair. For mechanism v1, this reports 19 accepted raw evaluations, when only **six** actually satisfy legacy acceptance. Baseline is 22 versus 19. Other run denominators are retained in findings.json. Either filter by the chosen acceptance policy or label the group “successfully scanned raw candidates.”

**Missing evaluable output is still called an original miss.** `original_miss` is added whenever no clean attempt recorded a detection, including cases with no valid rule or no clean scan. In mechanism v1, its 12 cases consist of **10 with a clean scan but no original detection**, plus CASE-0238 (no parsed rule) and CASE-0298 (no clean scan). Thus “12/24 had no successful visible detection” is a valid broad operational statement, but “12 patterns failed to match the vulnerability” is not established. Keep no-valid-output/no-clean-scan separate from a demonstrated match failure. A synthetic episode with no parsed output is currently tagged `original_miss`.

**Acceptance attribution ignores the new policy.** `any_accepted` still checks `legacy_accepted`. A corrected-policy episode rejected solely for wrong localization is not tagged `never_accepted`. Reproduced with `final_rule_path=None`, corrected policy and a legacy-only visible pass. Use the episode's actual accepted outcome and record/read the policy explicitly.

**Error classification is still heuristic.** Any error without a `path` becomes a rule-construction error. A target parse error plus the runner's generic exit-status message is consequently tagged as both target and rule error. A synthetic target-only failure reproduces this. Use structured error types and separate process/infrastructure/annotation failures. This finding does not establish that the current historical “10 construction errors” count is inflated: inspected episodes counted there do contain explicit rule-error types. The defect affects classification reliability across possible inputs.

The code should also distinguish ever-observed failures from terminal failures. Current construction errors/patched false positives mean “at least one attempt,” while original miss means “no observed detection across clean attempts.” The tracking document should state these definitions alongside the table.

### 2. Medium: TSX verification is not performed on every call

Location: `pipeline/diagnostic_v2.py:106–115`.

Byte checks remain inside `if cid not in _TSX_STAGE_CACHE`. Reproduction in a temporary fixture:

1. Start with a stale/partial staging directory. First call repairs it: **fixed**.
2. Replace a staged file after that first call. Second call returns the stale bytes: **still broken**.
3. Delete another staged file. Second call leaves it absent: **still broken**.

Move per-file verification outside that cache guard or use content-addressed, immutable staging with explicit integrity checks. Writes currently use `write_bytes` directly; atomic replacement is needed if concurrent or interrupted writes must be handled. No real benchmark or existing TSX files were altered by these reproductions.

### 3. High for experimental validity: AST isomorphism alone does not certify preserved behavior

Location: `Bounded_Investigation_Tracking.md`, Item 5, beginning around line 286.

Removing the baseline rule as oracle fixes circularity. However, the replacement oracle only proves a structural property. This binding-consistent rename leaves literals and attributes untouched and passes the stated AST equality check modulo renamed identifiers:

```python
def probe():
    token = "unsafe"
    return locals()["token"]
```

Renaming the bound local `token` to `renamed_token` changes the result from `"unsafe"` to `KeyError`. This was executed in the retained reproduction. Reflection, keyword-visible parameters, dynamic evaluation and language-specific name-sensitive constructs need explicit eligibility restrictions and suitable behavioral/independent semantic checks. Python's AST module alone does not supply a binding resolver or a semantic equivalence proof.

The specification also contradicts itself: it proposes renaming while requiring a different family from held-out renaming/restructuring, then later describes “same-transform-FAMILY-but-different-instance.” Choose and label the intended comparison. Within-family generalization can be a valid experiment if honestly declared; it is different from transfer to unseen transformation families.

### 4. Medium: integration verification can record the wrong engine version

Location: `pipeline/verify_scan_integration.py:55`.

The version subprocess omits `dv2.semgrep_env(out)`, although actual scans use that environment. Under the current default shell environment, the exact verifier-style version call returned **1.140.0**, while the scan-environment call returned **1.177.0**. Both returned exit zero. Absolute launcher paths alone do not pin the delegated Python launcher.

Use the same environment for both, verify the return code and require the pinned version. The two existing retained summaries record 1.177.0; this reproduction does not invalidate those runs, but establishes environment-dependent false provenance. The summary currently hashes the selection only, not evaluator code, annotation inputs or rule files, despite its broad input-hash claim. Add these for a reproducible verification artifact.

### 5. Lower-priority contract gaps remain in TypedRule

Location: `pipeline/typed_rule.py:56–106` and `to_semgrep_yaml()`.

The previously reported inputs are rejected now, but validation is not complete for every field:

- `metadata=['not a mapping']` passes and is emitted unchanged.
- The list validator explicitly accepts tuples. `languages=('python',)` consequently passes, but `yaml.dump()` emits a Python tuple tag and `yaml.safe_load()` of the produced text raises `ConstructorError`. Normalize accepted tuples to plain lists or reject them, and restrict metadata to a supported plain-data mapping.

These are reproduced contract/serialization gaps; no historical model score is attributed to them. The serializer remains an intentionally restricted prototype, and its live model-output integration has not been tested.

## Important clarification about historical exclusions

The tracking update says that the unused typed-rule prototype means “no reported model result used the broken exclusion form.” The first clause is true; the inference is false. An inventory of saved accepted rules found sibling top-level `pattern` and `pattern-not` in:

| Run | Accepted rules | Rules with sibling exclusions |
|---|---:|---:|
| Original qwen3_v3 | 19 | 19 |
| Mechanism v1 | 11 | 0 |
| Mechanism v2 | 15 | 8 |
| Mechanism v3 | 14 | 8 |
| Mechanism v4 | 15 | 5 |
| Mechanism v5 | 13 | 2 |
| Total | 87 | 42 |

The measured scores remain observations of the actual executed rules. An ignored exclusion can leave the score unchanged when it is redundant on the samples; existence of the sibling field does not establish how many failures it caused. Conversely, those scores do not prove the exclusions functioned as intended. The inventory is saved with exact file paths.

A useful next offline investigation would preserve those rules, create a separately named variant composing the existing clauses correctly, and compare all six sample outcomes and lost/gained cases. This would isolate a concrete operator-composition intervention without another model call. It has **not** been executed by this review, is not a reason to overwrite historical scores, and should retain compiler failures and any lost positives as well as improvements.

## Recommended disposition

Close the original exclusion defect and model acceptance-loop defect. Credit the new input checks and real integration assertions. Keep the audit, staging integrity and probe design findings open until the reproductions above are addressed; distinguish the verifier's assertion fix from its remaining provenance issue. Item 3 independent review remains pending. The current passing suite is valuable but has no regression for the auditor population errors, same-process staging invalidation or probe semantics.

## Evidence and file accounting

- Added `bounded_followup_checks.py`, this follow-up review, and `bounded_followup_artifacts_20261011T215946041546Z/` containing findings.json and historical_exclusion_inventory.json (plus local Semgrep settings/log artifacts if created).
- Added command logs `20261011T215817861658Z_bounded_followup_regressions.log` and `20261011T215945480232Z_bounded_followup_findings.log`.
- Updated audit README with a link and appended command/review records to events.jsonl. The review milestone inventories added files and hashes.
- Eight reviewed implementation/test/document files were hashed and unchanged by the checks; their hashes are in findings.json. No implementation fixes, benchmark edits, historical-result edits or model calls were made. Imports/tests may refresh Python/pytest caches.
- Temporary staging corruption was confined to automatically removed fixtures. The AST counterexample executed only its literal local snippets. Two engine-version probes and three regression-test scans ran outside the sandbox to permit certificate initialization. No new full baseline replay was necessary in this follow-up.

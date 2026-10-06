# Root Cause Analysis: Why 6 of 8 Models Failed the aiohttp Smoke-Test Case

*A diagnostic investigation into the Phase 1 smoke-test results, going beyond the surface-level error messages to find the actual mechanism of each failure.*

---

## 1. The test case

**CVE mechanism:** a directory-traversal bug in `aiohttp`'s static-file server (`aiohttp/web_urldispatcher.py`), CWE-22. The real vulnerable code:

```python
# VULNERABLE (before fix)
filepath = self._directory.joinpath(filename).resolve()
if not self._follow_symlinks:
    filepath.relative_to(self._directory)
```

The real fixed code:

```python
# FIXED (after patch)
unresolved_path = self._directory.joinpath(filename)
if self._follow_symlinks:
    normalized_path = Path(os.path.normpath(unresolved_path))
    normalized_path.relative_to(self._directory)
    filepath = normalized_path.resolve()
else:
    filepath = unresolved_path.resolve()
    filepath.relative_to(self._directory)
```

The bug: the vulnerable version calls `.resolve()` (which follows symlinks) *before* checking whether symlink-following was even supposed to happen. The fix restructures the logic so path resolution only happens after the symlink policy is decided.

This is a genuinely subtle patch — the fix isn't "add a missing check," it's "reorder when resolution happens relative to a branch." That subtlety turned out to matter a lot.

---

## 2. Per-model diagnosis

### `qwen2.5-coder:7b-instruct` — succeeded

Correctly modeled the vulnerable structure using proper Semgrep metavariables and matched at the real changed lines. No further diagnosis needed.

### `qwen2.5-coder:32b` — looked correct, actually a masked tooling bug

Generated pattern:
```
$filepath = $directory.joinpath($filename).resolve()
if not $follow_symlinks:
```

This is structurally an almost perfect match for the real vulnerable code. But `$filepath`, `$directory`, `$filename`, `$follow_symlinks` are **lowercase** — and Semgrep requires metavariables to be all-uppercase (`$FILEPATH`, not `$filepath`). Running this rule directly against the real vulnerable file confirms Semgrep rejects it outright:

```
[ERROR] Rule parse error in rule tmp.vuln-aiohttp-1c335944:
 Invalid pattern for Python: `$filepath' is neither a valid identifier in Python nor a valid meta-variable
```

**This is not a semantic failure — it's an invalid rule that never ran at all.** The model's mistake was a syntax convention (metavariable casing), not a misunderstanding of the vulnerability.

### `codegemma:7b` — modeled the fix, not the bug

Generated pattern:
```
unresolved_path = self._directory.joinpath($FILENAME)
if self._follow_symlinks:
    normalized_path = Path(os.path.normpath(unresolved_path))
    normalized_path.relative_to(self._directory)
    filepath = normalized_path.resolve()
else:
    filepath = unresolved_path.resolve()
```

Compare this line-for-line against the **fixed** code above — it's essentially a direct copy. The model appears to have read the unified diff and anchored on the wrong side of it: it wrote a pattern describing the patched behavior, which of course never matches the actual vulnerable file. This rule genuinely, correctly reports 0 matches — Semgrep did its job; the rule just targets the wrong code.

### `yi-coder:9b` — right shape, wrong identifiers

Generated pattern:
```
filepath = directory.joinpath(filename).resolve()
if not follow_symlinks:
```

This is structurally the correct shape (matches the vulnerable code's logic), but uses bare names (`directory`, `filename`, `follow_symlinks`) instead of the real code's attribute-access form (`self._directory`, `self._follow_symlinks`), and uses no metavariables to bridge the gap. A literal Semgrep pattern with fixed identifiers only matches that exact identifier — `directory` is a different AST node from `self._directory`, so this can never match the real code regardless of logic correctness. (It also mislabeled the CWE as CWE-297, which is unrelated to directory traversal — a factual error alongside the pattern error.)

### `codellama:7b-instruct-fp16` — hallucinated hybrid

Generated pattern mixes fragments of both the vulnerable line (`filepath = self._directory.joinpath(filename).resolve()`) and the fixed code's branching structure, with the branch condition polarity inverted relative to the real fix. It doesn't correspond to either real version of the code — best explained as the model producing a plausible-*sounding* pattern rather than one grounded in the actual diff content.

### `magicoder:7b` and `deepseek-coder:6.7b` — malformed output

Both produced YAML documents with extra explanatory prose appended after the rule (e.g., "This rule will match any usage of...") that broke YAML parsing entirely, across all 3 retries. A formatting/instruction-following failure, not a reasoning failure — the underlying pattern content (where visible) was never even reached by the validator.

### `DeepHat/DeepHat-V1-7B` — over-generalized

First attempt's rule matched *both* the vulnerable and the patched file — the specific failure the design's Patch Discrimination Score is built to catch. Later attempts reverted to simply missing the vulnerability.

---

## 3. Summary table

| Model | Failure mechanism | Category |
|---|---|---|
| `qwen2.5-coder:32b` | Lowercase metavariables → Semgrep rejects the rule, but Autogrep reports it as a clean non-match | **Masked tooling bug** (see Section 4) |
| `codegemma:7b` | Pattern matches the *fixed* code's structure, not the vulnerable code's | Diff-side confusion |
| `codellama:7b-instruct-fp16` | Pattern is a hallucinated hybrid of both code versions | Hallucination |
| `yi-coder:9b` | Correct logical shape, wrong literal identifiers, no metavariables | Identifier/AST mismatch |
| `magicoder:7b`, `deepseek-coder:6.7b` | Extra prose breaks YAML parsing | Output-format failure |
| `DeepHat/DeepHat-V1-7B` | Rule also matches the patched code | Over-generalization |

Six failures, five genuinely distinct causes. Nothing here is a single, uniform "these models are bad" story — it's five different, specific ways a patch-to-rule task can go wrong, several of which are exactly what the study's metrics (SCR for format failures, PDS for over-generalization, MCC/VGR for semantic mismatch) are designed to distinguish and measure.

---

## 4. The one genuine bug: Autogrep silently swallows rule-parse errors

Autogrep's `rule_validator.py` classifies Semgrep's JSON error output like this:

```python
if any(t in error_type for t in ['ParseError', 'SyntaxError', 'TokenError']):
    return [], None  # target file couldn't be parsed -- skip
if 'InvalidRuleSchemaError' in error_type or 'InvalidRuleError' in error_type:
    return [], error_msg  # surface as a real error
```

Confirmed directly: when Semgrep rejects a rule for using invalid metavariable syntax, the JSON error's `type` field is literally the string **`"Rule parse error"`** — which matches neither check above. It falls through to the default `return results, None`, i.e. "no error, zero findings" — indistinguishable from a syntactically valid rule that simply didn't match anything.

**Why this matters for the study:** this silently reclassifies a category of *invalid, unexecutable rules* as *valid rules with genuine semantic misses*. That contaminates two things the study measures directly:
- **Raw Syntactic Compilation Rate (RQ1)** — this case should count as a rule-generation failure, not a rule-generation success with a semantic miss.
- **The failure taxonomy (Section 24)** — it would be filed under "vulnerability missed" instead of "unsupported Semgrep operator" / "invalid metavariable use," which are separately-tracked categories in the design.

This is a real defect worth fixing before Phase 5, not a finding about model quality.

**Fixed, then hardened** (2026-09-13):

1. First pass: added `"Rule parse error"` to the set of recognized error-type strings. This closed the *one instance* found, but left the underlying design unchanged — an **allow-list** of recognized error types, where anything not on the list still silently fell through to "0 results, no error." That's the same structural gap that caused the original bug in the first place, just with the one known string patched.
2. Second pass, on review: inverted the logic to a **deny-list**. Now only target-file parse errors (`ParseError`/`SyntaxError`/`TokenError` — genuinely safe to skip, since the *file* couldn't be parsed, not the rule) are treated as non-fatal. Every other error type Semgrep can report is surfaced by default, whether or not its exact string has been seen before.

Also, `pipeline/sample_evaluation.py`'s `evaluate_original_pair()` now returns and propagates the actual error text into `GenerationRecord.validation_error` instead of leaving it null.

**Verified with no regression**: re-ran both a known-successful case (`qwen2.5-coder:7b-instruct`, still succeeds cleanly) and the known-failing case (`qwen2.5-coder:32b`, still correctly surfaces the real "Invalid pattern... not a valid meta-variable" error) after the deny-list rewrite.

(The autogrep condition's `validation_error` still shows `null` on total failure across all 3 retries — a separate, smaller, pre-existing limitation: Autogrep's own `process_patch()` never returned per-attempt error text on total failure, even before this fix. Left as a minor follow-up for Phase 5 hardening.)

---

## 5. What this does *not* mean

- It is **not** evidence about which models are "better" — one hard case, run once, proves nothing about general model quality. That requires the actual 300-case dataset (Phase 5).
- Diff-side confusion, hallucination, identifier mismatches, and over-generalization are **not bugs to fix** — they are the actual phenomena the research questions (RQ1–RQ6) exist to measure. "Fixing" them (e.g., by rewriting the prompt until models stop making these mistakes) would bias the study rather than protect it.
- The only actionable defect here is Section 4's error-masking bug, which is a measurement-integrity issue, not a model-quality issue.

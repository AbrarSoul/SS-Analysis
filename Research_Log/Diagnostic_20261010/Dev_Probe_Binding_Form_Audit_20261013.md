# Bounded binding-form audit — 2026-10-13

**Corrected 2026-10-13 (second pass)**, after `Binding_Form_Audit_Review_20261013.md` found three
real gaps in the version below: (1) the JS/TS destructuring "confirmed safe" row was wrong for a
same-named collision (only an unrelated-candidate scenario had been tested) — now fixed in code
and the table corrected; (2) Python decorator expressions, explicitly listed as out of scope, were
not actually rejected by the builder — now fixed in code, and the table's "known gaps" section
updated to state that the decorator exclusion is now enforced, not just documented; (3) the per-case artifact was a
decision inventory, not an edit audit, and several table rows had no linked test — both addressed
below. See `Bounded_Investigation_Tracking.md`'s 2026-10-13 "review findings 1-2 fixed" entry for
the full reproduction-before-and-after detail; this document reflects the corrected, current state
rather than re-deriving each fix.

Scope and purpose, as requested: replace the "find another counterexample, patch it" cycle with
a bounded, documented boundary for what `pipeline/dev_probe.py` safely renames, per language. This
records checked forms, not a completeness claim for arbitrary programs: the builder enforces
the specific exclusions implemented below; it does not automatically reject every unreviewed
binding form. Where a construct is marked "not independently audited," its safety is unestablished.
**Closure qualification, 2026-10-13:** `Binding_Form_Audit_Closure_20261013.md` independently
verifies the concrete fixes and edits in the 11 current probe pairs. That validation is scoped
to the reviewed development inputs; applying the builder to new source needs fresh review or an
enforced supported-syntax contract.

While building this table, systematic enumeration (not waiting for another externally-supplied
counterexample) found and fixed **4 new real bugs** before writing anything down: Python nested
def/class names, Python import aliases, Python `match`/`case` captures, and the JS/TS equivalent
of the nested-function/class-name bug. Each was independently reproduced (broken before, fixed
after) via direct execution before being accepted — see the dated entries in
`Bounded_Investigation_Tracking.md` and `Correction_Log.md` for the full reproduction detail. This
document records the resulting boundary, not a re-derivation of each fix.

## Method

For each language, the actual AST/CST node types were inspected directly (via `ast.dump()` for
Python, direct `tree_sitter` parses for Java/JS/TS — not assumed from memory), cross-referenced
against `dev_probe.py`'s current logic, and every row below with an executable test is backed by
one in `pipeline/tests/test_dev_probe.py` (named in the Test column). A few low-probability,
recent-syntax rows (Python 3.12+ generics) were analyzed but not independently executed; marked
as such rather than asserted safe.

The core invariant the whole design rests on: **a binding form is only safely renameable if its
declaration site is a real `ast.Name` node (Python) or `identifier` node (Java/JS/TS) that
participates in the SAME text-span replacement as every one of its own references.** Every bug
found in this project (across all rounds) is an instance of exactly one failure of that invariant:
either (a) the declaration site is some OTHER kind of node (a string attribute, a differently-typed
node) invisible to replacement while references elsewhere are real identifiers and get swept in
anyway, or (b) the declaration and a reference are both real identifier nodes but belong to
semantically different scopes that the renamer did not yet distinguish.

## Python

| Construct | Declaration site | Scope relative to probed function | Disposition | Enforcing code | Test |
|---|---|---|---|---|---|
| Simple local assignment (`x = ...`) | `ast.Name` (Store) | Own scope | **Supported** | `_py_candidate_locals` | `test_python_successful_rename_and_patched_side` |
| Aug/ann-assign (`x += ...`, `x: T = ...`) | `ast.Name` (Store) | Own scope | **Supported** | `_py_candidate_locals` | `test_python_augassign_and_annassign_targets_are_supported` |
| `for`/`with ... as` simple target | `ast.Name` (Store) | Own scope | **Supported** | `_py_candidate_locals` | `test_python_for_and_with_targets_are_supported` |
| Function parameters (incl. `*args`/`**kwargs`) | `ast.arg` | Own scope (different role) | Rejected (excluded from candidacy) | `_py_param_names` | `test_python_parameter_never_renamed` |
| `global`/`nonlocal` declared names | plain strings on `Global`/`Nonlocal` | Outer scope | Rejected | `_py_global_nonlocal_names` | `test_python_global_declared_name_is_excluded` |
| Tuple/list/starred assignment targets (`a, token = ...`) | `ast.Name` (Store), nested inside `Tuple`/`List`/`Starred` | Own scope | Rejected (not offered; plain-Name-target policy) — **confirmed safe**, not just conservative | `_py_candidate_locals` (`isinstance(t, ast.Name)` check) | `test_python_walrus_and_tuple_unpacking_confirmed_safe` |
| Walrus (`:=`) target | `ast.Name` (Store), via `NamedExpr` | Own scope (binds in nearest enclosing function, even from inside a comprehension) | Rejected (not offered) — **confirmed safe** when chosen as an unrelated candidate's sweep target | `_py_candidate_locals` (not in collected node types) | `test_python_walrus_and_tuple_unpacking_confirmed_safe` |
| Comprehension `for` target (`[x for x in ...]`) | `ast.Name` (Store), own scope boundary in Py3 | Comprehension's own scope | Rejected (scope-boundary exclusion) | `_py_names_touched_in_nested_scopes` | `test_python_comprehension_scope_review_reproduction_is_ineligible` |
| Nested `def`/`lambda`/`class` body contents | varies | Nested scope | Rejected (any name touched anywhere inside, excluded) | `_py_names_touched_in_nested_scopes` | `test_python_nested_scope_review_reproduction_is_ineligible` |
| Nested `def NAME()`/`class NAME:` **own name** | plain string (`FunctionDef`/`ClassDef`/`AsyncFunctionDef`.name) | Enclosing (containing) scope | Rejected — **fixed this round** | `_py_names_touched_in_nested_scopes` | `test_python_nested_def_name_rebinding_is_ineligible` |
| Parameter defaults / annotations | `ast.Name` (Load), evaluated in enclosing scope | Enclosing scope | Rejected | `_py_names_in_signature` | `test_python_default_argument_scope_review_reproduction_is_ineligible` |
| Decorator expressions (`@decorate(token)`) | `ast.Name` (Load), evaluated at def-time in enclosing scope | Enclosing scope | Rejected — **fixed this round** (previously listed as "outside the audit" with no enforcement at all; the review correctly rejected that as insufficient — a bounded audit must enforce its declared boundary, not just document it) | `_py_names_in_signature` (extended to also walk `func.decorator_list`) | `test_python_decorator_expression_scope_is_excluded` |
| `except E as NAME:` | plain string (`ExceptHandler.name`) | Handler body only (implicitly deleted after) | Rejected | `_py_exception_bound_names` | `test_python_exception_binding_review_reproduction_is_ineligible` |
| `import X as NAME` / `from M import X as NAME` | plain string (`alias.asname`/`.name`) | Own scope | Rejected — **fixed this round** | `_py_import_bound_names` | `test_python_import_alias_rebinding_is_ineligible` |
| `match`/`case` capture (`case X() as NAME:`, `case [*NAME]:`, `case {**NAME}:`) | plain string (`MatchAs`/`MatchStar`/`MatchMapping`) | Own scope (persists after match, unlike except) | Rejected — **fixed this round** | `_py_match_bound_names` | `test_python_match_case_binding_is_ineligible` |
| `locals`/`globals`/`getattr`/`setattr`/`vars`/`eval`/`exec` anywhere in function | n/a | n/a | Whole function rejected | `_py_has_reflection` | `test_python_reflection_locals_makes_function_ineligible`, `test_python_reflection_getattr_makes_function_ineligible` |
| Name reachable via a string literal | n/a | n/a | Candidate skipped, falls through to next | `_py_string_literal_contains` | `test_python_name_only_reachable_via_string_literal_is_skipped` |
| PEP 695 type-parameter syntax (`def f[T](...)`, `type X = ...`) | `ast.TypeVar.name` is a plain string; `ast.TypeAlias.name` IS an `ast.Name` | n/a | **Not independently executed.** Analysis: a type-param name is only usable in annotation positions, already excluded via `_py_names_in_signature`; `TypeAlias` targets are real `Name` nodes, same safe-by-omission class as walrus/tuple-unpack. Python 3.12+ only; essentially absent from this study's CVE-fix-era source. | n/a | none — flagged as a low-priority open item, not claimed safe by test |

## Java

| Construct | Declaration site | Scope relative to probed function | Disposition | Enforcing code | Test |
|---|---|---|---|---|---|
| `local_variable_declaration` as a direct child of the method's own body block | `variable_declarator`'s `identifier` | Own scope | **Supported** | `_ts_collect_declared_locals` | `test_real_development_case_builds_a_valid_probe[CASE-0184-java]` |
| `local_variable_declaration` nested inside any other block (`if`/`try`/`for`/bare `{}`) | same | Block scope (Java has no `var`-equivalent) | Rejected | `_ts_block_scoped_outside_function_body` (generalized to Java this session) | `test_java_block_local_vs_field_review_reproduction_is_ineligible`, `test_real_java_case_now_ineligible_after_block_scope_fix` |
| Method/constructor formal parameters | `formal_parameter` | Own scope (different role) | Rejected | `_ts_param_names` | `test_java_parameter_role_change_risk_is_excluded` |
| Method/constructor/class/interface declaration's own name | `identifier` in the declaration's "name" field | Own/enclosing scope | Name position excluded from rename; **and** whole candidate rejected if any OTHER same-named declaration exists elsewhere in the text | `_DECLARATION_NAME_PARENT_TYPES` + `_ts_has_same_named_declaration` | `test_java_declaration_name_review_reproduction_now_preserves_callability` |
| Field access (`this.token`, `obj.token`) | `field_access`'s "field" child | n/a (not a local at all) | Excluded from rename | `_ts_is_excluded_position` | `test_java_field_access_property_not_confused_with_local_variable` |
| Unqualified method call (`token()`) | `method_invocation`'s "name" child | n/a | Excluded from rename position | `_ts_is_excluded_position` | implicitly covered — no case in the real 24-case set exercises a local/method-name collision, and this module only ever sees ONE function's text (sibling methods are never visible to it, so a same-named sibling method is out of the tool's analysis scope entirely, not a gap) |
| Local class declared inside a method body (`class NAME { ... }`) | `identifier` in `class_declaration`'s "name" field | Enclosing scope | **Confirmed structurally safe, not exploitable**: all VALUE-position references to a local class use `type_identifier` (constructor calls, type declarations), a different node type than the declaration's own `identifier`; the one plausible same-node-type path (unqualified static-method call shadowed by a same-named local variable) does not compile in Java at all | n/a (safe by language semantics, confirmed via `javac`) | verified via direct `javac` compilation during this audit (not promoted to a permanent regression test, since there is nothing for `dev_probe.py` to get wrong here) |
| `catch (Type NAME)` parameter | `catch_formal_parameter`'s `identifier` | Block scope | Rejected (not offered as a candidate — different node type than `variable_declarator`) — **confirmed non-exploitable**: Java disallows a catch parameter from sharing a name with any variable already visible in the enclosing method (compile error), so the collision this audit worried about can never arise in valid input | n/a (safe by language semantics, confirmed via `javac`) | verified via direct `javac` compilation during this audit |
| `getDeclaredField`/`getField`/`getDeclaredMethod`/`getMethod`/`Class.forName`/`.invoke` anywhere | n/a | n/a | Whole function rejected | `_ts_has_reflection` | `test_java_reflection_getDeclaredField_makes_method_ineligible` |

## JavaScript / TypeScript

| Construct | Declaration site | Scope relative to probed function | Disposition | Enforcing code | Test |
|---|---|---|---|---|---|
| `var`/`let`/`const` declared as a direct child of the function's own top-level body block | `variable_declarator`'s `identifier` | Own scope | **Supported** | `_ts_collect_declared_locals` | `test_js_member_access_property_not_confused_with_variable`, `test_typescript_successful_rename` |
| `let`/`const` nested inside any other block | same | Block scope | Rejected | `_ts_block_scoped_outside_function_body` | `test_js_block_scope_review_reproduction_would_break_behavior`, `test_real_js_case_now_ineligible_after_scope_fix` |
| `var` nested inside any other block | same | Function scope (unaffected by block nesting — real JS semantics) | **Supported** (not excluded, correctly) | `_ts_block_scoped_outside_function_body` (only checks `lexical_declaration`, not `variable_declaration`, for JS/TS) | `test_js_nested_var_remains_function_scoped_and_supported` |
| Shorthand destructuring (`const {token} = obj`) | `shorthand_property_identifier_pattern` — a DIFFERENT node type than plain `identifier`, representing the key and the bound local simultaneously | Own scope | **Corrected 2026-10-13 (second pass):** the FIRST version of this row claimed "confirmed safe," verified only against an UNRELATED candidate sitting next to the destructuring binding — the review found this fails for a SAME-NAME collision (`var token=1; var {token}=obj; return token;`, valid via `var` redeclaration): original returns the destructured value, the pre-fix probe returned the stale initial value. Now an explicit candidate-rejection case, not a safe-by-omission one: any name used as a shorthand destructuring pattern anywhere is rejected (same mechanism as the pre-existing object-literal-construction shorthand risk) | `_ts_has_shorthand_property` (extended to cover both shorthand node types) | `test_js_shorthand_destructuring_same_name_collision_is_ineligible` |
| Array destructuring (`const [a, token] = arr`) / renamed-key object destructuring (`const {key: token} = obj`) | plain `identifier`, same type as an ordinary reference, nested in `array_pattern`/`pair_pattern` | Own scope | **Supported** — confirmed safe including for a SAME-NAME collision (not just an unrelated candidate), since both bind via the same node type as a normal reference and are therefore already renamed consistently | `_ts_rename_all` (no special-case needed; ordinary `identifier` matching already covers it) | `test_js_array_and_renamed_key_destructuring_confirmed_still_safe` |
| Function/arrow/method parameters (plain or default-valued) | `identifier` (plain) or `identifier` inside `assignment_pattern`/`required_parameter`/`optional_parameter` | Own scope (different role) | Rejected | `_ts_param_names` | covered via role-change checks in `_rename_patched_tree_sitter` |
| Parameter default value expressions (`function f(x=token)`) | `identifier` inside `assignment_pattern.right` / `required_parameter.value` / `optional_parameter.value` | Enclosing scope (sees caller-visible scope, not body `let`/`const`) | Rejected — **fixed this round** | `_ts_names_in_signature_defaults` | `test_js_default_argument_scope_review_reproduction_is_ineligible` |
| Nested `function`/arrow function/method body contents | varies | Nested scope | Rejected (any param/local touched inside, excluded) | `_ts_shadowed_in_nested_function` | existing coverage, not re-tested this round |
| Nested `function NAME(){}` / `class NAME{}` **own name** | `identifier` in the declaration's "name" field | Enclosing scope | Rejected — **fixed this round** | `_ts_has_same_named_declaration` | `test_js_nested_function_name_rebinding_is_ineligible` |
| Candidate ever called as a bare function (`cb()`) | n/a | n/a | Whole candidate rejected (not just the callee position) | `_ts_is_called_as_bare_function` | `test_js_callee_exclusion_review_reproduction_would_raise_referenceerror` |
| ES6 shorthand object-literal property (`{token}` when constructing, not destructuring) | `shorthand_property_identifier` | n/a | Candidate rejected (or falls through if another candidate exists) | `_ts_has_shorthand_property` | `test_js_shorthand_property_candidate_is_skipped`, `test_js_shorthand_property_risk_falls_through_to_another_candidate` |
| Member/property access (`obj.token`) | `member_expression`'s "property" child | n/a | Excluded from rename | `_ts_is_excluded_position` | `test_js_member_access_property_not_confused_with_variable` |
| `catch (NAME)` parameter | plain `identifier`, direct child of `catch_clause` | Block scope (shadows an outer same-named binding) | Rejected (not offered — different node type than `variable_declarator`) — **confirmed safe** when an outer same-named candidate is swept in, since uniform textual relabeling preserves the shadow relationship | n/a (safe by uniform-rename argument, confirmed via real `node` execution) | `test_js_catch_clause_and_for_of_shadowing_confirmed_safe` |
| `for (let/const/var NAME of/in ...)` loop variable | plain `identifier`, direct child of `for_in_statement` (no `variable_declarator` wrapper at all) | Loop scope (shadows an outer same-named binding) | Rejected (not offered) — **confirmed safe** by the identical uniform-relabeling argument as `catch` | n/a (same as above) | `test_js_catch_clause_and_for_of_shadowing_confirmed_safe` |
| `eval(...)`, dynamic bracket access on `window`/`globalThis`/`self` with a non-literal key | n/a | n/a | Whole function rejected | `_ts_has_reflection` | `test_js_eval_makes_function_ineligible` |

## Known, deliberately out-of-scope gaps

- **No real closure/free-variable resolution anywhere.** The module's entire strategy is
  "resolve nothing; reject the whole candidate if the name is touched anywhere a real resolver
  would need to disambiguate." This is why eligibility is 11/24 on the real development set, not
  higher — it is the intended trade (safety over coverage), not an oversight.
- **PEP 695 Python generics** (see table) — analyzed, not executed; negligible practical risk
  given the dataset's code era.
- **Any construct not in these tables** (e.g., class attribute declarations, JS generators/async,
  TS enums/namespaces) was not individually enumerated. The audit followed the review's explicit
  instruction to derive the inventory from the actual grammars rather than assume a fixed category
  list, but a full walk of every node type in three separate grammars was not completed to
  exhaustion — this document is the boundary that **was** checked, not a claim that nothing outside
  it exists. Critically, per the review's Finding 2: being outside this document's checked list is
  NOT the same as being safely ignored by the builder — Python decorators WERE listed here as
  out-of-scope in the first version of this document and turned out to be actively exploitable
  (see the Decorator row above, now fixed). Any construct genuinely untouched by this audit should
  be assumed UNENFORCED, not assumed safe, until independently checked the same way.

## Per-case review across the real 24-case development set

**Corrected 2026-10-13 (second pass):** the review's Finding 3 correctly noted the first version
of `probe_binding_audit_report.py` recorded only case/language/eligible/old_name/new_name — a
decision inventory, not the requested edit audit. It is now rewritten to additionally record, per
case: a SHA-256 of every input/output source; a line-level diff of `vulnerable_function` ->
`vulnerable_probe` and `patched_function` -> `patched_probe` (the exact edit, independently
reviewable without re-running the builder); and, for every ineligible case, a per-raw-candidate
classification naming the SPECIFIC check that rejected each candidate the builder considered (not
just the overall generic reason string). Output is now written to a NEW timestamped file every run
(the prior version's docstring claimed "writes nothing" while actually overwriting one fixed path
— also fixed). Full detail, produced by this corrected script (pure `build_probe()` calls, no
model calls, no Semgrep scans), is in
`Dev_Probe_Binding_Audit_Decisions_20261013T090739177579Z.json`. Summary unchanged from the first
pass (confirming the destructuring/decorator fixes above did not alter any of these 24 outcomes):

```
case_id      language     eligible  decision
CASE-0046    python       True      renamed 'dont_save_keys' -> 'dont_save_keys_renamed'; patched_renamed=False
CASE-0063    javascript   False     REJECTED: vulnerable_function does not parse cleanly
CASE-0081    typescript   False     REJECTED: no eligible local binding found (all candidates excluded or exhausted)
CASE-0116    java         False     REJECTED: no eligible local binding found (all candidates excluded or exhausted)
CASE-0124    python       True      renamed 'sagemaker_dependency' -> 'sagemaker_dependency_renamed'; patched_renamed=True
CASE-0134    python       True      renamed 'result' -> 'result_renamed'; patched_renamed=True
CASE-0136    java         True      renamed 'f' -> 'f_renamed'; patched_renamed=True
CASE-0163    javascript   False     REJECTED: vulnerable_function does not parse cleanly
CASE-0171    java         True      renamed 'url' -> 'url_renamed'; patched_renamed=True
CASE-0173    typescript   True      renamed 'key' -> 'key_renamed'; patched_renamed=True
CASE-0184    java         True      renamed 'msg' -> 'msg_renamed'; patched_renamed=False
CASE-0193    java         False     REJECTED: no eligible local binding found (all candidates excluded or exhausted)
CASE-0220    javascript   False     REJECTED: no eligible local binding found (all candidates excluded or exhausted)
CASE-0221    java         False     REJECTED: no eligible local binding found (all candidates excluded or exhausted)
CASE-0222    python       True      renamed 'headers' -> 'headers_renamed'; patched_renamed=True
CASE-0231    python       True      renamed 'user_dir' -> 'user_dir_renamed'; patched_renamed=True
CASE-0235    typescript   False     REJECTED: vulnerable_function does not parse cleanly
CASE-0238    typescript   False     REJECTED: vulnerable_function does not parse cleanly
CASE-0239    javascript   False     REJECTED: vulnerable_function does not parse cleanly
CASE-0276    python       True      renamed 'file' -> 'file_renamed'; patched_renamed=True
CASE-0298    typescript   False     REJECTED: no eligible local binding found (all candidates excluded or exhausted)
CASE-0323    javascript   False     REJECTED: vulnerable_function does not parse cleanly
CASE-0339    javascript   False     REJECTED: no eligible local binding found (all candidates excluded or exhausted)
CASE-0340    typescript   True      renamed 'output' -> 'output_renamed'; patched_renamed=True

11/24 cases eligible.
```

None of the 6 bugs found and fixed during this audit's two passes (Python nested def/class names,
import aliases, match-case captures, decorator expressions; JS nested function/class names,
shorthand destructuring same-name collisions) occur in any of these 24 real cases — every
eligibility/decision number above is identical across both the pre-audit and both post-fix runs.
This was confirmed by rerunning `pipeline/probe_coverage_check.py` in a fresh namespace
(`_probe_coverage_20261013T090920800445Z`), not assumed: eligibility 11/24, 100/195 accepted
episodes covered, 94 pass / 6 fail / 0 patched findings — numerically identical across all runs,
with the same 6 failing episodes by case/model/repeat
(`qwen3-coder:30b`/B/CASE-0171 ×3, `gpt-4o`/A/CASE-0136 ×2, `gpt-4o`/A/CASE-0173 ×1).

## Frozen versions (reviewed implementation)

- `pipeline/dev_probe.py` SHA-256: `d2d7364a77670e6d448da82bdf895a33aca785e9e08d1fe1941e5fae2af88114`
  (updated after the second-pass fixes above; the first-pass hash
  `120bd1ea86c355ef57b9cad26588c30f1c4eee5ccbaf21407beb6c85739132aa` is preserved here for
  provenance of what the first review actually checked)
- Python: 3.14.4
- Semgrep: 1.177.0
- `tree_sitter`: 0.26.0
- `tree_sitter_java`: 0.23.5
- `tree_sitter_javascript`: 0.25.0
- `tree_sitter_typescript`: 0.23.2
- Full test suite: 90/90 passing (`pytest pipeline/tests/ --ignore=pipeline/tests/test_stats_section22.py`)

## What this does and does not establish

**Does:** gives a reviewable, test-backed boundary for every binding form actually found in the
pinned grammars that this audit checked, across two passes — six total silent gaps found and
fixed, each independently reproduced broken-then-fixed by direct execution, with an edit-level
(not just decision-level) per-case artifact and a corrected table where the first pass's own
"confirmed safe" claim turned out to be wrong. Confirms (again, across three separate reruns now)
that the six observed coverage misses are unaffected by any mechanism change in either pass.

**Does not:** prove the builder is correct for every construct in three language grammars (see
"Known, deliberately out-of-scope gaps" above) — a few rows are analyzed-not-executed, and a full
grammar walk to exhaustion was not performed. The review's own closing lesson applies directly:
being listed as "out of scope" in this document is a statement about what was checked, not a
safety guarantee — the decorator gap proves a listed-as-unchecked construct can be actively
exploitable, not merely untested. It also does not implement or test C/D's combined acceptance
gate, deterministic caching, or anything about whether probe-feedback repair actually improves
end-to-end success — those remain separately deferred, as requested, pending explicit approval
before any new inference spend.

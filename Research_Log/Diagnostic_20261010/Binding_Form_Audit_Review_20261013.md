# Review of bounded binding-form audit — 2026-10-13

The new fixes, decision inventory, frozen versions and coverage evidence are useful and
reproducible. The audit does not yet meet its stated acceptance boundary: one construct labeled
safe is demonstrably unsafe, unreviewed constructs are not actually rejected, and the per-case
artifact records name choices rather than the requested exact edit review. These are gaps inside
the agreed bounded task, not a demand to prove arbitrary programs equivalent or exhaust every
language grammar before proceeding.

## Verified

- The probe test file passes **38/38 in 1.59s**. The author reports 82 tests in the full suite;
  this review reran only the changed probe file. Its count increased from 32 to 38: six additional
  tests, consistent with 76 to 82 overall. The message's "8 added" does not match that increase.
- The frozen `dev_probe.py` SHA-256 matches
  `120bd1ea86c355ef57b9cad26588c30f1c4eee5ccbaf21407beb6c85739132aa`.
  Python 3.14.4 and all four recorded tree-sitter versions match the environment.
- All 24 decision rows regenerate identically. All 22 current probe sources regenerate
  byte-for-byte and match stored hashes. Eligibility remains 11/24.
- All 100 raw scanner outputs from `_probe_coverage_20261013T014605839062Z` report Semgrep
  1.177.0, no errors and both intended targets scanned. Independent recount is **94 pass,
  6 miss, 0 patched findings**. All six failing model/condition/repeat/case identities are
  unchanged. Coverage is 100/195 accepted episodes; 95 are uncovered.
- Among the prior closure's hashed inputs, only the builder and probe test file changed.
  Previous recorded scan and probe inputs remain unchanged.

Verification and counterexamples are retained in `audit_binding_form_review_20261013.py`,
`Binding_Form_Audit_Review_Evidence_20261013.json`, and
`commands/20261013T084530750407Z_binding_form_audit_review_20261013.log` (exit 0).
No new model calls or real Semgrep scans were made.

## Finding 1 — high: the destructuring safety claim fails for a same-named binding

The JS/TS table calls destructuring safe because it is not independently offered as a candidate,
and reports testing it alongside an unrelated candidate. That does not test the failure class:
a candidate selected from one declaration can share its binding with a destructuring target.

This valid JavaScript source returns 99:

```javascript
function f(obj) { var token=1; var {token}=obj; return token; }
// f({token:99}) === 99
```

The builder accepts it and emits:

```javascript
function f(obj) { var token_renamed=1; var {token}=obj; return token_renamed; }
// f({token:99}) === 1
```

The shorthand destructuring binding is not an ordinary identifier, so it is left behind while
the initial declaration and return reference are renamed. The assignment form
`var token=1; ({token}=obj); return token` produces the same 99-to-1 change. Both were executed
with Node and are returned as eligible `ProbeResult` objects on both source sides.

Reject a candidate used in an unsupported destructuring binding/assignment form, or implement
correct reference/binding handling. Test same-name collisions and rebinding, not only an unrelated
candidate next to a construct. Correct the table's "confirmed safe" claim. The current 24-case
coverage counts are not contradicted by this synthetic counterexample.

## Finding 2 — high: the declared unsupported-syntax boundary is not enforced

The document explicitly puts decorators outside its checked forms while claiming the builder
rejects candidates touched by unhandled forms. There is no corresponding rejection path.
With global `token=10` and `decorate = lambda value: lambda fn: fn`, this source returns 1:

```python
@decorate(token)
def f():
    token = 1
    return token
```

The accepted probe changes the decorator to `@decorate(token_renamed)` along with the local
assignment and return. Executing the transformed definition raises `NameError` because the
decorator expression resolves the enclosing global, not the body local. This is a construct
already listed as outside the audit, not an invented extra requirement.

A bounded audit may deliberately decline to support decorators or other syntax. Its admissibility
logic must then reject affected candidates, rather than relying on a prose caveat. Either provide
an enforced supported-syntax contract with tests for rejection at its boundary, or explicitly
restrict a development pilot to independently reviewed, immutable case-specific probe artifacts.
The latter would be a narrower experimental implementation, not evidence of a safe general
renaming engine. Neither route requires exhaustive language support.

## Finding 3 — medium: the artifact is a decision inventory, not the promised edit audit

`probe_binding_audit_report.py` records only case/language, eligible, old/new name and a patched
boolean, or a generic reason returned by `build_probe`. It does not record individual replacement
offsets/lines, declaration/reference roles, input/output hashes, or independent checks that only
the intended binding was changed. Re-running the builder cannot independently validate the
builder's chosen edits. The prior closure's bounded-task criteria explicitly requested exact spans
and candidate-specific rejection reasons.

Add per-side source hashes and exact edit spans with binding roles and reviewer checks for the
11 generated pairs; record a precise exclusion category for the 13 ineligible cases. Preserve
each report version: despite its "writes nothing" docstring, the current script unconditionally
overwrites a fixed `Dev_Probe_Binding_Audit_Decisions_20261013.json` filename. The separate coverage
namespaces are immutable, but this report itself is not.

The table also contains several rows explicitly lacking independent tests (augmented/annotated
assignment, for/with targets, global/nonlocal, some Java parameter paths, nested JS var). This is
more than only generics/future-destructuring gaps. Link a real test for each supported/rejected
disposition in the chosen boundary, combine equivalent rows only with a stated tested invariant,
or mark the disposition unvalidated and enforce rejection where needed. The overall pass count
does not fill these missing links.

## Path forward

Keep the existing coverage result and historical E2E measurements. Close these bounded audit
gaps before declaring the supported-syntax boundary complete. The two behavior failures concern
unhandled or falsely-certified edits; they do not establish that the six retained misses were
artifacts. After an enforced boundary and exact case-edit review, proceed to the separately
scoped C/D combined gate and caching with offline tests. This review does not implement those
features or authorize/run inference.

## File accounting

Added: this review, its audit script, evidence JSON and command log listed above.
Modified: README, append-only events, and appended review entries in Tracking and Correction logs.
No implementation, tests, dependency manifests, benchmark sources, existing audit decisions,
probe sources or saved outcomes were modified. The proposed fixes above remain open.

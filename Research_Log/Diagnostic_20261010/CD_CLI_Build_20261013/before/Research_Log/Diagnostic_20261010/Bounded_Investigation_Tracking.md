# Bounded investigation tracking (per Research_Direction_20261011.md)

Live tracking document for the 5 "do now, offline, no new inference" items from
`Research_Direction_20261011.md`'s "Bounded investigation before additional broad runs" section.
Updated as each item progresses. The larger 2x2 controlled comparison + confirmation study from
that same document is explicitly NOT started here -- gated on these 5 finishing first.

**2026-10-12, all 5 items now done** (items 1/2/4/5 corrected across 3 external review rounds;
item 3 expanded to full 24-case coverage, then corrected again same day after a 4th review found
its 11/24 rule-based-only characterization overclaimed -- see Item 3's section below). A draft (not
frozen, not executed) protocol for the 2x2 comparison was written up at
`Controlled_2x2_Protocol_Draft_20261012.md`, then itself reviewed
(`Controlled_2x2_Protocol_Review_20261012.md`) and corrected in place -- most notably its
confirmation-set-size estimate, which was off by more than 2x (claimed 80-100 cases for 80% power,
independently recomputed and confirmed at 207). A follow-up review
(`Controlled_2x2_Protocol_Followup_20261012.md`) then found a real environmental qualification on
CASE-0222's semantic-preservation claim, three description-precision fixes (CASE-0323/0136/0124),
and a genuine contradiction in the protocol's C/D stopping rule (fixed with an explicit combined
accept/stop gate) -- all independently reproduced before accepting, none of which change any
reported number. 6 open decisions (was 5) now flagged for the user before the protocol can
actually be frozen or run.

| # | Item | Status |
|---|---|---|
| 1 | Wire evaluator fixes (.tsx staging, merged location ranges, location-aware acceptance gate) into `diagnostic_v2.py`'s own runner, not a separate rescore pass | **Done, corrected across 3 review rounds, 2026-10-12** (round 1: acceptance gate + TSX integrity check were incomplete; round 2: the TSX check's own fix only ran once per process, not every call; round 3: closure independently re-verified, no further issues found) |
| 2 | Audit every saved output by failure category (construction / wrong-location / patched-FP / renamed-miss / structural-miss / safe-benign-FP), both denominators | **Done, corrected across 3 review rounds, 2026-10-12** (round 1: 57/144 episodes silently excluded; round 2: raw-stage denominator mislabeled "accepted", `original_miss` conflated two different things, acceptance gate hardcoded instead of policy-aware; round 3: generic status-wrapper messages were miscounted as rule-construction errors -- fixed, verified to not change any historical count) |
| 3 | Independent review of transformation semantics + the 24 reference rules | **Best-effort self-review done 2026-10-12, corrected same day** (reference-rule audit: 24/24, direct source-based semantic review: 24/24 -- a follow-up review found the first pass's 11/24 "non-confounded rule-based" characterization overclaimed what rule-passing actually establishes; corrected by completing direct review of those 11. See caveat below, which still genuinely applies: this is NOT genuine independence) |
| 4 | Build + validate typed-rule-representation + deterministic-serializer offline against already-saved malformed candidates | **Done, corrected across 3 review rounds, 2026-10-12** (round 1: exclusion-logic bug + missing validation; round 2: `metadata` type and `languages`-as-tuple YAML-roundtrip gaps; round 3: closure independently re-verified, no further issues found) |
| 5 | Design the "extra behavioral probe" factor as a clean, isolated, hidden-data-firewalled addition | **Done (design only), corrected across 3 review rounds, 2026-10-12** (round 1: circular probe-validation oracle; round 2: internal contradiction on transform-family + no reflection-safety restriction; round 3: the "different family" fix was itself incomplete -- Construction still specified renaming, and renaming a parameter can break a keyword caller outside the probe's visibility; now explicitly scoped as a within-family signal with renaming restricted to local, non-parameter bindings) |

**2026-10-12: three successive independent review rounds on this same work.** Round 1
(`Bounded_Investigation_Review_20261012.md`) found 7 real issues across items 1, 2, 4, and 5 (first
update section below). Round 2 (`Bounded_Investigation_Followup_Review_20261012.md`) found 5 more
issues in those fixes (second update section below). Round 3
(`Bounded_Investigation_Round3_Review_20261012.md`) verified rounds 1-2's fixes closed and found 2
further issues -- one in the item-2 auditor's error classification, one in item 5's probe design
(third update section below). Every finding across all three rounds was independently re-verified
before being accepted -- none were taken on faith. Item 3's status was unchanged by all three
rounds (still not started at that point) -- it was done afterward, same day; see its own section
below for what was actually done and the independence caveat that still genuinely applies to it.

**Caveat on item 3**: true independence requires a reviewer who hasn't been constructing this exact
diagnostic's own hypotheses and fixes all week. I'm the same agent that's been doing that work, so I
cannot claim genuine independence -- I'll do the most rigorous check I can and flag this limitation
explicitly in the output, not claim something this process can't actually provide.

## 2026-10-12 update: an independent review found real bugs in this work -- all confirmed and fixed

`Bounded_Investigation_Review_20261012.md` reviewed everything below and found 7 real issues (3
high-severity), none of which I had caught myself. Every one was independently re-verified before
accepting it (not taken on faith) -- see each item's section below for the exact repro and fix.
Summary:

| # | Finding | Verified? | Fixed? |
|---|---|---|---|
| 1 | Typed serializer's "simple case" (sibling `pattern`+`pattern-not`) silently failed to exclude anything under real execution, despite passing `semgrep --validate` | **Yes** -- reproduced the exact `foo("unsafe")`/`foo("safe")` test, matched both lines | **Yes** -- always composes via `patterns:` now; permanent executable regression test added |
| 2 | `run_model_case()`'s actual stopping decision still gated on `legacy_accepted`; the `*_corrected` fields only changed reporting | **Yes** -- reproduced with a mocked wrong-location evaluation, confirmed one call + false accept | **Yes** -- new explicit `--acceptance-policy legacy\|corrected` flag; `legacy` is the untouched default, `corrected` gates on `visible_correct` with real repair feedback |
| 3 | Failure auditor only looked at the accepted-final evaluation; 57/144 episodes across the 6 datasets had none and were silently excluded from every category | **Yes** -- recomputed the 57/144 figure independently, matched exactly | **Yes** -- rewritten to walk retained attempt records for a visible-stage audit covering all 24 episodes, with the hidden-stage categories kept as an explicitly-labeled conditional-on-acceptance analysis |
| 4 | Probe-validation design (Item 5) was circular: discarding a probe because the baseline rule fails it discards exactly the probes that would expose baseline brittleness | Accepted on the logic alone (no empirical test needed) | **Yes** -- redesigned to use an AST-isomorphism check, never any rule, as the validity oracle; softened the "can never leak" overclaim too |
| 5 | `TypedRule` had no runtime type validation -- `pattern_either="foo()"` (a string) was accepted and iterated character-by-character; taint rules silently dropped `pattern_not` | **Yes** -- reproduced both exactly as described | **Yes** -- `validate()` now checks real types/shapes for every field; unsupported combinations raise instead of silently dropping |
| 6 | TSX staging cache trusted an existing directory without checking its bytes -- a stale/partial stage would be served forever | Accepted on code inspection (matches the described logic exactly) | **Yes** -- every call now verifies staged bytes against the frozen source and repairs on mismatch; annotation-file hashes also added to run provenance |
| 7 | `verify_scan_integration.py` printed "expected 6" without ever asserting it -- exit 0 wasn't evidence of anything | Accepted on code inspection (matches exactly) | **Yes** -- now asserts the count, the exact case set (not just the count), and both conditions' scan-error counts; writes a versioned, timestamped summary instead of a fixed scratch path |

All 29 regression tests (18 original + 9 new `typed_rule` + 2 new acceptance-policy) pass. The
rewritten `verify_scan_integration.py` passes its own assertions: iterative complete_success = 6,
exact case set matches, raw scan_errors = 1, iterative scan_errors = 0.

**What this means for every number reported earlier in this diagnostic campaign** (the 5 live
mechanism-prompt trials, the original Item 2 audit): the AGGREGATE complete_success counts (6/24,
4/24, 5/24, etc.) are unaffected -- those were always read directly from `report()`'s
`complete_success` field, which was correct throughout. What was wrong was (a) the typed-rule
prototype nobody has used in a live run yet, so no reported model result used the broken
exclusion form, and (b) the Item 2 failure-category audit's PRESENTATION, which undercounted how
bad the early trials actually were by only showing "among accepted" numbers under an "all-24"
label. The corrected audit (re-run below) shows e.g. `mechanism_v1`'s `original_miss` at 12/24 --
far worse than the old presentation implied, though consistent with that trial's already-known
confounded-examples bug.

## 2026-10-12 follow-up update: a second independent review found further issues in the fixes above -- all confirmed, all fixed

`Bounded_Investigation_Followup_Review_20261012.md` reviewed the fixes from the update above and
found 5 more issues, none of which I had caught myself. Every one was independently re-verified
before accepting it, same discipline as the first round:

| # | Finding | Verified? | Fixed? |
|---|---|---|---|
| 1 | `audit_failure_categories.py`'s rewrite still mixed two different denominators in its "raw" hidden-stage output -- for `qwen3_mechanism_v1` it reported 19 under a label implying "accepted" when only 6 were truly `legacy_accepted`; separately, `original_miss` conflated "clean scan, genuinely not detected" (10/24) with "never got a clean scan to check at all" (2/24); separately, the acceptance gate was hardcoded to `legacy_accepted` regardless of the run's actual `--acceptance-policy` | **Yes** -- reproduced 19 vs 6 exactly, reproduced 10+2=12 exactly, confirmed the hardcoding by code inspection | **Yes** -- `acceptance_field_for()` now reads the run's own recorded policy; raw-stage output now reports `n_scanned_successfully` and `n_actually_accepted` as two explicitly distinct numbers, never one conflated label; `original_miss` split into `original_miss_clean`/`original_unevaluable` |
| 2 | `resolve_target_path()`'s TSX-staging integrity check (the previous round's own fix for finding 6 above) only actually ran on the FIRST call per case id per process -- a `_TSX_STAGE_CACHE` guard skipped the byte check on every subsequent call, contradicting the "verified on every call" claim in both the code comment and the first update's own summary table | **Yes** -- re-read the code, confirmed the `if cid not in _TSX_STAGE_CACHE` guard exists and does exactly this | **Yes** -- the cache dict and guard are removed entirely; every call now unconditionally re-reads and compares bytes, no process-lifetime shortcut |
| 3 | Item 5's redesigned probe spec had an internal contradiction (said the probe transform family must be "explicitly different" from the hidden families in one paragraph, then called it a "same-transform-FAMILY-but-different-instance signal" in a later paragraph) and never addressed that AST-isomorphism alone doesn't guarantee behavior preservation -- a rename can still break code that references the renamed identifier by string (`locals()`, `getattr`, `eval`, etc.), which an isomorphism check over `Name`/`arg` nodes cannot see | Accepted on the logic alone (no empirical test needed for the contradiction; the reflection concern was checked against how Python's `ast` module resolves bindings and confirmed as a real gap, not a hypothetical one) | **Yes** -- design text corrected to resolve the contradiction in favor of the "different family" requirement (the one that actually serves the no-leakage purpose); added an explicit reflection-construct exclusion filter (`locals`/`globals`/`getattr`/`setattr`/`vars`/`eval`/`exec`) as a probe-eligibility gate, with its exclusion rate to be recorded as a finding if large, not silently discarded |
| 4 | `verify_scan_integration.py`'s recorded `semgrep_version` came from a bare `subprocess.run(["--version"])` with no `env=` override, bypassing the project's own documented `semgrep_env()` PATH-prepending fix for pysemgrep's PATH-delegation bug (the same class of bug `diagnostic_v2.py` itself already guards against at its only other `--version` call site) | Did not reproduce a wrong version in the shell this was fixed in (got `1.177.0` correctly either way), but accepted the underlying risk as real and already documented elsewhere in this project | **Yes** -- now calls `dv2.semgrep_env(out)`, the same construction every real scan in this script already uses; rerun confirms identical PASSED output (complete_success = 6, same case set, same error counts) |
| 5 | `TypedRule.validate()` accepted `metadata` as any type with no check (e.g. a string), and `languages` passed as a tuple satisfied `isinstance(value, (list, tuple))` but produced YAML with a `!!python/tuple` tag that `yaml.safe_load()` cannot parse back | **Yes** -- reproduced both exactly: `metadata='not-a-dict'` passed validate() silently; `languages=('python',)` round-tripped to a YAML error "could not determine a constructor for the tag 'tag:yaml.org,2002:python/tuple'" | **Yes** -- `validate()` now rejects non-dict `metadata`; `to_dict()` now always emits `list(self.languages)` regardless of the input container type, so the serializer (not caller discipline) guarantees parseable output |

All 29 regression tests still pass after these fixes (`test_typed_rule.py` + `test_diagnostic_regressions.py`,
unchanged pass count -- these fixes didn't need new tests, since findings 1 and 2 are covered by
rerunning the existing audit/TSX code paths directly, and findings 4-5 were verified by direct
reproduction scripts rather than new permanent tests). `verify_scan_integration.py` re-run after its
fix: identical PASSED output. `typed_rule.py`'s own real-Semgrep validation check: all 4 reconstructed
candidates still PASS.

The reviewer separately flagged a new research finding (not a bug in this investigation's own code):
42/87 historically-accepted rules across the real diagnostic runs -- including all 19 of
`qwen3_v3`'s baseline accepted rules -- use the same sibling `pattern`+`pattern-not` exclusion form
now confirmed non-functional for exclusion (finding 1 of the first review round, above). This means
some unknown fraction of those 42 "accepted" rules may never have actually excluded anything via
their `pattern-not`, and would score identically if that clause were deleted -- a possible inflation
of historical accepted-rule counts unrelated to this investigation's own bugs. This has NOT been
investigated: it would require rewriting each of the 42 rules with correct `patterns:` composition
and re-running them through real Semgrep to see whether any of their historical TP/TN/FP/FN outcomes
actually change. Flagging it here, not acting on it -- it's new scope beyond the 5 bounded-investigation
items and needs an explicit decision on whether to pursue it before any work starts.

## 2026-10-12 round-3 update: a third review verified rounds 1-2's closures and found 2 further issues -- both confirmed, both fixed

`Bounded_Investigation_Round3_Review_20261012.md` independently re-verified every fix from both
earlier rounds (29 regression tests, the live TSX cache removal, the policy-aware auditor, the
`metadata`/`languages` typed-rule fixes, `verify_scan_integration.py`'s `semgrep_env()` fix) and
confirmed all of them closed -- no re-litigation needed there. It then found 2 further issues, both
independently reproduced before accepting:

| # | Finding | Verified? | Fixed? |
|---|---|---|---|
| 1 | `audit_failure_categories.py`'s `_is_target_error` was the only error classifier -- any error without a `path` key was counted as `rule_construction_error`, which folds `diagnostic_v2.py`'s own synthetic status-wrapper messages ("Semgrep exited with status N", "Semgrep did not scan every requested sample") into the rule-construction count even though they're not Semgrep's own report of a malformed rule | **Yes** -- reproduced the double-count with a synthetic fixture; separately checked every real retained episode across all 6 datasets for the actual co-occurrence (a path-error and a non-path-error in the same scan's errors list) and confirmed it never happens in retained data, so no historical `rule_construction_error`/`target_error` count is affected | **Yes** -- `_is_status_wrapper()` now recognizes the synthetic messages by content and excludes them from `rule_construction_error`; a new `unclassified_scan_error` category catches the case of a scan failing with ONLY status-wrapper messages (confirmed 0/24 on every real dataset -- never occurs, kept for forward safety on a future run) |
| 2 | Item 5's probe-design fix from round 2 only patched the "What this is NOT" paragraph's wording to say "different family" -- the Construction paragraph, which actually specifies the mechanism, still described renaming, the SAME family reserved for `variant_vulnerable_1`. Separately, even granting renaming, the AST-isomorphism check has no visibility into callers outside `vulnerable_function`/`patched_function`, so renaming a parameter can break an external keyword-caller the construction can't see or check | **Yes** -- reproduced exactly: `def probe(token): return token` has no reflection call (passes round 2's filter) and passes AST-isomorphism when its parameter is renamed to `tok`, but a keyword call `probe(token="unsafe")` elsewhere raises `TypeError` against the renamed version | **Yes** -- design now explicitly frames renaming-based probes as a WITHIN-family development signal rather than claiming a different family (the honest option, since inventing and validating a genuinely new transform family under time pressure would be exactly the kind of speculative mechanism this project avoids building before it's needed); probe renaming is restricted to purely local, non-parameter bindings, which removes the keyword-caller failure mode directly. Design-only, no code yet |

Re-ran the full regression suite after the auditor fix: 29/29 still pass. Re-ran
`audit_failure_categories.py` across all 6 real datasets after the fix: `rule_construction_error`
and `target_error` counts are byte-identical to before the fix on every dataset, and
`unclassified_scan_error` is 0/24 everywhere -- confirming directly, not just arguing, that this
fix changes no previously-reported number.

**Net effect on every number reported before this round**: unchanged, same as both earlier rounds
-- these are a classifier-precision fix (verified to not move any historical count) and a
design-text correction (no code exists yet to have produced a number). Item 3 remains not started.

## 2026-10-12: offline composition-ablation experiment on the 42 historical sibling-exclusion rules

Beyond the 5 bounded-investigation items: per the round-3 review's recommended protocol and the
user's explicit go-ahead, ran the proposed offline experiment on the 42 historically-accepted rules
(across all 6 real datasets) that use the sibling `pattern`+`pattern-not` form now confirmed
non-functional for exclusion. `pipeline/exclusion_composition_ablation.py` -- new script, not a
model call, no historical rule or result modified.

**Protocol followed** (all 5 points from the review): froze the input from the existing inventory
(`bounded_followup_artifacts_20261011T215946041546Z/historical_exclusion_inventory.json`,
sha256-recorded, re-summed to confirm 42 exactly); built a pure, pre-specified rewrite
(`rewrite_composition()`) that moves `pattern`/`pattern-inside`/`pattern-not`/`pattern-not-inside`
into one `patterns:` list, carrying every other field over byte-identical, rejecting (not
improvising on) any rule that doesn't match the expected shape; scanned every original/rewritten
pair under the identical pinned engine, TSX staging, and annotations every other scan in this
project uses; reported gained AND lost outcomes, not just reduced false positives; kept every run's
denominator at its real 24 requested cases, substituting only the ablated subset; labeled the whole
thing exploratory throughout.

**All 42 instances matched the pre-specified shape (0 rejected).** A sanity replay of every
original rule against the existing `environment.json`/`episode.json` on disk matched exactly
(0/42 mismatches) -- confirming the experiment's own scanning setup reproduces the historical
measurement faithfully before touching anything new.

**CORRECTED 2026-10-12, same day**, after a follow-up review (`Exclusion_Ablation_Review_20261012.md`)
found two real issues in the first pass of this experiment, both independently reproduced before
accepting:

1. **The "nesting artifact" framing for CASE-0063 was a misdiagnosis, not a separate bug.** The
   first pass treated wrapping `pattern`+`pattern-inside` in `patterns:` (no exclusion present) as
   an unrelated Semgrep composition quirk, and briefly "fixed" `typed_rule.py` to keep
   `pattern_inside` as a sibling whenever no exclusion was present, to avoid triggering it.
   Reproduced directly that this was backwards: a probe a positive-only check can't catch --
   `pattern-inside` naming a function that DOES NOT EXIST in the target file -- still matches as a
   sibling. A top-level sibling `pattern-inside` is **silently ignored** by Semgrep, never enforced;
   it only ever appeared to "work" because the base `pattern` alone was doing all the matching. The
   NESTED form is Semgrep's own documented required composition for `pattern-inside` to have any
   effect, and it correctly returns 0 for CASE-0063's named-function constraint because the real
   vulnerable code sits inside an ANONYMOUS function, not a named one -- the model's own rule has the
   wrong scope constraint, and the broken sibling form was masking that, exactly like CASE-0220 and
   CASE-0323 below. The brief `typed_rule.py` "fix" was reverted the same day (back to always
   composing `pattern_inside` via `patterns:`); the backwards regression test it had added
   (asserting a sibling form, i.e. the broken behavior) was replaced with a real behavioral test
   using both an in-scope and an out-of-scope example.
2. **The sole reported "FP improvement" was a compile failure, not a behavioral change.**
   `scan()` still returns a `samples` record on a failed scan (`scan_ok=False` -- the rule never
   ran, so `findings=[]`), and the first pass compared outcomes without checking `scan_ok` on either
   side. Confirmed directly: CASE-0184's rewritten rule has a genuine Java rule-parse error
   (`scan_ok=False`), and its trivial FN/TN defaults were counted as 2 hidden-TP losses and 1
   hidden-FP improvement that never behaviorally happened. Fixed: any instance where either scan
   failed is now marked unevaluable and excluded from the behavioral TP/FP transition tallies,
   reported as its own separate count instead -- it is NOT excluded from the all-instance
   complete_success accounting, where it correctly remains counted as the failure it already was
   in both arms (see "corrected results" below: this is why complete_success stays 0/9/33 unchanged
   even though the TP/FP tallies move).

**Corrected results** (summary.json:
`results/diagnostic_20261010/_exclusion_ablation_20261011T234010189193Z/`; the superseded first-pass
summary at `..._20261011T225111285041Z/` is left in place, not deleted, per this project's standing
practice of never silently erasing a retracted number):
- 42 instances, 19 distinct case ids (NOT independent -- the same 3 cases recur across runs; see
  below), 1 instance unevaluable (CASE-0184's compile failure, excluded from tallies).
- `complete_success`: 0 gained, 9 lost, 33 unchanged -- UNCHANGED from the first pass (CASE-0184 was
  already an E2E failure in both arms, so excluding it from outcome tallies doesn't move this count).
- Hidden-variant true positives (41 evaluable pairs): 0 gained, **20 lost** (not 22 -- 2 of the
  original 22 were CASE-0184's compile-failure artifact, now excluded).
- Hidden-negative false positives (41 evaluable pairs): **0 gained, 0 lost** -- the "one FP improved"
  claim is withdrawn; it was CASE-0184's compile failure, not a real behavioral change. No evidence
  in this dataset, in either direction, that the broken composition was hiding inflated or deflated
  false-positive counts.
- **All 9 complete_success losses trace to only 3 distinct rule_ids**: `vuln-phpldapadmin-dd6e9583`
  (CASE-0220, 4 instances), `vuln-ckeditor-oembed-plugin-10f6169e` (CASE-0323, 4 instances), and
  `vuln-jspdf-d8bb3b39` (CASE-0063, 1 instance) -- each reused across several runs. In CASE-0220 and
  CASE-0323, the model's own `pattern-not` is identical or near-identical to its own `pattern`, a
  self-cancelling exclusion. In CASE-0063, the model's `pattern-inside` names a function scope
  (`function $FUNC(...)`) that doesn't match the real anonymous-function structure of the vulnerable
  code. All three are the SAME category of defect: a model-authored constraint (an exclusion or a
  scope restriction) that the historical sibling-composition bug rendered inert, which is the only
  reason these 3 cases' rules "worked" at all.
- **Per-run complete_success under correct composition, same 24-case denominator as every
  historical report**: qwen3_v3 6->4, qwen3_mechanism_v1 4->4 (0 affected), qwen3_mechanism_v2
  5->4, qwen3_mechanism_v3 5->3, qwen3_mechanism_v4 6->3, qwen3_mechanism_v5 3->2 (unchanged from
  the first pass -- none of these per-run numbers involved CASE-0184).

**What this does NOT mean**: none of the historically-reported `complete_success` numbers were
WRONG. Every historical measurement correctly, faithfully executed the model's actual, literal rule
file through real Semgrep -- that is exactly what happened and exactly what was measured; there is
no retroactive correction to make to any already-published number. Enforcing the intended DSL can
legitimately improve fidelity to the authored rule (CASE-0063/CASE-0220/CASE-0323's "success"
depended on a model-authored logical error -- a self-cancelling exclusion, or a scope constraint
that doesn't match the real code -- that the old composition bug happened to mask) WHILE AT THE
SAME TIME still reducing measured `complete_success` -- both are true at once. **A lower future E2E
score on a prespecified task metric is still a real, reportable regression**; a correctly-composing
representation (e.g. `typed_rule.py`, or a future typed-representation arm in the 2x2 comparison)
scoring lower than the broken baseline on cases like these does not get explained away by this
mechanism -- the mechanism explains WHY the score moved, it does not redefine a lower score as not
a regression. (An earlier draft of this paragraph said a lower score "is not evidence the typed
representation is worse" -- that framing is retracted; it contradicted the sentence that followed
it, and a round-3-style review correctly flagged the inconsistency.)

**The same underlying defect -- a silently-ignored sibling constraint -- was also found in
`typed_rule.py` itself**, as a direct byproduct of running this experiment (not from any review,
from using `typed_rule.py`'s own logic as an input elsewhere): its `to_dict()` routed
`pattern_inside` through the `patterns:` wrapper whenever it was set, even with NO exclusion present
at all -- reproduced directly that `TypedRule` itself reproduces CASE-0063's exact failure. This was
briefly (mis-)"fixed" by keeping `pattern_inside` as a sibling -- i.e. briefly reintroducing the very
ignored-constraint bug this whole investigation exists to eliminate -- then reverted once the
CASE-0063 misdiagnosis above was corrected: `pattern_inside` is now ALWAYS composed via `patterns:`,
same as any exclusion key, since the sibling form is confirmed to silently ignore it rather than
enforce it. A new permanent regression test pair (`test_pattern_inside_actually_restricts_scope` and
`test_bare_pattern_inside_sibling_is_silently_ignored_not_enforced`, using an in-scope/out-of-scope
fixture, not a positive-only one) guards against this specific class of regression recurring. Full
suite: 31/31 pass.

**Caveat on unit of analysis, stated directly** (per the review's protocol point 4): this is an
ablation on ALREADY-ACCEPTED rules only. It says nothing about how many REJECTED rules might have
been accepted under correct composition, and nothing about a different repair-loop policy. These
are fixed-rule rewrites, not generations under a typed prompt -- a model given a different output
contract and compiler/visible feedback may produce different clauses entirely; this experiment
cannot predict a future typed-representation arm's actual score, only explain a mechanism observed
in this one. 19 distinct case ids are touched across 42 instances; only 3 distinct cases
(CASE-0063, CASE-0220, CASE-0323) account for every single complete_success change found -- the
other 16 distinct cases' rules are untouched by this fix, consistent with "most of these rules'
exclusions, even though inert under the historical bug, happened not to need to actually exclude
anything in practice."

## Item 3 — done, with the independence caveat above genuinely applying (best-effort self-check, not independent review)

**EXPANDED 2026-10-12, same day**, from a 6-of-24 manual spot-check to full, objective coverage of
all 24 diagnostic cases, per the user's explicit go-ahead to do Item 3's best-effort review before
drafting the frozen 2x2 protocol.

**Reference-rule precision, now checked exhaustively, not spot-checked**: ran all 24
`benchmark/diagnostic_20261010/reference_rules/v1/*.yml` rules through real pinned Semgrep against
their own full 6-sample bundle (`results/diagnostic_20261010/_item3_reference_rule_check/`) --
objective, scriptable, and exhaustive rather than a manual read of "most of the 24." Two findings:

1. **Zero false negatives anywhere.** Every one of the 24 reference rules correctly detects
   `original_vulnerable`, `variant_vulnerable_1`, AND `variant_vulnerable_2`. No rule misses its own
   case's vulnerability or either hidden-variant transform.
2. **9 of 24 (37.5%) have a demonstrated precision gap** -- the rule fires on at least one sample
   that should be negative (`original_patched`, `variant_safe`, or `benign_lookalike`) within its
   own bundle. This is MORE than triple the 3 found by the earlier manual spot-check (`CASE-0193`,
   `CASE-0184`, `CASE-0116`); the additional 6 (`CASE-0046`, `CASE-0063`, `CASE-0163`, `CASE-0235`,
   `CASE-0238`, `CASE-0339`) were not caught by reading pattern text alone. Full list, with the
   specific mechanism for each (inspected individually, not just counted):
   - `CASE-0046`: `pattern: '$CONFIG.update({$KEY: $VALUE})'` has NO constraint tied to the actual
     vulnerability (blacklist- vs whitelist-based key filtering) at all -- it matches any
     single-key dict `.update()` call. Fires on `original_patched` because the patched code still
     calls `.update({key: value})`, just inside a whitelist-gated branch instead of a
     blacklist-gated one. The weakest-constrained rule found.
   - `CASE-0063`: `pattern-regex` matching the literal ambiguous-regex source text. Fires on
     `benign_lookalike` because that file legitimately contains the exact same regex, applied to a
     different (non-attacker-controlled) string -- a syntactic pattern cannot distinguish execution
     context/reachability, a known, expected limitation for this class of signature (consistent
     with `CASE-0134`'s own documented caveat: "data reachability... [is] not established by this
     signature").
   - `CASE-0116`: bare `new TSocket($SOCKET)` constructor call, zero constraint on
     verification/certificate options -- matches any TSocket construction, secure or not (already
     known from the first pass).
   - `CASE-0163`: the pattern matches the `['clone', $FLAG, ...]` array shape but never checks
     whether `$FLAG` is actually the `--` option terminator -- the one thing the vulnerability is
     about. Fires on `variant_safe` because the safe version constructs a same-shaped array that
     happens to still satisfy the pattern.
   - `CASE-0184`/`CASE-0193`: bare `File.createTempFile(...)` / 
     `DocumentBuilderFactory.newInstance().newDocumentBuilder()` chains, zero constraints (already
     known from the first pass).
   - `CASE-0235`: the pattern's `.replace(...)` argument is an unconstrained `...` wildcard, so it
     matches regardless of what the replace actually does -- fires on `original_patched` because
     the patch changed the regex passed to `.replace()`, not the surrounding call shape the pattern
     actually checks.
   - `CASE-0238`: uses this session's own hard-won correct `patterns:`-nested exclusion form (not
     the broken sibling form) -- but the `pattern-not`'s `escapeFormulae: true` check doesn't cover
     every way to safely handle this, so it still fires on `variant_safe` and `benign_lookalike`,
     both legitimately-safe uses the rule's one specific exception doesn't anticipate.
   - `CASE-0339`: `pattern-regex` on literal source text containing `.replace('/[<\{\}]/g', '')` --
     fires on both `original_patched` and `variant_safe` because that exact literal string (the bug
     is treating a regex as a plain string argument) still appears in both, just reached from
     `stripMarkers()`'s call site, not the vulnerability itself -- see transformation-semantics
     check below for this exact helper-extraction pattern.

   None of this changes the project's standing position that these 24 are "diagnostic feasibility
   aids, not blind expert performance or a generalization ceiling" -- it substantially deepens the
   evidence for that position with a complete, not partial, count.

**Transformation semantics, CORRECTED 2026-10-12 (same day) after a follow-up review
(`Controlled_2x2_Protocol_Review_20261012.md`) found the first pass's coverage claim overclaimed.**
The first pass directly diffed 13/24 cases and, for the other 11, reasoned from each one's
reference rule having zero demonstrated false positives on its own bundle, calling that "non-
confounded evidence of genuine preservation." The review correctly rejected that inference: a rule
correctly rejecting three CHOSEN negative samples does not establish that a transformed positive
retains attacker control, reachability, the relevant data/control flow, or the vulnerability's
actual security consequence -- it only establishes syntactic re-matching, exactly the sample-level-
fit limitation the Research Direction itself already names for these assistant-authored rules.
Accepted this correction directly -- it is logically sound and was not something the first pass had
independently verified -- and completed the remaining 11 direct source-based reviews rather than
settling for the weaker rule-based inference:

Directly diffed `vulnerable_source` against `variant_vulnerable_02` for all 11 remaining cases
(`CASE-0323`, `0276`, `0221`, `0136`, `0340`, `0124`, `0222`, `0171`, `0298`, `0231`, `0081`),
checking in each case whether the vulnerable call/expression itself is preserved verbatim, whether
it is reached from the same control-flow position (not gated behind a new, narrower condition), and
whether any surrounding rewrite changes the actual trust boundary or data flow rather than just the
syntax. All 11 confirmed genuine:
- `CASE-0323` (CKEditor `allowedContent` wildcard config): **CORRECTED 2026-10-12** -- the
  `allowedContent` SUBOBJECT (containing the wildcard `attributes: '*'` entries) is extracted
  verbatim into a variable; the surrounding `editor.widgets.add('oembed', {draggable, mask, dialog,
  allowedContent: embedRules})` call keeps every other field inline. Not "the entire config object,"
  as an earlier draft of this entry said -- only the vulnerable subobject moves.
- `CASE-0276`/`0221`/`0171`/`0231`/`0298`: the same helper-extraction pattern as the 13 already
  checked -- the exact vulnerable call (`_io.open_code`, `new DefaultHttpHeaders(false)`,
  `url.replaceFirst(...)`, `os.path.join(user_dir, filename)`, the raw `${src}` HTML-attribute
  interpolation) is moved verbatim into a new private helper, called from the same site with the
  same arguments and the same reachability -- no new guard condition, no changed input.
- `CASE-0136`: **CORRECTED 2026-10-12** -- the vulnerable `File.createTempFile(_prefix, _suffix)`
  call itself stays at its ORIGINAL call site, unmoved; only its RETURN VALUE is passed through a
  new `registerForCleanup(...)` wrapper. Not "moved into a new private helper," as this entry
  previously generalized across all 7 of this group -- CASE-0136 is the one exception where the
  sink itself never relocates, which if anything makes preservation even more direct to verify.
- `CASE-0340`: `execSync(...)` with the same template-string interpolation of `adb`/`applicationId`
  moved into `runPidof()`, called with the same arguments from the same site.
- `CASE-0124`: **re-described for precision** -- this is a STRING-CONSTRUCTION change, not a
  control-flow rewrite (no branching changes at all): the shell command string is built via
  `" ".join([...])` instead of an f-string, producing the byte-identical string for the same
  inputs, and the same untrusted `requirements_path`/`os.getcwd()` values still reach the same
  `os.system(command)` sink immediately after, unchanged.
- `CASE-0222`: **CORRECTED 2026-10-12** after `Controlled_2x2_Protocol_Followup_20261012.md`
  reproduced a real environmental qualification. `requests.post(..., verify=False)` passes `False`
  explicitly at the call site, which Requests' own `merge_environment_settings` never overrides
  (the override path only triggers when `verify` is `True` or `None`). The restructured
  `session.verify = False; session.post(...)` calls `post()` WITHOUT an explicit `verify=` kwarg,
  so `verify` defaults to `None` at that call -- which DOES trigger the override path: if
  `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE` is set in the environment, it takes precedence over
  `session.verify = False` (confirmed directly by reading Requests 2.34.2's actual
  `merge_environment_settings`/`merge_setting` source). So the two forms are only equivalent when
  neither variable is set -- **conditional preservation, not unconditional equivalence**, as an
  earlier draft of this entry claimed. This does not change the complete_success/precision-gap
  numbers (the diagnostic's own CI/scan environment does not set either variable) and no sample or
  label needs changing -- it is a precision correction to this review's own wording, recorded here
  per this project's standing discipline of never letting a convenient simplification stand once a
  real counterexample is found.
- `CASE-0081`: the mutable for-loop is rewritten as a `.reduce()` -- the one genuine control-flow
  rewrite in this group -- but the actual vulnerable
  expression (`` `${key}="${value}"` ``, unescaped interpolation of `value` into the env-file line)
  is preserved byte-for-byte inside the new `.reduce()` callback, with the same per-key
  test-then-replace-or-append logic -- a genuine control-flow rewrite that does NOT change the
  vulnerable expression or its reachability.

**Corrected characterization of what Item 3 now covers** (per the review's recommended framing,
adopted directly): **24/24** reference-rule behavior audited by real execution (the precision-gap
scan); **24/24** direct, source-based semantic review of the restructured variant (13 from the
first pass + 11 completed just now) -- not 13/24 with 11/24 inferred from rule behavior, as the
first pass incorrectly characterized it. What this is still NOT: a genuinely independent review
(the caveat on this item, stated since it was first opened, continues to apply in full -- this is
the same agent that built the diagnostic doing the most rigorous self-check it can, not an
independent adjudicator), and not a check of all 150 eligible cases outside the diagnostic subset
(never in scope for this item, which the Research Direction scoped to "the 24 reference rules").

## Item 1 — done

`pipeline/diagnostic_v2.py` changes:
- `load_merged_ann()`: Finding-1's original ranges + the 2026-10-11 v2-additive ranges, merged
  (a finding counts as correct-location if it falls in EITHER range -- additive only, never narrower).
- `resolve_target_path()`: checks the dataset-wide condition (upstream `changed_file` ends `.tsx`,
  stored sample ends `.ts`) rather than hardcoding `CASE-0298`; stages byte-identical `.tsx` copies
  at `results/_diagnostic_tsx_stage/<case_id>/` (stable, outside `benchmark/cases/`, created once).
- `scan()`'s location check now handles a list of candidate ranges per sample instead of one.
- `report()` now reports BOTH `legacy_accepted`-gated and `visible_correct`-gated (location-aware)
  denominators side by side for every hidden-sample metric, rather than only the legacy gate --
  historical field names/values unchanged, new `*_corrected` fields added alongside.

**Verified**: `pipeline/verify_scan_integration.py` (new, kept) replays `qwen3_v3`'s already-saved
rule files (no new inference) through the updated `scan()`/`report()` and reproduces exactly 6/24
complete_success -- matching `rescore_qwen3_v3_corrected.py`'s independent result exactly. Also shows
the expected incremental improvement baked in natively: raw `scan_errors` drops from 2 to 1 (CASE-0298
now scans cleanly via the built-in `.tsx` staging, same outcome the standalone replay already found).

The regression suite caught a real compatibility break during this work: `pipeline/tests/
test_diagnostic_regressions.py` constructed test annotations in the old single-tuple-per-key format;
fixed to the new list-of-ranges format (3 tests were failing, now pass). All 18 regression tests pass.

Every future diagnostic run (and any rescoring of an already-completed one) now gets both fixes
automatically, without a separate rescore pass -- consistent with the Research Direction's "apply
the same protocol to every newly compared condition."

**CORRECTED 2026-10-12, two more real gaps found by independent review and fixed**:

1. **The generation/repair loop's actual stopping decision still ignored the location-aware gate.**
   `report()`'s `*_corrected` fields only ever changed aggregate reporting -- `run_model_case()`
   itself still checked `evaluation["legacy_accepted"]` to decide whether to accept a rule and stop
   retrying. Reproduced directly: a mocked evaluation with `legacy_accepted=True,
   visible_correct=False` made the loop accept after exactly one call and never try again, meaning
   every wrong-location "win" (confirmed present in every single trial, e.g. `CASE-0081`,
   `CASE-0184`) was never given a real chance at repair. Fixed with a new, explicitly-named,
   opt-in `--acceptance-policy` flag (`legacy` default, byte-identical to every already-completed
   run; `corrected` requires `visible_correct` and feeds back specific wrong-location repair
   guidance instead of silently taking the false win). Two new regression tests
   (`test_acceptance_policy_controls_wrong_location_stopping`) confirm `legacy` reproduces the
   historical 1-attempt false-accept exactly, and `corrected` retries all 3 attempts without ever
   accepting the same wrong-location rule.
2. **The `.tsx` staging cache trusted an existing directory without checking its bytes.** A stale or
   partially-written stage (e.g. from an interrupted prior run) would have been served forever once
   present. Fixed: every call now verifies each staged file's bytes against the frozen source and
   repairs any mismatch, rather than trusting existence alone. Also added the annotation files'
   (`variant_vulnerable_lines.jsonl` + the v2 additions) sha256 to `environment.json`'s provenance,
   since the existing code-hash tracking couldn't catch someone editing the location data itself
   without touching any `.py` file.

`pipeline/verify_scan_integration.py` was also rewritten: it previously printed "(expected 6)"
without ever asserting it, so a regression could have passed with exit code 0. It now asserts the
exact complete_success count AND the exact set of successful case IDs (not just the count, which
could hide a same-total-different-cases swap) AND both conditions' scan-error counts, writing a
versioned, timestamped summary rather than reusing one fixed scratch path. Reran after all the above
fixes: still passes all assertions (6/24, exact case set, raw scan_errors=1, iterative scan_errors=0).

## Item 2 — done

`pipeline/audit_failure_categories.py` (new): categorizes every saved case into all applicable
failure categories (not just the first found) -- construction_error, wrong_original_location,
patched_code_fp, renamed_miss, structural_miss, safe_benign_fp -- reporting both the all-24-requested
and conditional-among-scan_ok==True denominators. Found and fixed a real bug in the first draft: the
conditional denominator initially included construction-error cases (which have scan_ok=False by
definition) in its own base count.

Ran across all 6 real diagnostic datasets (`qwen3_v1`/`v2` are the earlier failed-key attempts --
confirmed every case has `raw=None, iterative=None`, nothing to categorize, excluded). Iterative
condition, all-24-requested denominator:

| Dataset | construction_error | wrong_location | patched_fp | renamed_miss | **structural_miss** | **safe_benign_fp** |
|---|---:|---:|---:|---:|---:|---:|
| `qwen3_v3` (baseline) | 0 | 1 | 0 | 1 | **7** | **7** |
| `mechanism_v1` | 0 | 1 | 0 | 2 | **4** | **4** |
| `mechanism_v2` | 0 | 2 | 0 | 2 | **7** | **4** |
| `mechanism_v3` | 0 | 2 | 0 | 2 | **6** | **4** |
| `mechanism_v4` | 0 | 2 | 0 | 3 | **5** | **5** |
| `mechanism_v5` | 0 | 1 | 0 | 2 | **4** | **6** |

**Finding**: `structural_miss` (failure to generalize to the restructured-logic hidden variant) and
`safe_benign_fp` (false positives on the safe/benign negative samples) are the two dominant failure
categories in EVERY one of the 6 datasets, by a wide margin over `wrong_original_location` (1-2),
`renamed_miss` (1-3), `patched_code_fp` (0), and `construction_error` (0, by construction -- only
accepted rules reach the iterative condition). This holds essentially unchanged across every prompt
variant tried, including the ones that changed examples, added quoting guidance, or added composite-
operator guidance -- directly consistent with the earlier gpt-4o-parity finding that the bottleneck
is model/task capability (generalizing past literal code shape, avoiding false positives on
lookalike-but-safe code), not prompt wording. None of the prompt interventions moved either dominant
category meaningfully in either direction.

**SUPERSEDED 2026-10-12**: the table above is accurate as far as it goes, but its "all-24-requested"
label was misleading -- independent review found that for the ITERATIVE condition, every category
could only ever count cases that reached an accepted-final evaluation, so `construction_error: 0`
and the other low numbers reflected "among accepted cases" dressed up as "of 24," silently excluding
57/144 episodes across the 6 datasets that never got an iterative evaluation at all. `structural_miss`
and `safe_benign_fp` being dominant AMONG ACCEPTED CASES is still true and still correctly computed
(verified independently by the reviewer too) -- what changes is that this can no longer be read as
"the dominant cause of failure overall," since most non-accepted cases never even reached the stage
these categories describe.

`pipeline/audit_failure_categories.py` was rewritten to walk the retained attempt records (not just
the final accepted evaluation), producing a genuine VISIBLE-STAGE audit covering all 24 requested
episodes, with the hidden-stage categories kept as an explicitly-labeled conditional analysis:

| Dataset | never_parsed | rule_construction_error | target_error | **original_miss** | wrong_location | patched_fp | never_accepted |
|---|---:|---:|---:|---:|---:|---:|---:|
| `qwen3_v3` (baseline) | 0 | 2 | 1 | **5** | 1 | 3 | 5 |
| `mechanism_v1` | 1 | 2 | 1 | **12** | 1 | 1 | 13 |
| `mechanism_v2` | 1 | 3 | 1 | **8** | 2 | 2 | 9 |
| `mechanism_v3` | 2 | 2 | 1 | **9** | 2 | 2 | 10 |
| `mechanism_v4` | 0 | 3 | 1 | **7** | 2 | 3 | 9 |
| `mechanism_v5` | 0 | 10 | 0 | **9** | 2 | 2 | 11 |

(`original_miss` = the vulnerable construct was never detected in ANY of the 3 attempts, the
visible-stage analogue of `structural_miss` -- the model's pattern never even matched the real
construct at all, a more fundamental failure than "detected but wrong-location" or "detected but
also false-positives the patch.") This is a materially worse and more honest picture than the old
table implied, especially for `mechanism_v1` (12/24 never even detected the vulnerability visibly,
not the "4/24 structural_miss among the lucky 11 that got accepted" the old table suggested) and
`mechanism_v5` (10/24 rule construction errors -- consistent with the confirmed composition-guidance
regression already logged in `Correction_Log.md`, now visible in the right denominator).

The HIDDEN-stage conditional numbers (renamed_miss/structural_miss/safe_benign_fp among cases that
DID reach that stage) are unchanged from the original table and remain correctly computed -- see the
rewritten script's own output for the full per-dataset conditional breakdown.

## Item 4 — done, then corrected 2026-10-12 after an independent review found a real behavioral bug

`pipeline/typed_rule.py` (new): a `TypedRule` dataclass + `to_semgrep_yaml()` deterministic
serializer (built on real `yaml.dump()`, never hand-formatted strings). The model would emit this
simpler, structurally-constrained form; this module -- not the model -- assembles the final YAML.

**Validated against the REAL pinned Semgrep compiler** (`semgrep --validate`, not just offline
`yaml.safe_load()` -- the Research Direction's explicit bar: "compiling examples alone does not
establish semantic correctness"), using reconstructions of the actual confirmed malformed
candidates:

| Real failure (case, run) | Mechanism | Result under TypedRule |
|---|---|---|
| `CASE-0221` (`qwen3_mechanism_v5`) | Bare strings under `pattern-either` instead of `{pattern: ...}` | **PASS** -- structurally impossible, always wrapped |
| `CASE-0276` (`qwen3_mechanism_v4`) | `pattern-either` + sibling `pattern-not` doesn't compose (confirmed via isolated test) | **PASS** -- always nested in one `patterns:` list together |
| `CASE-0238` (`qwen3_mechanism_v1`-`v4`) | Unquoted value with its own embedded `key: value` breaks YAML | **PASS** -- `yaml.dump()` handles all quoting |
| `CASE-0231` (`qwen3_mechanism_v5`) | Two mutually exclusive top-level operators (`pattern-either` + `patterns`) | **PASS** -- `validate()` raises before serialization is even attempted |
| (multi-rule output) | More than one rule under `rules:` | **PASS** -- always exactly one, by construction |
| `CASE-0222` (`qwen3_mechanism_v1`, real accepted rule) | `pattern` + 2 `pattern-not` + `pattern-inside`, all combined | **PASS** -- extended `pattern_not` to a list after finding this real need |

**Expressiveness check, not just a claim**: scanned all 87 real accepted rules across every one of
the 6 diagnostic datasets for every Semgrep key ever actually used. Found and fixed one real gap
(`pattern_not` needed to be a list, not a single string -- `CASE-0222`/`CASE-0184`/`CASE-0193`
legitimately need 2-3 exclusions). **One honest, remaining restriction, reported rather than
papered over**: `CASE-0323` and `CASE-0173` (in `v2`/`v3`) use two *bare* `pattern:` entries ANDed
via `patterns:`, which `TypedRule` cannot express (only one `pattern` field). Checked whether this
is a real need: in `CASE-0323`, the second pattern (`attributes: $ATTRS`) is a strict
generalization of the first (`attributes: "*"`) -- ANDing them is logically equivalent to the first
alone, so this looks like redundant/accidental duplication, not genuine AND semantics the model
intended. Deliberately not added to `TypedRule`'s vocabulary on that basis, but flagged here as a
real, known restriction rather than silently dropped.

This is a syntax/structure-layer fix only -- it cannot and does not claim to fix semantic mistakes
(the model can still misidentify the vulnerable construct). It directly targets `construction_error`
and the syntax-level contributors buried inside `structural_miss`/`renamed_miss` (a model whose
rule never even executes due to a structural mistake can't possibly generalize), not the dominant
`structural_miss`/`safe_benign_fp` categories found in Item 2, which are about WHAT the rule should
match, not HOW to write it syntactically.

**CORRECTED 2026-10-12**: an independent review reproduced a real behavioral bug in the "simple
case" above -- a rule with top-level sibling `pattern: foo($X)` / `pattern-not: foo("safe")`
**matched both** `foo("unsafe")` and `foo("safe")` under real pinned-Semgrep execution, despite
passing `semgrep --validate` cleanly (confirmed directly: validate checks schema, never behavior).
Every real historical rule I'd cited as precedent for this form (e.g. `CASE-0124`) happened to use
a `pattern-not` for a construct totally unrelated to the main pattern, so the exclusion was never
actually exercised -- I mistook "this rule was historically accepted" for "this composition form
works," which it doesn't. Fixed: ANY `pattern_not`, even exactly one, is now always composed inside
`patterns:`; there is no sibling shortcut any more. Reconfirmed with the real compiler: the fixed
form matches only line 1 (unsafe). A permanent executable regression test
(`pipeline/tests/test_typed_rule.py`) now runs real target files through real Semgrep and checks
actual match behavior, specifically so a schema-only check can never again stand in for this.

Also fixed in the same pass, both independently reproduced before accepting: `validate()` had no
real runtime type checking (`pattern_either="foo()"`, a bare string, was silently accepted and
iterated character-by-character into 5 single-character "alternatives"; `pattern_either=[]` was
accepted as if non-empty; a taint rule's `pattern_not` was silently dropped by `to_dict()` rather
than rejected). `validate()` now checks real types/shapes for every field and raises on every one
of these instead of silently misbehaving or dropping data.

## Item 5 — design only, not implemented or run

Spec for the "development probe" factor (Research_Direction_20261011.md's Condition C/D: "Original
pair plus separate development probes"), scoped so it can be reviewed/critiqued before any code or
inference spend.

**REVISED 2026-10-12** after an independent review found the original design circular: "discarding a
probe because the baseline rule fails it would discard precisely the valid examples that might
expose poor generalization... A baseline rule passing the original pair has not established
generalization -- the present research is testing exactly that limitation." Using the thing-under-
test as the oracle for whether a test case counts is backwards. The review also flagged that a
"fixed substitution table" rename is not automatically semantics-preserving (it can rename a string
literal, an attribute, or a reflected name that merely shares text with the target identifier), and
that independent construction doesn't make a leakage-impossibility claim valid -- it reduces risk,
it doesn't prove zero overlap. Both points are accepted; neither was independently verified before
the original wording was written, which is exactly the standard this project otherwise holds to.

**Construction, from permitted information only, AST-aware (REVISED again 2026-10-12, see point 3
below)**: `PatchInfo` carries `vulnerable_function`/`patched_function` (full bodies, not diff
lines). A probe renames identifiers via a scope-binding-aware AST transform (e.g. Python's `ast`
module rewriting only `Name` nodes resolved to the same LOCAL binding, not a blind find-replace
over source text) -- this avoids renaming a string literal or attribute that merely shares the
target's spelling. **Function parameters (`arg` nodes) and anything else part of the function's
externally-visible signature are never renamed** -- only bindings that are purely local to the
function body (local variables assigned and used only inside it) are eligible. This is narrower
than "rename any identifier," specifically to close a correctness gap found 2026-10-12 (point 3
below): renaming a parameter can break a caller that invokes the function with that parameter as a
keyword argument, and the probe construction has no visibility into callers outside
`vulnerable_function`/`patched_function` to check for that.

This construction is explicitly a WITHIN-FAMILY development signal, not a different-family one --
see point 3 below for why that's now the stated design rather than something to apologize for.

**Independent semantic check, NOT using any rule (baseline or candidate) as the oracle**: validate
the probe by (1) confirming the transformed code still parses as valid source in the target
language, and (2) an AST-isomorphism check against the original -- the transformed tree must be
structurally identical to `vulnerable_function`/`patched_function` except at the renamed identifier
nodes, confirmed by walking both trees in parallel. This never runs ANY Semgrep rule to decide
validity, so it cannot be biased toward probes a particular rule already happens to handle. Running
the baseline rule against an already-AST-validated probe can still be recorded as DIAGNOSTIC
evidence (e.g. "the baseline also fails this probe," which is itself informative) -- but it is never
the accept/reject gate for whether the probe is used.

**Firewalling**: the probe pair is a NEW, probe-specific pair of files, stored under a clearly
separate path (e.g. `_dev_probes/<case_id>/`), never written into or read from `benchmark/cases/`.
Only conditions C and D (per the 2x2 design) ever see it; conditions A and B's prompt/repair-loop
code path must not import or reference the probe module at all, not just "not call it" -- so a
future refactor can't accidentally wire it into every condition by mistake.

**Feedback mechanism**: fed into the REPAIR step only (after a rule has already been generated and
validated against the real visible pair), as additional text: "Your rule must also correctly handle
this additional test case: <probe vulnerable snippet> (expected: detected), <probe patched snippet>
(expected: not detected)." If the current rule already gets the probe right, no extra feedback is
added -- the probe is a check, not a mandatory prompt addition every round.

**What this is NOT**: not a substitute for the real held-out `variant_vulnerable_1/2`, and not a
different-instance copy of either -- each probe is freshly constructed from
`vulnerable_function`/`patched_function` with its own independent renaming, never derived from or
compared against the actual `variant_vulnerable_1` file. It tests Research Question 3 ("does
additional development-only behavioral feedback improve held-out complete success"), but see point
3 below for the now-narrower claim this specific construction can actually support. Its own probes
must never be confused with or substituted for the real hidden evaluation.

**REVISED again 2026-10-12** (follow-up review, both points independently reproduced before this
edit):

1. **This paragraph previously said the opposite of the Construction section above.** It called the
   probe signal "same-transform-FAMILY-but-different-instance," directly contradicting the
   Construction section's requirement that the probe family be "explicitly different from (not a
   close variant of)" the hidden families. The Construction section's requirement is the one that
   actually serves the design's purpose -- if the probe used the SAME family as `variant_vulnerable_1`
   (renaming), repair feedback built from it would be training the model directly against a weaker
   copy of the exact transform the hidden evaluation measures, which risks the reported "probe
   improves held-out success" result being driven by narrow overfitting to the renaming schema
   itself rather than genuine generalization -- precisely the confound Research Question 3 is
   supposed to rule out. This paragraph was wrong and is corrected above; the Construction section
   was never changed.

2. **AST-isomorphism is necessary but not sufficient for behavior preservation**, and the design as
   written did not say so. A structurally-isomorphic rename can still change behavior when the
   renamed identifier is also referenced outside the AST's own name-resolution -- e.g. renaming a
   parameter bound to `token` to `tok` leaves `locals()["token"]`, `globals()["token"]`,
   `getattr(obj, "token")`/`setattr(obj, "token", ...)`, or an `eval`/`exec` call containing the
   literal string `"token"` silently broken, even though the transformed tree is isomorphic to the
   original at every `Name`/`arg` node. The isomorphism check cannot see this because the mismatch
   lives in a string literal, not an identifier node. Fix: before accepting a candidate function for
   probe construction, scan its AST for any use of `locals`, `globals`, `getattr`, `setattr`,
   `vars`, `eval`, or `exec` (as a `Call` whose `func` resolves to that name) and exclude the
   function from probe eligibility if found, rather than attempting to also rename matching string
   literals (which would itself need a further correctness argument this design is not prepared to
   make). This is a real restriction on which functions can get a probe at all, not just a caveat --
   it should be implemented as an eligibility filter in the same pass as the AST-isomorphism check,
   with the exclusion rate recorded (if a large fraction of cases get excluded, that is itself a
   finding worth reporting, not silently discarded).

**REVISED a third time, 2026-10-12** (round-3 review, both points independently reproduced before
this edit):

3. **The immediately-preceding fix (point 1 above) was itself incomplete.** It corrected the "What
   this is NOT" paragraph's wording to say "different family," but never changed the Construction
   paragraph, which still specified renaming -- the exact family reserved for `variant_vulnerable_1`
   -- as the probe's actual mechanism. Saying "different family" in one place while the only
   specified construction is the SAME family as a reserved hidden transform does not make it a
   different family; it just moves the contradiction one paragraph over. Separately, even granting
   renaming as the mechanism, the AST-isomorphism check only guarantees structural equivalence at
   `Name`/`arg` nodes within the function body -- it says nothing about callers outside that body.
   Reproduced directly: `def probe(token): return token` has no reflection call, passes the
   reflection-exclusion filter from point 2, and passes AST-isomorphism when its parameter is
   renamed to `tok`; but a caller elsewhere invoking `probe(token="unsafe")` (a keyword call,
   invisible to the probe construction since only `vulnerable_function`/`patched_function` are
   available, not the whole codebase) raises `TypeError` against the renamed version. The
   isomorphism check cannot see this because the break lives in a caller the construction never
   has access to, not in the transformed function itself.

   Two real options were available: invent and validate an actual different-family transformation
   under time pressure, or be honest that renaming-based probes are a WITHIN-family development
   signal and scope the claim accordingly -- "within-family development is not automatically test
   leakage; it changes the generalization claim that can be supported" (the review's own framing,
   accepted as correct). Took the second option, since inventing an unvalidated new transform family
   right now would be exactly the kind of speculative mechanism this project avoids building before
   it's actually needed. Fixed: the Construction section is now explicit that probes use the SAME
   renaming family as `variant_vulnerable_1`, just a freshly-constructed, independent instance of it
   (never the real hidden file, never compared against it) -- so Research Question 3 as testable by
   this specific construction is narrower than originally framed: "does feedback from an additional,
   independently-renamed development instance improve held-out complete success," not "does feedback
   from a genuinely different transform family generalize." If a true different-family probe is
   wanted later, it needs its own design pass, not a label change on this one. Separately, to close
   the keyword-caller gap directly: probe renaming is now restricted to purely local bindings only
   (never function parameters / `arg` nodes, i.e. never anything part of the externally-visible
   signature), which removes the specific failure mode reproduced above without needing visibility
   into callers the construction doesn't have.

This has NOT been implemented or run -- it requires new engineering (the mechanical transform
generator including the reflection-exclusion filter above, the firewalled storage path, wiring into
the repair loop) and any live test of it needs new inference, which is explicitly gated behind the
user's decision on whether to proceed to the larger controlled comparison at all.

## 2026-10-12: Condition B implemented -- typed-JSON construction mode, offline-tested, no live inference yet

Per the user's explicit go-ahead to start implementing Condition B
(`Controlled_2x2_Protocol_Draft_20261012.md` §4), built the new output-contract path and exercised
it offline, per `Protocol_Review_Closure_20261012.md`'s concrete next-implementation-scope list.
**No model calls were made; no A/B pilot was run.**

**What was built**, as a separately-named construction mode, never touching condition A's existing
behavior:
- `autogrep/config.py`: new `Config.construction_mode` field, default `"original_prompt"` (every
  historical/existing caller's behavior, byte-unchanged) with a new `"typed_json"` value for
  condition B.
- `autogrep/llm_client.py`: `generate_rule()` now dispatches on `construction_mode` FIRST, returning
  early into a new `_generate_rule_typed_json()` method when set to `"typed_json"` -- the original
  YAML-generation body below that check is untouched. The new path adds:
  `_build_prompt_typed_json()` (same patch context -- repo/commit/diff -- as `autogrep_default`,
  but asks for a single JSON object matching `TypedRule`'s field names and never mentions Semgrep's
  operator-composition syntax at all, since the model doesn't need to get `patterns:`/`pattern-not`/
  `pattern-inside` nesting right -- `TypedRule.to_dict()` does that deterministically);
  `_system_message_typed_json()`; `_extract_json_text()` (parallel to `extract_response()`, handles
  a stray ```json fence or surrounding prose); `_parse_typed_json_response()` (JSON-decodes, fills
  the SAME defaults `_sanitize_rule()` fills for condition A so neither condition gets a
  construction advantage, constructs a `TypedRule`, and returns `.to_dict()`'s fully-composed rule
  dict -- the same shape `parse_and_sanitize_response()` returns for A, so `run_model_case()`'s
  existing wrap-and-`yaml.safe_dump()` logic works unchanged for either condition).
- `pipeline/gptlab_config.py`'s `build_config()` and `pipeline/diagnostic_v2.py`'s CLI gained a
  `construction_mode`/`--construction-mode` parameter (`original_prompt`|`typed_json`), recorded in
  `environment.json`, with `typed_rule.py` added to the run's tracked code-hash list.

**Offline checks exercised, per the review's required list** (`pipeline/tests/
test_typed_json_construction.py`, 8 new tests, no model calls):
1. Valid JSON -> an executable rule (`semgrep --validate` passes).
2. A model wrapping valid JSON in a ```json fence plus surrounding prose is still recovered.
3. Invalid JSON (unquoted keys) -> `self.last_error` set with a specific message, `None` returned --
   the same bounded-repair-feedback shape condition A's YAML-parse failures already produce.
4. An unexpected/unsupported field name (e.g. a model inventing `"patternNot"` instead of
   `"pattern_not"`) -> caught as `TypeError` from `TypedRule(**decoded)`, not an uncaught crash.
5. Mutually-exclusive fields set together (`pattern` + `pattern_either`) -> caught as `ValueError`
   from `validate()`/`to_dict()`.
6. Empty/`None` response -> handled identically to condition A's empty-response case.
7. **The actual regression this whole investigation was about, exercised as a permanent test**: a
   JSON response containing `pattern_not` produces a rule that is NOT just schema-valid but
   BEHAVIORALLY correct under real Semgrep execution -- the test asserts the composed rule excludes
   a "safe" line and keeps matching an "unsafe" one, not merely that `--validate` passes. Confirms
   `TypedRule.to_dict()`'s own fix (patterns:-nesting, never a sibling) is actually reachable and
   effective through this new generation path, not just through `typed_rule.py`'s own direct tests.
8. Condition A's dispatch path is unaffected by default (`construction_mode` defaults to
   `"original_prompt"`; `_build_prompt()` still returns A's original YAML-oriented prompt text).

Also verified end-to-end via the real CLI in `preflight` mode (no model calls, no output beyond
`environment.json`): `--construction-mode typed_json` records `"construction_mode": "typed_json"`
and includes `pipeline/typed_rule.py`'s hash in the run's code-provenance; the default (omitted)
flag still records `"construction_mode": "original_prompt"`; `references` mode (independent of this
flag) still reproduces its already-known 15/24 complete_success exactly, confirming nothing in
`main()`'s broader control flow regressed from this change. Full `pipeline/tests/` suite (excluding
the pre-existing, unrelated `test_stats_section22.py`, which crashes pytest's own collector via a
module-level `sys.exit(0)` and predates this session entirely): 44/44 pass -- the 31 already-passing
tests from earlier this session, plus the 8 new typed-JSON construction tests, plus 5 other
pre-existing `pipeline/tests/` files this session had not previously had reason to run together.

**What this does NOT include yet, stated directly**: no live model call under `typed_json` mode has
been made; no A/B development-pilot episode has been run; C/D's combined accept/stop gate (§4's
correction) and the probe mechanism (§5) remain unimplemented, as scoped. The next step toward an
actual pilot is a fresh condition-A baseline run under `--acceptance-policy corrected` (not yet
run), followed by a real `--construction-mode typed_json` run on the same 24-case development set
-- both still gated on the user's decision to spend real inference budget, which this
implementation step did not do.

## 2026-10-12: Condition B implementation review -- 4 real issues found and fixed, all independently reproduced before accepting

A review (`Condition_B_Implementation_Review_20261012.md`) reproduced the 44/44 passing suite and
ran its own 6-scenario mocked-workflow audit (real `generate_rule()`/decoder/`run_model_case()`/
raw-capture, only provider responses and scanner outcomes mocked), all passing. It then found 4
real issues, every one independently reproduced here before fixing:

1. **B's prompt had no worked examples; A's does (2 per language).** Confirmed by re-reading
   `_build_prompt_typed_json()` directly -- it listed field names but included nothing analogous to
   `_build_prompt_autogrep_default()`'s 6 worked examples. This is a real confound the protocol's
   own §3 ("same ... except for the two named interventions") exists to prevent: any later A-vs-B
   difference would be attributable to EITHER the construction intervention OR the loss of worked
   examples, with no way to separate them. Fixed by translating the SAME 6 examples (byte-identical
   vulnerability/fix intent) into `TypedRule`'s JSON field shape and adding them to B's prompt --
   all 6 fit the supported grammar exactly (confirmed by constructing each through `TypedRule`
   directly and checking `.to_dict()`'s output composes correctly), so no expressiveness gap forced
   a different example set.
2. **`environment.json`'s `prompt_policy` field ignored `construction_mode` entirely.** Confirmed by
   re-reading `main()`'s env-dict construction: it derived `prompt_policy` purely from
   `args.prompt_variant`, so a `typed_json` run with the default (unset) `--prompt-variant` recorded
   `"historical_autogrep_default_unchanged"` even though generation actually used
   `_build_prompt_typed_json()`, which ignores `prompt_variant` completely. Fixed: `prompt_policy`
   now checks `construction_mode` first (`"CONDITION_B_TYPED_JSON"` when typed_json), with new
   `requested_prompt_variant`/`prompt_variant_ignored` fields so a `--prompt-variant` passed
   alongside `typed_json` (which has no effect) stays visible as "requested but ignored," never
   silently dropped. Verified via real `preflight` runs for both modes: each now records exactly
   the correct label.
3. **The frozen-prompt-hash tripwire (`pipeline/tests/verify_prompt_hashes.py`) failed.** Reproduced
   directly: `_build_prompt_autogrep_default`'s source hash no longer matched its pinned value.
   Diffed against the `before/` snapshot and found the exact drift -- a single trailing-whitespace-
   only line (12 spaces) immediately before that function's `return prompt`, which had been
   replaced by a plain empty line at some point before this review (not from anything touched this
   session's editing of nearby methods, confirmed by the drift being whitespace-only, with the
   48-case rendered-prompt-text comparison and AST-equivalence both already confirming A's actual
   output never changed). Restored the exact original whitespace rather than updating the pinned
   hash to conceal the drift -- re-ran `verify_prompt_hashes.py`, now passes cleanly.
4. **The two-provider preflight gate unconditionally required `GPTLAB_API_KEY`, blocking a
   gpt-4o-only (`OPENAI_API_KEY`-only) environment before the correct host-specific credential was
   even checked.** Confirmed by re-reading `main()`: the check happened BEFORE `MODEL_HOSTS[args.model]`
   was resolved, even though `get_key_for_host()` already correctly dispatches to
   `OPENAI_API_KEY` for the `"OPENAI"` host. Fixed by resolving the host first and letting
   `get_key_for_host()`'s own, correctly-targeted `RuntimeError` surface instead of the hardcoded
   check; also fixed the HTTP-failure message (previously always said "Check GPTLAB_API_KEY" even
   for an OpenAI-host failure) and `credential_available`'s metadata (previously always checked
   `GPTLAB_API_KEY` regardless of the resolved host). Verified directly with 3 scenarios in a
   credential-scrubbed environment: no keys at all for gpt-4o -> correct `OPENAI_API_KEY`-specific
   error, no output directory created; only a (fake) `OPENAI_API_KEY` for gpt-4o -> now gets PAST
   the credential-presence gate and reaches a real (correctly-failing, since the key is fake) HTTP
   preflight call against OpenAI, with the error message naming `OPENAI_API_KEY`; no keys at all
   for `qwen3-coder:30b` -> still correctly requires `GPTLAB_API_KEY`, no regression to the
   historical path.

Also noted: the review's file-accounting point that `pipeline/diagnostic_v2.py` must be counted as
changed for this work -- it already was, in this document's own "What was built" list above; the
review's concern was that a `git diff --stat`-only accounting would miss it entirely since this
research branch tracks the whole file as untracked (`??`, not `M`), not that this document's prose
omitted it.

Full regression suite re-run after all 4 fixes: 44/44 pass. `verify_prompt_hashes.py`: both
tracked functions pass. All three preflight scenarios above reproduced directly. **Still no live
model call, no A/B pilot** -- these remain the next step, now with the confound, mislabeling, and
provider-gating issues resolved first.

## 2026-10-12/13: the A/B development pilot executed -- 288/288 episodes, real model calls, descriptive results only

With the user's explicit approval (a separate, real-inference-spend decision from everything
above), executed the full 12-run allocation from `Condition_B_Readiness_and_Pilot_20261012.md` /
`AB_Pilot_Allocation_20261012_v1/`. **The user ran all 12 commands themselves** (in their own
terminal, with their own `GPTLAB_API_KEY`/`OPENAI_API_KEY` -- never typed into a file or persisted
by this process), pasting each command's output back one at a time; I verified every single run's
`environment.json` (`construction_mode`, `prompt_policy`, `acceptance_policy`, `model`,
`selection_sha256` against the correct `selection_repeat_N.json`) and case-directory count before
giving the go-ahead for the next command, per the allocation's own "verify hashes, verify namespace
unused" instruction. One hiccup: command #1's first attempt hit a stale, empty, zero-episode output
directory (`FileExistsError` on `out.mkdir(exist_ok=False)`) -- inspected it directly (only
`environment.json`/`selection.json`/empty `raw/` folders, zero `CASE-*` subdirectories, so zero
research data at risk), confirmed safe to delete, and the user re-ran it cleanly. All 12 runs then
completed with exit code 0 on the first clean attempt, in the order A-then-B/B-then-A alternating
exactly as the allocation specified.

**Total actual resource use**: 486 of the 864-call ceiling (56%), confirming "equal ceilings do not
imply equal actual expenditure" was the right caveat to carry into this run rather than report the
ceiling as if it were the cost.

**Per-run `complete_success` (iterative, corrected-policy gate), all 12 confirmed against the live
`report()` output**:

| Model | Condition | Repeat 1 | Repeat 2 | Repeat 3 | Mean (/24) |
|---|---|---:|---:|---:|---:|
| qwen3-coder:30b | A (original_prompt) | 6 | 6 | 6 | 6.00 |
| qwen3-coder:30b | B (typed_json) | 7 | 7 | 7 | 7.00 |
| gpt-4o | A (original_prompt) | 6 | 5 | 5 | 5.33 |
| gpt-4o | B (typed_json) | 5 | 5 | 7 | 5.67 |

**Paired per-case comparison** (mean success rate across the 3 repeats per case, B vs. A, same 24
cases, never treating a repeat as an independent case per §6a's repeat-aggregation rule).
**CORRECTED 2026-10-13** (`AB_Pilot_Results_Review_20261013.md` found an arithmetic error here,
independently reproduced before fixing): the E2E (`complete_success`) outcome vector is stable
across repeats for qwen3 -- the same 6-vs-7 count every time -- but this is NOT the same as "zero
within-model variance" overall, which the first draft of this entry wrongly implied; qwen3 B's
`iterative_accepted` count actually varies (15, 16, 16 across the 3 repeats, see the construction
table below), even though which cases end up `complete_success` doesn't change. The qualifier
matters: stability is specific to the E2E outcome, not a claim about construction or acceptance.

- `qwen3-coder:30b`: B gained exactly 1 case outright (`CASE-0340`, 0/3 -> 3/3 across repeats),
  lost 0. 6 cases succeed under both conditions every single repeat
  (`CASE-0134`/`0136`/`0220`/`0221`/`0276`/`0323`); 17 fail under both every time. The E2E outcome
  for every one of these 24 cases is identical across all 3 repeats (hence "stable E2E," corrected
  above).
- `gpt-4o`: B gained 3 cases (`CASE-0136` +2/3, `CASE-0239` +1/3, `CASE-0276` +1) but LOST 2
  (`CASE-0063` -1, `CASE-0220` -2/3) -- real churn in both directions. **CORRECTED**: summing these
  per-case mean changes gives **+1/3 case**, not "net +1 case on average" as an earlier draft of
  this entry said -- that was a real arithmetic slip, caught by independently re-summing the five
  changed cases' per-repeat deltas: (2/3+1/3+1) - (1+2/3) = 1/3. +1/3 case over 24 is exactly the
  +1.39-percentage-point figure already in the headline table above; the two numbers were
  inconsistent within this same document before this fix. This is noisier across repeats than
  qwen3's completely stable outcome (6/5/5 vs. 5/5/7) -- consistent with, not proof of, the round-3
  review's warning that a model-by-intervention interaction cannot be ruled out a priori. **Also
  corrected per the same review**: calling this an established, demonstrated interaction (as an
  earlier draft of the companion Correction_Log entry did) overclaims what a single small pilot can
  show -- this is a descriptive difference in the observed responses, not a confirmatory interaction
  test or evidence of a general, population-level interaction. The within-model reporting
  requirement is still sensible on its own terms; this pilot doesn't additionally prove or explain
  it by model lineage.
- For qwen3's one gained case: all 3 repeats show the SAME mechanism -- `CASE-0340`'s B rule
  avoids a `benign_lookalike` false positive that A's rule has in every repeat (verified directly:
  A's sample outcome for `benign_lookalike` is `FP` in repeat 1, B's is `TN`, with all 3 positive
  detections identical between A and B) -- repeat 1's A rule matches a broad `execSync($CMD, ...)`
  pattern; B's uses a more specific string/template/concatenation form. This supports a
  specificity/generalization explanation grounded in the actual retained rules, not a claim that
  serialization alone caused the gain. **gpt-4o's `CASE-0063` loss is also a benign-lookalike FP**
  (in the opposite direction) -- directly showing that correct construction alone does not
  guarantee specificity; a typed representation can compose a pattern correctly and still be too
  broad or too narrow for a given model's authored content.

**Construction validity and visible discrimination, a genuinely interesting and honestly-reported
asymmetry between the two models**:

| Model | Condition | never_accepted (of 24, any repeat) | raw scan_errors (any repeat) |
|---|---|---|---|
| qwen3-coder:30b | A | 6 (all 3 repeats identical) | 1 (all 3 repeats identical) |
| qwen3-coder:30b | B | 8-9 | 6 (all 3 repeats identical) |
| gpt-4o | A | 8 (all 3 repeats identical) | 2, 1, 1 |
| gpt-4o | B | 8-9 | 1 (**all 3 repeats** -- corrected 2026-10-13; the first draft said "2 of 3 repeats," independently reproduced as wrong: it's 1, 1, 1 in every repeat) |

**Finer-grained first-attempt breakdown, added 2026-10-13** (independently reproduced exactly,
72 = 24 cases x 3 repeats per row) -- distinguishes a response that never even became a scannable
rule (JSON decode or `TypedRule` construction/validation failure) from one that parsed fine but
Semgrep itself rejected (a genuine "Rule parse error"). The earlier table's
"scan_errors" count excluded responses that never reached Semgrep; it did not combine the two
categories. This fuller table adds the previously omitted decode/schema failures:

| Model/condition | Decode/schema failure (never reached Semgrep) | Semgrep rule-parse error | Clean scan |
|---|---:|---:|---:|
| Qwen A | 0/72 | 3/72 | 69/72 |
| Qwen B | 1/72 | 18/72 | 53/72 |
| GPT-4o A | 0/72 | 4/72 | 68/72 |
| GPT-4o B | 0/72 | 3/72 | 69/72 |

Qwen B's one decode/schema failure is `CASE-0173` repeat 2: `pattern_not` was emitted as a bare
string instead of a list (`TypedRule.validate()` correctly caught and rejected it -- confirmed
directly from the retained feedback text: `"Invalid typed rule: pattern_not must be a list of
strings, got str"`). Every other extra Qwen B failure (18 vs. 3 for A) reaches Semgrep successfully
as valid JSON/`TypedRule` output and THEN gets rejected by Semgrep itself -- meaning the typed
contract is NOT where most of Qwen's extra failures come from; the model is reliably emitting
valid typed structures, it's the PATTERN TEXT inside those structures (invalid Semgrep syntax for
this language, incomplete expressions, wrong-language text) that's failing. Spot-checked 5 of
repeat 1's rule-parse errors directly: `CASE-0063` (an incomplete `.exec(` expression), `CASE-0193`
(an invalid multi-statement Java exclusion), `CASE-0235` (an exclusion containing an unfinished
`if (...) {` fragment), `CASE-0298` (invalid TypeScript string/template pattern text), `CASE-0323`
(CSS-selector-like text used as a JavaScript pattern). **Revised framing**: typed construction
fixes the OUTER representation and operator composition (confirmed: only 1/72 failures are at that
layer for Qwen B), but leaves embedded Semgrep pattern-string authoring validity as a separate,
still-unresolved bottleneck -- a more precise claim than "construction validity is worse," which
conflated the two layers.

One additional contributing factor, not isolated by this pilot: correct composition also makes
exclusion/scope clauses ACTIVE compiler inputs for the first time (per this session's own
exclusion-composition findings) -- some A rules still use the historically-ignored sibling form, so
an exclusion that would previously have silently done nothing can now genuinely fail to compile
once it's actually evaluated. This is a plausible contributor to Qwen B's extra rule-parse errors
alongside changes to the positive patterns themselves; isolating the two causes would need a
separate frozen offline ablation, which this pilot did not run and does not claim to have run.

For **gpt-4o**, B's first-attempt scan-error rate is lower than or equal to A's (1 in all 3 repeats
vs. A's 2/1/1) -- the entire aggregate "improvement" in this specific metric comes from one fewer
error in repeat 1 alone, not a broad pattern. Stated precisely, per the correction above: this is a
descriptive difference in how the two models' error rates moved under the same intervention, not a
demonstrated population-level model-by-intervention interaction -- the within-model reporting
requirement in §6a remains sensible on independent grounds, but this pilot's small sample doesn't
itself prove or explain a general interaction by model lineage.

In every single one of the 12 runs, `visible_correct` exactly equals the accepted count --
confirming the `corrected` acceptance policy is working as intended across both conditions and both
models: nothing gets accepted at the wrong location under either output contract.

**Actual resource cost, not the ceiling**:

| Model | Condition | Calls | Input tokens | Output tokens | Generation time |
|---|---|---:|---:|---:|---:|
| qwen3-coder:30b | A | 108 | 101,246 | 32,700 | 278s |
| qwen3-coder:30b | B | 132 | 138,916 | 32,245 | 311s |
| gpt-4o | A | 121 | 115,316 | 28,864 | 266s |
| gpt-4o | B | 125 | 129,371 | 21,648 | 205s |

qwen3's B condition costs noticeably more (132 vs. 108 calls, +22%) -- consistent with its worse
construction validity above (more repair attempts consumed before either accepting or exhausting
the budget). gpt-4o's B condition costs about the same as A (125 vs. 121 calls) despite using fewer
output tokens overall, plausibly because the typed-JSON contract is a more compact target for this
model specifically.

**What this pilot does NOT establish, stated as directly as the Research Direction and both
protocol reviews require**:
- Every observed difference (+1/24 qwen3, +0.33/24 gpt-4o) is far below the draft protocol's own
  10-percentage-point minimum-worthwhile-effect threshold (§8) -- nothing here should be read as
  "B beats A" or vice versa.
- 24 cases x 3 repeats was never sized for a confirmatory claim. §8's 207-case calculation is an
  illustrative single-independent-pair binary scenario, not a sample-size requirement for this
  repeat-averaged design; the finalized estimator needs its own power calculation. This pilot
  verifies that B's infrastructure works end-to-end on real models and provides descriptive
  evidence for subsequent decisions, rather than resolving confirmation questions.
- No candidate, case, or repeat was selected, discarded, or treated as a "winner" -- all 3 repeats
  for both models and both conditions are reported above, exactly as run.
- The gpt-4o descriptive-heterogeneity finding above is itself a reason the eventual confirmation
  run's statistical plan (§6a) should report within-model results rather than pooling across
  models, as already specified -- this pilot is small-sample, descriptive evidence consistent with
  that requirement mattering, not a demonstration that a general population-level interaction
  exists.
- The accepted-only and all-requested denominators must never be mixed in the same phrase (fixed
  above, where an earlier draft said "complete_success among accepted episodes is higher (7/24 vs.
  6/24)" -- 7/24 and 6/24 are already all-requested-denominator numbers; there is no separate
  accepted-only version of them in this write-up). Any future accepted-only metric must use each
  run's actual accepted count (15 or 16, not 24) and be explicitly labeled conditional.

**Concrete motivation for the planned probe mechanism (§5), found in this pilot's own retained
data, added 2026-10-13** (independently reproduced exactly): among Qwen B's ACCEPTED episodes
specifically, the renamed hidden variant (`variant_vulnerable_1`) is missed 11 times across 5
distinct cases -- `CASE-0163`, `CASE-0171`, `CASE-0239` in all 3 repeats each (9), `CASE-0173` in
repeat 2 (1), `CASE-0238` in repeat 3 (1). These are conditional descriptive counts (among accepted
episodes only, not a matched-denominator comparison against condition A), not a new estimate of
anything -- but they show concretely, in the retained real data, exactly the class of failure an
independently-constructed visible-source renaming probe (per §5's design) might expose during
development, before final hidden evaluation. Whether a probe actually catches these specific cases,
and whether the model successfully repairs when it does, remains untested -- this is motivation for
building it, not a result from it. One mechanical constraint already specified in §5 bears
repeating here: probe feedback is only fed in AFTER a visible pass, so it can never directly help a
candidate that fails to compile in the first place -- a candidate in Qwen B's 18/72 rule-parse-error
bucket above would need to get past that layer before any probe check could ever reach it.

**Raw data**: `results/diagnostic_20261010/ab_dev_20261012_v1_{qwen3,gpt4o}_r{1,2,3}_{a,b}/`, 12
directories, 288 `episode.json` files total. **CORRECTED 2026-10-13**: saying none of the 6 open
decisions (§11) are resolved is still true, but calling this pilot "not a step toward any of them"
understated its value, per the same review -- it IS evidence relevant to several of those
decisions (e.g. it directly informs what's worth implementing next -- the probe mechanism, per the
finding above -- and gives real observed variability/cost numbers for reassessing the pilot-repeat
and eventual confirmation-budget decisions) without automatically resolving the full protocol.

## 2026-10-13: the probe mechanism (Item 5) is built and offline-tested; coverage measured against the pilot's own saved rules; no new model calls

Per the recommended next sequence (steps 1-3: build the renaming probes, validate them offline,
measure coverage using already-saved rules before spending any inference budget), `pipeline/
dev_probe.py` now implements Item 5's design end-to-end for all 4 languages the diagnostic uses.
**Step 4 (a budgeted C/D pilot) was explicitly NOT run** -- it's gated behind the mechanism working,
which this entry establishes, not behind this entry itself authorizing new inference.

**New dependencies**: `tree_sitter`, `tree_sitter_java`, `tree_sitter_javascript`,
`tree_sitter_typescript` (grammar packages, pip-installed, no network access at runtime). Python
uses the stdlib `ast` module, which gives real scope/binding information (Store/Load context,
explicit `global`/`nonlocal`); the other three use `tree_sitter` concrete syntax trees, which do
NOT resolve scope -- documented in the module as a conservative heuristic, not a semantic
guarantee.

**Three real engineering findings made while building this, beyond what the design anticipated:**

1. **A genuine bug, found and fixed before it could produce a false result**: the first version
   reconstructed the renamed source via `ast.unparse()`. Confirmed directly against a real
   development case (`CASE-0134`): Python's own parser collapses adjacent implicit string-literal
   concatenation (`r'a'` `r'b'` `r'c'` on separate lines, a common long-regex idiom) into a single
   `Constant` at parse time, so `ast.unparse()` always re-emits it as ONE literal -- but Semgrep's
   own Python parser does NOT perform this collapse (confirmed: a real accepted rule's pattern was
   literally just one of four adjacent raw-string lines, and it matched the real benchmark file at
   exactly that one line). `ast.unparse()`'s reformatting silently destroyed the structure that
   match depended on, which would have produced a false "the probe exposes a weakness" result for
   reasons having nothing to do with renaming. Fixed by switching Python's reconstruction to
   TEXT-SPAN replacement (using each `Name` node's `lineno`/`col_offset`/`end_lineno`/
   `end_col_offset`, applied back-to-front), the same approach already used for the tree-sitter
   languages -- `ast.unparse()` is no longer used anywhere in the module. Re-verified directly:
   the fixed probe now matches the same real rule at the same line.
2. **A new eligibility risk, not in the original design, found empirically**: in JavaScript/
   TypeScript, an ES6 "shorthand" object property (`{token}`, equivalent to `{token: token}`) ties
   the resulting object's KEY to the variable's NAME, not just its value -- renaming the variable
   there would silently rename the object's key too, an observable structural change outside the
   variable itself, the same class of risk the reflection filter exists to catch. Confirmed via
   tree-sitter's own distinct node type (`shorthand_property_identifier`, different from both
   `identifier` -- a genuine reference, safe to rename -- and `property_identifier` -- an explicit
   key or member-access field name, never a variable reference). Any candidate whose name appears
   in a shorthand property is excluded; the mechanism falls through to the next candidate if one
   exists (tested directly), or the whole function becomes ineligible if it doesn't.
3. **Java's CST does not distinguish a field-access property or method-call name from a genuine
   local-variable reference by node type the way JavaScript/TypeScript do** (confirmed empirically:
   `this.token`'s `token` and a local variable named `token` are both plain `identifier` nodes in
   tree-sitter-java). Handled via each grammar's own NAMED FIELDS instead of node type --
   `field_access`'s `field` child and `method_invocation`'s `name` child are identified and
   excluded from renaming regardless of text match (confirmed directly: `this.token` survives a
   `token`-renaming untouched in a real test case). Also confirmed separately: a bare Java
   constructor mis-parses in tree-sitter-java without a class wrapper (no return type makes it
   ambiguous) -- fixed by wrapping every Java snippet in `class Dummy { ... }` before parsing and
   stripping the wrapper back out afterward.

**Offline test suite** (`pipeline/tests/test_dev_probe.py`, 18 tests, no model calls): covers the
Python reflection filter (`locals`/`getattr`), the string-literal-reachability skip, parameter
exclusion, name-collision avoidance, the JS shorthand-property exclusion AND its correct fallthrough
to a second candidate, JS member-access-property non-confusion, JS `eval` exclusion, a TypeScript
end-to-end rename, Java field-access non-confusion, Java reflection exclusion, Java's
constructor-wrapper handling, and one real end-to-end build per language against an actual
development-set case (manually cross-checked by hand before being written up as a test).

**Probe eligibility across the real 24-case development set**: 15/24 (62.5%). The 9 ineligible:
6 are JavaScript/TypeScript cases whose `model_context` extraction produced a non-self-contained
snippet (unbalanced brackets, a mid-expression start -- confirmed by direct inspection of each,
e.g. `CASE-0163`'s text literally begins with a stray `)`) -- a pre-existing data-extraction
limitation, not a bug in this module. The other 3 (`CASE-0220`, `CASE-0221`, `CASE-0298`) parse
fine but have no local, non-parameter binding eligible after all the exclusions above.

**Coverage measurement (`pipeline/probe_coverage_check.py`), step 3 of the plan, no new model
calls**: built a probe pair for every eligible case, stored firewalled under `results/
diagnostic_20261010/_dev_probes/<case_id>/` (never written into or read from `benchmark/cases/`),
then re-scanned every ALREADY-ACCEPTED final rule from all 12 A/B pilot runs against those probe
files with real, pinned Semgrep -- new Semgrep execution, no inference. Of **116 accepted episodes
with an eligible probe** (across all 12 runs): **110 pass** (detect the renamed-vulnerable probe,
not the renamed-patched one), **6 fail** (miss the renamed-vulnerable probe), **0** false-positive
on the renamed-patched probe.

| Model | Condition | Total | Pass | Fail (missed) |
|---|---|---:|---:|---:|
| qwen3-coder:30b | A | 33 | 33 | 0 |
| qwen3-coder:30b | B | 29 | 26 | 3 |
| gpt-4o | A | 27 | 24 | 3 |
| gpt-4o | B | 27 | 27 | 0 |

**All 6 failures trace to exactly 3 distinct cases, each independently inspected and confirmed as
the SAME genuine failure mode**: the model's accepted rule hardcodes a specific LOCAL VARIABLE
NAME as literal pattern text instead of using a Semgrep metavariable (`$VAR`) there, even though it
correctly uses metavariables elsewhere in the same rule.
- `CASE-0171` (qwen3 B, all 3 repeats): `pattern: 'url.replaceFirst(...); url.replaceAll(...)'` --
  `url` is a hardcoded receiver name; the probe's `url_renamed` breaks the match.
- `CASE-0136` (gpt-4o A, repeats 2-3): `pattern: 'File f = File.createTempFile($PREFIX, $SUFFIX);'`
  -- `f` is a hardcoded assignment target; `$PREFIX`/`$SUFFIX` ARE correctly metavariables, `f`
  is not.
- `CASE-0173` (gpt-4o A, repeat 3): `pattern: 'const key = ASSET_MANIFEST[$PATH] || $PATH'` --
  `key` is a hardcoded assignment target; `$PATH` is correctly a metavariable.

This is exactly the class of weakness the probe mechanism exists to surface, now empirically
quantified rather than hypothesized: **5.2% (6/116) of accepted episodes in this pilot would fail
a trivial, independently-constructed renaming probe**, concentrated in 3 specific, named,
inspectable cases -- not spread evenly, and in every instance traceable to the same root cause
(an incidental variable name treated as load-bearing instead of using the metavariable Semgrep
already provides for exactly this purpose).

**What this does NOT establish**: this measures DETECTION potential against already-saved rules,
not whether a model, given this feedback during repair, would successfully fix the pattern (the
stated purpose of step 3, not step 4). No new model calls were made. Probe feedback is only fed in
AFTER a visible pass (per §5's design), so it can never directly help a candidate that fails to
compile in the first place -- irrelevant to construction-layer failures, relevant only to this
specific "visible pass, hidden/renamed-variant miss" failure mode. C/D's combined accept/stop gate
(§4) remains unimplemented; a budgeted C/D development pilot (step 4) remains the next step
requiring the user's separate approval to spend new inference budget, exactly as it did before this
entry.

## 2026-10-13: independent probe implementation review — coverage verified, readiness claim qualified

Full findings, reproductions, priorities and file accounting are in
`Dev_Probe_Implementation_Review_20261013.md`; machine-readable evidence is in
`Dev_Probe_Review_Evidence_20261013.json`, generated by `audit_dev_probe_20261013.py`.

The latest retained scans independently reproduce **116 checks, 110 passes, 6 vulnerable misses,
0 patched findings**. All 116 raw outputs report Semgrep 1.177.0 and both targets scanned.
Eligibility reproduces at 15/24 cases; current sources reproduce byte-for-byte. There are 30 probe
source files in 15 directories. The new test file independently passes 18/18; this review did not
rerun the full 62-test suite. Every frozen A/B allocation input hash remains unchanged.

The builder is **not yet ready as a repair oracle**. Eight retained counterexamples pass its
validation despite changing behavior/interface or retaining invalid patched source. High-priority
findings: (1) name-based renaming crosses Python/JS scopes, skips local function call references,
and can change Java method names; (2) patched-side validation lacks independent parameter,
collision and eligibility checks; (3) raw substring reflection filtering misses `eval (text)`.
Structural AST/CST isomorphism does not establish correct binding resolution. The review also
finds missing scan-target verification and incomplete FP accounting, overwritten shared probe
inputs across coverage namespaces, and installed-but-undeclared parser dependencies. These are
open findings, not fixes performed by this review. The combined C/D gate remains unimplemented.

Correct the scope of the headline percentage: **6/116 (5.17%) of accepted episodes with eligible
probes**, not all accepted episodes. There are 195 accepted episodes, 79 uncovered. The current
mechanism flags 3 of the 11 motivating Qwen B hidden-renaming misses. All six flagged episodes
also miss the restructured positive, so successful probe repair would not alone prove E2E success.
These qualifications do not withdraw the six observed probe misses or the zero patched findings.

Next: fix the builder and accounting, add independent behavior regressions, implement/offline-test
the combined gate and immutable caching, then remeasure coverage in a new namespace before C/D
inference. This review changed only research records and added its audit/evidence; no implementation,
tests, benchmark sources, existing probes or saved outcomes changed, and no real scans/model calls
were made. Historical entries and both retained coverage runs remain preserved.

## 2026-10-13: all six review findings fixed in `dev_probe.py`/`probe_coverage_check.py`, each counterexample independently reproduced before and after; coverage remeasured in a new namespace

Every one of the review's reproductions was run directly first, confirmed broken against the
pre-fix code, then re-run against the fix to confirm it closes. No change was accepted on the
review's word alone.

**High 1 (scope-incorrect renaming), three sub-cases, all fixed:**
- Python: candidate collection now walks only the function's own scope (a new `walk_own_scope()`
  helper that does not descend into nested `FunctionDef`/`AsyncFunctionDef`/`Lambda`/`ClassDef`),
  and any name touched anywhere in a nested scope is excluded outright rather than attempting real
  closure/free-variable resolution (`_py_names_touched_in_nested_scopes`). The review's exact
  counterexample (`token=10` global; `f()` reads it; nested `g()` has its own local `token`) is now
  a dedicated regression (`test_python_nested_scope_review_reproduction_is_ineligible`): `f()` has
  no local-to-its-own-scope candidate at all, so the builder correctly refuses it.
- Java: a method/constructor/class declaration's own name field is now excluded from renaming
  (`_DECLARATION_NAME_PARENT_TYPES`). The review's `int token() { int token = 1; return token; }`
  now compiles and runs correctly when called by its original name after renaming (verified by
  actually compiling and running it with `javac`/`java`, not just structural inspection).
- JavaScript/TypeScript: a candidate ever called as a bare identifier (`cb()`) is now rejected
  entirely rather than having only its callee occurrence skipped
  (`_ts_is_called_as_bare_function`). The review's `const cb = () => 7; return cb();` is now
  ineligible (confirmed), and a real `node` run of the old naive (buggy) transformation is kept as
  a regression demonstrating it really does raise `ReferenceError` at runtime.
- Self-discovered during this fix, not in the original review: JS/TS `let`/`const` block scoping
  (`lexical_declaration`) was not checked at all -- a declaration inside a nested block is a
  different binding from a same-named reference outside it. Added
  `_ts_block_scoped_outside_function_body`. Building this required switching tree-sitter parent
  comparisons from `is` to `.id` equality: tree-sitter's Python bindings return a fresh wrapper
  object on every attribute access, so `node.parent is other_node` can wrongly return `False` for
  the identical tree position (confirmed directly). This fix correctly drops real-case eligibility
  from 15/24 to 13/24 (`CASE-0081`, `CASE-0339` lost eligibility because their only candidates were
  genuinely block-scoped) -- treated as the correct cost of a real safety fix, not something to
  work around.

**High 2 (patched-side eligibility/collision gaps), fixed:** `_rename_patched_python` and
`_rename_patched_tree_sitter` now independently re-run the full eligibility check set (reflection,
parameter exclusion, nested/block-scope exclusion, callee ambiguity) against the patched source
specifically, plus a new collision check against the patched function's own identifiers, instead of
blindly reusing the vulnerable side's clearance and name choice. Both of the review's reproductions
(role-change via a patched-side parameter sharing the old name; an accidental collision with an
existing `token_renamed` changing a return value from 3 to 4 while isomorphism still passed) no
longer occur.

**High 3 (reflection whitespace bypass), fixed:** `_ts_has_reflection` is now AST/CST-based
(checking actual `call_expression`/`method_invocation` structure) instead of a raw substring check,
closing the `eval (token)` (space before paren) bypass by construction. While rebuilding this,
dynamic-global bracket access (`window[computedKey]`) was added as a new reflection vector --
`window`/`globalThis`/`self` under `subscript_expression` only, and only when the index is not a
literal `string`/`number`/`template_string`. Two sub-bugs introduced while adding this were found
and fixed before landing: a first version also flagged ordinary dot-notation access
(`window.XMLHttpRequest`), and even restricted to brackets it still flagged a literal string key
(`window['alertHttpRequest']`, real case `CASE-0220`) -- both are semantically identical to dot
notation and must not be treated as reflection.

**Medium 4 (scan misclassification / FP accounting), both fixed in `probe_coverage_check.py`:**
`scan_probe` now requires both probe targets to actually appear in Semgrep's own `paths.scanned`
list before trusting any detection outcome, rather than inferring `scan_ok=True` from exit
code/errors alone. The FP aggregate no longer requires `vulnerable_detected AND patched_detected`;
outcomes are now reported as an explicit four-way breakdown (clean pass / pass-with-patched-FP /
clean miss / miss-with-patched-FP) so a patched-only false positive can never be hidden by a
simultaneous vulnerable-probe miss.

**Medium 5 (overwritten probe inputs), fixed:** probe source files are now written under each run's
own timestamped `_probe_coverage_<ts>/_probe_inputs/<case_id>/` directory instead of the shared
`_dev_probes/<case_id>/` path, and each probe's SHA-256 is recorded in `eligibility` -- no later run
can silently overwrite an earlier run's exact input again.

**Medium 6 (undeclared dependencies), fixed:** `tree_sitter==0.26.0`, `tree_sitter_java==0.23.5`,
`tree_sitter_javascript==0.25.0`, `tree_sitter_typescript==0.23.2` (the exact versions this review
reported installed) are now pinned in `autogrep/requirements.txt`.

**Behavioral regressions added, the review's central methodological ask:** 6 new tests in
`pipeline/tests/test_dev_probe.py` actually execute code -- Python via `exec()`, JavaScript via a
real `node` subprocess, Java via real `javac`+`java` compilation and execution -- and compare real
return values/output before vs. after renaming, rather than relying on structural isomorphism
alone. Each pairs with one of the review's reproductions. Full suite: **68/68 pass** (62 prior + 6
new), rerun in full this time (not just `test_dev_probe.py` in isolation).

**Coverage remeasured, new namespace, no new model calls:**
`_probe_coverage_20261013T002146736021Z`. Eligibility: **13/24** (down from 15/24, expected per the
block-scope fix above). Of the true 195 total accepted episodes across all 12 pilot runs, **104**
now have an eligible probe (down from 116; the difference is exactly the episodes that were only
covered via `CASE-0081`/`CASE-0339`, which lost eligibility). Of those 104: **98 pass, 6 fail
(vulnerable missed), 0 patched findings** — i.e. 98/104 = 94.2% pass rate, close to the review's
110/116 = 94.8%; the small drop is consistent with losing two cases' worth of (mostly-passing)
episodes rather than any new mechanism bug, since the same 6 failing episodes recur unchanged. The
exact same 6
failing episodes as previously identified were independently re-confirmed by case/model/repeat:
`qwen3-coder:30b`/B/CASE-0171 (repeats 1-3), `gpt-4o`/A/CASE-0136 (repeats 2-3), `gpt-4o`/A/CASE-0173
(repeat 3) — this specific finding is robust to every mechanism bug fixed in this round, since none
of the fixes touched these particular cases' eligibility or outcome. Restated cleanly: 6/104 (5.77%)
of accepted episodes with an eligible probe fail it; 6/195 (3.08%) of all accepted episodes are
flagged; 91/195 accepted episodes remain uncovered (no eligible probe).

**Still not done, explicitly deferred:** the combined C/D accept/stop gate, deterministic caching,
and any new budgeted C/D model-inference pilot remain unimplemented and ungated on new approval, per
the standing agreement that step 4 requires separate explicit sign-off before spending new inference
budget.

## 2026-10-13: follow-up review verifies coverage and fixes, but two semantic findings remain open

See `Dev_Probe_Followup_Review_20261013.md` and its audit script/JSON evidence for complete
reproductions and file accounting. Independently verified 24/24 probe tests, the seven corrected
prior transformation fixtures, scanner target-coverage checks, four-way outcome counting,
immutable per-run probe inputs with matching hashes, and pinned parser requirements. The full
68-test suite remains the author's reported result; this review reran the changed test file only.

The latest 104 scans independently recount to **98 passes, the same 6 misses, 0 patched findings**,
all using Semgrep 1.177.0 with both targets scanned. Eligibility is 13/24; 91 of 195 accepted
episodes are uncovered. All twelve removed covered episodes were passes. Current generated
sources reproduce byte-for-byte and all prior historical result hashes remain unchanged.

The earlier statement that all semantic findings are closed is premature. Remaining high-priority
issues are (1) scope handling still accepts Python comprehension/global and default-argument/global
mis-renames plus Java inner-block-local/field mis-renames, and (2) the patched path can rename a
global load without any patched local declaration and still accepts syntactically invalid patched
source as an eligible pair. Executed reproductions yield original values 10, 11 and 7 followed by
Python NameErrors, and original Java output 10 followed by a probe compilation failure. These
findings do not demonstrate contamination of the six retained coverage misses.

Two documentation/test corrections: the JavaScript block-scope counterexample was already in the
prior review, not absent from it; the new block-scope test's hand-written supposed-broken source
renames only the inner declaration and still returns 10, whereas the actual prior bug renamed the
outer reference too. Its builder-ineligibility assertion is valid, but its behavioral example does
not demonstrate the prior failure as its prose claims.

Next bounded task: close these two semantic findings and add their execution regressions. The
combined C/D gate, deterministic caching and inference remain separately deferred as requested.
This review added records/evidence only: no implementation, test, dependency, benchmark, existing
probe or result edits, no real scans and no model calls.

## 2026-10-13: both remaining semantic findings fixed, each reproduction independently run before and after; the documentation/test precision issue also fixed; coverage remeasured again

Every reproduction in the follow-up review was run directly against the pre-fix code first
(confirmed broken, matching the exact original-vs-probe return values the review reported), then
re-run against the fix (confirmed closed) -- nothing accepted on the review's word alone.

**Open finding 1 (lexical scope still incomplete), all three sub-cases fixed in `dev_probe.py`:**
- Python comprehensions (`ListComp`/`SetComp`/`DictComp`/`GeneratorExp`) are scope boundaries in
  Python 3 -- a comprehension's own `for` target is not a binding of the enclosing function. The
  review's `def f(): [token for token in (1,2)]; return token` (module global `token=10`) is now
  ineligible; confirmed by execution that the original genuinely returns 10 (depends on the
  global), closing the prior silent `NameError`.
- Parameter default values/annotations are evaluated at `def`-time in the ENCLOSING scope, not the
  function's own body. A new `_py_names_in_signature` excludes any name appearing in
  `args.defaults`/`kw_defaults`/any annotation. The review's `def f(x=token): token=1; return
  x+token` (module global `token=10`) is now ineligible; confirmed by execution that simply
  defining the original function depends on the outer `token`.
- Java has no `var`-like function-scoped-regardless-of-nesting local at all -- EVERY Java local
  declaration is block-scoped. `_ts_block_scoped_outside_function_body`'s unconditional `if
  language == "java": return False` (a real bug, not an intentional design choice) is removed and
  generalized to check `local_variable_declaration` for Java using the identical direct-child-of-
  body structural test already used for `lexical_declaration` in JS/TS. The review's `int f() { {
  int token=1; } return token; }` (enclosing field `int token=10`) is now ineligible; confirmed by
  actually compiling and running the original method with `javac`/`java` that it genuinely returns
  the field's value (10), not the block-local's (1).

**Open finding 2 (patched-source validation gaps), both fixed:**
- `_rename_patched_python`'s and `_rename_patched_tree_sitter`'s "is `old_name` present in the
  patched function at all" checks were built from every `Name`/`identifier` node regardless of
  Store/Load context or declaration status -- not strict enough to rule out a free/global
  reference. Both now require `old_name` to be one of the patched function's OWN independently-
  eligible local candidates (`_py_candidate_locals(func)` for Python; `_ts_collect_declared_locals`
  plus the newly-factored-out `_ts_is_eligible_local` for tree-sitter -- the same functions the
  vulnerable side already uses, rather than a second, drifted copy of the checks). The review's
  vulnerable-local-`token`-vs-patched-global-`token` reproduction (`def f(): return token` reading
  a module global `token=7`) now correctly leaves the patched side unchanged
  (`patched_probe_renamed=False`, text byte-for-byte identical to the input) instead of corrupting
  it; confirmed by execution that the unrenamed patched function still returns 7.
- A patched function that fails to PARSE at all (`def f(:`) was previously indistinguishable from
  a patched function that parses fine but legitimately doesn't need renaming (e.g. the variable
  was removed by the fix, as in the real CASE-0046/CASE-0184 pairs, where leaving the patched side
  unchanged is the correct, non-erroneous outcome) -- both silently produced an eligible
  `ProbeResult`. New `_py_parses_to_function`/`_ts_parses_to_function` checks run once, up front,
  in `_build_probe_python`/`_build_probe_tree_sitter`; an unparseable patched function now makes
  the WHOLE case ineligible (`"patched_function does not parse"`), while a parseable-but-
  variable-absent patched function still correctly falls through to the legitimate unchanged
  fallback, unaffected.

**Documentation/test precision issue, fixed:** the prior round's JS block-scope test's "naively
renamed" fixture only renamed the inner block-local DECLARATION and left the outer `return token`
reference untouched, which doesn't reproduce a crash (just confirms the harmless fallback still
works) -- correctly flagged by the review as not matching its own prose claim of a `ReferenceError`.
Fixed by renaming BOTH occurrences (faithfully replaying what the pre-fix code, which had no
notion of block scope at all, actually would have done) -- this now genuinely raises
`ReferenceError` at runtime, confirmed via a real `node` run, and the docstring now says so
accurately.

**6 new regression tests added** (2 structural-ineligibility + behavioral-execution confirmations
for the Python/Java scope cases, 2 for the patched-side fixes, plus the corrected JS block-scope
fixture), bringing `test_dev_probe.py` to 30 tests and the full suite to **74/74 passing** (rerun
in full, not just the changed file).

**Coverage remeasured again, new namespace, no new model calls:**
`_probe_coverage_20261013T005231042394Z`. Eligibility: **11/24** (down from 13/24 -- `CASE-0116`
and `CASE-0193`, both Java, lost eligibility to the now-correct Java block-scope check; both were
previously misclassified as eligible only because that check was a no-op for Java). Of the true
195 total accepted episodes, **100** now have an eligible probe (down from 104, exactly accounting
for the episodes only covered via those two cases). Of those 100: **94 pass, 6 fail (vulnerable
missed), 0 patched findings** -- 100-6=94 and 104-4=100 are both self-consistent, confirming the 4
newly-lost episodes were all previously-passing ones, not any of the 6 failures. The exact same 6
failing episodes were independently re-confirmed yet again by case/model/repeat:
`qwen3-coder:30b`/B/CASE-0171 (repeats 1-3), `gpt-4o`/A/CASE-0136 (repeats 2-3), `gpt-4o`/A/CASE-0173
(repeat 3) -- this finding has now survived two full rounds of independent review and mechanism
correction unchanged, strong evidence it reflects a genuine model behavior rather than any builder
artifact. Restated cleanly: 6/100 (6.0%) of accepted episodes with an eligible probe fail it; 6/195
(3.08%) of all accepted episodes are flagged; 95/195 accepted episodes remain uncovered.

**Still not done, explicitly deferred:** the combined C/D accept/stop gate, deterministic caching,
and any new budgeted C/D model-inference pilot remain unimplemented and ungated on new approval,
unchanged from every prior round.

## 2026-10-13: third probe review — prior reproductions fixed; binding safety still has two concrete gaps

Independently verified 30/30 probe tests (full 74-test suite not rerun here), all five substantive
counterexamples from the previous follow-up, and the corrected JS block fixture. All 100 retained
scan outputs reproduce 94 passes, the same six misses and zero patched findings; all use Semgrep
1.177.0 and scan both targets. Eligibility reproduces at 11/24; all 22 source files match regenerated
bytes and stored hashes. Only the builder and its test file changed among the previous audit's
hashed inputs; historical artifacts remain unchanged.

The previously reported inputs are fixed, including invalid patched source. However, the broader
claim of closed lexical scope is premature: a Python `except ValueError as token` binding is left
unrenamed while its return reference becomes `token_renamed`, changing a returned ValueError(7)
into integer 1. A JavaScript default argument that reads global `token` is renamed alongside a
body-local `token`, changing return value 11 into ReferenceError. Both are accepted by the builder
and were demonstrated by execution. These are one remaining binding-safety finding, not evidence
that the six retained coverage misses were artifacts.

Full sources, outcomes, verification and file accounting: `Dev_Probe_Round3_Review_20261013.md`,
`Dev_Probe_Round3_Evidence_20261013.json` and `audit_dev_probe_round3_20261013.py`. Recommend an
explicit supported-binding contract or scope resolver, with execution regressions for these cases.
Stable saved-rule outcomes across revisions are not independent new model-trial replications.
The C/D gate, caching and inference remain deferred. Review records only were changed; no real
scans, model calls or implementation/test/result edits occurred.

## 2026-10-13: both round-3 binding-safety gaps fixed, each reproduction independently run before and after; coverage remeasured a fourth time with unchanged numbers

Both reproductions were run directly against the pre-fix code first (confirmed broken, matching
the exact original-vs-probe values reported: `ValueError(7)`→`1`; `11`→`ReferenceError`), then
re-run against the fix (confirmed closed).

**Python exception binding, fixed:** `except SomeError as token:` binds `token` via
`ExceptHandler.name`, a plain string attribute, not an `ast.Name` node -- invisible to text-span
replacement by construction. New `_py_exception_bound_names(func)` collects every name ever used
as an `except ... as <name>:` binding anywhere in the function and excludes it from candidacy
entirely (same philosophy as nested-scope/comprehension exclusion), wired into
`_py_candidate_locals`'s exclusion set so both the vulnerable and patched sides are protected via
the one shared function. The review's reproduction is now ineligible; confirmed by execution that
the original genuinely returns the caught `ValueError(7)` object, not an unrelated outer int.

**JS/TS parameter-default scope, fixed:** a default value expression
(`function f(x=token) {...}`) is evaluated in a scope that sees the ENCLOSING scope, not the
function body's own `let`/`const`/`var` declarations -- the Python-side fix
(`_py_names_in_signature`) had no tree-sitter equivalent at all. New
`_ts_names_in_signature_defaults(func, language)` walks `assignment_pattern`'s `right` field (JS)
and `required_parameter`/`optional_parameter`'s `value` field (TS) and excludes every name found
there from candidacy on both the vulnerable and patched sides (a no-op for Java, which has no
default parameter values). The review's reproduction is now ineligible; confirmed by a real `node`
run that the original genuinely returns 11.

**2 new regression tests added** (one Python exec()-based, one real `node`-subprocess-based),
bringing the full suite to **76/76 passing** (rerun in full).

**Coverage remeasured a fourth time, new namespace, no new model calls:**
`_probe_coverage_20261013T011301679535Z`. Eligibility, covered-episode count, pass/fail split and
the exact 6 failing episodes (by case/model/repeat) are **all numerically identical** to the prior
round (11/24; 100/195 covered; 94 pass, 6 fail, 0 patched findings) -- neither of this round's two
bugs is exercised by any of the 24 real development-set cases; both were only reproduced via the
review's synthetic examples. This is a genuine, confirmed null result, not a skipped
remeasurement: the check was run and its output file is new, it simply reproduces the same
numbers because none of the real cases hit either gap.

**Still not done, explicitly deferred:** the combined C/D accept/stop gate, deterministic
caching, and any new budgeted C/D model-inference pilot remain unimplemented and ungated on new
approval, unchanged from every prior round. Per the review's own framing, closing two more
concrete counterexamples does not by itself establish that EVERY lexical-binding form is now
handled -- the builder's safety rests on "reject any candidate touched by an unhandled form,"
not on an exhaustive enumeration of Python/JS/TS binding forms, which remains an open-ended
surface in principle even as each concretely-reproduced gap gets closed.


## 2026-10-13: known probe reproductions verified closed; systematic admissibility audit remains a separate next step

Independent closure verification: 32/32 probe tests pass (full author-reported 76-test suite not
rerun here). The latest Python exception and JS default fixtures are ineligible; patched-side
checks preserve the valid original sources unchanged. A typed TypeScript default fixture is also
ineligible. All 100 saved raw outputs from `_probe_coverage_20261013T011301679535Z` independently
recount to 94 passes, the same six misses and zero patched findings, with both targets scanned
under Semgrep 1.177.0. Eligibility regenerates at 11/24 and all 22 source files match saved hashes.
Coverage remains 100/195 accepted episodes; 95 are uncovered. Prior saved evidence is unchanged.

The specific known reproductions are closed. This does not establish exhaustive binding safety,
and unknown forms are not automatically rejected merely because the implementation is described
as conservative. The next recommended validation task is a finite, grammar-derived supported-syntax
matrix with explicit accept/reject dispositions, enforcing code and independent behavior tests,
followed by an exact-span audit of the 24 current cases. That task is proposed, not performed here.
C/D gate implementation, deterministic caching and inference remain deferred as requested.

See `Dev_Probe_Known_Findings_Closure_20261013.md`, `Dev_Probe_Closure_Evidence_20261013.json` and
`audit_dev_probe_closure_20261013.py` for verification, a concrete bounded-audit proposal and file
accounting. Only review records were changed; no implementation, test, dependency, benchmark,
existing probe or saved outcome edits, no new model calls and no real scans.

## 2026-10-13: bounded binding-form audit completed per the recommended-next-step proposal — 4 further bugs found and fixed via systematic enumeration (not another externally-supplied counterexample), supported-syntax tables written for all three languages, per-case review recorded, versions frozen

Per the agreed next task, built the requested deliverables: a supported-syntax table per language
in `Dev_Probe_Binding_Form_Audit_20261013.md`, independent tests for every disposition, a recorded
per-case review across the real 24-case set, and frozen reviewed versions. **Before writing the
table**, systematically inspected the actual AST/CST node types (via `ast.dump()` and direct
`tree_sitter` parses, not memory) against the current implementation, which surfaced 4 further
real bugs this round — all reproduced directly (broken before, fixed after) before being accepted,
same discipline as every prior round, not supplied by an external review this time.

**Python, 3 bugs found and fixed, all the same root-cause class as the already-fixed
`except...as` bug** (a binding whose declaration site is a plain string attribute, not an
`ast.Name` node, so it stays unrenamed while OTHER same-spelled references elsewhere get swept
in): (1) a nested `def NAME(): ...`/`class NAME: ...` statement's own name
(`FunctionDef`/`ClassDef`.name) -- reproduced with `token=1; def token(): return 2; return
token()`: original returns `2`, the pre-fix probe raised `TypeError: 'int' object is not
callable`. (2) Import aliases (`import os as token`, `ast.alias.asname`) -- reproduced with
`token=1; import os as token; return token.getcwd()`: pre-fix probe corrupted the alias reference.
(3) `match`/`case` capture patterns (`case int() as token:`, `MatchAs.name`) -- reproduced with a
match statement returning the matched value (99) vs. the pre-fix probe returning the unrelated
outer local (1). All three fixed by adding to the same exclusion-set pattern already established
(`_py_names_touched_in_nested_scopes`, new `_py_import_bound_names`, new
`_py_match_bound_names`).

**JavaScript/TypeScript, 1 bug found and fixed:** the same nested-declaration-name problem as
Python's finding (1), for `function NAME(){}`/`class NAME{}`. Required careful construction to
isolate from JS hoisting/sequential-overwrite semantics (the most obvious direct-call shape was
already incidentally protected by the existing callee-ambiguity check) -- reproduced with `var fn
= token; var token = 1; function token() { return 2; } return fn() + token;`: original returns
`3`, pre-fix probe raised `TypeError: fn is not a function`. Fixed via new
`_ts_has_same_named_declaration`, wired into the already-shared `_ts_is_eligible_local`.

**Also systematically checked and confirmed SAFE (not bugs, no fix needed), each verified by
direct execution rather than assumed:** Python tuple/list unpacking and the walrus operator
(both bind via genuine `ast.Name` nodes, unlike the broken forms above); JS/TS destructuring
(the pattern's own node type differs from plain `identifier`, so it is simply never offered,
confirmed untouched when an unrelated candidate is renamed); JS/TS `catch` clause parameters and
`for-of`/`for-in` loop variables (both are real `identifier` nodes that shadow an outer
same-named binding, but uniform textual relabeling preserves the shadow relationship correctly --
confirmed via real `node` execution); Java local classes and `catch` parameters (Java's
type/value identifier distinction, or an outright compile failure for the one plausible collision
shape, rules out the risk -- confirmed via `javac`).

**8 new tests added**, full suite now **82/82 passing**. Coverage remeasured in a fresh namespace
(`_probe_coverage_20261013T014605839062Z`), no new model calls: **numerically identical** to the
pre-audit run (11/24 eligible; 100/195 covered; 94 pass, 6 fail, 0 patched findings; same 6 failing
episodes by case/model/repeat) -- none of these 4 new bugs occurs in any of the 24 real
development cases.

**Frozen versions:** `pipeline/dev_probe.py` SHA-256
`120bd1ea86c355ef57b9cad26588c30f1c4eee5ccbaf21407beb6c85739132aa`; Python 3.14.4; Semgrep 1.177.0;
`tree_sitter` 0.26.0 / `tree_sitter_java` 0.23.5 / `tree_sitter_javascript` 0.25.0 /
`tree_sitter_typescript` 0.23.2.

**What this does and does not establish**, stated explicitly in the audit document: it is a
reviewable, test-backed boundary for every binding form actually checked against the pinned
grammars -- not a proof of correctness for every construct in three language grammars. A few rows
(JS/TS destructuring as its own future candidate, PEP 695 Python generics) are analyzed but not
independently executed, flagged as such rather than silently assumed safe. The audit found 4 MORE
bugs via systematic enumeration even after three prior rounds each claimed the known
counterexamples were closed -- this pattern itself is evidence that "no known bugs" and "no more
bugs" remain different claims, consistent with the standing caveat already on record.

**Still not done, explicitly deferred:** the combined C/D accept/stop gate, deterministic caching,
and any new budgeted model-inference pilot remain unimplemented and ungated on new approval,
unchanged from every prior round. Per the user's own framing: only after this audit should C/D
engineering begin, and only after THAT should new inference budget be allocated to test whether
probe feedback improves E2E success.


## 2026-10-13: binding-form audit review — counts and versions verified; audit closure remains open

Independent verification: 38/38 probe tests pass (full author-reported 82-test suite not rerun
here), frozen builder hash and parser/Python versions match, all 24 decision rows regenerate and
all 22 probe sources match their stored hashes. All 100 raw scans report Semgrep 1.177.0, both
targets scanned, no errors; recount is 94 passes, the same six misses, zero patched findings.
Coverage remains 11/24 eligible cases and 100/195 accepted episodes, with 95 uncovered.

The audit's closure claim is premature for three concrete reasons. (1) Its claimed-safe JS/TS
destructuring category is unsafe with a same-named candidate: `var token=1; var {token}=obj;
return token` becomes an accepted probe returning 1 instead of 99; the assignment form does too.
(2) Its unsupported-form boundary is not enforced: an explicitly out-of-audit Python decorator
referencing global `token` gets renamed with the body-local token, raising NameError. A prose
caveat is not candidate rejection. (3) The per-case artifact records selected names and generic
reasons, not exact edit spans, binding roles or independent edit validation; its script also
silently overwrites a fixed report despite claiming no writes. Several table dispositions lack
independent tests, not just the two limited rows highlighted in the summary. Probe test count
increased 32 to 38 (six), consistent with 76 to 82 overall, rather than eight added tests.

See `Binding_Form_Audit_Review_20261013.md` and its executable audit/JSON for exact reproductions,
bounded completion criteria and file accounting. These synthetic failures do not invalidate the
six observed misses. Enforce the supported/rejected boundary and complete exact per-case edit
review before declaring this audit complete. A narrower alternative is independently reviewed,
immutable case-specific probe artifacts for the development pilot, with an explicitly narrower
claim than a general safe renamer. Neither route requires exhaustive support for all syntax.
No implementation, tests or historical artifacts changed; no model calls, real scans or C/D
work occurred in this review.

## 2026-10-13: all three binding-form-audit review findings fixed and independently reproduced before/after; audit document and per-case artifact both corrected; coverage remeasured again with unchanged numbers

Both High findings were run directly against the pre-fix code first (confirmed broken, matching
the exact values reported), then re-run against the fix (confirmed closed).

**Finding 1 (destructuring same-name collision), fixed:** the prior "destructuring is confirmed
safe" claim was verified only against an UNRELATED candidate sitting next to a destructuring
binding -- never against the SAME name used both as the outer `var` declaration and as a
shorthand destructuring target (`var token=1; var {token}=obj; return token;`), which `var`'s
redeclaration semantics make perfectly valid JS. Confirmed: original returns 99 (the destructured
value), the pre-fix probe returned 1 (the stale initial value) -- the shorthand destructuring node
(`shorthand_property_identifier_pattern`) is a DIFFERENT type than plain `identifier`, so it never
got renamed while the declaration and return did. Fixed by extending `_ts_has_shorthand_property`
to also check this node type (unifying it with the pre-existing object-LITERAL-construction
shorthand check). Array destructuring and renamed-key object destructuring were separately
confirmed to remain safe even for a same-name collision (both bind via plain `identifier` nodes,
the same type as an ordinary reference) -- the fix is scoped to the one actually-broken form, not
a blanket destructuring rejection.

**Finding 2 (unenforced decorator boundary), fixed:** decorator expressions
(`FunctionDef.decorator_list`) are evaluated at def-time in the ENCLOSING scope, the identical
free-reference risk already fixed for parameter defaults -- but decorators are a separate AST
field `_py_names_in_signature` never walked. Confirmed: `@decorate(token)\ndef f(): token=1;
return token` with global `token=10` raised `NameError` at the decorator line itself (evaluated
while DEFINING `f`) after the pre-fix rename. Fixed by extending `_py_names_in_signature` to also
walk `func.decorator_list`. The audit document's "known gaps" section is corrected to state
explicitly that being listed as out-of-scope is not the same as being safely ignored -- the exact
lesson this finding demonstrates.

**Finding 3 (decision inventory, not edit audit), addressed:** `probe_binding_audit_report.py` is
rewritten to record, per case: SHA-256 of every input/output source; a line-level diff of
`vulnerable_function`->`vulnerable_probe` and `patched_function`->`patched_probe` (the exact edit,
independently reviewable without re-running the builder); and, for every ineligible case, a
per-raw-candidate classification naming the SPECIFIC check that rejected each candidate considered
(not just the overall generic reason string). Output is now written to a new timestamped file
every run (the prior version's "writes nothing" docstring was wrong -- it unconditionally
overwrote one fixed path). Also added five missing-link tests covering augmented/annotated
assignment, for/with targets, global declarations, Java parameter
role-change, and nested-block JS `var`.

**8 new tests added this round** (2 bug-reproduction + 1 confirmed-safe companion + 5 missing-link
tests for Finding 3's flagged rows), bringing `test_dev_probe.py` from 38 to 46 tests; full suite
now **90/90 passing**, rerun in full.

**Coverage remeasured again, new namespace, no new model calls:**
`_probe_coverage_20261013T090920800445Z`. Every number is **unchanged** across all three runs
this session (pre-audit, first-pass-fixes, second-pass-fixes): eligibility 11/24; 100/195 accepted
episodes covered; 94 pass, 6 fail, 0 patched findings; same 6 failing episodes by case/model/repeat
-- the latest destructuring/decorator fixes do not change the current real-case probes. Earlier
scope fixes did reduce real-case eligibility from 15 to 13 to 11, and the initial Python formatting
bug affected CASE-0134, so this unchanged result must not be generalized to every prior fix.

**Audit document corrected in place**, not silently rewritten: `Dev_Probe_Binding_Form_Audit_
20261013.md` now carries an explicit "Corrected 2026-10-13 (second pass)" note at the top, the
destructuring row is split into a corrected (fixed) shorthand row and a separate confirmed-safe
array/renamed-key row, a new decorator row is added, previously-unlinked test references are
filled in, and the frozen `dev_probe.py` hash is updated (with the first-pass hash preserved
alongside it for provenance of what the first review actually checked).

**Still not done, explicitly deferred:** the combined C/D accept/stop gate, deterministic caching,
and any new budgeted model-inference pilot remain unimplemented and ungated on new approval,
unchanged from every prior round.


## 2026-10-13: binding-audit closure for the fixed development subset

Independent verification confirms 46/46 probe tests (full author-reported 90-test suite not rerun
here), rejection of both shorthand-destructuring forms and the decorator counterexample, and the
updated frozen builder hash. All 24 edit-report rows regenerate. Input/output hashes and line
diffs were independently recomputed; exact identifier spans were checked without the builder's
replacement/isomorphism functions, and the edits for all 11 pairs were manually inspected and
assigned roles. Beyond recorded Python dedent/strip normalization, every change is the intended
identifier replacement. Valid unchanged patched sources remain byte-identical.

The latest 100 raw scans independently reproduce 94 passes, the same six misses and zero patched
findings; all use Semgrep 1.177.0 with both targets scanned. Eligibility is 11/24; coverage is
100/195 accepted episodes, leaving 95 uncovered. No inference gain is established.

The concrete findings and case-edit evidence gap are closed FOR THESE REVIEWED INPUTS. The audit
front matter was qualified to match its limitations: implemented exclusions are enforced, but
unknown forms are not automatically rejected. The next separately scoped task can be offline C/D
integration using reviewed/hash-bound probe artifacts, source/builder/parser hash checks, explicit
fallback/error behavior and the existing call ceiling. New inputs need fresh admissibility review.
No C/D work or inference was performed in this closure.

See `Binding_Form_Audit_Closure_20261013.md` and its audit/JSON for the manual case-role table,
exact spans, integration criteria and file accounting. Corrected two stale Tracking statements:
five missing-link tests (eight total added), not eleven; latest coverage is unchanged, but earlier
scope/formatting fixes did affect real cases. The append-only Correction Log records this correction.
No implementation, tests, dependencies, benchmarks or saved results changed; no model calls or real
Semgrep scans were made.

## 2026-10-13: C/D's combined acceptance gate and deterministic probe caching implemented and offline-tested -- the closure review's six specified scenarios, plus resource accounting, no model calls

Per the closure's "next engineering task" (implement C/D's combined acceptance gate and
deterministic caching, offline-test repair/acceptance/budget-exhaustion/ineligible-fallback/
scan-error/cache-mismatch behavior, before any new inference), built two new pure, importable
modules and a 20-test offline suite. Nothing in this round makes a model call or a live Semgrep
scan -- every test exercises the decision logic directly against synthetic evaluation dicts shaped
exactly like `diagnostic_v2.py`'s `scan()` and `probe_coverage_check.py`'s `scan_probe()` already
return, so the gate/cache can be dropped into the real episode loop later without changing either
scanner.

**`pipeline/combined_gate.py`** implements the corrected 4-path gate from
`Controlled_2x2_Protocol_Draft_20261012.md` §4 exactly:

```
A/B:                                   accept and stop on visible_correct
C/D, case HAS an eligible probe pair:  accept and stop on
                                        visible_correct AND vulnerable_probe_correct AND patched_probe_correct
C/D, case has NO eligible probe pair:  accept and stop on visible_correct alone (declared fallback)
```

`evaluate_probe_pair()` reduces two `scan_probe()`-shaped dicts to the three booleans the gate
needs, treating a probe scan error as a FAILED check (both `*_correct` forced False,
`probe_scan_error` flagged) -- never silently collapsed into "no eligible probe," per the
closure's central warning. `combined_decision()` short-circuits on `visible_correct` being False
WITHOUT requiring `probe_checks` at all (a real episode would never even run the probe scan for an
attempt whose visible check already failed, matching "fed into the REPAIR step only, after a rule
already passes the visible pair") -- this correction was found and fixed DURING test-writing, not
assumed from the design doc: an initial version required `probe_checks` whenever `probe_eligible`
was True regardless of `visible_correct`, which broke a realistic repair-then-accept trajectory
test. `summarize_episode_resources()` adds the explicitly-required "count additional scans and any
repair calls" accounting, correctly excluding a probe scan for any attempt whose visible check
never passed.

**`pipeline/probe_cache.py`** implements deterministic per-case probe caching keyed on THREE
hashes together: the case's own `vulnerable_function`/`patched_function` text AND `dev_probe.py`'s
own content hash -- binding cache validity to the specific REVIEWED builder version is what "use
the reviewed probe artifacts with hash checks" actually requires, not just the case inputs. A key
mismatch (changed input text, OR a different `dev_probe.py` revision) never silently serves the
stale cached result: default behavior rebuilds and overwrites the entry (`"mismatch_rebuilt"`
status, always visible to the caller, never silent); `strict=True` instead raises
`CacheMismatchError`, the "reject" alternative the spec also allows.

**20 new offline tests** in `pipeline/tests/test_dev_probe.py`'s sibling `test_combined_gate.py`,
covering all 6 of the closure's specified scenarios plus resource accounting and two full
multi-attempt episode-trajectory simulations (repair-then-accept across 3 attempts; full budget
exhaustion across 3 attempts) built by threading `combined_decision()` the same way a real retry
loop would, never calling real model/Semgrep code. Full suite now **110/110 passing** (90 prior +
20 new).

**Explicitly NOT done, matching the requested scope**: no wiring into `diagnostic_v2.py`'s live
`run_model_case()` retry loop (the gate/cache are tested as standalone, importable modules that
COULD be dropped in, but actually doing so is deferred until C/D inference is separately approved,
since there is no reason to touch the live model-calling code path before that budget decision).
No new model calls, no real Semgrep scans, no C/D inference -- all remain separately deferred
pending explicit approval, unchanged from every prior round.


### 2026-10-13 — Independent C/D gate/cache review: normal paths pass; cache and accounting gaps remain

Independently ran the 20 new gate/cache tests: all pass (0.12s); the author's full 110-test suite
was not rerun in this review. Retained executable reproductions in
`CD_Gate_Cache_Review_Evidence_20261013.json` confirm:

1. A modified cached probe body is returned as a strict-mode hit when the input/builder key is
   unchanged. Output artifacts are not verified against reviewed hashes. Strict cache misses
   also build unseen cases, so this is not yet enforcement of the reviewed development selection.
2. A TypeScript request can hit a JavaScript cache entry for the same case/text. Language and
   parser/runtime identities are absent from the key; the parser gap is established by code
   inspection, not by installing another parser version.
3. The real runner, with model/scanner dependencies mocked, makes two calls but only one visible
   scan after a decode failure followed by success. The resource helper reports two scans if
   both attempt decisions are retained, or misses the repair call if only parsed attempts count.
   Resource totals must come from actual events, not inferred decision counts.

The four ordinary gate paths are covered. Additional bounded hardening: reject unknown condition
values and out-of-range attempt numbers; retain eligibility/reason for failed as well as accepted
ineligible cases. A passing attempt 4/max 3 was accepted by the helper, but the current real loop
already bounds attempts to three: no actual budget overrun is claimed.

The two trajectory simulations are test-local loops; production C/D retry/feedback integration
remains absent. That integration can be implemented and verified offline before any inference
budget is approved. Next: reviewed-manifest/payload validation, complete cache identity, real
resource-event accounting, then mocked production-loop tests. No inference or new E2E result.

Full findings, remedies, limits and exact file accounting: `CD_Gate_Cache_Review_20261013.md`.
Only research records/audit artifacts changed; implementation, tests and historical evidence were
left intact. Audit command exited 0; zero real model calls and zero real Semgrep scans.

## 2026-10-13: all three CD gate/cache review findings fixed and independently reproduced before/after; real retry-loop integration built and tested with mocked model/scanner, per the review's own recommended next step

Both High/Medium findings were run directly against the pre-fix code first (confirmed broken,
reproducing the review's exact scenarios), then re-run against the fix (confirmed closed).

**Finding 1 (cache hits didn't verify payload integrity), fixed:** a cached entry's `payload`
text could be edited in place while its key stayed untouched, and `get_or_build_probe(...,
strict=True)` still returned the tampered text as a `"hit"` -- confirmed directly (replaced a
cached `vulnerable_probe` with `"return 999"`, still served). Fixed by storing a
`payload_sha256` alongside the key and verifying it on every read; a payload-integrity mismatch
is now treated exactly like a key mismatch (rebuild by default, raise in strict mode). Also added
a SEPARATE, stricter tier per the review's explicit request to "keep ordinary development cache
rebuilding separate from frozen experimental loading": `build_experiment_manifest_entry()` +
`load_probe_for_experiment()` in `probe_cache.py`, which validate a returned probe against a
frozen manifest of expected hashes/dispositions for the fixed 24-case selection, raising on ANY
deviation (language, input hash, builder/parser version, eligibility, or probe-text hash) --
`get_or_build_probe` remains the general-purpose, freely-rebuilding cache for ordinary
development work on new/changed cases.

**Finding 2 (cache identity omitted language/parser versions), fixed:** the key previously had no
`language` field and no parser/runtime version pins. Confirmed directly: caching an eligible
JavaScript probe, then requesting the same case/text as TypeScript in strict mode, returned
`"hit"` with the JS result. Fixed by adding `language` plus the four tree-sitter package versions
and the running Python version to the key; any of these changing now invalidates the cache the
same way an input/builder-hash change already did.

**Finding 3 (resource accounting assumed one scan per attempt), fixed:** `diagnostic_v2.py`'s
real loop only scans when generation actually produces a parseable rule -- a decode/parse failure
consumes a model call and a repair step but never reaches `scan()` at all. The prior
`summarize_episode_resources(decisions)` could not represent this without either overcounting
visible scans or undercounting repairs. Fixed by introducing `AttemptEvent` (an explicit
per-attempt record distinguishing "generation failed, no scan ran" from "generation succeeded, a
decision was made") and rewriting the summarizer to operate on a list of these; also made
`probe_scanner_invocations` an explicit caller-supplied field per event rather than inferred from
`probe_checks`, since `evaluate_probe_pair` is deliberately agnostic to whether the caller used
one combined scan or two separate ones (the review's "these are different quantities" point).

**API-boundary hardening also added** (the review's two "observations," not demonstrated
production failures, but now enforced rather than merely true by convention): an unrecognized
`condition` string now raises instead of silently behaving like A/B; `attempt > max_attempts` now
raises on the ACCEPT path too, not just the failure path. `GateDecision` now carries
`probe_eligible` independently of `is_fallback`, so failed-and-ineligible episodes can still be
correctly counted for eligibility coverage (the review noted `is_fallback` alone is False for
those by design).

**Real retry-loop integration built and tested**, per the review's explicit recommended next
step ("wire these decisions into the actual retry and feedback path... this offline work can
precede inference-budget approval"): new `diagnostic_v2.run_model_case_cd()` -- a SEPARATE
function, not a modification of `run_model_case()`, which remains byte-for-byte untouched (its
own 20-test regression suite, `test_diagnostic_regressions.py`, reruns unchanged, confirming A/B
truly stay unchanged rather than merely being asserted to). The new function follows the exact
same mocking pattern `test_diagnostic_regressions.py` already established for `run_model_case()`
(monkeypatch the module-level `scan`, inject a fake LLM object) -- no new testing convention
invented. 9 new integration tests in `test_run_model_case_cd.py` verify, through the REAL
generation/scan/probe-scan loop (not the standalone simulation): probe-failure feedback reaches
the next `generate_rule()` call; all-checks-pass accepts and stops on the first attempt; budget
exhaustion consumes exactly 3 attempts and never accepts; an ineligible case falls back to
visible-only and is explicitly flagged, with the probe scanner never even called; a probe scan
error triggers repair (never a fallback) through to exhaustion; hidden scans never run until
generation finishes (`["visible", "probe", "hidden", "hidden"]`, exactly once each); and the
decode-failure-then-success resource-accounting scenario (Finding 3) reproduces correctly through
the real runner, not just the synthetic simulation.

**23 new tests total this round** (14 for the cache/gate fixes in `test_combined_gate.py`, 9 for
the real-runner integration), full suite now **133/133 passing** (110 prior + 14 + 9).

**Still not done, explicitly deferred:** any new C/D model-inference pilot remains unimplemented
and ungated on new approval -- nothing in this round spent inference budget or ran a real Semgrep
scan. The frozen experiment manifest itself (actual entries for the real 24-case development
selection, built via `build_experiment_manifest_entry()`) has not yet been generated and committed
-- the manifest MECHANISM is built and tested, but no concrete manifest file exists yet; that is
the natural next step before any real C/D run, not performed here since it wasn't explicitly
requested this round.


### 2026-10-13 — C/D integration follow-up: prior findings closed, scan-boundary gaps reproduced

Independently verified 63 focused tests pass (34 gate/cache + 9 runner + 20 existing diagnostic
regressions; 1.19s). Full author-reported 133-test suite not rerun. Corrected the immediately
preceding entry's arithmetic in place: 110 + 14 + 9 = 133, hence 23 new tests, not 29.

The previous three findings are closed by direct executable checks: edited cache payloads are
rejected, even a recomputed cache-local checksum cannot bypass the independent expected manifest,
language/parser drift is rejected, and the real C/D loop counts the decode-failure trajectory as
2 generation calls / 1 visible scan / 1 probe scan / 1 repair call.

New integration findings, all reproduced offline:

1. A manifest-validated probe object is independent of the paths actually scanned. After changing
   a materialized probe file, the runner still passes the changed bytes to the scanner and accepts
   a mocked passing result. Bind and hash actual per-run scan inputs, not just in-memory objects.
2. `probe_result=None` silently takes the ineligible fallback and accepts visible success. Require
   explicit typed eligibility, verified case/language identity and a retained rejection reason.
3. A module-level `dev_probe` import now brings probe/tree-sitter dependencies into A/B, contrary
   to the protocol. Fresh-process checks verify both import presence and failure when those
   dependencies are synthetically unavailable. Keep the import inside the C/D path.

The real retry function is implemented, but no production adapter yet joins strict manifest
loading, immutable materialization, construction-mode selection, provenance and CLI dispatch.
Also reproduced a probe TimeoutExpired escaping after one mocked generation without an
attempt/episode record. Existing raw capture can independently preserve the call; add a recorded
failure/interruption policy and budget-preserving handling before any launch/resume procedure.

Next: resolve the bounded integration findings, build the actual manifest against reviewed case/
probe hashes, and verify the full adapter offline. No further renamer audit or inference was
performed. Full findings, limits, remedies and file accounting:
`CD_Integration_Followup_Review_20261013.md`; retained executable evidence and audit log linked there.
Only research records and audit artifacts changed in this review; implementation/tests and
historical results remain intact. Zero real model calls and zero real Semgrep scans.

## 2026-10-13: all four integration follow-up findings fixed and independently reproduced before/after; test-count arithmetic corrected

All four issues (3 Findings plus the probe-timeout gap) were run directly against the pre-fix
code first (confirmed broken, matching the review's exact reproductions), then re-run against the
fix (confirmed closed).

**Finding 1 (validated probe text not bound to actual scanned files), fixed:** `run_model_case_cd`
previously only checked `probe_result.eligible`/`probe_paths is not None`, never the actual bytes
at those paths. Confirmed directly: a probe file edited in place after materialization (bypassing
the validated `probe_result` object entirely) still reached the mocked scanner and the episode
was accepted. Fixed by hashing and comparing the files' actual text against
`probe_result.vulnerable_probe`/`.patched_probe` ONCE, before any generation call -- a mismatch now
raises `ProbeMaterializationError` immediately. The verified hashes are recorded on the episode
(`verified_probe_hashes`) for provenance. The existing tests' fake `/dev/null/...` probe paths
(which nothing ever read, so they could never have caught this) were replaced with a
`_materialize_probe()` helper writing real files under `tmp_path`.

**Finding 2 (unresolved probe state became an accepted fallback), fixed:** `probe_result=None`
previously fell through to the same code path as a genuine `ProbeIneligible`, generating a rule,
skipping probe scanning, accepting on visible success, and reporting `probe_fallback_used=True`
-- indistinguishable from a real reviewed ineligibility decision. Confirmed directly. Fixed: the
function now requires `probe_result` to be a genuine `ProbeResult` or `ProbeIneligible` instance,
raising `ValueError` immediately (before any model call) for anything else, and additionally
validates that `probe_result.case_id`/`.language` match the episode's own `cid`/`manifest[cid]
["language"]` -- a probe resolved for the wrong case can no longer be silently used. The episode
record also now persists `probe_ineligible_reason` (previously dropped).

**Finding 3 (A/B importing the probe module), fixed:** moved `combined_gate`/`dev_probe` imports
from module level to LOCAL (inside `run_model_case_cd()` only). Confirmed directly in a fresh
subprocess: `import diagnostic_v2` alone no longer puts `dev_probe` or `tree_sitter` in
`sys.modules`, closing the contradiction with Section 5's "Conditions A and B's code path must
not import the probe module at all" -- `run_model_case()`'s own function body was never touched,
but the review correctly noted that alone doesn't preserve the MODULE's import isolation.

**Probe timeout gap, fixed:** an injected `subprocess.TimeoutExpired` (what the real
`probe_coverage_check.scan_probe`'s own `subprocess.run(timeout=120)` raises) previously
propagated uncaught, exiting the function after one generation call with neither
`attempt.json` nor `episode.json` written -- confirmed directly. Fixed by catching
`TimeoutExpired` around the probe-scan call and converting it into an ordinary `scan_ok=False`
probe-scan-error result, flowing through the EXISTING error-handling path (recorded, retried
within budget, no reset of consumed attempts).

**16 new/updated tests** in `test_run_model_case_cd.py` (9 existing tests updated to use real
materialized probe files instead of fake `/dev/null/...` paths that could never catch Finding 1;
7 new tests directly reproducing each of the four issues through the real runner). Full suite now
**140/140 passing** (133 prior + 7 net new).

**Test-count arithmetic corrected** (the review caught this, independently verified here): the
prior round's "29 new tests" was wrong; 110 to 133 is **23** (14 gate/cache + 9 runner
integration), matching 14+9 exactly. This entry's own counts were checked against
`pytest --collect-only` before being written down, not asserted from memory, given this is the
second such arithmetic slip this session.

**Still not done, explicitly matching the review's own stated ordering:** the concrete frozen
manifest for the real 24-case development selection (actual entries built via
`build_experiment_manifest_entry()`, not just the tested mechanism) has not been generated: `main()`
still dispatches only `run_model_case` -- no production caller yet connects the manifest loader,
materialization, and `run_model_case_cd()` into one adapter that also binds condition C to
original-prompt construction and D to typed-JSON construction. Both remain the explicit next steps,
not performed this round. No model calls, no real Semgrep scans, no C/D inference.


### 2026-10-13 — C/D materialization follow-up: three fixes closed, one verification gap remains

Independently executed 70 affected tests: all pass (6.27s). Separately collected 140 tests across
seven named files; collection establishes inventory, not 140 executed passes. A six-file audit
collection contains 135; the other five are validator-classification tests. The initial broader
collection failed on the known standalone statistics script's import-time SystemExit; its failed
command log is preserved, and no implementation was changed to accommodate it.

Direct checks close unresolved-state/identity rejection, A/B import isolation (fresh subprocess
with probe imports prohibited), and timeout handling, including three consecutive timeouts
recorded through budget exhaustion. Ineligibility reason is retained even across three decode
failures. The pre-existing materialized-file mismatch is rejected before generation/scanning.

One part of that file-verification finding remains: the runner checks once before generation,
then reopens the paths without rechecking. Changing a probe during generation or between attempts
still reaches the mocked scanner and accepts its passing result, while recording the old hash.
Also, read_text() normalizes CRLF, so its re-encoded hash is not necessarily the actual file-byte
hash. These are synthetic reproductions, not evidence of corrupted historical outcomes.

Complete this boundary alongside the planned adapter: exclusively owned immutable per-run
materialization, raw-byte verification before each probe invocation, actual per-invocation hashes,
and a recorded integrity failure that preserves consumed calls. Then build the concrete manifest
against reviewed sources/probes and wire the full CLI path offline. No additional renamer audit or
inference is required for those steps. Full evidence, remedies, audit hiccups and file accounting:
`CD_Materialization_Followup_Review_20261013.md`. Implementation/tests unchanged by the review;
zero real model calls and zero real scans.

## 2026-10-13: materialization-verification gap fixed and independently reproduced before/after -- byte-exact comparison, exclusively-owned snapshot, re-verified before every scan

All three reproductions were run directly against the pre-fix code first (confirmed broken,
matching the review's exact scenarios), then re-run against the fix (confirmed closed).

**Scenario 1 (file changed during generation), fixed:** the original startup-only check verified
files once, before `load_case`/generation ever ran -- confirmed directly that changing the
caller-supplied probe file during the mocked `generate_rule()` call let the scanner receive the
changed bytes, and the episode was still accepted.

**Scenario 2 (file changed between attempts), fixed:** confirmed directly that replacing the
caller-supplied file after attempt 1's probe scan let attempt 2 scan different bytes, while the
episode's `verified_probe_hashes` kept reporting the original, now-stale hash.

**Scenario 3 (CRLF vs. LF hash disagreement), fixed:** the prior comparison used `Path.read_text()`,
which universal-newline-translates CRLF to LF -- confirmed directly that a CRLF-written file passed
the text comparison while its real on-disk bytes hashed differently from the recorded (LF) hash.

**Fix, all three closed by one coherent change:** switched every comparison from `read_text()` to
`read_bytes()` (closing Scenario 3 outright -- a CRLF file now correctly fails the very first
check, raising `ProbeMaterializationError`, rather than silently passing). For Scenarios 1/2,
after the initial byte-exact verification, the verified bytes are copied into a freshly-created,
exclusively-owned snapshot directory (`out/<cid>/_probe_snapshot/`, created `exist_ok=False` under
the run's own fresh output directory) -- every subsequent probe scan, in every attempt, reads from
THIS snapshot, never the caller-supplied `probe_paths` again, so a change to the original file
after materialization has no effect by construction. Each attempt additionally re-verifies the
snapshot's own bytes immediately before scanning it (defensive, per the review's explicit request,
even though nothing else should be writing to it); any detected drift is treated as an ordinary
probe-scan error -- the SAME established, already-tested path a probe timeout uses -- rather than
inventing a new fallback or silently granting a fresh attempt budget, exactly matching the review's
"without converting it into reviewed ineligibility or giving the episode a fresh budget."

**3 new tests** reproducing each scenario directly through the real runner. Full suite now
**143/143 passing** (140 prior + 3 new) -- verified via `pytest --collect-only` as well as a full
run, not computed from memory, given this session's two prior arithmetic slips.

**Still not done, matching the review's own explicit ordering:** the concrete frozen manifest for
the real 24-case selection and `main()`'s CLI adapter (binding the manifest loader, snapshot
materialization, `run_model_case_cd()`, and construction-mode selection for C vs. D into one
production path) remain unimplemented -- both are the acknowledged next steps, not performed this
round. No model calls, no real Semgrep scans, no C/D inference.


### 2026-10-13 — Snapshot review: prior materialization scenarios verified as fixed; two bounded follow-ups

Independent focused execution: 73 tests passed (1.47s); separately collected 143 tests across
seven files. Full author-reported 143-pass execution not rerun here. The original-path changes
during generation/between attempts now leave the snapshot bytes and recorded hashes unchanged;
CRLF disagreement is rejected before generation. All three previous scenarios are verified as
fixed, with fresh executable evidence.

Two new deterministic snapshot issues were reproduced:

1. Different input directories containing the same basename map to one snapshot destination.
   The patched write overwrites the vulnerable bytes, so the runner spends three mocked generation
   calls and fails integrity checks without ever invoking the probe scanner. Use distinct
   role-specific destinations, independent of caller basenames. Current coverage files already
   use distinct names, so no historical measurement impact is asserted.
2. The new drift branch still sets scanner_invocations=1 although it skips scan_probe_fn.
   Both the collision and an independent snapshot-drift reproduction yield zero actual probe
   invocations but three reported probe_scans. Set the counter only when entering the scan call;
   timed-out calls still count, rejected integrity checks do not.

These are small corrections to carry into the pending offline manifest/CLI handoff, not another
renamer audit. Full evidence, remedies, limits and file accounting: `CD_Snapshot_Review_20261013.md`.
No model calls, real scans, implementation/test changes or historical artifact changes by this
review. The concrete reviewed manifest and production CLI adapter remain outstanding.

## 2026-10-13: both snapshot review findings fixed and independently reproduced before/after

Both were run directly against the pre-fix code first (confirmed broken, matching the review's
exact reproductions), then re-run against the fix (confirmed closed).

**Finding 1 (same-basename collision), fixed:** both snapshot destinations were previously built
from `Path(input_path).name` in the SAME directory -- confirmed directly that
`input_vulnerable/function.py` and `input_patched/function.py` (distinct, valid, independently
supplied paths that merely share a basename) collided into one file, with the second write
silently overwriting the first; the snapshot then contained only the patched content under both
roles, and every attempt failed its own integrity re-check. Fixed with role-specific
subdirectories (`_probe_snapshot/vulnerable/`, `_probe_snapshot/patched/`), making a cross-role
collision structurally impossible regardless of caller-supplied names.

**Finding 2 (integrity-skipped attempts counted as scans), fixed:** `scanner_invocations = 1` was
previously set unconditionally after the drift/real-scan branch, even when the drift branch
deliberately never calls `scan_probe_fn`. Confirmed directly (via the Finding 1 collision, and
separately via a forced snapshot corruption): zero actual scanner calls were made, but
`resource_accounting.probe_scans` still reported 3. Fixed by moving the increment inside the
real-scan branch only (still counting a timeout as an entered call, since the scan WAS attempted
there) -- the defensive integrity guard skipping a scan is no longer miscounted as one.

**2 new tests**, full suite now **145/145 passing** (143 prior + 2 new), confirmed by both a full
run and `pytest --collect-only`.

**Still not done:** the concrete frozen manifest for the real 24-case selection and `main()`'s CLI
adapter remain unimplemented, per the review's own stated ordering. No model calls, no real
Semgrep scans, no C/D inference.

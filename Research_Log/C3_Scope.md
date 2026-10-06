# C3 (Homogeneous Multi-Agent) — Scope

Written 2026-10-04, grounded in design Sections 17.1-17.3, 18.3, 20. Covers what C3 concretely
requires, what's reusable from Phase 3's role-screening work, and two real design decisions that
need resolving before building, not assuming silently.

## Correction to an earlier framing

Section 18.3 is explicit: "The same underlying model performs all LLM roles with separate role
prompts and contexts." **C3 uses ONE model for all 5 roles** — not the per-role best models Phase 3
just assigned. The per-role table (Section 18) names THAT as C4-A ("Best pilot model assigned to
each role / Model specialization"), a separate, later configuration. Phase 3's screening work isn't
wasted — it's exactly what C4-A needs — but it doesn't directly determine C3's model choice.

## The workflow, exactly as diagrammed (Section 17.1)

```
Patch evidence -> Patch Analysis Agent -> Rule Generation Agent -> Syntax Review Agent
  -> Semgrep Executor -> Semantic Review Agent -> Accepted?
       -> No: Rule Repair Agent -> back to Syntax Review Agent (loop)
       -> Yes: Final rule -> Hidden Evaluator
```

Semgrep Executor and Hidden Evaluator are deterministic (real Semgrep runs), not LLM calls — this
part is already fully built (`RuleValidator`, `evaluate_case_bundle()`), reused unmodified.

Patch Analysis and Rule Generation each run ONCE, before the loop. Everything from Syntax Review
onward can repeat across repair rounds.

## Open decision 1 — which single model plays all 5 roles (C3-S vs C3-E)? RESOLVED

**Decided (user, 2026-10-04): by parameter scale.** C3-S = `qwen2.5-coder:32b`. C3-E =
`qwen2.5-coder:7b-instruct`.

Section 18.3's table names two variants: C3-S (strongest model) and C3-E (efficient model), to
isolate "does role separation help" from "does model scale matter," then compare each to C2 under
the same model/budget (Section 18.3: "Compare C3-S directly with C2 using the same model and
budget" — meaning C2 needs to be re-run with whichever model C3-S uses, since the existing C2 run
used all 8 primary models, including whichever gets picked here).

Phase 5's primary MCC ranking (Implementation_Log 12.31) is the natural basis for this pick, since
Section 19's own instruction ("follow measured pilot performance") extends naturally to this choice
too. Two reasonable readings of "strongest" / "efficient":

- **By measured rank**: strongest = `qwen2.5-coder:7b-instruct` (#1 MCC, 0.613). But it's also one
  of the smallest models in the primary set (7B) — an odd fit for "strongest" if that's meant to
  track scale/cost, not just rank.
- **By parameter scale** (matching "efficient" clearly meaning lower-cost): strongest =
  `qwen2.5-coder:32b` (the only 32B model in the primary set, #4 MCC at 0.589 — still
  close to top), efficient = `qwen2.5-coder:7b-instruct` (7B, and also the #1 measured performer).

**Recommendation**: the second reading. It gives a cleaner experimental contrast (scale varies,
not just an arbitrary rank cutoff), and sets up a genuinely interesting secondary finding either
way — if C3-E (the smaller model) matches or beats C3-S (the larger one), that's itself worth
reporting, and it would be consistent with Phase 5's own finding that raw MCC rank doesn't track
model size. This is a real choice, not an engineering detail — flagging for sign-off before
building either variant.

## Open decision 2 — the literal workflow doesn't fit the Section 20 budget as written. RESOLVED

Worked this out directly rather than assuming the Rule Repair Agent's own "stop after three repair
rounds" description (Section 17.2) is compatible with Section 20's `max_llm_calls: 6`:

```
First pass (no repairs): Patch Analysis(1) + Rule Generation(1) + Syntax Review(1) + Semantic Review(1) = 4 calls
Remaining budget: 6 - 4 = 2 calls
One repair round WITH a second full Semantic Review pass: Rule Repair(1) + Syntax Review(1) + Semantic Review(1) = 3 calls -- does NOT fit
One repair round WITHOUT a second Semantic Review call (Semgrep Executor's own deterministic result used as the accept/reject check instead): Rule Repair(1) + Syntax Review(1) = 2 calls -- fits exactly
```

Under the stated 6-call budget, **at most 1 repair round fits** — and only if that round's
accept/reject decision after repair comes from the Semgrep Executor's own deterministic pass/fail,
not a second Semantic Review LLM call. Three repair rounds (what Section 17.2 describes for the
Rule Repair Agent in isolation) would need at least 10 calls under this accounting, nearly double
the budget. This is the same kind of ambiguity C2's call-accounting had — resolved there by deriving
the answer from the budget numbers themselves (Implementation_Log 12.36) — and the same approach
applies here.

**Decided (user, 2026-10-04): 1 repair round, skip the 2nd Semantic Review call.** Exact call
sequence: (1) Patch Analysis, (2) Rule Generation, (3) Syntax Review [round 0], (4) Semantic Review
[round 0, real Semgrep execution on the original pair happens between 3 and 4, deterministic] ->
accepted? if yes, done (4 calls used, 2 of slack). If no: (5) Rule Repair, (6) Syntax Review [round 1]
-> real Semgrep execution on the original pair (deterministic, this IS the final accept/reject check
for round 1, no further LLM call). Exactly 6 calls in the worst case, matching Section 20 precisely
with zero slack rather than silently exceeding it. Documented explicitly as a design choice, same as
C2's call-accounting resolution.

## What's reusable from Phase 3's role-screening work

- **Syntax Review**: `pipeline/run_syntax_review.py`'s prompt and response-parsing are directly
  reusable — same role, same expected output (diagnosis + optional corrected rule).
- **Semantic Review**: `pipeline/run_semantic_review.py`'s prompt structure is close, but its
  response needs adapting — Section 17.2 wants "structured repair instructions," not just a
  category label. The screening version only asked for a classification; C3 needs that classification
  PLUS enough structured detail for the Rule Repair Agent to act on.
- **Rule Repair**: `pipeline/run_rule_repair.py`'s prompt is close, but Section 17.2 says repair
  should use "deterministic diagnostics AND review output" — i.e., both the real Semgrep error and
  the Semantic Review Agent's structured instructions, not just the raw error alone as the screening
  version did.
- **Hidden Evaluator / Semgrep Executor**: fully reused, unmodified (`RuleValidator`,
  `evaluate_case_bundle()`).

## What's genuinely new

- **Patch Analysis Agent prompt**: directly reusable from `pipeline/run_patch_analysis.py`'s
  candidate prompt almost as-is (same role, same "structured vulnerability specification" output) —
  the one piece of Phase 3 work that transfers with the least modification.
- **Rule Generation Agent prompt**: genuinely new — must consume the Patch Analysis Agent's
  structured spec as input (not the raw diff directly, which is what every other generation path in
  this project has used so far, including C1/C2/Autogrep).
- **The orchestration loop itself**: new, wiring all of the above together with the budget
  resolution above, reusing case-loading/GPT-Lab-calling infrastructure the same way `run_c2.py` did.

## Recommended build order

1. Resolve the two open decisions above (model choice, call-budget interpretation).
2. Build the Patch Analysis + Rule Generation prompt pair first (reusing most of Phase 3's work),
   verify on a couple of cases without the repair loop yet.
3. Add the repair loop (Syntax Review -> Semgrep Executor -> accept/reject -> Rule Repair -> back
   to Syntax Review), verify the budget accounting matches the resolution above exactly.
4. Run C3-E (the smaller/cheaper model) first as the cheaper, faster verification pass; then C3-S.
5. Once both exist: re-run C2 with whichever model C3-S uses (if different from what C2 already
   ran), for the actual "compare C3-S directly with C2 using the same model and budget" test
   Section 18.3 asks for.

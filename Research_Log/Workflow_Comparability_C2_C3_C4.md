# Step 5 — Workflow Comparability: C2 vs C3 vs C4

Written 2026-10-06 as part of the methodological audit (`Correction_Log.md`). Required output:
"one configuration table showing both shared settings and differences." Every row below is verified
directly against `pipeline/run_c2.py`/`run_c3.py`/`run_c4.py`'s actual code, not inferred from the
design document's intent — several real, previously-unstated asymmetries were found this way.

## The comparison table

| Dimension | C2 (iterative single agent) | C3-S / C3-E (homogeneous multi-agent) | C4-A / C4-B (heterogeneous multi-agent) |
|---|---|---|---|
| **Models involved** | 1 (same model every call) | 1 (same model plays all 5 roles) | 4 (C4-A) or 2 (C4-B) distinct models across the 5 roles |
| **Generator input** | The FULL original prompt: raw diff text, vulnerable/patched function text, CVE/CWE metadata, imports, containing-class context (`LLMClient._build_prompt()`, identical to the primary benchmark's own prompt) | A 4-field STRUCTURED SPEC (mechanism/source/sink/fix) produced by a separate Patch Analysis call — the Rule Generation call never sees the raw diff or CVE/CWE metadata directly | Same structured spec as C3 (Rule Generation's prompt is imported unchanged from `run_c3.py`) |
| **Review stages before first accept check** | None — the model's own output is checked directly against Semgrep | Syntax Review (dedicated call) -> Semgrep Executor (deterministic) -> Semantic Review (dedicated call) | Same 3-stage sequence, different models per role |
| **Round-0 acceptance gate** | `validate_rule()` alone (deterministic: rule executes cleanly AND correctly discriminates the visible pair) | **Semantic Review's own "ACCEPTED" verdict AND `validate_rule()`** — a strictly stricter, two-part gate | Same dual gate as C3 |
| **Round-1 (post-repair) acceptance gate** | `validate_rule()` alone (same as round 0 — C2 has no separate agent-verdict step at any round) | `validate_rule()` alone (the 2nd Semantic Review call is deliberately skipped — Implementation_Log 12.50 — so round 1's gate matches C2's gate exactly) | Same as C3 |
| **Repair opportunities** | **Up to 3 repair rounds**, each fed the PREVIOUS round's real Semgrep validation error as feedback (`error_feedback` passed to `LLMClient.generate_rule()`) | **Exactly 1 repair round**, fed BOTH the real Semgrep error AND the Semantic Review agent's own repair instructions | Same as C3 (1 round, same dual feedback) |
| **Enforced budget — calls** | `max_llm_calls: 6` (1 initial + up to 3 repair rounds, 1 call each) | `max_llm_calls: 6` (up to 6 calls: analysis, generation, syntax review, semantic review, repair, syntax review round 1) | Same as C3 |
| **Enforced budget — cumulative input/output tokens** | Tracked and enforced every round (`max_combined_input_tokens: 30000`, `max_combined_output_tokens: 6000`) | **NOT tracked or enforced at all** — only a per-call `max_tokens=2048` output cap exists, with no cumulative check across the episode | Same as C3 — not enforced |
| **Enforced budget — wall clock** | Tracked and enforced (`max_wall_clock_minutes: 10`) | **NOT tracked or enforced** | Same as C3 — not enforced |
| **Hidden-evaluation protection (§17.3)** | N/A at generation time — only the ORIGINAL vulnerable/patched pair is ever checked during the episode; hidden variants are scored afterward, identically across all three configurations | Same | Same |

## What this means for interpreting C2-vs-C3 and C3-vs-C4 comparisons

Three genuine, confirmed asymmetries exist between C2 and C3/C4 beyond "one model doing everything"
vs "roles split across calls":

1. **Different generator input.** C3/C4's Rule Generation call works from a compressed, agent-authored
   summary, never the raw diff. If that summary is incomplete or wrong (documented failure mode,
   §24's "incorrect analysis propagated to later agents"), Rule Generation is handicapped by
   information loss that has nothing to do with "role separation" as a mechanism — it's an input
   quality difference. **Any C2-vs-C3 quality gap could be partly or wholly attributable to this,
   not to review/repair roles existing.** This was not previously stated plainly anywhere in
   `Paper_Draft_Notes.md`.
2. **Unequal repair opportunity.** C2 gets 3 repair rounds; C3/C4 get 1. This is NOT a matched
   comparison of "same repair budget, different role structure" — C2 structurally gets 3x the
   self-correction chances. Section 20's own budget resolution (Implementation_Log 12.50) forced
   this asymmetry by call-count arithmetic (3 repair rounds would need 2 calls/round in C3/C4,
   overshooting the shared 6-call cap) — a real, load-bearing design constraint, not an oversight,
   but its consequence for comparability was not previously stated as plainly as it should be.
3. **A stricter round-0 gate in C3/C4.** Requiring BOTH a correct agent verdict AND the deterministic
   check (vs. C2's deterministic-only gate) means some of C3/C4's lower round-0 acceptance rate is
   mechanically expected from the gate itself, independent of rule quality.

**Conclusion for the manuscript** (per the audit's explicit instruction): C2, C3, and C4 should be
presented as comparisons of **complete, differently-configured workflows**, not as an isolated test
of "role separation" as a single causal variable. The design document's own framing ("compare C3-S
directly with C2 using the same model and budget," §18.3) is accurate for MODEL and CALL-COUNT
budget, but not for generator input, repair-round count, or acceptance-gate strictness — none of
which were actually held constant. Every causal claim in `Paper_Draft_Notes.md` attributing a
C2-vs-C3 or C3-vs-C4 difference to "role separation" or "interface mismatch" specifically (rather
than "this configuration, as a whole, performs differently from that one") should be explicitly
hedged as a hypothesis, consistent with what Section 22's statistics already show (no significant
difference in most of these comparisons regardless).

## Everything genuinely held constant across all three

- The underlying model(s) available to choose from, and the specific models used in the matched
  comparisons (C2 uses the same model tags as C3-S/C3-E; C4-B reuses that same pair).
- The deterministic acceptance check itself (`RuleValidator.validate_rule()`, Autogrep's own,
  unmodified) whenever it IS the gate (round 1 for all three; the shared half of C3/C4's round-0
  dual gate).
- The hidden-evaluation bundle and protection (§17.3) — none of the three ever see the hidden
  transformed/benign samples during generation or repair.
- The `max_llm_calls: 6` ceiling (the one budget dimension genuinely enforced identically in all
  three).
- The final scoring methodology (ESR/MCC/VGR/FPR, `evaluate_case_bundle()`), now further corrected
  per Finding 1.

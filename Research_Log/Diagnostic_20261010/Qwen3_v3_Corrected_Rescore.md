# Qwen3 v3: rescore under the corrected evaluator (no new inference)

Answers one question in isolation before testing any workflow change: is `qwen3_v3`'s 6/24
complete-success result an artifact of the evaluation bugs found in this diagnostic campaign, or
does it hold even once those bugs are fixed? Three corrections applied together, for the first time
as one evaluator, entirely offline (no new model calls):

1. **`.tsx` staging for `CASE-0298`** — rescan the already-saved `attempt_1/rule.yml` (the only
   attempt that ever parsed; attempts 2/3 never produced a valid rule, confirmed in
   `Qwen3_v3_Review.md`) against byte-identical `.tsx` copies instead of the frozen `.ts` files.
2. **Merged location ranges for `CASE-0163`/`0173`/`0239`/`0235`** — re-derive
   `variant_vulnerable_2` location-correctness from the already-recorded `finding_lines` using the
   Finding-1 + v2-additive ranges together. Pure re-read of existing data, no rescan.
3. **Acceptance gate strengthened**: "legacy" acceptance (any finding on vulnerable, none on
   patched, location-blind) replaced by "corrected" acceptance (vulnerable outcome must be `TP` —
   i.e. location-correct — and patched outcome must be `TN`). Applied to all 24 cases, not just the
   4-5 touched by fixes 1–2, since a location-blind "accept" could in principle have been masking a
   wrong-location match anywhere.

Implementation: `pipeline/rescore_qwen3_v3_corrected.py`. Output: `results/diagnostic_20261010/qwen3_v3_corrected_v1.json`.

## Result

**Complete-success count: 6/24, both conditions — identical to the original, uncorrected report.**

The only case whose status changes at all is `CASE-0081`: it loses `legacy_accepted` (`True` →
`corrected_accepted`: `False`). This is correct, not a regression — its only "detection" was at line
10, outside the annotated vulnerable range (confirmed directly against the episode record in the
prior review), so it was never a genuine match. It was never a complete success either way, so the
6/24 count doesn't move.

`CASE-0298` now scans cleanly under the `.tsx` fix (`scan_ok: true`, no more syntax error) — but the
rule itself still misses the real vulnerability (`original_vulnerable: FN`) and adds two false
positives (`original_patched: FP`, `variant_safe: FP`). Same conclusion as the 16-model replay
(`Research_Log/Correction_Log.md`'s 2026-10-11 entry): fixing the file-extension bug changes *why*
the case fails, not *whether* it fails.

## What this establishes, and what it doesn't

- **Establishes**: the three confirmed evaluation-mechanics bugs found in this diagnostic campaign
  are not responsible for any part of `qwen3_v3`'s 6/24 result. Evaluation correctness and
  generation quality are now known to be separable questions for this specific run, with the answer
  "evaluation corrections contribute zero" for all three fixes checked.
- **Does not establish**: that these are the *only* evaluation issues that could exist, or that no
  future evaluation fix could ever move this number. It only speaks to the three specific,
  independently-verified bugs checked here.
- **Next question** (a different, generation-side change, not an evaluation fix): does a revised
  prompt — explicitly permitting composite/taint rules, with better treatment of vulnerability
  mechanism and structural variation — recover any of the 18 remaining failures? That requires new
  model calls and is tracked separately.

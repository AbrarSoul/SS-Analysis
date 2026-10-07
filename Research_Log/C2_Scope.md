# C2 (Iterative Single Agent) — Scope

Written 2026-09-30, after reading design doc Sections 17–20 in full (previously only partially read).
This corrects one thing I told the user earlier in the session: I'd said C2 was blocked on Phase 3
(the 50-case development set) because its budget is tied to C3's. That's not quite right — read
carefully, Section 20 already specifies a concrete recommended budget directly, with no dependency
on empirical role-screening data. **C2 does not need Phase 3.** What Phase 3 actually gates is C3/C4's
per-role model assignment (Section 19), which is a different, later problem. This document is the
corrected scope.

## What C2 actually is

Design Section 18.2: *"The same model generates, interprets Semgrep feedback, and repairs its rule.
Give it the same call and token budget as C3."* One model, one continuous role, iterative — as
opposed to C1 (one shot, no feedback) and C3 (the same task split across multiple specialized agent
roles, each a separate call/context: patch analysis, generation, syntax review, semantic review,
repair — Section 17.2).

## This is NOT the same thing as Phase 5's "autogrep" condition

Phase 5 already has a model-generates-then-repairs-with-feedback condition, and it's tempting to treat
that as "C2 already done." It isn't, for two concrete reasons:

1. **No enforced budget.** Phase 5's autogrep condition uses Autogrep's own retry loop: up to 3
   attempts, each capped at `max_tokens=2048` per call (a limit only just added this session). There
   is no cumulative input-token, output-token, or wall-clock budget across the whole episode.
   Section 20's recommended C2 budget is multi-axis and cumulative:
   ```yaml
   max_llm_calls: 6
   max_combined_input_tokens: 30000
   max_combined_output_tokens: 6000
   max_repair_rounds: 3
   max_wall_clock_minutes: 10
   ```
   None of this is currently tracked anywhere in the pipeline.

2. **Purpose.** C2 exists specifically to be the fair baseline for a C2-vs-C3 comparison under an
   *equalized* budget (Section 20: "the main causal multi-agent comparison is C2 versus C3 using the
   same model and budget"). Phase 5's autogrep condition answers a related but different question
   ("does Autogrep's own default repair loop help at all?" — yes, substantially, per Section 12.31).
   It was never built to be budget-matched against anything.

## What's genuinely new engineering work

- **Cumulative token tracking across calls in one episode** — nothing in the current pipeline sums
  input/output tokens across a multi-call sequence; it only has a per-call cap.
- **A wall-clock deadline across the whole episode** — currently only a per-call timeout exists
  (`request_timeout_seconds`).
- **A call-count budget** (`max_llm_calls: 6`) that needs an explicit decision on what a "call" means
  for one repair round, since the spec's phrasing ("generates, interprets Semgrep feedback, and
  repairs") is ambiguous about whether interpretation and repair are one call or two per round. This
  needs to be decided and documented before writing the runner, not left implicit — worth deciding
  alongside whoever reviews this scope, since it changes how many effective repair attempts a 6-call
  budget actually buys.
- **A standalone runner**, not a further modification of Autogrep's own retry loop (which is tightly
  coupled to its own behavior and already faithfully serves as the "raw"/"autogrep" conditions —
  changing it risks quietly altering Phase 5's already-locked results). Reuses the existing
  case-loading and GPT-Lab-calling infrastructure (`case_loader.py`, `gptlab_config.py`), with new
  budget-enforcement logic layered on top.

## What C2 does NOT need

- Phase 3 (the 50-case development set) — not required for C2 alone.
- Section 19's role-capability screening — that's specifically for assigning different models to
  different roles in C3/C4, which C2 has none of (one model, one role, throughout).
- C3 to exist first — the two can be built in either order, since Section 20 already fixes the shared
  budget both must use; nothing about C2 depends on C3's implementation details.

## Model choice

Section 19 states role assignments "must follow measured pilot performance." For C2, which has only
one role (the whole task), the pilot's own screening already settles this: `qwen2.5-coder:7b-instruct`
ranked first by MCC in the pilot (mean MCC 0.598, Section 12.6) — a result the Phase 5 primary
benchmark independently reproduced on the locked 300-case set (Section 12.31), without that
confirmation being needed to justify the choice. Recommend running C2 with this model, consistent with
Section 19's instruction to use pilot evidence, not final-set evidence, for this kind of selection.

## Recommended next steps (not started — for whenever work resumes)

1. Decide the call-accounting convention (interpret+repair as one call per round, or two) and write
   it down before coding.
2. Build the budget-tracking runner as a new, standalone script.
3. Verify budget enforcement on a small number of cases (not all 300) before any full run — same
   discipline used for every other launch this study has done.
4. Run C2 on the 153 supported cases (matching Phase 5's primary comparison set) once verified.
5. C3 remains separate, later work, and does depend on Phase 3 + Section 19 role screening.

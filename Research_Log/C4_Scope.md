# C4 (Heterogeneous Multi-Agent) — Scope

Written 2026-10-05, grounded in design Sections 18.4-18.6. Unlike C2 and C3, most of C4's real
decisions are already resolved by earlier work — this is mostly an implementation task.

## The two configurations, exactly as defined

- **C4-A** (Section 18.4): "Select the best pilot-performing model for each role according to
  predefined role metrics." **This is exactly Phase 3's role-capability screening output, already
  measured and assigned** (Implementation_Log 12.40-12.49):
  - Patch analysis -> `qwen3-coder-next:latest`
  - Rule generation -> `qwen2.5-coder:7b-instruct` (pilot's own top MCC performer, Section 19's
    "no new screening needed" case)
  - Syntax review -> `qwen2.5-coder:7b-instruct`
  - Semantic review -> `deepseek-r1:14b`
  - Rule repair -> `qwen2.5-coder:32b`

  No new decision needed — these were measured and frozen during Phase 3 specifically for this use.

- **C4-B** (Section 18.5): "Use a strong model for analysis, generation, and repair and a smaller
  model for syntax and semantic review." The design doesn't name specific models, only roles by
  strength tier. **Recommended: reuse the exact strong/efficient pair C3-S/C3-E already
  established** (`qwen2.5-coder:32b` strong, `qwen2.5-coder:7b-instruct` efficient) rather than
  introduce a third arbitrary choice — consistent with that already-approved decision, and it keeps
  the eventual C3-vs-C4-B comparison cleaner (same models, different role-assignment strategy only):
  - Patch analysis, Rule generation, Rule repair -> `qwen2.5-coder:32b`
  - Syntax review, Semantic review -> `qwen2.5-coder:7b-instruct`

## Workflow and budget: unchanged from C3

Nothing about C4 changes the Section 17.1 workflow or the Section 20 budget. The same resolution
already made for C3 (Implementation_Log 12.50) applies identically: one repair round, with the
post-repair accept/reject check using the deterministic Semgrep Executor's result directly instead
of a second Semantic Review call, for exactly 6 calls in the worst case. The only thing that changes
between C3 and C4 is WHICH model answers each of the 5 role-specific calls.

## Implementation approach

`run_c3.py`'s prompt-building and response-parsing functions (`build_patch_analysis_prompt`,
`build_rule_generation_prompt`, `build_syntax_review_prompt`, `build_semantic_review_prompt`,
`build_rule_repair_prompt`, and their matching parsers) are pure functions with no model-specific
behavior baked in -- directly reusable for C4 without modification, imported rather than duplicated,
the same way `run_c3.py` itself reused functions from the Phase 3 screening scripts.

A new `pipeline/run_c4.py` will NOT modify `run_c3.py`'s own orchestration code (`run_c3_episode()`),
to avoid any risk to C3's already-reported, trusted results -- instead it implements its own episode
loop, identical in structure to C3's, but routing each of the 5 calls to a per-role `(model_tag,
LLMClient)` pair instead of one shared model/client for the whole episode. Each unique model in a
given configuration gets its own `Config`/`LLMClient` instance (built once per run, not per case).

## Verification plan (same discipline as C2/C3)

1. Fake-LLM test first (same 3-scenario pattern as `run_fake_c3.py`: accept round 0, accept round 1
   via repair, never accepted) -- but this time also confirming the right MODEL is called at each
   step, not just the right prompt/budget sequence, since routing is the one genuinely new thing C4
   adds.
2. Tiny real test (1-2 cases) on C4-A before any full run.
3. Full run: C4-A first (reuses Phase 3's already-measured-best assignments, the more directly
   justified of the two configurations), then C4-B.
4. Analysis: pooled MCC/VGR/FPR/PDS exactly as done for C2/C3, plus the natural three-way
   comparison this unlocks -- C4-A (best-per-role) vs C4-B (cost-conscious heterogeneous) vs C3-S/C3-E
   (homogeneous) vs C2 (single-agent, same models) -- all on the same 153 supported cases, all
   already-collected or about-to-be-collected data, no additional conditions needed beyond these two.

# Phase 3 — Role-Capability Screening Plan

Written 2026-10-02. Grounded in design doc Sections 19 (role-capability screening), 29 (execution
plan, Phase 3), and 17.2 (agent role definitions). Covers what Phase 3 actually requires now that
the data-source question is settled, and what's already verified versus what remains to build.

## Data source: the existing 40-case pilot set

Design Section 29 lists Phase 3 as "use 50 development CVEs **if available**" — explicitly
conditional. Section 19 states role-capability screening should "test role-specific performance on
**pilot or development data**" — the design doc itself sanctions using the pilot set instead of a
fresh dev partition. Decided 2026-10-02 (user's choice, recommended): use the pilot set. It already
has full six-sample bundles, is already run through all 8 primary models, and already has
rule-generation-role metrics (MCC/ESR/PDS) sitting unused for this exact purpose. A fresh 50-case
curation would repeat the full multi-day advisory-verification/bundle-construction/classification
pipeline that built the original pilot and the 300-case final set, for a data-independence benefit
Section 19 doesn't require.

## The 5 agent roles (Section 17.2) and what each needs

| Role | Expected output | Selection measurement | Status |
|---|---|---|---|
| Patch analysis | Structured vulnerability specification | Mechanism, source, sink, and fix accuracy | **DONE 2026-10-04** — `qwen3-coder-next:latest` assigned (31.7% overall good rate vs `deepseek-r1:14b`'s 25.0%, judged by fixed judge model `qwen2.5-coder:32b`; see Implementation_Log 12.45-12.49) |

## All 5 roles assigned — Phase 3 role-capability screening complete

| Role | Assigned model |
|---|---|
| Patch analysis | `qwen3-coder-next:latest` |
| Rule generation | (no new screening — pilot data directly settles this) |
| Syntax review | `qwen2.5-coder:7b-instruct` |
| Semantic review | `deepseek-r1:14b` |
| Rule repair | `qwen2.5-coder:32b` |

Next: build C3 (homogeneous multi-agent, Section 17.1 workflow wiring these 5 assignments together), run the C2-vs-C3 matched-budget comparison (Section 20's actual "main causal" test), then select ≤2 C4 heterogeneous configurations and freeze before final evaluation.
| Rule generation | Semgrep YAML | ESR, MCC, and PDS | **Already covered** — pilot screening data has this directly |
| Syntax review | Diagnosis or corrected rule | Error-diagnosis and compilation-recovery rate | **DONE 2026-10-02** — `qwen2.5-coder:7b-instruct` assigned (66.7% diagnosis accuracy vs `magicoder:7b`'s 26.7%; see Implementation_Log 12.40) |
| Semantic review | Failure classification | Correct failure diagnosis | **DONE 2026-10-03** — `deepseek-r1:14b` assigned (38.8%, non-degenerate; `DeepHat` 22.4% degenerate-excluded; `QwQ-32B` inconclusive — infrastructure timeout limits, not a capability finding; see Implementation_Log 12.42-12.44) |
| Rule repair | Revised executable rule | Repair success and regression rate | **DONE 2026-10-02** — `qwen2.5-coder:32b` assigned (4.4% success, only candidate with any; `DeepHat`/`qwen3-coder-next` both 0%; see Implementation_Log 12.41) |

Rule generation needs no new work — the pilot's existing per-model MCC/ESR/PDS numbers (Implementation_Log Section 12.6) directly answer this role's selection measurement. The other 4 roles have no prompt template, response schema, or measurement harness yet; this is genuinely new engineering, independent of which case data gets screened against.

## Candidate models — live-verified 2026-10-02, not just the static catalog snapshot

Section 19's preliminary candidate table is explicitly "hypotheses," but checking they're real and reachable before screening against them is still worth doing up front (cheap, and this project has repeatedly found the static `Open Models/MODELS.md` snapshot drifts from the live catalog).

| Role | Candidates (Section 19) | Verified live |
|---|---|---|
| Patch analysis | DeepSeek-R1 14B, QwQ-32B, Qwen3-Coder-Next | All 3 reachable. **Found a real bug**: `gptlab_config.py`'s `MULTI_AGENT_MODEL_HOSTS` had `"GPT-Lab/QwQ-32B-GGUF"` without its required quantization suffix — the real tag is `GPT-Lab/QwQ-32B-GGUF:Q6_K`; the bare name would have 404'd on first real use. Fixed, plus added `qwen3-coder-next:latest` (host `GPU-farmi-004`), which wasn't in the dict at all before. |
| Rule generation | Qwen2.5-Coder 32B, DeepHat, Qwen3-Coder-Next | First two are already-verified primary models; Qwen3-Coder-Next verified above. |
| Syntax review | Qwen2.5-Coder 7B, Magicoder 7B | Both already-verified primary models. |
| Semantic review | DeepSeek-R1 14B, QwQ-32B, DeepHat | DeepHat already primary; other two verified above. |
| Rule repair | Qwen2.5-Coder 32B, DeepHat, Qwen3-Coder-Next | All already covered above. |

**A real, preliminary signal from a tiny one-line instruction-following probe** (not a real screening result — just a sanity check before investing in full harnesses): `deepseek-r1:14b` and `GPT-Lab/QwQ-32B-GGUF:Q6_K` both ignored a strict "reply with exactly one line" instruction and produced rambling reasoning-style output (expected — they're reasoning models that emit `<think>` blocks; `llm_client.py`'s existing `extract_response()` already strips these, so the infrastructure to handle it exists). `qwen3-coder-next:latest` followed the format cleanly on the first try (after an initial 60s timeout that turned out to be a one-time cold-start delay, not a real problem — confirmed by a successful retry with a longer timeout). This suggests the two reasoning models will need a larger `max_output_tokens` budget and reliance on the existing think-tag stripping for any role screening, not a blocker, just a parameter to get right before running real screening calls.

## What's needed before role screening can run for real

For each of the 4 missing roles (patch analysis, syntax review, semantic review, rule repair):
1. A prompt template matching the role's "expected output" column (e.g., patch analysis's prompt asks for a structured vulnerability spec, not a Semgrep rule).
2. A response parser for that output shape (structured spec / diagnosis-or-rule / failure classification / revised rule — each different from the YAML-rule parsing `llm_client.py` already has).
3. A measurement computation matching the role's "selection measurement" column — several of these (mechanism/source/sink/fix accuracy; error-diagnosis rate; failure-diagnosis correctness) need a labeled ground truth to score against, which the pilot's cases don't currently carry in that specific shape (the six-sample bundles answer "does the rule work," not "did the model correctly identify the vulnerability mechanism in prose"). **This is the main open design question**: either hand-label a subset of pilot cases with the needed ground truth (e.g., the real mechanism/source/sink for patch analysis), or design each measurement as a comparison against Autogrep's own already-known-correct validation outcome (e.g., syntax review's "compilation-recovery rate" can reuse real Semgrep execution directly, no new labels needed — but "mechanism/source/sink accuracy" for patch analysis likely needs human judgment or labels).

## Recommended build order

Cheapest/most self-contained first, since each role's harness is independent:
1. **Syntax review** — needs no new ground truth; "does the model's diagnosis/corrected rule actually compile" is answerable directly via real Semgrep execution, the same machinery every other phase already uses.
2. **Rule repair** — same reasoning; "repair success and regression rate" are directly measurable via real bundle re-execution (already built for C2/Phase 5).
3. **Semantic review** — needs a small labeled set of real failure categories (e.g., "missed the vulnerable branch" vs "overly broad pattern") to check classification against; more design work than 1-2 but still scoped to existing validation data.
4. **Patch analysis** — needs real human-judged ground truth for mechanism/source/sink/fix accuracy; the most labor-intensive of the four, likely needs a modest hand-labeling pass over a pilot subset.

## After role screening

Per Section 29: assign the winning model to each role from measured performance (not the preliminary hypothesis table), build C3 (wiring the 5 roles into the real multi-agent workflow, Section 17.1), run C2-vs-C3 at the Section 20 matched budget (C2 already built — Implementation_Log 12.36-12.38), then select at most 2 C4 heterogeneous configurations from pilot/dev evidence and freeze everything before Phase 6's real multi-agent benchmark run.

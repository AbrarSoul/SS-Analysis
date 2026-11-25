# Run v2 specification (DRAFT, 2026-11-25)

The plan for the one complete rerun of the study. Every setting is fixed here **before** any model is run.
The run then happens once, is scored once by analysis code written in advance, and the paper is written
from those results. This document replaces `Preregistration_Checklist.md` (2026-09-29) for run v2.

**Status of each item**

| Mark | Meaning |
|---|---|
| KEEP | Same as the first run (v1), so results stay comparable. |
| FIX | Changed to fix an issue from the supervisor's review of 2026-10-18 (issue number given). |
| DECIDE | Needs the researcher's decision. A recommendation is given. |
| AFTER REVIEW | Filled in when the ground-truth review is complete. |

---

## 1. Why a rerun

The 2026-10-18 review found setup problems that change what the models could produce or how their rules
were scored (Issues 1, 3, 4, 5, 7). The first run kept raw model responses only for GPT-4o, so the effect of
these problems cannot be measured afterwards for the other 15 models. They can only be fixed by running again.
The ground-truth review (Issue 2) also changes the benchmark itself.

## 2. Stop rule and run discipline (fixed now)

1. Nothing in this document changes after the freeze (section 10). The frozen state gets a git tag.
2. **Infrastructure failure** (server down, timeout, rate limit): the run resumes where it stopped. Finished
   episodes are never rerun, and no setting changes.
3. **A real bug found during the run**: stop, fix it, record it in `Correction_Log.md`, and restart the
   **whole** run from zero in a new results folder. Results from the stopped run are kept but never analysed
   or mixed in.
4. **A model becomes unavailable on GPT-Lab during the run**: it is reported as missing. It is never
   replaced by another model.
5. A short smoke test on the real servers measures timing before the freeze. Its results go to a separate
   folder and are never analysed or reported.
6. Low-scoring or failed episodes are never rerun.

## 3. Benchmark

| Item | Setting | Mark |
|---|---|---|
| Case population | The eligible ("supported") cases that remain after the ground-truth review's exclusions. Unsupported cases are not run: their labels were never independently checked, so results on them could not be trusted. | DECIDE (recommended) |
| Corrections | All review decisions applied in one batch, logged in `review/changelog.json`: exclusions, regenerated look-alikes and alternative fixes, corrected `vulnerable_lines` and CWEs. | AFTER REVIEW |
| Frozen benchmark | Version tag and SHA-256 of every case file, recorded in the freeze record. | AFTER REVIEW |
| CASE-0055 | Repaired or excluded, according to its review decision (Issue 4). | AFTER REVIEW |
| Six samples per case | Vulnerable, patched, renamed variant, restructured variant, alternative fix, benign look-alike. The models see only the first two. | KEEP |

## 4. Models

| Group | Models | Mark |
|---|---|---|
| Original 8 | qwen2.5-coder:7b-instruct, qwen2.5-coder:32b, codellama:7b-instruct-fp16, deepseek-coder:6.7b, codegemma:7b, yi-coder:9b, magicoder:7b, DeepHat/DeepHat-V1-7B | KEEP |
| Follow-up 7 | qwen3-coder:30b, gpt-oss:20b, opencoder:8b-instruct-q4_K_M, granite-code:8b-instruct-128k-q4_1, llama3.1:8b-instruct-q4_K_M, Mistral-Small-24B-Instruct-2501 (Q8_0), phi4:14b-q4_K_M | KEEP |
| Current generation (new in v2) | qwen3-coder-next, gpt-oss:120b, qwen3.6:35b, gemma4:26b. Each must first pass the instruction-tuning check (`pipeline/verify_instruction_tuning.py`). | DECIDED 2026-11-25 (added because the first 15 are mostly small 2023–2024 models) |
| Commercial reference | gpt-4o is deprecated: OpenAI shuts down its API on 14 Jan 2027, which is probably before the run. Its replacement is chosen by cost. See section 4a. | DECIDE |

The first 15 open models are kept for continuity, so v2 has 19 open-weight models. The largest open models
(Kimi K3, GLM-5.x, DeepSeek V4) are not hosted on GPT-Lab and are too large for its GPUs; this is stated in
Threats to Validity. `:cloud` model tags are not used, because they run on a remote provider rather than
being self-hosted.

### 4a. Commercial reference models (cost options, estimated 2026-11-25)

Estimated from the real prompt sizes (about 1,100 tokens on average over the 150 eligible cases), the call
budgets in this document, and list prices on 25 Nov 2026. Reasoning models are assumed to run at low effort.

| Option | Set-up | Standard price | With Batch API (50% off) |
|---|---|---|---|
| A | 1 mid-tier model, Part I only, no stability. Part II uses open models only. | $11–31 | $5–15 |
| B | 3 mid-tier models (one per provider), Part I + stability. Part II open only. | $57–138 | $29–69 |
| C | As B, plus the cheapest-tier commercial model in Part II | $61–147 | $30–73 |
| D | As B, plus 1 mid-tier model in Part II | $123–321 | $61–161 |
| E | 3 flagships, Part I + stability; 1 mid-tier model in Part II | $218–551 | $109–275 |

Since the shared attempt chain (Issue 5, section 5), Part I needs at most 4 calls per model and case instead of 6,
so the Part I part of these estimates is on the high side.

Rules that apply whichever option is chosen:
- Temperature cannot be set on current reasoning models: they run at the provider default with a fixed,
  declared effort level, and the stability runs measure their variation.
- Reasoning models get a larger output cap (for example 16,000 tokens), so their thinking is not cut short.
- Refusals are recorded as their own outcome and never retried with a reworded prompt.
- A hard spending limit is set in each provider's console before the run.

- In v2, all models are one population, run in the same campaign. There is no longer a separate
  "original" and "follow-up" campaign. (Issue 5: models were run at different times.)
- Before the freeze, every tag is checked against the live GPT-Lab catalogue, and the model digests are
  recorded where the API exposes them. If a model is gone, decide before the freeze; never during the run.
- CodeLlama stays the only fp16 model and is flagged as the precision exception in every table. KEEP
- The API key is read from the environment only and never written to a file. KEEP

## 5. Workflows (Part I)

| Workflow | Definition | Budget | Mark |
|---|---|---|---|
| Single-shot | Attempt 1 of the shared chain (below). | 1 call | KEEP |
| Autogrep | Attempts 1–3 of the shared chain: each attempt gets the previous rejection as feedback, the same call v1's Autogrep loop made. v1's early stop on target parse errors is dropped, because the parse preflight (checklist 8a) rules those out. | 3 attempts (`max_retries=3`) | KEEP (budget) |
| Iterative | Attempts 1–4 of the same chain, as far as the iterative budget allows; the budget is checked before each call, as v1's `run_c2.py` did. v1 hardcoded the old system message here; v2 uses the run v2 one. | 6 calls, 3 repair rounds, 30,000 input and 6,000 output tokens, 10 minutes | KEEP (budget) |
| Multi-agent (C3/C4) | Not part of v2; stays future work. | | DECIDE (recommended: leave out) |

**Fixes that apply to every workflow**

| Fix | What changes | Issue |
|---|---|---|
| Rule types | The wrapper accepts every valid Semgrep rule form (`pattern`, `patterns`, `pattern-either`, taint mode), using the existing `semgrep_search_taint_v2` policy. The v1 policy `legacy_pattern_only` stays in the code, so v1 results can still be reproduced. | 1 (DONE) |
| Prompt | New prompt version `autogrep_v2`: v1's text with only the defects visible by reading it corrected (see the rule below). | 1, 7 (DONE) |
| Failure stages | Every rejected attempt records its stage: empty response, no rule text, YAML, rule count, schema, API error, parser crash. v1 recorded only "a rule came out of parsing", which put schema rejections under "YAML did not parse". | 1 (DONE) |

**Rule for the run v2 prompt: fix only what is visibly wrong, never tune on the benchmark.** The October
diagnostic prompts (`diagnostic_mechanism_v3`/`v4`) added advice after looking at model failures on
specific benchmark cases (CASE-0221, 0238, 0276), and their TypeScript example restates CASE-0238's own
fix. They are not used in run v2, because that would tune the prompt on the evaluation set. `autogrep_v2`
makes exactly five changes to v1, each visible without running anything:

1. The example rules are v1's own rules, made valid YAML. Semgrep validates every one, and a TypeScript
   entry is added: the JavaScript rules with the language changed. v1 gave TypeScript cases no example.
2. "Required field: pattern" becomes the list of all accepted matching forms.
3. "Use `|>` to pipe patterns" is removed, because `|>` is not Semgrep syntax.
4. The response template becomes valid YAML.
5. The prompt states that the response must contain exactly one rule, which the parser requires.

The system message lists all accepted forms, instead of asking only for `pattern`.
`pipeline/tests/test_run_v2_issue1.py` checks, for all 150 eligible cases, that the run v2 prompt equals the
v1 prompt with exactly these edits and nothing else. The prompt's fingerprint is pinned in
`pipeline/tests/verify_prompt_hashes.py`, provisional until the freeze.
| Raw responses | Every request and raw response is saved for every model and every call. | 1, 3 |
| Same time window | All three workflows are read from the same calls, so they share their time window by construction. Across models, the runner works through the cases in one fixed, seeded order. | 5 (DONE for workflows; runner order: run mechanics) |
| Shared attempt chain | One chain of up to 4 attempts per model and case, stopping at the first accepted rule; every workflow is read from it (see below). | 5 (DONE) |
| Acceptance check | The chain stops at the first rule that passes the run v2 visible gate: both visible files scanned cleanly, the vulnerable file detected at the annotated location (overlap), the patched file not detected. The v1-style check (no location) is recorded for every attempt as a secondary measure. A new feedback message covers "matched, but not at the code changed by the patch", without line numbers. | 5 (DONE) |

**Generation settings:** temperature 0 and a 2,048-token output cap per call, the same for every model and
workflow. Semgrep 1.177.0 and Autogrep commit `ace3c87` stay pinned. KEEP

**New in v2:** GPT-4o calls also send a fixed `seed`. This reduces run-to-run variation where the API supports
it; GPT-Lab's servers have no equivalent setting.

**Why one shared chain (Issue 5).** In v1, Autogrep's retry loop and the iterative loop made the same call each
round: the prompt plus the previous round's error. They differed only in budget: Autogrep up to 3 attempts; the
iterative loop up to 4, within token and time limits. Because they were run separately, days apart, their difference
mixed one extra attempt with run-to-run variation and timing. In v2 they share every attempt, so any difference
between them comes from the budget alone. The paper describes them as the same repair loop with a smaller and a
larger budget. Every attempt records its prompt, system message, raw response, token use, timing, failure stage,
gate result and the budget used before it. Every rule in the chain is scored on all six samples.
Code: `pipeline/run_v2_episode.py`; tests: `pipeline/tests/test_run_v2_issue5.py`.

**Infrastructure failures.** API errors are retried with backoff (10 s, 60 s, 300 s). If they persist, the episode is
not recorded and is resumed later from scratch. They never count as a model failure.

## 6. Stability (run-to-run variation)

v1 measured stability on a 100-case subset at temperature 0.2, with 5 runs per model and case, for the
original 8 models only.

| Option | Description |
|---|---|
| A (recommended) | All eligible cases, all 16 models, Single-shot only, temperature 0.2, 3 runs. |
| B | v1's design (5 runs) rebuilt on the eligible cases, for all 16 models. |
| C | Leave out; report the temperature-0 run only. |

DECIDE after the smoke test shows how long one run takes.

## 7. Part II: typed rule construction (2×2)

| Item | v1 | v2 | Mark |
|---|---|---|---|
| Design | Free-form vs typed construction × Semgrep-only vs probe feedback (cells A, B, C, D) | Same | KEEP |
| Models | qwen3-coder:30b, gpt-4o | qwen3-coder:30b plus one commercial model (gpt-4o is being shut down; see 4a) | DECIDE |
| Code | Its own loop (`diagnostic_v2.py`), scanner and feedback | The same episode code as Part I (`run_v2_episode.py`): same gate, scanner, raw records and server-error handling; 3 attempts, no token or time limit, as in v1 | FIX (DONE) |
| Cases | 24 cases chosen using Qwen3-Coder's own earlier results | `run_v2_settings.part2_cases()`: all eligible cases, or a seeded random sample stratified by language. Never uses model results. | FIX (Issue 7, DONE), DECIDE size (D7) |
| Example quality | Free-form used the broken prompt example; typed did not. Neither had a TypeScript example. | Both use the same corrected rules (free-form `autogrep_v2`; typed `EXAMPLE_RULES_TYPED_JSON_RUN_V2`), both with a TypeScript entry. The v1 typed prompt is byte-identical after the refactor (checked over all 150 cases). | FIX (Issue 7, DONE) |
| Call budget | 3 attempts per episode in every cell; typed used about 22% more calls because its episodes used more of their 3 attempts (one call per attempt in both modes) | Same ceiling (3 attempts) in every cell; calls and tokens reported per cell as a cost outcome | KEEP (ceiling), report |
| Wrong-location feedback | Told the model the annotated bug lines ("expected within [vulnerable_lines]"), equally in all cells | The neutral run v2 message, without line numbers | FIX (DONE) |
| Repeats | 3 | 3, each case's success averaged over its repeats before paired comparison | KEEP |
| Case order | Shuffled in A/B, canonical in C/D | One fixed, seeded order for every model, cell and repeat (`run_order()`) | FIX (DONE) |
| Time window | A/B and C/D run days apart | All four cells interleaved case by case in the same campaign (runner) | FIX (runner) |
| Probes | Built for 24 hand-reviewed cases; 11 eligible | Built automatically by the same deterministic builder (`run_v2_probes.py`) from the visible functions only: 87 of the 150 eligible cases. It agrees with the October hand review on the 24 reviewed cases (the same 11). All 174 probe files parse cleanly. | FIX (DONE); DECIDE spot-check (D7b) |
| Probe coverage | 11 of 24 cases | All cases are reported; probe-eligible cases also separately | KEEP |

## 8. Scoring

| Item | Setting | Mark |
|---|---|---|
| Accepted | Valid rule that discriminates the visible pair at the right location. | KEEP (common gate) |
| Complete success | Accepted, catches both hidden vulnerable variants, and stays silent on both hidden safe samples (VGR = 1.00, FPR = 0.00). | KEEP |
| Location | Uses the finding's full span (start to end line), not only its start line. **Primary rule: overlap** (the span shares a line with an annotated range). Also stored for every finding and reported as pre-declared sensitivity checks: v1's start-line rule and a strict "entirely inside" rule. All three positive samples are checked against every annotated range, read from the benchmark at run time, so review corrections apply automatically. | FIX (Issue 3, DONE) |
| Semgrep binary | Every run v2 Semgrep call goes through `pipeline/semgrep_runner.py`. It uses the pinned 1.177.0 in `.venv` (checked at start), always runs from the repo root, and scans all six samples of a case in one call. v1's wrapper called whichever `semgrep` was first on the PATH (the system copy is 1.140.0). Running from another folder made scans of repository files take minutes instead of seconds. | FIX (Issue 4, DONE) |
| Target parse errors | Every scan gets a status: `ok`, `target_parse_error`, `not_scanned` (normally a rule written for another language), `rule_error` or `semgrep_failure`. Only `ok` scans are scored TP/FP/FN/TN; any other status makes the sample's outcome `ERROR`, so a case with an `ERROR` sample cannot be a complete success. In v1, a rule for the wrong language counted as correctly silent on every safe sample. | FIX (Issue 4, DONE) |
| Failure categories | "YAML did not parse", "parsed but not a valid Semgrep rule" and "valid but rejected" are separate categories. | FIX (Issue 1) |
| Conditional MCC | Hidden samples only, never the visible pair. | KEEP (already fixed, Issue 8) |
| Positive control | Reference rules scored by the same scorer, to show the cases can be solved. | FIX (Issue 6), see 9 |

## 9. Positive control (Issue 6)

The aim is a reference rule for each case in a declared set, written without seeing any model output and
scored exactly like the model rules.

| Option | Description |
|---|---|
| A (recommended) | Reference rules for the 38 Batch 1 cases, written as part of their review (check G), plus the 15 cases that already have a public rule. |
| B | Reference rules for every eligible case. Strongest, but a large amount of extra work. |
| C | Only the 15 existing public rules. |

The reference rules are frozen with the benchmark, before the run. DECIDE

## 10. Analysis, written before the run

All of these are coded and tested on simulated results before the freeze, and the run's results then go
straight through them. Nothing is added after seeing the results, except analyses clearly labelled
"exploratory".

**Part I**
- Per model and workflow: accepted rate and complete-success rate, with 95% Wilson intervals.
- Hidden results by sample type (renamed, restructured, alternative fix, look-alike), and conditional MCC.
- Workflow comparisons within each model: McNemar on complete success, repository-aware bootstrap (10,000
  resamples, seed 42) on the rates, Holm correction across all comparisons.
- First-attempt failure funnel and failure categories (section 8).
- Overlap between models' solved cases, and overlap with public rules.
- Stability: agreement between repeated runs (section 6).

**Part II**
- C − A and D − B within each model, and the construction × feedback contrast, all paired by case after
  averaging over repeats.
- Calls and tokens per cell.

**Fixed reporting rules**
- Denominator: every requested case, including cases where the model produced nothing.
- Power stated in Threats to Validity: at about 150 cases, a 7% vs 3% difference has roughly 30% power.

**Implemented (DONE): `pipeline/analyze_v2.py`**, tested on a simulated run in `pipeline/tests/test_analyze_v2.py`.
Every number in those tests was worked out by hand. One test also feeds a real episode (fake model, real
Semgrep) through the analysis. The file fixes, before the run:
- the results layout it reads;
- the exact definitions of "accepted" and "complete success" (an `ERROR` sample is never correct, and a missing
  episode counts as not accepted);
- the statistics, which reuse the audited v1 helpers: exact McNemar, Holm, and the repository-aware bootstrap
  with 10,000 resamples and seed 42.

Usage: `.venv/bin/python3 pipeline/analyze_v2.py RUN_DIR`, which writes `RUN_DIR/analysis/*.json` and `summary.md`.

**Reading the workflow comparisons.** With the shared chain (section 5), single-shot is attempt 1 of Autogrep's own
attempts. A case that single-shot solves is therefore always solved by Autogrep too, and "only single-shot" is 0 by
construction. The comparison counts the cases gained by allowing more attempts. Iterative is not always a superset
of Autogrep, because its token and time limits can end it earlier.

## 11. Freeze checklist (all must be done before the run)

| # | Item | Depends on |
|---|---|---|
| 1 | Ground-truth review complete: both judges final, agreement computed, disagreements settled | judges |
| 2 | Benchmark corrections applied, logged and hashed | 1 |
| 3 | Code fixes for Issues 1, 3, 4, 5, 7 done, each with tests | **DONE** (2026-11-25; see sections 5, 7, 8) |
| 4 | Analysis code (section 10) written and tested on simulated results | **DONE** (`pipeline/analyze_v2.py`) |
| 5 | Reference rules for the positive control frozen | 1 |
| 6 | Model catalogue checked live and digests recorded | before freeze |
| 7 | Dry run with a fake model through every workflow and the analysis | Machinery **DONE** and tested on 2 cases; repeat with the frozen models file at the freeze |
| 8 | Smoke test on GPT-Lab and OpenAI: timing and connectivity; results discarded | 7 |
| 8a | `pipeline/target_preflight.py` passes: every sample file of every case in the run parses cleanly. On 2026-11-25 it fails on 9 files, all in two cases already known from October: CASE-0055 (4 samples, syntax error near line 4422) and CASE-0298 (5 samples, JSX stored as `.ts`). The review decides to repair or exclude each. | 2 |
| 9 | Stability and Part II sizes decided from the smoke-test timing | 8 |
| 10 | Freeze record written (hashes of code, prompts, benchmark, config), git tag `run-v2-frozen` | all |

## 11a. Running it

One command runs everything (`pipeline/run_v2.py`; tests: `pipeline/tests/test_run_v2_entrypoint.py`). The models,
their hosts, and the stability and Part II sizes are in `pipeline/run_v2_models.json`, which is frozen with the
code (currently a DRAFT).

| Mode | Command | Purpose |
|---|---|---|
| dry run | `.venv/bin/python3 pipeline/run_v2.py --mode dryrun --run-dir results_v2_dryrun/<name> --cases 2` | Checklist item 7: a built-in fake model with real Semgrep, through every part. No API key, no inference. |
| smoke | `.venv/bin/python3 pipeline/run_v2.py --mode smoke --run-dir results_v2_smoke/<name> --cases 2` | Checklist item 8: real models, a few cases, one repeat, to measure timing. Never analysed. |
| real | `.venv/bin/python3 pipeline/run_v2.py --mode real --run-dir results_v2/<name>` | The frozen run. Refuses to start unless every freeze check passes. |
| analysis | `.venv/bin/python3 pipeline/analyze_v2.py results_v2/<name>` | Once, after the real run. Refuses smoke and dry runs. |

What the entrypoint guarantees:
- **Freeze checks before a real run:** pinned Semgrep; prompt fingerprints; every sample parses; every vulnerable
  sample has bug lines; the models file is no longer a draft; no uncommitted changes to tracked files; HEAD tagged
  `run-v2-frozen`; API keys present.
- **A manifest records everything:** git commit, Semgrep version, prompt fingerprints, a fingerprint of every
  benchmark file used, the models file, the cases, the seeded order and the settings.
- **Resuming:** running the same command again fills only missing episodes. It refuses if the code, benchmark,
  cases, models or prompts changed since the run started.
- **Order:** Part I, then stability, then Part II. Models run in parallel, with at most one episode at a time per
  GPT-Lab host (configurable). Part II runs its cells and repeats case by case.
- **The stop rule is enforced:** persistent API failures are logged and resumable; any other error stops the run.

Still open before the freeze: adapters for the commercial providers chosen in 4a (reasoning effort, output cap,
no temperature), and live confirmation of the four new models' hosts.

## 12. Decisions needed

| # | Decision | Recommendation |
|---|---|---|
| D1 | Case population: eligible cases only, after review exclusions | Yes |
| D2 | Open models: the first 15 plus 4 current-generation models | **Decided: yes** (2026-11-25) |
| D2b | Commercial reference models: option A–E in section 4a | Decide by cost; the budget must stay below about $900 |
| D3 | Multi-agent workflows left out | Yes |
| D4 | One shared attempt chain for all three workflows (extends the earlier "shared first attempt") | **Implemented**: Autogrep and Iterative were the same loop with different budgets in v1 too; this makes the comparison a pure budget comparison and costs at most 4 calls per model and case instead of 6 |
| D5 | Same acceptance check in the loops as in scoring | **Implemented** (secondary v1-style check recorded) |
| D6 | Stability design (section 6) | Option A, sized after the smoke test |
| D7 | Part II cases: all eligible, or a seeded random sample | All eligible if timing allows |
| D7b | Part II probes: use the builder's 87 automatic probes, with a spot-check of a random sample (for example 15) by a reviewer, instead of hand-reviewing all | Yes: the builder matched the October hand review on all 24 reviewed cases |
| D8 | Positive control (section 9) | Option A |
| D9 | Primary location rule: overlap (alternatives: strict containment, v1's start line), the other two reported as sensitivity checks | Overlap. A very broad match passes it, but such a match also fires on the patched and safe samples, which already fails the case. |

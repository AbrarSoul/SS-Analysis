# Pinned Configuration Reference

Consolidated record of every fixed/pinned value the study depends on, gathered across Phase 1 Steps 1–4. Cross-reference with `Research_Log/Implementation_Log.md` for how each was established.

## Software versions (Step 1)

| Component | Pinned value | Source |
|---|---|---|
| Autogrep commit | `ace3c87a707a5b02632906b76195b6f97d411b8d` | `autogrep/PINNED_COMMIT` |
| Semgrep (inside `.venv`) | `1.177.0` | `autogrep/PINNED_VERSIONS.txt` — **note:** differs from the system-wide `1.140.0`; always activate `.venv` |
| Python | `3.14.4` | `autogrep/PINNED_VERSIONS.txt` |
| openai, GitPython, PyYAML, requests, sentence-transformers, torch | see `autogrep/PINNED_VERSIONS.txt` | pip-resolved at install time |

## Generation configuration (Steps 2–4)

| Parameter | Pinned value | Enforced? |
|---|---|---|
| `max_retries` | 3 | ✅ Enforced — confirmed exactly 3 attempts occur on a failing case (Step 3 verification) |
| `temperature` (generation) | 0.0 | ✅ Enforced — passed through `config.generation_temperature` into every API call |
| `max_files_changed` | 1 | ❌ **Not enforced by Autogrep** — stored in `Config` but never checked against `patch_info.file_changes` anywhere in the codebase (confirmed empirically: a 2-file patch was processed without rejection). **The one-file-fix constraint must be enforced during dataset curation (Phase 2/4) by filtering candidate CVE cases directly, not by trusting this flag.** |

## Rule-filtering configuration (Step 4)

| Parameter | Pinned value | Notes |
|---|---|---|
| Embedding model (dedup) | `all-MiniLM-L6-v2` | CLI default in `rule_filter.py`, unchanged |
| Duplicate similarity threshold | `0.9` (cosine similarity) | Hardcoded default parameter in `RuleFilter.is_duplicate()`, never overridden at its one call site — not exposed via CLI at all, so it is inherently fixed already |
| Judge model (generalizability pass) | `qwen2.5-coder:32b` on `GPU-farmi-004` | Fixed constant in `pipeline/gptlab_config.py` (`JUDGE_MODEL`) — deliberately never the model under evaluation, to avoid self-certification bias (see Implementation Log Section 4.3) |

## Prompt templates (Section 30 checklist item #6, pinned 2026-09-29)

| Prompt variant | Template source hash (sha256 of the `_build_prompt_*` method source) | Status |
|---|---|---|
| `autogrep_default` | `6e7d840e71782db4c9bd367d1e2a846f0f7b8707c9f2aacc6b040482c1613e42` | **Winner** — selected by the pilot as the better-performing prompt (Implementation Log Section 12.6: mean MCC 0.541 vs 0.394) |
| `design_v1` | `ae50ab374bb441f08e466491d0cf1099c2c5576255ed5833e89de7e27419edaf` | Secondary — implemented per design Section 13.2, not the pilot winner |

The rendered prompt differs per case (real CVE/CWE/function data is interpolated in), so what's hashed is the *template itself* — the source of the `LLMClient._build_prompt_autogrep_default`/`_build_prompt_design_v1` methods in `autogrep/llm_client.py`. Verify with `python pipeline/tests/verify_prompt_hashes.py`; a mismatch means the template was edited since this was pinned, which should be a deliberate, recorded decision, not silent drift. (Every individual generated prompt is separately hashed too, per-call, via `prompt_hash` in the generation record — this is the FROZEN-TEMPLATE hash, a different thing.)

## Precision and quantization policy (Section 30 checklist item #8, decided 2026-09-29)

**Policy: all-quantized**, per design Section 11.6 option 2. Checked what GPT-Lab's catalog (`Open Models/MODELS.md`, snapshot 8 Sept 2026) actually offers before deciding: only 2 of the 8 primary model tags have an FP16 alternative at all (`codellama:7b-instruct-fp16` and `qwen2.5-coder:7b-instruct-fp16`); the other 6 (`qwen2.5-coder:32b`, `deepseek-coder:6.7b`, `codegemma:7b`, `yi-coder:9b`, `magicoder:7b`, `DeepHat/DeepHat-V1-7B`) exist only as their default (quantized) pull — so an all-FP16 policy is not achievable on this infrastructure, and all-quantized is the only uniform policy that is.

7 of the 8 already-selected primary tags are the default quantized pull as chosen. **`codellama:7b-instruct-fp16` is the one exception**, and not by choice: the only OTHER CodeLlama tag on GPT-Lab, `codellama:7b`, was never empirically verified as instruction-tuned (Section 2.3/2.4's probe was run against the fp16 tag, which passed; the base `codellama:7b` tag was never tested and, per standard Ollama naming, is very likely the completion/base model, not instruction-tuned) — so there is no quantized, instruction-tuned CodeLlama available to substitute.

**Resolution**: CodeLlama runs and is fully reported like every other model (results are not dropped), but per Section 11.6's own warning against comparing an FP16 model "as if only architecture differed," it is excluded from the primary cross-model ranking table and flagged in every table it appears in as the precision outlier — not compared head-to-head with the 7 quantized models as if precision were equal. This is a reporting/analysis-stage decision (Phase 7); it requires no change to Phase 5 generation, since every model already runs at whatever tag is on this list.

## Rule-validator repository dependency (resolved 2026-09-29, Implementation Log Section 12.24)

The Autogrep condition's rule validator (`autogrep/rule_validator.py`) originally validated a generated rule by cloning the real repository and checking out both commits -- across the 300 final cases that meant 258 repositories, ~48GB locally (measured, Implementation Log Section 12.20). **Curated cases (`patch_info.case_id` set) now validate against the standalone `vulnerable_source`/`patched_source` files each case already stores instead** -- `git_manager.prepare_repo()` skips the clone entirely for them, verified with zero `git clone` activity in the fake-model end-to-end test. The raw-`.patch`-file flow is unaffected. This removes the clone dependency from Phase 5's primary (single-shot) run.

## Known gaps to carry into dataset curation (Phase 2/4)

- Verify `len(file_changes) == 1` (recognized-language files only) directly when curating each CVE case, since Autogrep will not filter this itself.
- Consider whether a file like `tests/test_*.py` appearing alongside a production file should count toward the "one file changed" preference, or be excluded separately under the design's Section 7.2 test-only-change exclusion criterion — Autogrep does not distinguish test files from production files either.

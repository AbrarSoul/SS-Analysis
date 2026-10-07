# Autogrep fork — pinned commit and diff only

This study's "autogrep" condition runs a fork of [Autogrep](https://github.com/lambdasec/autogrep),
pinned at upstream commit `ace3c87a707a5b02632906b76195b6f97d411b8d`. Rather than redistribute a full
modified copy of someone else's tool, this directory contains only the diffs we actually made,
against that exact pinned commit — clone the real upstream repo at that commit and apply these to
reproduce our fork exactly.

Two of the nine vendored files are unmodified from upstream and have no diff here:
`cache_manager.py`, `rule_manager.py`.

| File | What changed |
|---|---|
| `config.py` | Added GPT-Lab (our model-serving infrastructure) adapter configuration fields |
| `git_manager.py` | Added shared-clone-cache support with per-repo locking (safe concurrent validation across models) and clone-free validation for curated cases (reads each case's own stored source files directly instead of cloning/checking out commits) |
| `llm_client.py` | Replaced the hardcoded OpenRouter client with our GPT-Lab model adapter; added deterministic rule-id generation |
| `main.py` | Orchestration changes to call the adapted client |
| `patch_processor.py` | Minor adjustments to support curated (non-raw-patch-file) cases |
| `rule_filter.py` | Minor adjustments for the pinned judge-model configuration |
| `rule_validator.py` | Validates curated cases directly against `benchmark/cases/CASE-XXXX/{vulnerable_source,patched_source}` rather than a cloned repository |

See `Research_Log/Implementation_Log.md` for the full narrative behind each of these changes
(search for "clone-free", "shared_repos_cache_dir", "GPT-Lab").

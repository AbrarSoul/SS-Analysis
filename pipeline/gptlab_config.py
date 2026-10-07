"""
GPT-Lab configuration helpers for the vendored Autogrep pipeline.

Maps each verified model tag to the GPT-Lab host that serves it, resolves the
API key from the GPTLAB_API_KEY environment variable (never hardcoded), and
builds a ready-to-use Autogrep Config object pointed at a specific model.

Autogrep's own modules (config.py, llm_client.py, ...) use flat, unqualified
imports (e.g. `from config import Config`), so they only work with autogrep/
itself on sys.path -- not as a subpackage. We add it to sys.path here rather
than restructuring the vendored code.
"""
import os
import sys
from pathlib import Path

AUTOGREP_DIR = Path(__file__).resolve().parent.parent / "autogrep"
if str(AUTOGREP_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOGREP_DIR))

from config import Config  # noqa: E402  (import must follow the sys.path patch above)

GPTLAB_BASE_TEMPLATE = "https://gptlab.rd.tuni.fi/GPT-Lab/resources/{host}/v1"

# Verified primary benchmark models (design doc Section 11.1), each empirically
# confirmed instruction-tuned via direct probe -- see Research_Log/Implementation_Log.md.
PRIMARY_MODEL_HOSTS = {
    "qwen2.5-coder:7b-instruct": "GPU-farmi-001",
    "qwen2.5-coder:32b": "GPU-farmi-004",
    "codellama:7b-instruct-fp16": "GPU-farmi-003",
    "deepseek-coder:6.7b": "GPU-farmi-004",
    "codegemma:7b": "GPU-farmi-004",
    "yi-coder:9b": "GPU-farmi-004",
    "magicoder:7b": "GPU-farmi-001",
    "DeepHat/DeepHat-V1-7B": "GPU-farmi-004",
}

# Multi-agent role candidates (design doc Sections 11.3/19) -- not part of the
# primary single-agent ranking, reported/used separately. Live-verified against the real GPT-Lab
# catalog 2026-10-02 (not just the static Open Models/MODELS.md snapshot) -- found the QwQ tag below
# was missing its required quantization suffix (the real tag is "GPT-Lab/QwQ-32B-GGUF:Q6_K"; the
# bare name alone would have 404'd on first real use) and added qwen3-coder-next (Section 19's
# "Qwen3-Coder-Next" patch-analysis candidate, not previously in this dict at all).
MULTI_AGENT_MODEL_HOSTS = {
    "GPT-Lab/QwQ-32B-GGUF:Q6_K": "GPU-farmi-001",
    "deepseek-r1:14b": "GPU-farmi-001",
    "qwen3-coder-next:latest": "GPU-farmi-004",
    "qwen2.5-coder-swe:latest": "CSC-P100",
    "ornith-swe:q4": "CSC-P100",
}

MODEL_HOSTS = {**PRIMARY_MODEL_HOSTS, **MULTI_AGENT_MODEL_HOSTS}

# Fixed judge model for rule_filter.py's generalizability-review pass. Deliberately
# never one of the models under evaluation -- an evaluated model must not judge its
# own output, the same self-certification concern the design doc raises in Section
# 9.2 for test-variant labeling, applied here to the quality-judge step.
JUDGE_MODEL = "qwen2.5-coder:32b"
JUDGE_HOST = PRIMARY_MODEL_HOSTS[JUDGE_MODEL]


def get_api_key() -> str:
    key = os.environ.get("GPTLAB_API_KEY")
    if not key:
        raise RuntimeError(
            "GPTLAB_API_KEY environment variable is not set. "
            "Export it before running any pipeline script."
        )
    return key


def host_base_url(host: str) -> str:
    return GPTLAB_BASE_TEMPLATE.format(host=host)


def build_config(model_tag: str, *, temperature: float = 0.0, max_retries: int = 3,
                  max_files_changed: int = 1, prompt_variant: str = "autogrep_default",
                  max_output_tokens: int = 2048,
                  patches_dir=None, generated_rules_dir=None,
                  repos_cache_dir=None, shared_repos_cache_dir=None) -> Config:
    """Build an Autogrep Config pointed at a specific GPT-Lab model.

    Despite the field names (openrouter_api_key/openrouter_base_url, kept as-is
    in the vendored Config to avoid touching every call site), these point at
    GPT-Lab's OpenAI-compatible API, not OpenRouter.
    """
    if model_tag not in MODEL_HOSTS:
        raise ValueError(f"Unknown model tag {model_tag!r}; add it to MODEL_HOSTS first.")
    host = MODEL_HOSTS[model_tag]
    kwargs = dict(
        max_files_changed=max_files_changed,
        max_retries=max_retries,
        openrouter_api_key=get_api_key(),
        openrouter_base_url=host_base_url(host),
        model_name=model_tag,
        generation_temperature=temperature,
        prompt_variant=prompt_variant,
        max_output_tokens=max_output_tokens,
    )
    if patches_dir is not None:
        kwargs["patches_dir"] = Path(patches_dir)
    if generated_rules_dir is not None:
        kwargs["generated_rules_dir"] = Path(generated_rules_dir)
    if repos_cache_dir is not None:
        kwargs["repos_cache_dir"] = Path(repos_cache_dir)
    if shared_repos_cache_dir is not None:
        kwargs["shared_repos_cache_dir"] = Path(shared_repos_cache_dir)
    return Config(**kwargs)


def build_judge_kwargs() -> dict:
    """kwargs to pass into RuleFilter(...) so the generalizability judge always
    uses the fixed JUDGE_MODEL, never the model under evaluation."""
    return dict(
        judge_api_key=get_api_key(),
        judge_base_url=host_base_url(JUDGE_HOST),
        judge_model=JUDGE_MODEL,
    )

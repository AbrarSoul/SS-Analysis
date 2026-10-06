"""
Adapter + raw-capture verification: runs the vendored Autogrep pipeline
against real patches using a specific GPT-Lab model, with raw-output capture
wired in, to confirm both the config-based adapter (pipeline/gptlab_config.py)
and the raw-capture wrapper (pipeline/raw_capture.py) work end-to-end.

Cases are processed one at a time (rather than via AutoGrep.run()'s bulk/
threaded loop) for two reasons: it lets us announce each case to the raw
capture recorder before processing it, and it sidesteps a pre-existing
Autogrep bug where run() redundantly re-saves an already-saved rule using a
'language' key the rule dict doesn't have (see Research_Log, Section 4.5).

Usage (from the project root, with the venv activated):
    export GPTLAB_API_KEY=...
    python pipeline/run_smoke_test.py <model_tag>

Note: this script gives each model tag its own repos_cache_dir. Autogrep
couples repo-clone caching and "already processed" patch tracking in the
same directory (CacheManager lives inside repos_cache_dir), so sharing one
cache dir across models would make the second model silently skip a patch
the first model already succeeded on. Fine for a smoke test; worth
revisiting before Phase 5's full-scale run across 8 models.
"""
import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gptlab_config import build_config, MODEL_HOSTS  # noqa: E402
from raw_capture import RawCaptureRecorder, wrap_llm_client  # noqa: E402
from main import AutoGrep  # noqa: E402


def run(model_tag: str):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    repo_root = Path(__file__).resolve().parent.parent
    safe_name = model_tag.replace("/", "_").replace(":", "_")
    run_dir = repo_root / "results" / "smoke_test" / safe_name

    config = build_config(
        model_tag,
        temperature=0.0,
        max_retries=3,
        max_files_changed=1,
        patches_dir=repo_root / "autogrep" / "cvedataset-patches",
        generated_rules_dir=run_dir / "generated_rules",
        repos_cache_dir=run_dir / "cache" / "repos",
    )
    config.generated_rules_dir.mkdir(parents=True, exist_ok=True)
    config.repos_cache_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n=== Running smoke test for {model_tag} ===")
    print(f"Base URL: {config.openrouter_base_url}")
    print(f"Output dir: {config.generated_rules_dir}")
    print(f"Raw capture dir: {run_dir / 'raw'}\n")

    autogen = AutoGrep(config)
    recorder = RawCaptureRecorder(run_dir)
    wrap_llm_client(autogen.llm_client, recorder)

    autogen.rule_manager.load_initial_rules()

    patch_files = sorted(config.patches_dir.glob("*.patch"))
    for patch_file in patch_files:
        case_id = patch_file.stem  # e.g. github.com_aio-libs_aiohttp_1c3359...
        recorder.begin_case(case_id)

        result = autogen.process_patch(patch_file)
        if result:
            rule, patch_info = result
            language = patch_info.file_changes[0].language
            autogen.rule_manager.add_generated_rule(language, rule)
            print(f"[{case_id}] SUCCESS -> saved rule '{rule['id']}' ({language})")
        else:
            print(f"[{case_id}] FAILED -> no valid rule produced (see logs above)")

    print(f"\n=== Done. Checking generated_rules dir: {config.generated_rules_dir} ===")
    produced = list(config.generated_rules_dir.rglob("*.yml"))
    for f in produced:
        print(f"  Generated: {f}")
    if not produced:
        print("  No rule file was produced.")

    print(f"\n=== Raw capture files ===")
    for f in sorted((run_dir / "raw").glob("*.json")):
        print(f"  raw:   {f}")
    for f in sorted((run_dir / "raw_retries").glob("*.json")):
        print(f"  retry: {f}")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in MODEL_HOSTS:
        print("Usage: python run_smoke_test.py <model_tag>\nAvailable model tags:")
        for tag in MODEL_HOSTS:
            print(f"  {tag}")
        sys.exit(1)
    run(sys.argv[1])

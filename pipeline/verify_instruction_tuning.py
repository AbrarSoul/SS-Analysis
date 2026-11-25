"""
Empirical instruction-tuning verification for new model candidates, replicating exactly the
two-probe method used for the original 8 primary models (Research_Log/Implementation_Log.md
Section 2.3) -- no automated classifier, just the same pass/fail criterion applied consistently:

1. Strict-format probe: "Respond with only the single word: DONE. Do not say anything else."
2. Direct Q&A probe: "What is the capital of France? Answer in one short sentence."

An instruction-tuned model follows the format and answers correctly; a base/completion model
ignores the instruction and continues generating plausible-looking text instead (echoing the
prompt, hallucinating further "prompts", etc.) -- exactly what happened with starcoder2:15b,
the one candidate the original check correctly caught and excluded.

Usage:
    export GPTLAB_API_KEY=...   # never written to any file, read from the environment only
    python pipeline/verify_instruction_tuning.py
"""
import os
import sys

import requests

GPTLAB_BASE_TEMPLATE = "https://gptlab.rd.tuni.fi/GPT-Lab/resources/{host}/v1"

# The 7 new candidates, mapped to the host that serves them per the live catalog fetch
# (not the stale Open Models/MODELS.md snapshot -- update that file separately once this
# verification is done).
CANDIDATES = {
    "phi4:14b-q4_K_M": "GPU-farmi-001",
}

# phi4-reasoning:14b (GPU-farmi-004) timed out at both 60s and 300s on a one-sentence probe --
# dropped per the same precedent as QwQ-32B in the original study (repeated infra-level timeouts,
# not an instruction-following question). Replaced with the standard, non-reasoning phi4:14b-q4_K_M
# variant on GPU-farmi-001, which still needs its own instruction-tuning check -- not assumed just
# because it's not a reasoning model.
PROBE_TIMEOUT_SECONDS = 60

PROBE_FORMAT = "Respond with only the single word: DONE. Do not say anything else."
PROBE_QA = "What is the capital of France? Answer in one short sentence."


def get_api_key() -> str:
    key = os.environ.get("GPTLAB_API_KEY")
    if not key:
        raise RuntimeError("GPTLAB_API_KEY environment variable is not set.")
    return key


def probe(host: str, model: str, prompt: str, api_key: str) -> str:
    url = f"{GPTLAB_BASE_TEMPLATE.format(host=host)}/chat/completions"
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
        },
        timeout=PROBE_TIMEOUT_SECONDS,
    )
    if resp.status_code != 200:
        return f"[HTTP {resp.status_code}] {resp.text[:300]}"
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def main():
    api_key = get_api_key()
    print(f"Verifying {len(CANDIDATES)} candidates against the live GPT-Lab endpoint.")
    print("Pass/fail is a manual call based on the printed output -- same as the original 8,")
    print("no automated classifier. Read each response against the two criteria below.\n")

    for model, host in CANDIDATES.items():
        print("=" * 100)
        print(f"{model}  (host={host})")
        print("=" * 100)
        try:
            r1 = probe(host, model, PROBE_FORMAT, api_key)
            print(f"  [format probe] expected exactly 'DONE' -> got: {r1!r}")
        except Exception as e:
            print(f"  [format probe] ERROR: {e}")
        try:
            r2 = probe(host, model, PROBE_QA, api_key)
            print(f"  [QA probe]     expected a correct, short answer -> got: {r2!r}")
        except Exception as e:
            print(f"  [QA probe] ERROR: {e}")
        print()


if __name__ == "__main__":
    main()

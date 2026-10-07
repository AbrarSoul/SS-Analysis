"""
Section 30 preregistration item #6 ("prompt frozen and hashed"). The rendered prompt differs per case (it
interpolates real CVE/CWE/function data), so what gets hashed is the STATIC TEMPLATE -- the source of the
function that builds it, which is exactly what changes if and only if the template itself changes. Any edit
to either _build_prompt_* method changes its hash; that's the intended trip-wire.

Run this after any change to autogrep/llm_client.py's prompt-building methods, and compare against
pipeline/PINNED_CONFIG.md. A mismatch means the frozen prompt was edited and the change needs to be a
deliberate, recorded decision, not silent drift.
"""
import hashlib
import inspect
import os
import sys
from pathlib import Path

os.environ.setdefault("GPTLAB_API_KEY", "not-used-in-this-check")
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]

from llm_client import LLMClient  # noqa: E402

PINNED = {
    "_build_prompt_autogrep_default": "6e7d840e71782db4c9bd367d1e2a846f0f7b8707c9f2aacc6b040482c1613e42",
    "_build_prompt_design_v1": "ae50ab374bb441f08e466491d0cf1099c2c5576255ed5833e89de7e27419edaf",
}

if __name__ == "__main__":
    ok = True
    for name, expected in PINNED.items():
        actual = hashlib.sha256(inspect.getsource(getattr(LLMClient, name)).encode()).hexdigest()
        status = "OK" if actual == expected else "MISMATCH"
        if actual != expected:
            ok = False
        print(f"{name:32} {status}  {actual}")
    sys.exit(0 if ok else 1)

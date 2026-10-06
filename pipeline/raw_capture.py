"""
Raw-output capture for the Autogrep pipeline.

Design doc Section 14 requires the *exact* model response saved before any
extraction, YAML cleanup, or retry/repair logic touches it -- so that the
"raw" condition (Section 15) genuinely reflects the model's first, untouched
attempt, distinct from what Autogrep's retry loop eventually settles on.

Autogrep's own generate_rule() doesn't expose a hook for this -- it mutates
the response in-place on its way to the returned dict. Rather than editing
that method, we wrap the OpenAI-compatible client object at the point
generate_rule() calls it (self.client.chat.completions.create), so every
raw completion is recorded before Autogrep's own processing ever sees it,
with zero changes to llm_client.py's logic.

A single recorder is shared across every patch a run processes; it tracks
call counts per case_id itself, so the caller only needs to announce which
case is about to be processed via begin_case() before invoking Autogrep's
process_patch() for it.
"""
import json
import time
from pathlib import Path
from typing import Optional


class RawCaptureRecorder:
    """Tracks per-case call counts and writes one JSON record per call.
    Call #1 for a case is the 'raw' condition; later calls in the same
    case's retry loop are recorded separately, tagged as retries.

    Files are namespaced under run_id, not just case_id: a fixed
    "raw/{case_id}.json" path would silently overwrite a previous run's
    capture on re-run, which both destroys reproducibility evidence and
    breaks the Section 13.4 stability experiment outright (5 runs of the
    same model against the same case are supposed to be preserved as 5
    distinct generations, not collapsed into one)."""

    def __init__(self, run_dir: Path, run_id: str):
        self.run_id = run_id
        self.raw_dir = Path(run_dir) / "raw" / run_id
        self.retries_dir = Path(run_dir) / "raw_retries" / run_id
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.retries_dir.mkdir(parents=True, exist_ok=True)
        self._current_case_id: Optional[str] = None
        self._call_counts = {}

    def begin_case(self, case_id: str):
        """Call this immediately before processing a given case, so
        subsequent recorded calls are correctly attributed to it."""
        self._current_case_id = case_id
        self._call_counts.setdefault(case_id, 0)

    def record(self, model: Optional[str], temperature, content: Optional[str],
               prompt_text: Optional[str] = None):
        case_id = self._current_case_id or "unknown_case"
        self._call_counts[case_id] = self._call_counts.get(case_id, 0) + 1
        attempt_index = self._call_counts[case_id]

        payload = {
            "run_id": self.run_id,
            "case_id": case_id,
            "attempt_index": attempt_index,
            "condition": "raw" if attempt_index == 1 else "retry",
            "model": model,
            "temperature": temperature,
            "timestamp": time.time(),
            "raw_content": content,
            "prompt_text": prompt_text,
        }

        if attempt_index == 1:
            target = self.raw_dir / f"{case_id}.json"
        else:
            target = self.retries_dir / f"{case_id}_attempt{attempt_index}.json"
        target.write_text(json.dumps(payload, indent=2))
        return target


class _CompletionsProxy:
    def __init__(self, real_completions, recorder: RawCaptureRecorder):
        self._real_completions = real_completions
        self._recorder = recorder

    def create(self, *args, **kwargs):
        response = self._real_completions.create(*args, **kwargs)
        try:
            content = response.choices[0].message.content
        except (AttributeError, IndexError):
            content = None

        prompt_text = None
        for message in kwargs.get("messages", []):
            if message.get("role") == "user":
                prompt_text = message.get("content")
                break

        self._recorder.record(
            model=kwargs.get("model"),
            temperature=kwargs.get("temperature"),
            content=content,
            prompt_text=prompt_text,
        )
        return response


class _ChatProxy:
    def __init__(self, real_chat, recorder: RawCaptureRecorder):
        self.completions = _CompletionsProxy(real_chat.completions, recorder)


class RawCaptureClient:
    """Drop-in replacement for an OpenAI-compatible client: same
    .chat.completions.create(...) interface, transparent to callers,
    records every raw response as a side effect."""

    def __init__(self, real_client, recorder: RawCaptureRecorder):
        self.chat = _ChatProxy(real_client.chat, recorder)


def wrap_llm_client(llm_client, recorder: RawCaptureRecorder):
    """Wrap an already-constructed Autogrep LLMClient's internal API client
    with raw-output capture, in place. Call once, right after constructing
    AutoGrep(config) / LLMClient(config)."""
    llm_client.client = RawCaptureClient(llm_client.client, recorder)
    return llm_client

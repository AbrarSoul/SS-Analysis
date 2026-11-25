"""
Deterministic probe caching for conditions C/D, per Controlled_2x2_Protocol_Draft_20261012.md
Section 5 ("Probe count per case: exactly 1 vulnerable + 1 patched probe pair per case, generated
once and cached... deterministic given the same vulnerable_function/patched_function input") and
the closure note's explicit scenario 6 ("Cache mismatch: reject or rebuild/review under a new
version; never silently reuse stale input").

CORRECTED 2026-10-13 (CD_Gate_Cache_Review_20261013.md found two real gaps, both reproduced
directly before fixing):

Finding 1 (payload integrity): the original version hashed only the INPUTS (case text + builder
file), not the OUTPUT it serves. A cache entry's `payload.fields` could be edited arbitrarily --
including in `strict=True` mode -- and `get_or_build_probe` would still return it as a `"hit"`,
since the key (built only from inputs) still matched. Reproduced directly: tampering a cached
`vulnerable_probe` string to `"return 999"` while leaving the key untouched still returned `"hit"`
with the tampered text. Fixed by storing a `payload_sha256` (hash of the serialized payload)
alongside the key and verifying it on every read -- a payload hash mismatch is treated exactly
like a key mismatch (rebuild by default, raise in strict mode), never silently served.

Finding 2 (cache identity): the key previously had no `language` field at all and no parser/
runtime version pins, despite `language` selecting an entirely different parsing/renaming code
path in `dev_probe.py`. Reproduced directly: caching an eligible JavaScript probe under
`case_id="CASE-Y"`, then requesting the SAME case_id/text as `language="typescript"` in strict
mode, returned `"hit"` with `result.language == "javascript"` -- a wrong-language probe served
under a mismatched request. Fixed by adding `language` plus the four tree-sitter package versions
and the running Python version to the key -- any of these changing now invalidates the cache the
same way an input/builder-hash change already did.

This module also distinguishes two usage tiers, per the review's explicit recommendation ("Keep
ordinary development cache rebuilding separate from frozen experimental loading"):
`get_or_build_probe` is the general-purpose, freely-rebuilding development cache (used while
iterating on new/changed cases); `load_probe_for_experiment` is the stricter loader for the
FIXED, already-reviewed 24-case development selection, validating the returned probe against a
frozen manifest of expected hashes/dispositions and refusing to proceed on any deviation --
including a deviation that would otherwise look like a legitimate rebuild.
"""
import hashlib
import json
import sys
from dataclasses import asdict
from importlib.metadata import version as _pkg_version
from pathlib import Path

import dev_probe as dp
from dev_probe import build_probe, ProbeResult, ProbeIneligible

_DEV_PROBE_PATH = Path(dp.__file__)
_PARSER_PACKAGES = ("tree_sitter", "tree_sitter_java", "tree_sitter_javascript", "tree_sitter_typescript")


class CacheMismatchError(Exception):
    """Raised only in strict=True mode when a cached entry's key or payload integrity hash does
    not match the current inputs/builder/runtime version -- the "reject" option the spec allows
    as an alternative to rebuilding."""


class ExperimentManifestError(Exception):
    """Raised by `load_probe_for_experiment` whenever the returned probe deviates from the frozen
    manifest in ANY way (disposition, names, or hashes) -- a changed or additional case may still
    be built offline via `get_or_build_probe` for review, but must never automatically inherit the
    manifest's old review."""


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _sha256_obj(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def dev_probe_sha256() -> str:
    return hashlib.sha256(_DEV_PROBE_PATH.read_bytes()).hexdigest()


def parser_versions() -> dict:
    versions = {pkg: _pkg_version(pkg) for pkg in _PARSER_PACKAGES}
    versions["python"] = sys.version.split()[0]
    return versions


def cache_key(language: str, vulnerable_function: str, patched_function: str) -> dict:
    return {"language": language,
            "vulnerable_function_sha256": _sha256_text(vulnerable_function),
            "patched_function_sha256": _sha256_text(patched_function),
            "dev_probe_sha256": dev_probe_sha256(),
            "parser_versions": parser_versions()}


def _probe_to_payload(result) -> dict:
    return {"eligible": isinstance(result, ProbeResult), "fields": asdict(result)}


def _payload_to_probe(payload: dict):
    cls = ProbeResult if payload["eligible"] else ProbeIneligible
    return cls(**payload["fields"])


def get_or_build_probe(case_id: str, language: str, vulnerable_function: str, patched_function: str,
                        cache_dir, *, strict: bool = False):
    """Returns (result, cache_status). cache_status is one of "hit", "miss_built", or
    "mismatch_rebuilt" -- there is no status (and no code path) corresponding to "serve the stale
    or tampered cached result despite a key or payload mismatch"; that outcome does not exist in
    this function.

    strict=False (default): a key OR payload-integrity mismatch triggers a fresh build,
    overwriting the cache entry -- the caller proceeds using the FRESH, correctly-keyed probe,
    never the stale/tampered one. strict=True: either kind of mismatch raises CacheMismatchError
    instead, for a caller that wants to force an explicit review/rebuild decision -- the "reject"
    alternative the spec also allows."""
    key = cache_key(language, vulnerable_function, patched_function)
    case_dir = Path(cache_dir) / case_id
    entry_path = case_dir / "probe_cache.json"

    if entry_path.exists():
        entry = json.loads(entry_path.read_text())
        key_ok = entry.get("key") == key
        payload_ok = key_ok and entry.get("payload_sha256") == _sha256_obj(entry.get("payload"))
        if key_ok and payload_ok:
            return _payload_to_probe(entry["payload"]), "hit"
        if strict:
            problem = "payload integrity hash" if key_ok else "key"
            raise CacheMismatchError(
                f"{case_id}: cached probe {problem} does not match current inputs/builder/runtime "
                f"version; refusing to serve stale or tampered data (strict mode).")
        status = "mismatch_rebuilt"
    else:
        status = "miss_built"

    result = build_probe(case_id, language, vulnerable_function, patched_function)
    case_dir.mkdir(parents=True, exist_ok=True)
    payload = _probe_to_payload(result)
    entry_path.write_text(json.dumps({"key": key, "payload": payload, "payload_sha256": _sha256_obj(payload)}, indent=2))
    return result, status


def build_experiment_manifest_entry(case_id: str, language: str, vulnerable_function: str,
                                     patched_function: str) -> dict:
    """Builds one frozen-manifest row directly from `build_probe()` (never from a cache, so the
    manifest's own construction cannot inherit a stale or tampered cache entry). Call this once,
    under review, for every case in a fixed selection, to produce the manifest
    `load_probe_for_experiment` validates against."""
    result = build_probe(case_id, language, vulnerable_function, patched_function)
    entry = {"case_id": case_id, "language": language,
              "vulnerable_function_sha256": _sha256_text(vulnerable_function),
              "patched_function_sha256": _sha256_text(patched_function),
              "dev_probe_sha256": dev_probe_sha256(), "parser_versions": parser_versions(),
              "eligible": isinstance(result, ProbeResult)}
    if isinstance(result, ProbeResult):
        entry.update(old_name=result.old_name, new_name=result.new_name,
                     vulnerable_probe_sha256=_sha256_text(result.vulnerable_probe),
                     patched_probe_sha256=_sha256_text(result.patched_probe),
                     patched_probe_renamed=result.patched_probe_renamed)
    else:
        entry["reason"] = result.reason
    return entry


def load_probe_for_experiment(case_id: str, language: str, vulnerable_function: str,
                               patched_function: str, cache_dir, manifest: dict):
    """Stricter loader for the FIXED, already-reviewed development selection -- validates the
    returned probe against `manifest[case_id]` (a `build_experiment_manifest_entry`-shaped dict)
    and raises `ExperimentManifestError` on ANY deviation: wrong language, changed input hashes,
    a different dev_probe.py/parser version than the manifest was built under, an eligibility
    flip, or (for an eligible case) a different old_name/new_name/probe-text hash than the
    manifest records. This is deliberately independent of `get_or_build_probe`'s own key/payload
    check -- that check only proves internal self-consistency (the cache wasn't tampered after
    being written); THIS check proves the probe still matches what was actually reviewed. A case
    missing from the manifest entirely raises immediately -- 'a changed or additional case may be
    built offline for review, but must not automatically inherit the old review.'"""
    if case_id not in manifest:
        raise ExperimentManifestError(f"{case_id}: not present in the frozen experiment manifest; "
                                        f"build and review it explicitly before experimental use.")
    expected = manifest[case_id]
    actual_vuln_hash = _sha256_text(vulnerable_function)
    actual_patched_hash = _sha256_text(patched_function)
    mismatches = []
    if expected["language"] != language:
        mismatches.append(f"language: manifest={expected['language']!r}, requested={language!r}")
    if expected["vulnerable_function_sha256"] != actual_vuln_hash:
        mismatches.append("vulnerable_function_sha256 differs from the manifest")
    if expected["patched_function_sha256"] != actual_patched_hash:
        mismatches.append("patched_function_sha256 differs from the manifest")
    if expected["dev_probe_sha256"] != dev_probe_sha256():
        mismatches.append("dev_probe_sha256 differs from the manifest (builder version changed)")
    if expected["parser_versions"] != parser_versions():
        mismatches.append("parser_versions differ from the manifest")
    if mismatches:
        raise ExperimentManifestError(f"{case_id}: does not match the frozen manifest: {'; '.join(mismatches)}")

    result, cache_status = get_or_build_probe(case_id, language, vulnerable_function, patched_function,
                                               cache_dir, strict=True)
    if isinstance(result, ProbeResult) != expected["eligible"]:
        raise ExperimentManifestError(f"{case_id}: eligibility flipped relative to the manifest "
                                        f"(manifest eligible={expected['eligible']}, now "
                                        f"{isinstance(result, ProbeResult)})")
    if isinstance(result, ProbeIneligible):
        if result.reason != expected["reason"]:
            raise ExperimentManifestError(f"{case_id}: ineligibility reason differs from the manifest "
                                            f"(manifest={expected['reason']!r}, now={result.reason!r})")
    else:
        actual_vuln_probe_hash = _sha256_text(result.vulnerable_probe)
        actual_patched_probe_hash = _sha256_text(result.patched_probe)
        if (result.old_name != expected["old_name"] or result.new_name != expected["new_name"]
                or actual_vuln_probe_hash != expected["vulnerable_probe_sha256"]
                or actual_patched_probe_hash != expected["patched_probe_sha256"]):
            raise ExperimentManifestError(f"{case_id}: generated probe differs from the manifest's "
                                            f"reviewed artifact")
    return result, cache_status

"""
Run v2 (Research_Log/Run_v2_Specification.md, supervisor Issue 4): one way to run Semgrep, with an explicit
status for every scan, so a scan that did not really happen can never be read as "scanned, nothing found".

What pinned Semgrep 1.177.0 actually reports (checked 2026-11-25, see pipeline/tests/test_run_v2_issue4.py):
  - target file with a syntax error: a level "warn" error of type ["PartialParsing", ...] whose path is the
    target, exit code 0, and the broken region yields no results;
  - rule written for another language than the target (e.g. a python rule on a .ts file): no error at all;
    the target is simply absent from paths.scanned;
  - invalid rule: a "Rule parse error" with rule_id set, exit code 2.
v1's wrapper (autogrep/rule_validator.py: RuleValidator._run_semgrep) matched error-type names and returned
"no results, no error" for the second case, and it called whichever `semgrep` came first on the PATH. Both
stay unchanged for v1; run v2 uses this module for every Semgrep call.

Scan statuses, in precedence order:
  "rule_error"          Semgrep rejected the rule
  "semgrep_failure"     Semgrep crashed, timed out or printed no JSON
  "not_scanned"         the target was not scanned (normally: rule language does not match the file)
  "target_parse_error"  the target was scanned but (part of) it could not be parsed
  "ok"                  the target was scanned cleanly; results are complete
Only "ok" scans may be scored as TP/FP/FN/TN. Any other status makes the sample's outcome "ERROR".
"""
import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml

ROOT = Path(__file__).resolve().parent.parent
SEMGREP_BIN = ROOT / ".venv" / "bin" / "semgrep"
PINNED_SEMGREP_VERSION = "1.177.0"
TIMEOUT_SECONDS = 60
STATUSES = ("ok", "target_parse_error", "not_scanned", "semgrep_failure", "rule_error")
BASE_ARGS = ["--json", "--metrics=off", "--disable-version-check"]


@dataclass
class ScanResult:
    status: str
    results: List[dict] = field(default_factory=list)
    message: Optional[str] = None
    exit_code: Optional[int] = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def semgrep_version(binary: Path = SEMGREP_BIN) -> str:
    p = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=60, cwd=str(ROOT))
    return p.stdout.strip()


def assert_pinned_version(binary: Path = SEMGREP_BIN) -> None:
    found = semgrep_version(binary)
    if found != PINNED_SEMGREP_VERSION:
        raise RuntimeError(f"Semgrep at {binary} is {found!r}, run v2 is pinned to {PINNED_SEMGREP_VERSION}")


def _error_text(e: dict) -> str:
    return (e.get("message") or e.get("long_msg") or e.get("short_msg") or str(e)).strip()


def _is_rule_error(e: dict) -> bool:
    t = e.get("type")
    t = t[0] if isinstance(t, list) and t else t
    return bool(e.get("rule_id")) or (isinstance(t, str) and "rule" in t.lower()) or \
        (e.get("level") == "error" and not e.get("path"))


def classify(stdout: str, exit_code: int, targets: List[str]) -> dict:
    """{target: ScanResult} for a Semgrep JSON run over one or more targets."""
    try:
        out = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return {t: ScanResult("semgrep_failure", message=f"no JSON output (exit {exit_code})", exit_code=exit_code)
                for t in targets}
    errors = out.get("errors", []) or []
    rule_errors = [e for e in errors if isinstance(e, dict) and _is_rule_error(e)]
    if rule_errors:
        msg = _error_text(rule_errors[0])
        return {t: ScanResult("rule_error", message=msg, exit_code=exit_code) for t in targets}
    scanned = set(out.get("paths", {}).get("scanned", []) or [])
    by_target = {}
    for t in targets:
        results = [r for r in out.get("results", []) if r.get("path") == t]
        t_errors = [e for e in errors if isinstance(e, dict) and e.get("path") == t]
        if t not in scanned:
            by_target[t] = ScanResult("not_scanned", results, "target not scanned (rule language vs file?)", exit_code)
        elif t_errors:
            by_target[t] = ScanResult("target_parse_error", results, _error_text(t_errors[0]), exit_code)
        elif exit_code not in (0, 1):
            by_target[t] = ScanResult("semgrep_failure", results, f"exit code {exit_code}", exit_code)
        else:
            by_target[t] = ScanResult("ok", results, None, exit_code)
    return by_target


def scan(rule, targets: List[str], binary: Path = SEMGREP_BIN, timeout: int = TIMEOUT_SECONDS) -> dict:
    """Run one rule (a dict, or a path to a rule file) over target files. Returns {target: ScanResult}.
    Targets are passed as given; result paths are matched on the same strings."""
    tmp = None
    if isinstance(rule, dict):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False)
        yaml.safe_dump({"rules": [rule]}, tmp)
        tmp.close()
        rule_file = tmp.name
    else:
        rule_file = str(rule)
    try:
        # Always run from the repo root. Checked 2026-11-25: with targets inside this repository, the same scan of
        # 318 files took 4.5 s from the repo root but did not finish in 280 s from an empty folder or from
        # pipeline/tests. A fixed working directory also keeps results independent of where a script is started.
        p = subprocess.run([str(binary), "--config", rule_file, *BASE_ARGS, *targets],
                           capture_output=True, text=True, timeout=timeout, cwd=str(ROOT))
        return classify(p.stdout, p.returncode, list(targets))
    except subprocess.TimeoutExpired:
        return {t: ScanResult("semgrep_failure", message=f"timeout after {timeout}s") for t in targets}
    finally:
        if tmp:
            Path(tmp.name).unlink(missing_ok=True)


def scan_one(rule, target: str, **kw) -> ScanResult:
    return scan(rule, [target], **kw)[target]

"""
Research_Direction_20261011.md / Controlled_2x2_Protocol_Draft_20261012.md Section 4's combined
accept/stop gate for conditions C/D -- implemented and offline-tested per
Binding_Form_Audit_Closure_20261013.md's six specified scenarios. This module makes NO model
calls and runs NO live Semgrep scans itself: it is a pure decision function over evaluation dicts
shaped exactly like diagnostic_v2.py's scan() and probe_coverage_check.py's scan_probe() already
return, so it can be dropped into the real episode loop without changing either scanner.

The combined gate, exactly as specified in the protocol (corrected 2026-10-12 after a review
found the original single accept-and-stop rule, read literally, silently skipped C/D's probe
check entirely):

    A/B:                                    accept and stop on visible_correct
    C/D, case HAS an eligible probe pair:    accept and stop on
                                              visible_correct AND vulnerable_probe_correct
                                              AND patched_probe_correct
    C/D, case has NO eligible probe pair:    accept and stop on visible_correct alone
                                              (declared A/B fallback, recorded as such --
                                              `is_fallback=True` on the returned decision)

`*_probe_correct` requires the probe's own scan to have genuinely succeeded (`scan_ok`) AND
produced the correct detection outcome. A probe scan error is a FAILED check like any other -- it
must NEVER be silently collapsed into "no eligible probe" (that would wrongly let an episode skip
probe evaluation just because the scan broke, rather than treating the break as a reason to
retry/fail like any other wrong answer). Conditions A and B never look at `probe_checks` at all,
by construction -- enforced here, not just documented (see `test_combined_gate.py`'s
`test_conditions_a_b_never_consult_probe_checks`).

CORRECTED 2026-10-13 (CD_Gate_Cache_Review_20261013.md Finding 3, reproduced directly before
fixing): the original `summarize_episode_resources` counted one visible scan per `GateDecision`,
assuming every attempt reaches `combined_decision` at all. The REAL runner
(`diagnostic_v2.run_model_case`) only scans when generation actually produces a parseable rule --
an attempt whose generation fails (a decode/parse error) consumes a model call and a repair step
but never runs a Semgrep scan and never reaches the gate at all. Reproduced directly: a mocked
decode-failure-then-success trajectory is TWO generation calls but only ONE visible scan; the old
summarizer, given one synthetic "decision" per attempt, could not represent the no-scan attempt at
all without either overcounting scans (one decision per attempt) or undercounting repairs (if the
failed attempt's non-event were simply omitted). Fixed by introducing `AttemptEvent`, an explicit
per-attempt record distinguishing "generation failed, no scan ran" from "generation succeeded, a
decision was made" -- `summarize_episode_resources` now operates on a list of these, never raw
decisions, so a no-scan attempt is counted as a call and a repair without being miscounted as a
visible scan. Probe-scanner-invocation count is likewise an explicit, caller-supplied field on
each event rather than inferred from `probe_checks` -- `evaluate_probe_pair` is deliberately
agnostic to whether the caller used one combined scan or two separate ones, so that distinction
cannot be recovered after the fact and must be supplied directly.

Also added (API-boundary hardening, per the same review's "two API boundary observations"):
`condition` is validated against the four known values (an unrecognized condition previously
behaved silently like A/B); `attempt` is validated against `max_attempts` on the ACCEPT path too,
not just the failure path (a passing candidate on an attempt number past the ceiling was
previously still accepted with no error). Neither was a demonstrated production failure --
`diagnostic_v2.py`'s real loop already uses `range(1, 4)` and never passes an out-of-range
condition -- but both are now enforced rather than merely true by convention. `GateDecision` also
now carries `probe_eligible` directly (independent of `is_fallback`, which is only True on the
successful-fallback path and therefore cannot by itself be used to count eligibility coverage
across failed episodes too, per the review's note).
"""
from dataclasses import dataclass
from typing import Optional

_VALID_CONDITIONS = ("A", "B", "C", "D")


@dataclass
class GateDecision:
    accept: bool
    stop: bool          # True when the episode's retry loop should stop (accept OR budget exhausted)
    reason: str
    is_fallback: bool   # True only for "C/D, no eligible probe pair, ACCEPTED on visible alone"
    probe_eligible: bool  # recorded independently of is_fallback -- true for any C/D case with an
                          # eligible probe pair, whether or not this particular attempt accepted
    probe_checks: Optional[dict] = None  # set only when condition is C/D and probe_eligible is True


def evaluate_probe_pair(vulnerable_probe_scan: dict, patched_probe_scan: dict) -> dict:
    """Takes two scan_probe()-shaped dicts (`pipeline/probe_coverage_check.py`'s own return shape:
    `scan_ok`, and when `scan_ok` is True, `vulnerable_detected`/`patched_detected`) -- one scan
    against the vulnerable probe target, one against the patched probe target. If the real episode
    loop runs a single combined scan against both targets at once (as `probe_coverage_check.py`
    already does), pass the SAME result dict for both arguments -- but then record
    `probe_scanner_invocations=1` (not 2) on the corresponding `AttemptEvent`; this function
    deliberately cannot recover that distinction on its own (see module docstring).

    A scan error on EITHER side makes `probe_scan_error` True and both `*_correct` values False --
    a deliberate conservative default (an error is not evidence of a pass). The caller
    (`combined_decision`) must treat this as a FAILED check, never as "no eligible probe"."""
    scan_ok = bool(vulnerable_probe_scan.get("scan_ok")) and bool(patched_probe_scan.get("scan_ok"))
    if not scan_ok:
        return {"vulnerable_probe_correct": False, "patched_probe_correct": False, "probe_scan_error": True}
    vulnerable_probe_correct = bool(vulnerable_probe_scan.get("vulnerable_detected"))
    patched_probe_correct = not bool(patched_probe_scan.get("patched_detected"))
    return {"vulnerable_probe_correct": vulnerable_probe_correct,
            "patched_probe_correct": patched_probe_correct, "probe_scan_error": False}


def combined_decision(*, condition: str, attempt: int, max_attempts: int, visible_correct: bool,
                       probe_eligible: bool, probe_checks: Optional[dict] = None) -> GateDecision:
    """condition: "A"/"B" (no probes, ever -- `probe_checks` is ignored even if supplied) or
    "C"/"D" (probes consulted when `probe_eligible` is True). `probe_checks` must be the dict
    `evaluate_probe_pair()` returns when condition is C/D, `probe_eligible` is True, and
    `visible_correct` is True (a real episode never scans a probe for an attempt whose visible
    check already failed); it is ignored in every other case, matching the protocol's "Conditions
    A and B's code path must not import the probe module at all."

    Only ever called for an attempt that actually produced a scannable rule -- an attempt whose
    generation failed entirely (no rule parsed) never reaches this function at all; see
    `AttemptEvent`/`summarize_episode_resources` for how that distinction is tracked."""
    if condition not in _VALID_CONDITIONS:
        raise ValueError(f"condition must be one of {_VALID_CONDITIONS}, got {condition!r}")
    if attempt > max_attempts:
        raise ValueError(f"attempt ({attempt}) exceeds max_attempts ({max_attempts}) -- "
                          f"the retry loop must never call this past its own declared ceiling")
    uses_probes = condition in ("C", "D")

    if not uses_probes or not probe_eligible:
        # A/B, or a C/D case with no eligible probe pair -- the declared, explicit fallback.
        if visible_correct:
            return GateDecision(accept=True, stop=True,
                                 reason="visible_correct (no probe check applied)",
                                 is_fallback=uses_probes and not probe_eligible,
                                 probe_eligible=probe_eligible)
        exhausted = attempt >= max_attempts
        reason = "visible_correct failed" + (" -- budget exhausted, retaining last candidate as a failure" if exhausted else "")
        return GateDecision(accept=False, stop=exhausted, reason=reason, is_fallback=False, probe_eligible=probe_eligible)

    # C/D with an eligible probe pair: all three checks must pass to accept. Per the protocol,
    # probes are fed into the REPAIR step only "after a rule already passes the visible pair" --
    # a real episode loop would never even run the probe scan for an attempt whose visible check
    # already failed, so `probe_checks` is short-circuited to not-required in that case (it may
    # legitimately be None here, not just unavailable by caller error).
    if not visible_correct:
        exhausted = attempt >= max_attempts
        reason = "visible_correct failed" + (" -- budget exhausted, retaining last candidate as a failure" if exhausted else "")
        return GateDecision(accept=False, stop=exhausted, reason=reason, is_fallback=False,
                             probe_eligible=True, probe_checks=probe_checks)

    if probe_checks is None:
        raise ValueError("probe_checks is required once visible_correct is True for an eligible C/D case")
    all_pass = probe_checks["vulnerable_probe_correct"] and probe_checks["patched_probe_correct"]
    if all_pass:
        return GateDecision(accept=True, stop=True, reason="visible_correct AND both probe checks passed",
                             is_fallback=False, probe_eligible=True, probe_checks=probe_checks)

    exhausted = attempt >= max_attempts
    if probe_checks["probe_scan_error"]:
        reason = "probe scan error -- treated as a failed check, never an ineligibility fallback"
    else:
        failed = [k for k in ("vulnerable_probe_correct", "patched_probe_correct") if not probe_checks[k]]
        reason = f"visible_correct passed but probe check(s) failed: {failed}"
    if exhausted:
        reason += " -- budget exhausted, retaining last candidate as a failure"
    return GateDecision(accept=False, stop=exhausted, reason=reason, is_fallback=False,
                         probe_eligible=True, probe_checks=probe_checks)


@dataclass
class AttemptEvent:
    """One real attempt's full resource record -- exactly what `summarize_episode_resources`
    needs to count correctly, regardless of whether generation itself failed before any scan
    could run. `generation_ok=False` means `decision` MUST be None (no scan, no gate decision --
    diagnostic_v2.py's real loop takes this path whenever `rule is None`). `generation_ok=True`
    means `decision` is the `GateDecision` `combined_decision()` returned for this attempt's scan.
    `probe_scanner_invocations` is supplied by the CALLER (0 if no probe scan ran this attempt --
    including when `decision.probe_checks` is None -- otherwise however many actual Semgrep
    invocations the caller's own scanning code made for the probe pair, 1 or 2; see
    `evaluate_probe_pair`'s docstring for why this can't be inferred)."""
    attempt: int
    generation_ok: bool
    decision: Optional[GateDecision] = None
    probe_scanner_invocations: int = 0

    def __post_init__(self):
        if not self.generation_ok and self.decision is not None:
            raise ValueError("a failed-generation attempt must not carry a GateDecision -- "
                              "no scan ran, so there was nothing to decide")
        if self.generation_ok and self.decision is None:
            raise ValueError("a successful-generation attempt must carry its GateDecision")


def summarize_episode_resources(events) -> dict:
    """Resource accounting for one episode's full attempt sequence -- a list of `AttemptEvent`,
    one per attempt actually made, in order. Required per the protocol: "different numbers of
    probes consume resources and must be accounted for, not treated as free evidence."

    `generation_calls` is always `len(events)` -- every attempt is a model call whether or not it
    produced a scannable rule. `visible_scans` counts only attempts where generation succeeded
    (matching `diagnostic_v2.py`'s real behavior: a decode/parse failure never reaches `scan()` at
    all). `probe_scans` sums each event's own `probe_scanner_invocations`, never inferred.
    `repair_calls` is every attempt after the first, regardless of whether that attempt's
    generation succeeded -- a decode-failure retry is still a repair call, the exact case the
    prior version got wrong (it either overcounted visible scans or undercounted repairs,
    depending which simplification was chosen; this version does neither)."""
    generation_calls = len(events)
    visible_scans = sum(1 for e in events if e.generation_ok)
    probe_scans = sum(e.probe_scanner_invocations for e in events)
    repair_calls = max(0, len(events) - 1)
    return {"generation_calls": generation_calls, "visible_scans": visible_scans,
            "probe_scans": probe_scans, "repair_calls": repair_calls}

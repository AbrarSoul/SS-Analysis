"""
Regression tests for RuleValidator._run_semgrep()'s error classification.

These exist because of a real bug found during Phase 1 smoke testing:
Semgrep's own "Rule parse error" (e.g. a rule using invalid lowercase
metavariables) was silently reported as "0 results, no error" --
indistinguishable from a valid rule that simply found nothing. See
Research_Log/Model_Failure_Root_Cause_Analysis.md for the full writeup.

The fix changed the classification from an allow-list (only specific known
error-type strings get surfaced) to a deny-list (only target-file parse
errors are safe to treat as "no error"; everything else is surfaced by
default). These tests lock in the four cases that distinguish a working
classifier from a broken one, run against the real, pinned Semgrep binary
(no mocking), so a Semgrep version bump or a future code change that
reintroduces the allow-list pattern will be caught here rather than
silently reappearing in benchmark data months from now.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "autogrep"))
from config import Config  # noqa: E402
from rule_validator import RuleValidator  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def validator():
    return RuleValidator(Config())


def test_valid_rule_with_real_match_returns_results_and_no_error(validator):
    results, error = validator._run_semgrep(
        str(FIXTURES / "valid_matching_rule.yml"),
        str(FIXTURES / "sample_target.py"),
    )
    assert error is None
    assert len(results) > 0


def test_valid_rule_with_no_match_returns_empty_and_no_error(validator):
    """The critical negative case: a syntactically valid rule that
    genuinely finds nothing must NOT be confused with an invalid rule."""
    results, error = validator._run_semgrep(
        str(FIXTURES / "valid_nonmatching_rule.yml"),
        str(FIXTURES / "sample_target.py"),
    )
    assert error is None
    assert results == []


def test_invalid_metavariable_rule_surfaces_as_an_error_not_a_silent_miss(validator):
    """The exact regression this suite exists for: an invalid rule (lowercase
    metavariables) must be surfaced with a non-None error, not returned as
    a clean "[], None" that looks identical to a legitimate non-match."""
    results, error = validator._run_semgrep(
        str(FIXTURES / "invalid_metavariable_rule.yml"),
        str(FIXTURES / "sample_target.py"),
    )
    assert results == []
    assert error is not None
    assert "meta-variable" in error or "Rule parse error" in error


def test_broken_target_file_is_skipped_not_surfaced_as_a_rule_error(validator):
    """A target file that can't be parsed is a data problem, not a rule
    problem -- must stay in the "safe to skip" bucket, distinct from an
    invalid rule."""
    results, error = validator._run_semgrep(
        str(FIXTURES / "valid_matching_rule.yml"),
        str(FIXTURES / "broken_syntax_target.py"),
    )
    assert error is None
    assert results == []


def test_unknown_future_error_types_default_to_surfaced_not_silenced(validator):
    """Guards against reintroducing the allow-list pattern: any error type
    that isn't a recognized file-parse error must be surfaced by default,
    not silently ignored just because its exact string hasn't been seen
    before. Simulated by re-using the invalid-metavariable fixture, which
    is unlikely to ever become a 'known' file-parse-error string."""
    results, error = validator._run_semgrep(
        str(FIXTURES / "invalid_metavariable_rule.yml"),
        str(FIXTURES / "sample_target.py"),
    )
    assert error is not None, (
        "An unrecognized Semgrep error type was silently treated as 'no error' -- "
        "this is exactly the bug this test suite exists to prevent. Check whether "
        "rule_validator.py's error classification reverted to an allow-list."
    )

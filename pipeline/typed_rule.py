"""
Research_Direction_20261011.md item 4: "separating rule semantics from YAML/operator construction
can reduce avoidable construction failures." This is the typed intermediate representation plus
deterministic serializer -- the model would emit THIS simpler, more constrained structure (not
hand-typed YAML text), and this module's serializer (not the model) assembles the final, guaranteed-
valid Semgrep YAML via a real YAML library (yaml.dump), not hand-rolled string formatting.

This directly targets every construction failure actually observed in the mechanism-prompt trials:
  - Bare strings under pattern-either instead of {pattern: ...} mappings (CASE-0134, CASE-0136,
    CASE-0220, CASE-0221, CASE-0276 in qwen3_mechanism_v4/v5) -- impossible here: TypedRule.pattern_either
    is a list of pattern strings, and the serializer ALWAYS wraps each as {"pattern": alt}.
  - pattern-either + a sibling top-level pattern-not not composing as an exclusion (CASE-0276,
    confirmed via an isolated test in Correction_Log.md) -- impossible here: the serializer always
    nests both inside one patterns: list when both are present together.
  - Two mutually exclusive top-level operators, e.g. both pattern-either and patterns (CASE-0231 in
    qwen3_mechanism_v5) -- impossible here: TypedRule's fields are mutually exclusive by construction
    (validate() raises if more than one form is set).
  - Unquoted scalar values containing their own "key: value" breaking YAML (CASE-0238) -- impossible
    here: yaml.dump() handles all quoting correctly; nothing is ever hand-formatted as a string.
  - More than one rule under `rules:` (CASE-0221 in qwen3_mechanism_v3's predecessor) -- impossible
    here: the serializer always emits exactly one rule.

A typed representation can't fix semantic mistakes (the model can still name the wrong vulnerable
construct) -- it only eliminates the SYNTAX/STRUCTURE layer of avoidable construction failures. This
module does not claim otherwise.

Usage (validation against real retained malformed candidates):
    python pipeline/typed_rule.py
"""
from dataclasses import dataclass, field
from typing import Optional

import yaml


@dataclass
class TypedRule:
    id: str
    message: str
    severity: str  # ERROR | WARNING | INFO
    languages: list
    metadata: dict = field(default_factory=dict)

    # Exactly one of these three forms -- enforced by validate(), not left to the caller's discipline.
    pattern: Optional[str] = None
    pattern_either: Optional[list] = None          # list of alternative pattern strings
    taint_sources: Optional[list] = None            # used together with taint_sinks
    taint_sinks: Optional[list] = None

    pattern_not: Optional[list] = None              # 0+ exclusions, compatible with pattern or pattern_either --
    # extended to a list after scanning all 87 accepted rules across every real diagnostic run: several
    # (CASE-0222, CASE-0184, CASE-0193) legitimately need more than one exclusion ANDed together.
    pattern_inside: Optional[str] = None
    pattern_not_inside: Optional[str] = None

    def validate(self):
        """Real runtime type/shape checks, not just the mutual-exclusivity logic -- a prior version
        of this method let `pattern_either='foo()'` (a bare string) through, which Python then
        iterates character-by-character wherever a list is expected (confirmed: produced 5
        single-character "alternatives"). Caught by an independent review 2026-10-12, verified
        directly before this fix, not taken on faith."""
        def require_nonempty_list_of_str(name, value):
            if not isinstance(value, (list, tuple)):
                raise ValueError(f"{name} must be a list of strings, got {type(value).__name__}")
            if len(value) == 0:
                raise ValueError(f"{name} must not be empty")
            if not all(isinstance(v, str) and v for v in value):
                raise ValueError(f"{name} must contain only non-empty strings")

        if not isinstance(self.id, str) or not self.id:
            raise ValueError("id must be a non-empty string")
        if not isinstance(self.message, str) or not self.message:
            raise ValueError("message must be a non-empty string")
        require_nonempty_list_of_str("languages", self.languages)
        if not isinstance(self.metadata, dict):
            raise ValueError(f"metadata must be a dict, got {type(self.metadata).__name__}")

        forms = [self.pattern is not None, self.pattern_either is not None,
                 (self.taint_sources is not None or self.taint_sinks is not None)]
        if sum(forms) != 1:
            raise ValueError(f"TypedRule must set exactly one of pattern/pattern_either/taint_sources+sinks, got {forms}")

        if self.pattern is not None and (not isinstance(self.pattern, str) or not self.pattern):
            raise ValueError("pattern must be a non-empty string")
        if self.pattern_either is not None:
            require_nonempty_list_of_str("pattern_either", self.pattern_either)

        if (self.taint_sources is not None) != (self.taint_sinks is not None):
            raise ValueError("taint_sources and taint_sinks must be set together")
        if self.taint_sources is not None:
            require_nonempty_list_of_str("taint_sources", self.taint_sources)
            require_nonempty_list_of_str("taint_sinks", self.taint_sinks)
            # Not silently dropped (the original bug): explicitly unsupported until verified correct
            # against the real compiler, since no historical accepted rule (0/87 scanned) ever used
            # taint mode, so there is no empirical precedent to validate a taint+pattern_not
            # composition against the way there was for pattern/pattern_either.
            if self.pattern_not or self.pattern_inside or self.pattern_not_inside:
                raise ValueError("taint rules do not support pattern_not/pattern_inside/pattern_not_inside "
                                  "in this serializer -- unsupported combination, not silently dropped")

        if self.pattern_not is not None:
            require_nonempty_list_of_str("pattern_not", self.pattern_not)
        if self.pattern_inside is not None and (not isinstance(self.pattern_inside, str) or not self.pattern_inside):
            raise ValueError("pattern_inside must be a non-empty string")
        if self.pattern_not_inside is not None and (not isinstance(self.pattern_not_inside, str) or not self.pattern_not_inside):
            raise ValueError("pattern_not_inside must be a non-empty string")

        if self.severity not in ("ERROR", "WARNING", "INFO"):
            raise ValueError(f"Invalid severity: {self.severity}")

    def to_dict(self) -> dict:
        """The actual Semgrep rule body, built as a plain dict -- yaml.dump() (a real serializer)
        handles ALL quoting/escaping/indentation correctly from here, never hand-formatted strings.

        Composition rule, corrected 2026-10-12 after an independent review found the prior "simple
        case" (top-level sibling pattern + pattern-not, no patterns: wrapper) silently fails to
        exclude anything under real execution -- verified directly: a rule with top-level
        `pattern: foo($X)` / `pattern-not: foo("safe")` matched BOTH `foo("unsafe")` and
        `foo("safe")` against pinned Semgrep 1.177.0, despite passing `semgrep --validate` cleanly.
        Wrapping both inside one `patterns:` list fixed it (confirmed: matches only the unsafe
        line). `semgrep --validate` checks schema/compilability, never behavior -- a clean validate
        pass is not evidence the exclusion actually works. Conclusion: ANY exclusion key
        (pattern_not or pattern_not_inside), even exactly one, is now always composed via patterns:;
        there is no "safe" sibling shortcut any more for an exclusion.

        REVERTED 2026-10-12, same day, after a follow-up review disproved the "corrected AGAIN" fix
        this docstring previously described here. That fix (keeping pattern_inside as a top-level
        sibling whenever no pattern_not was present) was based on a misread of CASE-0063: the
        earlier investigation saw the nested form match 0 and the sibling form match 1 and concluded
        nesting was broken. Directly reproduced, with a probe the sibling form itself disproves: a
        sibling `pattern-inside` naming a function that DOESN'T EXIST IN THE FILE (e.g.
        `function REVIEW_DOES_NOT_EXIST(...) {...}`) still matches. A top-level sibling
        `pattern-inside` is SILENTLY IGNORED by Semgrep, never enforced -- it only ever appeared to
        "work" in the historical rules because the base `pattern` alone was doing all the matching.
        CASE-0063's real vulnerable code sits inside an ANONYMOUS function expression, not a named
        one; the model's own `pattern-inside: "function $FUNC(...) {...}"` requires a NAME and
        therefore never actually describes the real code. The nested `patterns:` form correctly
        enforces this (0 matches against the named-function constraint, exactly as it should given
        the real code has no name there) -- this is Semgrep's own documented behavior for
        `pattern-inside` (it must be nested under `patterns`/`pattern-either` to have any effect at
        all), not a composition quirk to work around. Reverted to always composing `pattern_inside`
        via `patterns:`, same as any exclusion key -- the only way to make `pattern_inside` actually
        constrain anything rather than silently decorate the YAML. See
        `test_pattern_inside_actually_restricts_scope` for the behavioral (not just schema) test
        this now requires -- both an in-scope and an out-of-scope example, since a positive-only
        fixture cannot distinguish "enforced" from "silently ignored," which is exactly the gap that
        let the ignored-sibling-pattern_inside bug (and, before it, the ignored-sibling-pattern_not
        bug) go undetected for as long as it did."""
        self.validate()
        rule = {"id": self.id}

        pattern_not = self.pattern_not or []
        if self.taint_sources is not None:
            rule["mode"] = "taint"
            rule["pattern-sources"] = [{"pattern": s} for s in self.taint_sources]
            rule["pattern-sinks"] = [{"pattern": s} for s in self.taint_sinks]
        elif not pattern_not and self.pattern_inside is None and self.pattern_not_inside is None:
            # Nothing to compose/exclude/scope at all -- a bare top-level pattern or pattern-either.
            if self.pattern is not None:
                rule["pattern"] = self.pattern
            else:
                rule["pattern-either"] = [{"pattern": alt} for alt in self.pattern_either]
        else:
            # Any exclusion or scope (pattern_inside/pattern_not_inside) modifier: always compose
            # via patterns:, never a top-level sibling -- a sibling pattern_not is confirmed to
            # silently fail to exclude, and a sibling pattern_inside is confirmed to be silently
            # ignored entirely. Neither has a "safe" sibling shortcut.
            items = []
            if self.pattern is not None:
                items.append({"pattern": self.pattern})
            elif self.pattern_either is not None:
                items.append({"pattern-either": [{"pattern": alt} for alt in self.pattern_either]})
            if self.pattern_inside is not None:
                items.append({"pattern-inside": self.pattern_inside})
            for p in pattern_not:
                items.append({"pattern-not": p})
            if self.pattern_not_inside is not None:
                items.append({"pattern-not-inside": self.pattern_not_inside})
            rule["patterns"] = items

        # list(...) even though validate() already accepts a tuple here: yaml.dump() on an actual
        # tuple emits a !!python/tuple tag that yaml.safe_load() can't parse back (confirmed
        # directly -- "could not determine a constructor for the tag" -- caught by an independent
        # review 2026-10-12). The serializer, not the caller, is responsible for always producing
        # plain-YAML-loadable output.
        rule["languages"] = list(self.languages)
        rule["message"] = self.message
        rule["severity"] = self.severity
        if self.metadata:
            rule["metadata"] = self.metadata
        return rule

    def to_semgrep_yaml(self) -> str:
        return yaml.dump({"rules": [self.to_dict()]}, sort_keys=False, default_flow_style=False)


if __name__ == "__main__":
    import subprocess
    import sys
    import tempfile
    from pathlib import Path

    ROOT = Path(__file__).resolve().parent.parent
    SEMGREP = ROOT / ".venv/bin/semgrep"

    # Reconstructions of the REAL malformed candidates found in the mechanism-prompt trials --
    # same intended semantics, expressed as a TypedRule instead of hand-typed YAML.
    cases = [
        ("CASE-0221 bare pattern-either (qwen3_mechanism_v5)", TypedRule(
            id="micronaut-netty-http-headers-default-constructor",
            message="Use of DefaultHttpHeaders with 'false' parameter may lead to security vulnerabilities.",
            severity="WARNING", languages=["java"],
            pattern_either=["new DefaultHttpHeaders(false)", "new DefaultHttpHeaders($X, false)",
                             "new DefaultHttpHeaders($X, $Y, false)"],
            pattern_not=["new DefaultHttpHeaders()"])),
        ("CASE-0276 pattern-either + sibling pattern-not (qwen3_mechanism_v4)", TypedRule(
            id="vuln-cpython-482d6f8b",
            message="Missing SourcelessFileLoader in isinstance check.",
            severity="ERROR", languages=["python"],
            pattern_either=["isinstance($SELF, (SourceLoader, ExtensionFileLoader))",
                             "isinstance($SELF, (SourceLoader, SourcelessFileLoader, ExtensionFileLoader))"],
            pattern_not=["isinstance($SELF, (SourceLoader, SourcelessFileLoader, ExtensionFileLoader))"])),
        ("CASE-0238 unquoted embedded colon (qwen3_mechanism_v1-v4)", TypedRule(
            id="vuln-nocodb-079e3abe",
            message="Missing escapeFormulae option in Papaparse.unparse() call.",
            severity="ERROR", languages=["javascript"],
            pattern="Papaparse.unparse(...)",
            pattern_not=["Papaparse.unparse(..., { escapeFormulae: true })"])),
        ("CASE-0222 pattern + 2x pattern-not + pattern-inside (qwen3_mechanism_v1, real accepted rule)", TypedRule(
            id="requests-verify-false",
            message="Disabled TLS verification in requests.post call.",
            severity="ERROR", languages=["python"],
            pattern="requests.post(..., verify=False)",
            pattern_not=["requests.post(..., verify=True)", "requests.post(..., verify=verify_param)"],
            pattern_inside="def $FUNC(...):\n    ...\n    requests.post(...)\n    ...\n")),
    ]

    env = __import__("os").environ.copy()
    env["PATH"] = str(ROOT / ".venv/bin") + __import__("os").pathsep + env.get("PATH", "")
    env.update(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")

    all_ok = True
    for label, tr in cases:
        yaml_text = tr.to_semgrep_yaml()
        # 1. Does it even parse as YAML (it always will, since yaml.dump produced it -- sanity only).
        parsed = yaml.safe_load(yaml_text)
        assert parsed is not None and len(parsed["rules"]) == 1
        # 2. Does the REAL pinned Semgrep compiler accept it (not just yaml.safe_load -- the actual bar).
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tf:
            tf.write(yaml_text)
            rule_path = tf.name
        # --validate checks the rule's schema/compilability without needing a target file.
        proc = subprocess.run([str(SEMGREP), "--validate", "--config", rule_path],
                               capture_output=True, text=True, env=env, timeout=60)
        ok = proc.returncode == 0
        all_ok = all_ok and ok
        print(f"{'PASS' if ok else 'FAIL'}: {label}")
        if not ok:
            print("  ---stderr---")
            print("  " + proc.stderr.replace("\n", "\n  "))
    print()
    print("All reconstructed malformed candidates now validate:" , all_ok)
    sys.exit(0 if all_ok else 1)

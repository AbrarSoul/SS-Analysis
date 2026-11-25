from typing import Optional, Tuple
from config import Config
import logging
import yaml
from patch_processor import PatchInfo
import re
from openai import OpenAI
from pathlib import Path


# Language-specific example rules -- shared by every prompt variant that shows worked examples.
# Byte-identical string values to the original local dict inside _build_prompt_autogrep_default
# (verified via ast comparison) -- extracted to module level 2026-10-11 because
# _build_prompt_diagnostic_mechanism_v1's docstring claimed to reuse "the same per-language example
# rules" while its implementation never actually referenced them. That was a real bug, caught by
# comparing the new variant's actual captured raw prompt_text against the claim (confirmed: no
# examples were ever sent). autogrep_default's own prompt output is unaffected by this extraction.
EXAMPLE_RULES = {
    "python": '''
    rules:
    - id: "unsafe-deserialization"
        pattern: pickle.loads($DATA)
        pattern-not: pickle.loads(trusted_data)
        pattern-inside: |
            def $FUNC(...):
                ...
        languages: ["python"]
        message: "Detected unsafe deserialization using pickle.loads(). This can lead to remote code execution."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-502
            owasp: A8:2017-Insecure Deserialization
            references:
                - https://docs.python.org/3/library/pickle.html#pickle.loads

    - id: "sql-injection"
        patterns:
            - pattern: execute($QUERY)
            - pattern-not: execute("SELECT ...")
            - pattern-not: execute(sanitized_query)
        languages: ["python"]
        message: "Potential SQL injection detected. Use parameterized queries instead."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-89
    ''',
    "javascript": '''
    rules:
    - id: "xss-innerHTML"
        pattern: $ELEMENT.innerHTML = $DATA
        pattern-not-inside: |
            $ELEMENT.innerHTML = DOMPurify.sanitize($DATA)
        languages: ["javascript"]
        message: "Potential XSS vulnerability using innerHTML. Use DOMPurify or safe alternatives."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-79

    - id: "eval-injection"
        pattern: eval($DATA)
        pattern-not: eval("trusted_static_string")
        languages: ["javascript"]
        message: "Dangerous use of eval() detected. This can lead to code injection."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-95
    ''',
    "java": '''
    rules:
    - id: "path-traversal"
        pattern: new File($PATH)
        pattern-not: new File(sanitized_path)
        pattern-inside: |
            class $CLASS {
                ...
            }
        languages: ["java"]
        message: "Potential path traversal vulnerability. Validate and sanitize file paths."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-22

    - id: "weak-cipher"
        pattern: Cipher.getInstance("DES")
        languages: ["java"]
        message: "Usage of weak cryptographic algorithm DES detected. Use AES instead."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-326
    '''
}

# 2026-10-11: EXAMPLE_RULES (above) has invalid YAML indentation in all three languages --
# confirmed via yaml.safe_load() failing on each one, including the historical local copy inside
# _build_prompt_autogrep_default (same content, byte-identical, so this is a genuine pre-existing
# defect in the vendored upstream Autogrep tool's own prompt, present in every run that has ever
# used autogrep_default -- the full pilot screening, the 8-model primary benchmark, all 5 stability
# reps, C2/C3/C4, the 7-model follow-up campaign, and gpt-4o. Not fixed in EXAMPLE_RULES or in
# autogrep_default's own local copy: that prompt's whole methodological role is to represent the
# unmodified upstream tool exactly as pinned (its hash is recorded in pipeline/PINNED_CONFIG.md),
# so silently correcting it would change what every existing published result actually measured.
# The examples are illustrative text shown to the model, never parsed by this pipeline itself, so
# this doesn't corrupt any existing metric computation directly -- the only plausible effect is
# behavioral (a model partially imitating the shown broken indentation in its own output), which is
# a hypothesis, not something measured or established here. This corrected copy is used ONLY by
# diagnostic_mechanism_v2 (a new, distinctly-named condition -- see Research_Log/Correction_Log.md
# for why diagnostic_mechanism_v1 keeps its exact already-run content rather than being edited again).
EXAMPLE_RULES_V2 = {
    "python": '''
rules:
- id: unsafe-deserialization
  pattern: pickle.loads($DATA)
  pattern-not: pickle.loads(trusted_data)
  pattern-inside: |
    def $FUNC(...):
        ...
  languages: [python]
  message: Detected unsafe deserialization using pickle.loads(). This can lead to remote code execution.
  severity: ERROR
  metadata:
    category: security
    cwe: CWE-502
    owasp: A8:2017-Insecure Deserialization
    references:
      - https://docs.python.org/3/library/pickle.html#pickle.loads
- id: sql-injection
  patterns:
    - pattern: execute($QUERY)
    - pattern-not: execute("SELECT ...")
    - pattern-not: execute(sanitized_query)
  languages: [python]
  message: Potential SQL injection detected. Use parameterized queries instead.
  severity: ERROR
  metadata:
    category: security
    cwe: CWE-89
''',
    "javascript": '''
rules:
- id: xss-innerHTML
  pattern: $ELEMENT.innerHTML = $DATA
  pattern-not-inside: |
    $ELEMENT.innerHTML = DOMPurify.sanitize($DATA)
  languages: [javascript]
  message: Potential XSS vulnerability using innerHTML. Use DOMPurify or safe alternatives.
  severity: ERROR
  metadata:
    category: security
    cwe: CWE-79
- id: eval-injection
  pattern: eval($DATA)
  pattern-not: eval("trusted_static_string")
  languages: [javascript]
  message: Dangerous use of eval() detected. This can lead to code injection.
  severity: ERROR
  metadata:
    category: security
    cwe: CWE-95
''',
    "java": '''
rules:
- id: path-traversal
  pattern: new File($PATH)
  pattern-not: new File(sanitized_path)
  pattern-inside: |
    class $CLASS {
        ...
    }
  languages: [java]
  message: Potential path traversal vulnerability. Validate and sanitize file paths.
  severity: ERROR
  metadata:
    category: security
    cwe: CWE-22
- id: weak-cipher
  pattern: Cipher.getInstance("DES")
  languages: [java]
  message: Usage of weak cryptographic algorithm DES detected. Use AES instead.
  severity: ERROR
  metadata:
    category: security
    cwe: CWE-326
'''
}

# 2026-10-11, same day: EXAMPLE_RULES_V2's live trial (qwen3_mechanism_v3) traced a NEW, distinct
# problem back to the examples themselves, found during review of the run: CASE-0221 failed all 3
# attempts with "Expected exactly one rule mapping" because the model emitted two separate rules --
# confirmed directly against its raw captured response, which structurally mirrors EXAMPLE_RULES_V2
# showing exactly two worked examples per language. Plausible mechanism, not proven: the model
# imitated the example's COUNT, not just its style. Reduced to one rule per language here. Also adds
# a `typescript` entry -- EXAMPLE_RULES/EXAMPLE_RULES_V2 only ever had python/javascript/java (an
# upstream gap, inherited, present in autogrep_default too), so every TypeScript case in the 24-case
# dev subset (6/24, confirmed via benchmark/diagnostic_20261010/selection.json) got zero worked
# examples under every prior condition. And adds explicit colon-quoting guidance in the prompt body
# (see _build_prompt_diagnostic_mechanism_v1's examples= handling) targeting CASE-0238's own
# recurring, confirmed-unrelated-to-indentation failure: an unquoted pattern value containing its own
# embedded "key: value" (e.g. `{ escapeFormulae: true }`) breaks YAML's block-mapping parser. This
# example set's own sql-injection-equivalent style guidance is deliberately absent here (one rule per
# language only) -- the quoting lesson is taught via prose guidance in the prompt body instead, not by
# adding a second example back in.
EXAMPLE_RULES_V3 = {
    "python": '''
rules:
- id: unsafe-deserialization
  pattern: pickle.loads($DATA)
  pattern-not: pickle.loads(trusted_data)
  pattern-inside: |
    def $FUNC(...):
        ...
  languages: [python]
  message: Detected unsafe deserialization using pickle.loads(). This can lead to remote code execution.
  severity: ERROR
  metadata:
    category: security
    cwe: CWE-502
    owasp: A8:2017-Insecure Deserialization
    references:
      - https://docs.python.org/3/library/pickle.html#pickle.loads
''',
    "javascript": '''
rules:
- id: xss-innerHTML
  pattern: $ELEMENT.innerHTML = $DATA
  pattern-not-inside: |
    $ELEMENT.innerHTML = DOMPurify.sanitize($DATA)
  languages: [javascript]
  message: Potential XSS vulnerability using innerHTML. Use DOMPurify or safe alternatives.
  severity: ERROR
  metadata:
    category: security
    cwe: CWE-79
''',
    "java": '''
rules:
- id: path-traversal
  pattern: new File($PATH)
  pattern-not: new File(sanitized_path)
  pattern-inside: |
    class $CLASS {
        ...
    }
  languages: [java]
  message: Potential path traversal vulnerability. Validate and sanitize file paths.
  severity: ERROR
  metadata:
    category: security
    cwe: CWE-22
''',
    "typescript": '''
rules:
- id: csv-formula-injection
  patterns:
    - pattern: $LIB.unparse(...)
    - pattern-not: '$LIB.unparse(..., { escapeFormulae: true })'
  languages: [typescript]
  message: 'Potential CSV formula injection. Pass { escapeFormulae: true } when unparsing untrusted data.'
  severity: ERROR
  metadata:
    category: security
    cwe: CWE-1236
'''
}



def _make_suggested_id(patch_info: PatchInfo) -> str:
    """Builds the "vuln-{repo}-{commit}" id suggested to the model and used
    as _sanitize_rule()'s fallback. Real repo names can contain characters
    (underscores, dots, ...) the rule schema's id field forbids
    (^[a-z0-9-]+$) -- e.g. "openssh_key_parser" -- so every non-matching
    character is normalized to a hyphen (collapsing runs, trimming ends)
    rather than passed through raw. Found via a real pilot-case smoke test
    (CASE-0009): without this, the prompt suggested an id the schema itself
    would reject, and the model dutifully copied it verbatim on every retry."""
    commit_short = patch_info.commit_id[:8]
    raw = f"vuln-{patch_info.repo_name.lower()}-{commit_short}"
    normalized = re.sub(r'[^a-z0-9-]+', '-', raw)
    normalized = re.sub(r'-+', '-', normalized).strip('-')
    return normalized


class LLMClient:
    def __init__(self, config: Config):
        self.config = config
        self.client = OpenAI(
            api_key=config.openrouter_api_key,
            base_url=config.openrouter_base_url,
            timeout=getattr(config, "request_timeout_seconds", 120.0),
        )
        # Set on every failure inside parse_and_sanitize_response()/generate_rule(),
        # cleared on success. main.py's retry loop reads this so schema-validation
        # failures (e.g. "Invalid severity level...") get fed back into the next
        # attempt's error_feedback just like Semgrep-validation failures already
        # were -- previously only a generic "Failed to generate valid rule
        # structure" message was used for this category, which gave the model
        # nothing specific to correct across retries.
        self.last_error: Optional[str] = None
        
    def extract_response(self, text: str) -> str:
        """Remove thinking tags and extract the YAML content from markdown
        formatting.

        Prefers the CONTENT of a fenced code block over blind fence-marker
        stripping. Found via a live pilot-screening result: deepseek-coder:6.7b
        and magicoder:7b scored ~0% yaml_valid under autogrep_default while
        every other model scored well above 0% -- traced to these two models
        wrapping their YAML in explanatory prose before/after the fence
        ("Here is a basic example...", "This rule will match..."), which the
        old version only stripped the ```yaml/``` marker LINES from, leaving
        the surrounding prose in the string handed to yaml.safe_load() and
        breaking every single generation for those two models. qwen2.5-coder,
        by contrast, returns bare YAML with no fence at all -- confirmed by
        comparing raw_capture/*.json across models directly."""
        # Remove thinking tags
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)

        fence_match = re.search(r'```(?:yaml|yml)?[ \t]*\n(.*?)```', text, flags=re.DOTALL)
        if fence_match:
            text = fence_match.group(1)
        else:
            # No closed fence found (already-bare YAML, or a truncated
            # response with only an opening fence) -- fall back to stripping
            # any stray marker lines, matching prior behavior.
            text = re.sub(r'^```yaml\s*', '', text, flags=re.MULTILINE)
            text = re.sub(r'^```\s*$', '', text, flags=re.MULTILINE)

        # Remove any leading/trailing whitespace
        return text.strip()
    
    def clean_yaml_text(self, text: str) -> Optional[str]:
        """Clean and validate YAML text with better error handling."""
        if not text:
            return None
            
        # Remove any YAML document markers
        text = re.sub(r'^---\s*$', '', text, flags=re.MULTILINE)
        text = re.sub(r'^\.{3}\s*$', '', text, flags=re.MULTILINE)
        
        try:
            # First try to parse the YAML
            data = yaml.safe_load(text)

            # Ensure we have a valid rules structure
            if not isinstance(data, dict):
                data = {'rules': [data] if data else []}
            elif 'rules' not in data:
                data = {'rules': [data]}

            # Clean dump with proper formatting
            return yaml.dump(data, sort_keys=False, default_flow_style=False)
        except (yaml.YAMLError, RecursionError) as e:
            # RecursionError: observed live on CASE-0008 / deepseek-coder:6.7b --
            # pathologically nested/repetitive generated YAML can exceed
            # Python's default recursion limit inside PyYAML's own composer.
            # Treated the same as a YAML parse failure rather than left to
            # propagate, since an uncaught RecursionError here previously blew
            # past every caller's `except yaml.YAMLError`/`except Exception`
            # boundary that didn't also list it explicitly.
            logging.error(f"YAML parsing error: {e}")
            # Try to salvage malformed YAML by wrapping in rules structure
            try:
                wrapped_text = f"rules:\n  - {text}"
                data = yaml.safe_load(wrapped_text)
                return yaml.dump(data, sort_keys=False, default_flow_style=False)
            except (yaml.YAMLError, RecursionError):
                return None

    def validate_rule_schema(self, rule: dict) -> Tuple[bool, Optional[str]]:
        """Validate that the rule has all required fields."""
        policy = getattr(self.config, "rule_schema_policy", "legacy_pattern_only")
        if policy not in {"legacy_pattern_only", "semgrep_search_taint_v2"}:
            return False, f"Unknown rule schema policy: {policy}"
        required_fields = ['id', 'message', 'severity', 'languages']
        if policy == "legacy_pattern_only":
            required_fields.append('pattern')
        
        if not isinstance(rule, dict):
            return False, "Rule must be a dictionary"
            
        missing_fields = [field for field in required_fields if field not in rule]
        if missing_fields:
            return False, f"Missing required fields: {', '.join(missing_fields)}"

        if policy == "semgrep_search_taint_v2":
            # Lightweight envelope check only. Pinned Semgrep is authoritative
            # for nested operators, types, and pattern-language correctness.
            mode = rule.get("mode", "search")
            if mode == "taint":
                if not all(key in rule for key in ("pattern-sources", "pattern-sinks")):
                    return False, "Taint rules require pattern-sources and pattern-sinks"
            elif mode == "search":
                if not any(key in rule for key in ("pattern", "patterns", "pattern-either", "pattern-regex")):
                    return False, "Search rules require pattern, patterns, pattern-either, or pattern-regex"
            else:
                return False, f"Unsupported diagnostic rule mode: {mode}"
            
        # Validate severity
        valid_severities = ['ERROR', 'WARNING', 'INFO']
        if rule['severity'] not in valid_severities:
            return False, f"Invalid severity level. Must be one of: {', '.join(valid_severities)}"
            
        # Ensure id is properly formatted
        if not isinstance(rule['id'], str) or not re.match(r'^[a-z0-9-]+$', rule['id']):
            return False, "Invalid id format. Must contain only lowercase letters, numbers, and hyphens"
            
        return True, None

    def _sanitize_rule(self, rule: dict, patch_info: PatchInfo) -> dict:
        """Ensure rule has all required fields and correct format."""
        if not isinstance(rule, dict):
            rule = {'rules': [rule]}
        
        # Extract the actual rule if wrapped in 'rules' list. Only replace
        # `rule` when that first element is itself a dict -- clean_yaml_text()'s
        # salvage path (triggered when the model's YAML doesn't parse on the
        # first try) can produce a `rules:` list whose first element is a bare
        # scalar string, e.g. a stray label line like "YAML" the model put
        # right after the fence delimiter got parsed as rules[0] while the
        # REAL fields (id/pattern/message/...) ended up as sibling top-level
        # keys next to `rules`, not inside it. Observed live on CASE-0030 /
        # codellama:7b-instruct-fp16: unconditionally doing
        # `rule = rule['rules'][0]` there replaced a dict that already had
        # every required field with the string "YAML", and the next line
        # (`rule['id'] = ...`) crashed with "'str' object does not support
        # item assignment" instead of recovering the perfectly usable rule
        # sitting right next to it.
        if 'rules' in rule and isinstance(rule['rules'], list) and rule['rules']:
            candidate = rule['rules'][0]
            if isinstance(candidate, dict):
                rule = candidate
        
        # Ensure rule has an ID
        if 'id' not in rule:
            # Generate an ID based on the repository and commit
            rule['id'] = _make_suggested_id(patch_info)
        
        # Ensure rule has languages field
        if 'languages' not in rule:
            rule['languages'] = [patch_info.file_changes[0].language]
        
        # Ensure rule has severity
        if 'severity' not in rule:
            rule['severity'] = 'ERROR'
        
        # Ensure rule has metadata. Models occasionally return `metadata:` as
        # a YAML list (e.g. a list of key: value single-item mappings) rather
        # than a mapping -- observed live on codellama:7b-instruct-fp16
        # (CASE-0005/0025/0030/0031), which crashed metadata['source-url'] = ...
        # with "TypeError: list indices must be integers or slices, not str".
        # Coerce any non-dict metadata to a fresh dict instead of trusting the
        # model's shape, same principle as the id-sanitization fix above.
        if 'metadata' not in rule or not isinstance(rule['metadata'], dict):
            rule['metadata'] = {}

        metadata = rule['metadata']
        if 'source-url' not in metadata:
            metadata['source-url'] = f"github.com/{patch_info.repo_owner}/{patch_info.repo_name}/commit/{patch_info.commit_id}"
        
        if 'category' not in metadata:
            metadata['category'] = 'security'
        
        if 'technology' not in metadata:
            metadata['technology'] = [patch_info.file_changes[0].language]
        
        return rule

    def parse_and_sanitize_response(self, content: Optional[str], patch_info: PatchInfo) -> Optional[dict]:
        """Extract, clean, parse, and sanitize a raw LLM response string into
        a rule dict. Factored out of generate_rule() so that captured raw
        content (pipeline/raw_capture.py) can be independently re-evaluated
        later -- e.g. to score the design doc's "raw condition" (Section 15)
        using the exact same logic the live generation path uses, regardless
        of what the retry loop subsequently did with that same attempt."""
        if not content:
            self.last_error = "Empty response from LLM"
            logging.error(self.last_error)
            return None

        rule_text = self.extract_response(content)
        if not rule_text:
            self.last_error = "No valid content after extracting response"
            logging.error(self.last_error)
            return None

        rule_text = self.clean_yaml_text(rule_text)
        if not rule_text:
            self.last_error = "Failed to clean YAML text"
            logging.error(self.last_error)
            return None

        try:
            rule_data = yaml.safe_load(rule_text)
            if getattr(self.config, "rule_schema_policy", "legacy_pattern_only") == "semgrep_search_taint_v2":
                candidates = rule_data.get("rules") if isinstance(rule_data, dict) else None
                if not isinstance(candidates, list) or len(candidates) != 1 or not isinstance(candidates[0], dict):
                    self.last_error = "Expected exactly one rule mapping"
                    return None
            rule = self._sanitize_rule(rule_data, patch_info)

            is_valid, error = self.validate_rule_schema(rule)
            if not is_valid:
                self.last_error = f"Invalid rule schema: {error}"
                logging.error(self.last_error)
                return None

            self.last_error = None
            return rule

        except (yaml.YAMLError, RecursionError) as e:
            self.last_error = f"Error parsing generated rule YAML: {e}"
            logging.error(self.last_error)
            return None

    def generate_rule(self, patch_info: PatchInfo, error_feedback: Optional[str] = None) -> Optional[dict]:
        """Generate a Semgrep rule using the LLM with improved validation.

        Dispatches on Config.construction_mode, added for
        Controlled_2x2_Protocol_Draft_20261012.md condition B: "original_prompt" (default) is this
        method's original, unchanged body below -- every historical run used exactly this path,
        with prompt_variant selecting which free-form-YAML prompt. "typed_json" is a completely
        separate output contract (see _generate_rule_typed_json()) -- checked first and returned
        early so the YAML path below is byte-for-byte untouched for every existing caller/config."""
        if getattr(self.config, "construction_mode", "original_prompt") == "typed_json":
            return self._generate_rule_typed_json(patch_info, error_feedback)
        prompt = self._build_prompt(patch_info, error_feedback)

        try:
            kwargs = {}
            if self.config.max_output_tokens is not None:
                kwargs["max_tokens"] = self.config.max_output_tokens
            response = self.client.chat.completions.create(
                model=self.config.model_name,
                messages=[
                    {"role": "system", "content": self._system_message()},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.config.generation_temperature,
                **kwargs,
            )

            if not response.choices:
                self.last_error = "No response generated from LLM"
                logging.error(self.last_error)
                return None

            content = response.choices[0].message.content
            return self.parse_and_sanitize_response(content, patch_info)

        except Exception as e:
            self.last_error = f"Error generating rule: {e}"
            logging.error(self.last_error)
            return None

    def _generate_rule_typed_json(self, patch_info: PatchInfo, error_feedback: Optional[str] = None) -> Optional[dict]:
        """Condition B's generation path (Controlled_2x2_Protocol_Draft_20261012.md §4). The model
        never produces YAML or deals with Semgrep operator composition at all -- it emits a single
        JSON object matching pipeline/typed_rule.py's TypedRule field names, and TypedRule.to_dict()
        deterministically does 100% of the patterns:/pattern-not/pattern-inside composition. Mirrors
        generate_rule()'s own structure (same timeout/max_tokens/temperature handling) so A and B are
        identical everywhere except the prompt/parse path, per the protocol's "same source context,
        engine, ... model settings ... except for the two named interventions" requirement."""
        prompt = self._build_prompt_typed_json(patch_info, error_feedback)
        try:
            kwargs = {}
            if self.config.max_output_tokens is not None:
                kwargs["max_tokens"] = self.config.max_output_tokens
            response = self.client.chat.completions.create(
                model=self.config.model_name,
                messages=[
                    {"role": "system", "content": self._system_message_typed_json()},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.config.generation_temperature,
                **kwargs,
            )
            if not response.choices:
                self.last_error = "No response generated from LLM"
                logging.error(self.last_error)
                return None
            content = response.choices[0].message.content
            return self._parse_typed_json_response(content, patch_info)
        except Exception as e:
            self.last_error = f"Error generating rule: {e}"
            logging.error(self.last_error)
            return None

    def _system_message_typed_json(self) -> str:
        return """You generate Semgrep rule specifications as a single JSON object.
    Return ONLY the raw JSON object -- no markdown fences, no YAML, no explanatory text before or after it.
    Do not compose Semgrep operators (patterns:, pattern-either:, etc.) yourself -- a separate deterministic
    serializer does that from the plain fields you provide. Supported fields: id, message, severity,
    languages, metadata (all required except metadata), plus exactly ONE of: pattern (a single pattern
    string), pattern_either (a list of alternative pattern strings), or taint_sources + taint_sinks
    (each a list of pattern strings, used together). Optionally also: pattern_not (a list of one or more
    exclusion pattern strings), pattern_inside (a single scope-restriction pattern string),
    pattern_not_inside (a single negative-scope pattern string). taint rules cannot combine with
    pattern_not/pattern_inside/pattern_not_inside."""

    def _build_prompt_typed_json(self, patch_info: PatchInfo, error_feedback: Optional[str] = None) -> str:
        """Condition B's prompt: same patch context as autogrep_default (repo/commit/diff), but asks
        for the typed-field JSON object instead of free-form YAML, and never mentions Semgrep's
        pattern-not/pattern-inside/patterns: composition syntax at all -- the model only needs to name
        WHICH fields it wants populated; TypedRule.to_dict() composes the real YAML operators.

        Includes worked examples, added 2026-10-12 after an independent review correctly found their
        earlier absence was a real confound, not a neutral simplification: _build_prompt_autogrep_default()
        shows 2 worked examples per language, and dropping them for B would make any later A-vs-B
        difference attributable to EITHER the construction intervention OR the loss of worked
        examples, with no way to separate the two -- exactly what Controlled_2x2_Protocol_Draft_20261012.md
        §3's "same ... except for the two named interventions" requirement exists to prevent. Fixed
        by translating the SAME 6 examples (2 per language, byte-identical vulnerability/fix intent
        to EXAMPLE_RULES inside _build_prompt_autogrep_default) into TypedRule's JSON field shape --
        all 6 fit the supported grammar exactly (pattern/pattern_not/pattern_inside/pattern_not_inside),
        so no expressiveness gap forced a different example set."""
        import json as _json

        EXAMPLE_RULES_TYPED_JSON = {
            "python": [
                {"id": "unsafe-deserialization", "pattern": "pickle.loads($DATA)",
                 "pattern_not": ["pickle.loads(trusted_data)"],
                 "pattern_inside": "def $FUNC(...):\n    ...",
                 "languages": ["python"],
                 "message": "Detected unsafe deserialization using pickle.loads(). This can lead to remote code execution.",
                 "severity": "ERROR",
                 "metadata": {"category": "security", "cwe": "CWE-502",
                              "owasp": "A8:2017-Insecure Deserialization",
                              "references": ["https://docs.python.org/3/library/pickle.html#pickle.loads"]}},
                {"id": "sql-injection", "pattern": "execute($QUERY)",
                 "pattern_not": ['execute("SELECT ...")', "execute(sanitized_query)"],
                 "languages": ["python"],
                 "message": "Potential SQL injection detected. Use parameterized queries instead.",
                 "severity": "ERROR",
                 "metadata": {"category": "security", "cwe": "CWE-89"}},
            ],
            "javascript": [
                {"id": "xss-innerHTML", "pattern": "$ELEMENT.innerHTML = $DATA",
                 "pattern_not_inside": "$ELEMENT.innerHTML = DOMPurify.sanitize($DATA)",
                 "languages": ["javascript"],
                 "message": "Potential XSS vulnerability using innerHTML. Use DOMPurify or safe alternatives.",
                 "severity": "ERROR",
                 "metadata": {"category": "security", "cwe": "CWE-79"}},
                {"id": "eval-injection", "pattern": "eval($DATA)",
                 "pattern_not": ['eval("trusted_static_string")'],
                 "languages": ["javascript"],
                 "message": "Dangerous use of eval() detected. This can lead to code injection.",
                 "severity": "ERROR",
                 "metadata": {"category": "security", "cwe": "CWE-95"}},
            ],
            "java": [
                {"id": "path-traversal", "pattern": "new File($PATH)",
                 "pattern_not": ["new File(sanitized_path)"],
                 "pattern_inside": "class $CLASS {\n    ...\n}",
                 "languages": ["java"],
                 "message": "Potential path traversal vulnerability. Validate and sanitize file paths.",
                 "severity": "ERROR",
                 "metadata": {"category": "security", "cwe": "CWE-22"}},
                {"id": "weak-cipher", "pattern": 'Cipher.getInstance("DES")',
                 "languages": ["java"],
                 "message": "Usage of weak cryptographic algorithm DES detected. Use AES instead.",
                 "severity": "ERROR",
                 "metadata": {"category": "security", "cwe": "CWE-326"}},
            ],
        }

        all_changes = []
        for file_change in patch_info.file_changes:
            file_header = f"File: {file_change.file_path}\n"
            all_changes.append(file_header + file_change.changes)
        combined_changes = "\n\n".join(all_changes)
        language = patch_info.file_changes[0].language
        suggested_id = _make_suggested_id(patch_info)
        examples = EXAMPLE_RULES_TYPED_JSON.get(language, [])
        examples_text = "\n\n".join(_json.dumps(ex, indent=2) for ex in examples)

        prompt = f"""Analyze the following vulnerability patch and generate a precise Semgrep rule specification (as a JSON object) to detect similar vulnerabilities in {language} code.

    CONTEXT:
    Repository: github.com/{patch_info.repo_owner}/{patch_info.repo_name}
    Commit: {patch_info.commit_id}

    PATCH CHANGES:
    {combined_changes}

    JSON FIELDS (emit a single JSON object with exactly these field names):
    - "id": "{suggested_id}" (must be unique and descriptive, lowercase letters/digits/hyphens only)
    - "message": detailed description of what the vulnerability is, why it's dangerous, and how to fix it
    - "severity": one of "ERROR", "WARNING", "INFO"
    - "languages": ["{language}"]
    - "metadata": an object, e.g. {{"category": "security", "cwe": "...", "owasp": "..."}}
    - exactly ONE of:
        "pattern": a single pattern string matching the vulnerable code structure, using $VARNAME for
            any expression and ... for any sequence of statements
        "pattern_either": a list of alternative pattern strings (any of which should match)
        "taint_sources" + "taint_sinks": each a list of pattern strings (taint-tracking mode)
    - optionally also:
        "pattern_not": a list of one or more pattern strings that should NOT match (e.g. the fixed
            version) -- you do not need to know how this combines with "pattern"; that is handled
            for you
        "pattern_inside": a single pattern string restricting matches to inside this context
        "pattern_not_inside": a single pattern string excluding matches inside this context

    IMPORTANT GUIDELINES:
    1. Make "pattern" (or "pattern_either") as specific as possible to minimize false positives
    2. Include "pattern_not" for the fixed version when possible
    3. Add relevant metadata like CWE numbers and OWASP categories
    4. Write a clear, actionable "message" explaining both the problem and the fix
    5. Consider different variations of the vulnerable pattern

    EXAMPLES OF HIGH-QUALITY RULE SPECIFICATIONS:
    {examples_text}

    Respond with ONLY the JSON object, nothing else."""

        if error_feedback:
            prompt += f"\n\nPREVIOUS ERROR TO FIX:\n{error_feedback}\nEnsure your next attempt addresses these issues."

        return prompt

    def _extract_json_text(self, text: str) -> str:
        """Parallel to extract_response() but for condition B's JSON contract -- strips thinking
        tags and prefers the content of a fenced code block (```json, ```, or no fence at all) over
        any surrounding prose, same rationale as extract_response()'s own docstring (some models wrap
        output in explanatory text even when told not to)."""
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
        fence_match = re.search(r'```(?:json)?[ \t]*\n(.*?)```', text, flags=re.DOTALL)
        if fence_match:
            text = fence_match.group(1)
        else:
            text = re.sub(r'^```json\s*', '', text, flags=re.MULTILINE)
            text = re.sub(r'^```\s*$', '', text, flags=re.MULTILINE)
        return text.strip()

    def _parse_typed_json_response(self, content: Optional[str], patch_info: PatchInfo) -> Optional[dict]:
        """Decodes condition B's JSON response into a TypedRule, validates it, and returns the
        fully-composed rule dict via TypedRule.to_dict() -- the same shape parse_and_sanitize_response()
        returns for condition A, so run_model_case()'s existing wrap-and-dump logic (yaml.safe_dump({
        "rules": [rule]})) works unchanged for either condition. A JSON decode error, an unexpected/
        missing field (TypeError from TypedRule(**decoded)), or a semantic validation failure
        (ValueError from .validate()/.to_dict()) is treated exactly like a YAML parse/validate failure
        in condition A -- it sets self.last_error to the exception's own message and returns None,
        consuming one of the repair loop's attempts, never silently retried outside the budget."""
        import json as _json
        from typed_rule import TypedRule

        if not content:
            self.last_error = "Empty response from LLM"
            logging.error(self.last_error)
            return None

        text = self._extract_json_text(content)
        if not text:
            self.last_error = "No valid content after extracting response"
            logging.error(self.last_error)
            return None

        try:
            decoded = _json.loads(text)
        except _json.JSONDecodeError as e:
            self.last_error = f"Invalid JSON: {e}"
            logging.error(self.last_error)
            return None

        if not isinstance(decoded, dict):
            self.last_error = f"Expected a single JSON object, got {type(decoded).__name__}"
            logging.error(self.last_error)
            return None

        # Same default-filling as _sanitize_rule() applies for condition A, so neither condition
        # gets a construction advantage from more generous default-filling than the other.
        decoded.setdefault("id", _make_suggested_id(patch_info))
        decoded.setdefault("languages", [patch_info.file_changes[0].language])
        decoded.setdefault("severity", "ERROR")
        metadata = decoded.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        metadata.setdefault("source-url", f"github.com/{patch_info.repo_owner}/{patch_info.repo_name}/commit/{patch_info.commit_id}")
        metadata.setdefault("category", "security")
        metadata.setdefault("technology", [patch_info.file_changes[0].language])
        decoded["metadata"] = metadata
        decoded.setdefault("message", "")

        try:
            typed_rule = TypedRule(**decoded)
        except TypeError as e:
            self.last_error = f"Unexpected or missing field in typed rule JSON: {e}"
            logging.error(self.last_error)
            return None

        try:
            rule_dict = typed_rule.to_dict()
        except ValueError as e:
            self.last_error = f"Invalid typed rule: {e}"
            logging.error(self.last_error)
            return None

        self.last_error = None
        return rule_dict

    def _system_message(self) -> str:
        """Byte-identical to the original hardcoded text for every historical variant (autogrep_default,
        design_v1) -- this refactor only makes the message variant-aware for the new
        diagnostic_mechanism_v1 condition (2026-10-11), which must not inherit the old message's
        "Always include... pattern" wording, since that's the exact system-prompt bias the schema-policy
        fix's own caveat flagged (Research_Log/Diagnostic_20261010/README.md): enabling the parser to
        accept composite/taint rules does nothing if the system message still only asks for `pattern`."""
        variant = getattr(self.config, "prompt_variant", "autogrep_default")
        if variant in ("diagnostic_mechanism_v1", "diagnostic_mechanism_v2", "diagnostic_mechanism_v3",
                       "diagnostic_mechanism_v4"):
            return """You generate Semgrep rules in YAML format.
    Return only the raw YAML content without any markdown formatting or additional text.
    Always include these required fields: id, message, severity, languages, plus at least one of:
    pattern, patterns, pattern-either, pattern-regex, or (for taint-mode rules) pattern-sources and pattern-sinks."""
        return """You generate Semgrep rules in YAML format.
    Return only the raw YAML content without any markdown formatting or additional text.
    Always include these required fields: id, pattern, message, severity, languages"""

    def _build_prompt(self, patch_info: PatchInfo, error_feedback: Optional[str] = None) -> str:
        """Dispatches to the configured prompt variant (Config.prompt_variant).
        Both original variants are real, independently runnable options -- see
        Research_Log/Implementation_Log.md for why both exist. diagnostic_mechanism_v1
        (2026-10-11) is a third, explicitly separate condition -- see
        Research_Log/Diagnostic_20261010/ for why it exists and what it changes.
        diagnostic_mechanism_v2 (2026-10-11, same day) is a fourth, ALSO explicitly separate
        condition -- identical to v1 except it uses EXAMPLE_RULES_V2 (valid YAML) instead of
        EXAMPLE_RULES (confirmed invalid YAML, inherited from upstream autogrep_default -- see
        EXAMPLE_RULES_V2's own comment). v1 is never edited in place to become this; it keeps
        producing exactly what the already-completed qwen3_mechanism_v1/v2 runs actually used.
        diagnostic_mechanism_v3 (2026-10-11, same day, after reviewing v2's own live trial) is a
        fifth, ALSO explicitly separate condition -- EXAMPLE_RULES_V3 (one rule per language instead
        of two, closing the gap where diagnostic_mechanism_v2's two-rules-per-language examples were
        traced to a model emitting two rules itself on CASE-0221; plus a new typescript entry, since
        EXAMPLE_RULES/_V2 silently had none, leaving 6/24 of the dev subset with zero worked
        examples) plus explicit colon-quoting guidance (CASE-0238's own confirmed, examples-fix-
        unrelated failure: an unquoted pattern value containing its own "key: value" breaks YAML).
        diagnostic_mechanism_v4 (2026-10-11, after v3's own live trial -- qwen3_mechanism_v4 reached
        6/24, parity with autogrep_default, confirming CASE-0221's fix worked) is a sixth, ALSO
        explicitly separate condition: identical to v3 plus one more guidance addition, for a gotcha
        that recurred in a NEW case (CASE-0276) in that same trial -- the exact `pattern-either` +
        sibling top-level `pattern-not` composition bug already confirmed (via an isolated test) in
        the mechanism_v2 review, now shown to be a real, recurring model tendency, not a one-off."""
        variant = getattr(self.config, "prompt_variant", "autogrep_default")
        if variant == "design_v1":
            return self._build_prompt_design_v1(patch_info, error_feedback)
        if variant == "diagnostic_mechanism_v1":
            return self._build_prompt_diagnostic_mechanism_v1(patch_info, error_feedback)
        if variant == "diagnostic_mechanism_v2":
            return self._build_prompt_diagnostic_mechanism_v1(patch_info, error_feedback, examples=EXAMPLE_RULES_V2)
        if variant == "diagnostic_mechanism_v3":
            return self._build_prompt_diagnostic_mechanism_v1(patch_info, error_feedback, examples=EXAMPLE_RULES_V3,
                                                               quoting_guidance=True)
        if variant == "diagnostic_mechanism_v4":
            return self._build_prompt_diagnostic_mechanism_v1(patch_info, error_feedback, examples=EXAMPLE_RULES_V3,
                                                               quoting_guidance=True, composition_guidance=True)
        return self._build_prompt_autogrep_default(patch_info, error_feedback)

    def _build_prompt_design_v1(self, patch_info: PatchInfo, error_feedback: Optional[str] = None) -> str:
        """The prompt template specified in the research design doc's
        Section 13.2.

        Uses real case data (patch_info.cve_id / cwe_ids / cwe_definitions /
        vulnerable_function / patched_function) when present -- populated by
        pipeline/case_loader.py from a curated benchmark/cases/CASE-XXXX case
        (design doc Section 10 manifest + Section 8 Step 5 model context).
        Falls back to diff-derived reconstruction with placeholder CVE/CWE
        for the raw-.patch-file flow, which has no case metadata (Phase 1's
        original smoke-test path; still exercised by pipeline/tests/)."""
        language = patch_info.file_changes[0].language
        suggested_id = _make_suggested_id(patch_info)

        has_case_data = patch_info.vulnerable_function is not None and patch_info.patched_function is not None

        if has_case_data:
            cve = patch_info.cve_id or "unknown"
            if patch_info.cwe_ids and patch_info.cwe_definitions:
                cwe = "; ".join(
                    f"{cid} ({cdef})" for cid, cdef in zip(patch_info.cwe_ids, patch_info.cwe_definitions)
                )
            elif patch_info.cwe_ids:
                cwe = ", ".join(patch_info.cwe_ids)
            else:
                cwe = "unknown"

            context_parts = []
            if patch_info.imports:
                context_parts.append("Relevant imports:\n" + "\n".join(patch_info.imports))
            if patch_info.containing_class_declaration:
                context_parts.append("Containing class:\n" + patch_info.containing_class_declaration)
            context_block = ("\n\n".join(context_parts) + "\n\n") if context_parts else ""

            diff_blocks = [f"File: {fc.file_path}\n{fc.changes}" for fc in patch_info.file_changes]

            prompt = f"""Generate one Semgrep rule from the verified vulnerability-fixing evidence.

Language: {language}
CVE: {cve}
CWE: {cwe}

{context_block}Vulnerable function or method:
{patch_info.vulnerable_function}

Patched function or method:
{patch_info.patched_function}

Unified diff:
{chr(10).join(diff_blocks)}

The rule must detect the vulnerable behavior and avoid matching the patched
behavior. Generalize the security mechanism without depending on unnecessary
repository-specific names.

Return exactly one Semgrep YAML rule. Do not include Markdown fences or prose.
Include id, languages, message, severity, metadata, and the required pattern
or taint-mode fields. Use "{suggested_id}" as the id.
severity must be one of: ERROR, WARNING, INFO."""
        else:
            vulnerable_blocks, patched_blocks, patch_blocks = [], [], []
            for fc in patch_info.file_changes:
                vuln_lines, patched_lines = [], []
                for line in fc.changes.split('\n'):
                    # "--- a/file" / "+++ b/file" diff-header lines also start
                    # with -/+ but aren't content -- exclude them, or they leak
                    # into the reconstructed code blocks as garbage.
                    if line.startswith('---') or line.startswith('+++'):
                        continue
                    if line.startswith('-'):
                        vuln_lines.append(line[1:])
                    elif line.startswith('+'):
                        patched_lines.append(line[1:])
                header = f"File: {fc.file_path}"
                vulnerable_blocks.append(f"{header}\n" + "\n".join(vuln_lines))
                patched_blocks.append(f"{header}\n" + "\n".join(patched_lines))
                patch_blocks.append(f"{header}\n" + fc.changes)

            prompt = f"""Generate one Semgrep rule from the verified vulnerability-fixing evidence.

Language: {language}
CVE: unknown (no case metadata available for this patch)
CWE: unknown (no case metadata available for this patch)

Vulnerable code:
{chr(10).join(vulnerable_blocks)}

Patched code:
{chr(10).join(patched_blocks)}

Patch:
{chr(10).join(patch_blocks)}

The rule must detect the vulnerable behavior and avoid matching the patched
behavior. Generalize the security mechanism without depending on unnecessary
repository-specific names.

Return exactly one Semgrep YAML rule. Do not include Markdown fences or prose.
Include id, languages, message, severity, metadata, and the required pattern
or taint-mode fields. Use "{suggested_id}" as the id.
severity must be one of: ERROR, WARNING, INFO."""

        if error_feedback:
            prompt += f"\n\nPREVIOUS ERROR TO FIX:\n{error_feedback}\nEnsure your next attempt addresses these issues."

        return prompt

    def _build_prompt_autogrep_default(self, patch_info: PatchInfo, error_feedback: Optional[str] = None) -> str:
        """Autogrep's original, unmodified prompt (long-form, with embedded
        per-language example rules and an interleaved +/- diff)."""
        # Combine all file changes with context
        all_changes = []
        for file_change in patch_info.file_changes:
            file_header = f"File: {file_change.file_path}\n"
            all_changes.append(file_header + file_change.changes)
        
        combined_changes = "\n\n".join(all_changes)
        
        language = patch_info.file_changes[0].language
        suggested_id = _make_suggested_id(patch_info)

        # Language-specific example rules
        EXAMPLE_RULES = {
            "python": '''
    rules:
    - id: "unsafe-deserialization"
        pattern: pickle.loads($DATA)
        pattern-not: pickle.loads(trusted_data)
        pattern-inside: |
            def $FUNC(...):
                ...
        languages: ["python"]
        message: "Detected unsafe deserialization using pickle.loads(). This can lead to remote code execution."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-502
            owasp: A8:2017-Insecure Deserialization
            references:
                - https://docs.python.org/3/library/pickle.html#pickle.loads

    - id: "sql-injection"
        patterns:
            - pattern: execute($QUERY)
            - pattern-not: execute("SELECT ...")
            - pattern-not: execute(sanitized_query)
        languages: ["python"]
        message: "Potential SQL injection detected. Use parameterized queries instead."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-89
    ''',
            "javascript": '''
    rules:
    - id: "xss-innerHTML"
        pattern: $ELEMENT.innerHTML = $DATA
        pattern-not-inside: |
            $ELEMENT.innerHTML = DOMPurify.sanitize($DATA)
        languages: ["javascript"]
        message: "Potential XSS vulnerability using innerHTML. Use DOMPurify or safe alternatives."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-79

    - id: "eval-injection"
        pattern: eval($DATA)
        pattern-not: eval("trusted_static_string")
        languages: ["javascript"]
        message: "Dangerous use of eval() detected. This can lead to code injection."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-95
    ''',
            "java": '''
    rules:
    - id: "path-traversal"
        pattern: new File($PATH)
        pattern-not: new File(sanitized_path)
        pattern-inside: |
            class $CLASS {
                ...
            }
        languages: ["java"]
        message: "Potential path traversal vulnerability. Validate and sanitize file paths."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-22

    - id: "weak-cipher"
        pattern: Cipher.getInstance("DES")
        languages: ["java"]
        message: "Usage of weak cryptographic algorithm DES detected. Use AES instead."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-326
    '''
        }

        # Get examples for the current language
        examples = EXAMPLE_RULES.get(language, "")

        # Build the enhanced prompt
        prompt = f"""Analyze the following vulnerability patch and generate a precise Semgrep rule to detect similar vulnerabilities in {language} code.

    CONTEXT:
    Repository: github.com/{patch_info.repo_owner}/{patch_info.repo_name}
    Commit: {patch_info.commit_id}

    PATCH CHANGES:
    {combined_changes}

    SEMGREP PATTERN SYNTAX GUIDE:
    - Use $VARNAME to match any expression
    - Use ... to match any sequence of statements
    - Use |> to pipe patterns together
    - Use pattern-inside to limit matches to specific code blocks
    - Use pattern-not to exclude specific patterns (like the fixed version)
    - Use metavariable-pattern to add constraints on variables

    REQUIRED FIELDS:
    1. id: "{suggested_id}" (must be unique and descriptive)
    2. pattern: Clear pattern matching the vulnerable code structure
    3. languages: ["{language}"]
    4. message: Detailed description of:
    - What the vulnerability is
    - Why it's dangerous
    - How to fix it
    5. severity: One of [ERROR, WARNING, INFO]

    RECOMMENDED FIELDS:
    - pattern-not: Pattern that should not match (e.g., fixed version)
    - pattern-inside: Context pattern for where the rule should match
    - pattern-not-inside: Context pattern for where the rule should not match
    - metadata:
        source-url: github.com/{patch_info.repo_owner}/{patch_info.repo_name}/commit/{patch_info.commit_id}
        category: security
        cwe: [relevant CWE number]
        owasp: [relevant OWASP category]
        references: [links to documentation or standards]
        technology: [{language}]

    IMPORTANT GUIDELINES:
    1. Make patterns as specific as possible to minimize false positives
    2. Include pattern-not for the fixed version when possible
    3. Add relevant metadata like CWE numbers and OWASP categories
    4. Write clear, actionable messages explaining both the problem and solution
    5. Consider different variations of the vulnerable pattern

    EXAMPLES OF HIGH-QUALITY RULES:
    {examples}

    FORMAT YOUR RESPONSE AS A SINGLE YAML DOCUMENT:
    rules:
    - id: "{suggested_id}"
    pattern: [Your pattern here]
    pattern-not: [Fixed version pattern]
    languages: ["{language}"]
    message: [Clear description]
    severity: ERROR
    metadata: [Additional context]

    Remember to adapt the patterns to match the specific vulnerability in the patch while keeping them general enough to catch variations of the same issue."""

        if error_feedback:
            prompt += f"\n\nPREVIOUS ERROR TO FIX:\n{error_feedback}\nEnsure your next attempt addresses these issues."
            
        return prompt

    def _build_prompt_diagnostic_mechanism_v1(self, patch_info: PatchInfo, error_feedback: Optional[str] = None,
                                               examples: dict = None, quoting_guidance: bool = False,
                                               composition_guidance: bool = False) -> str:
        """2026-10-11 diagnostic condition, explicitly separate from autogrep_default (never a
        silent edit to it -- Research_Log/Diagnostic_20261010/README.md's own stated requirement:
        "any prompt change is a separately named condition"). Reuses autogrep_default's exact patch
        presentation (same CONTEXT/PATCH CHANGES block) AND THE SAME per-language example rules
        (module-level EXAMPLE_RULES, 2026-10-11 -- an earlier revision of this docstring claimed
        this was already true when the implementation never actually referenced the examples; that
        was a real bug, confirmed via the mechanism_v1 diagnostic run's own captured raw prompt_text
        showing no examples were ever sent; fixed here, not just in the docstring) so the only
        deliberate differences from autogrep_default are: (1) the pattern-syntax guide and
        required-fields section now mention patterns/pattern-either/pattern-regex/taint-mode as real
        options, matching what Config.rule_schema_policy="semgrep_search_taint_v2" actually accepts,
        plus explicit guidance on when `patterns` is (and is NOT) the right tool, added after the
        same mechanism_v1 run showed a model misusing `patterns` to AND together two unrelated
        sequential statements instead of writing one multi-line `pattern:` block (CASE-0220); (2)
        guidance asking the model to reason about the underlying vulnerability MECHANISM rather than
        matching the literal code shape of the one example in front of it, and to anticipate that
        the vulnerable logic may be moved into a differently-named helper function or otherwise
        restructured -- this targets the dominant failure mode this diagnostic and the broader study
        both found (models' rules overfitting to literal code shape, failing to generalize to
        hidden, structurally-transformed variants)."""
        all_changes = []
        for file_change in patch_info.file_changes:
            file_header = f"File: {file_change.file_path}\n"
            all_changes.append(file_header + file_change.changes)
        combined_changes = "\n\n".join(all_changes)

        language = patch_info.file_changes[0].language
        suggested_id = _make_suggested_id(patch_info)

        prompt = f"""Analyze the following vulnerability patch and generate a precise Semgrep rule to detect similar vulnerabilities in {language} code.

    CONTEXT:
    Repository: github.com/{patch_info.repo_owner}/{patch_info.repo_name}
    Commit: {patch_info.commit_id}

    PATCH CHANGES:
    {combined_changes}

    UNDERSTAND THE MECHANISM FIRST:
    Before writing a rule, identify the underlying vulnerability MECHANISM the patch fixes -- the
    specific unsafe condition (e.g. untrusted data reaching a dangerous sink without a check, a
    missing bounds/escaping/validation step, an unsafe default). Do not simply pattern-match the
    exact expression shown in the diff: the same vulnerable mechanism will also appear, in the held-out
    test variants, with renamed identifiers AND with the vulnerable logic moved into a different
    function or otherwise restructured (e.g. extracted into a small helper, inlined, or reordered).
    Write the rule to catch the mechanism wherever it appears in the file, not only at this exact
    call site or inside this exact function.

    SEMGREP PATTERN SYNTAX GUIDE:
    - Use $VARNAME to match any expression
    - Use ... to match any sequence of statements
    - Use pattern-inside to limit matches to specific code blocks
    - Use pattern-not to exclude specific patterns (like the fixed version)
    - Use metavariable-pattern to add constraints on variables
    - A single `pattern` is only one option. Where the vulnerable mechanism can show up in more
      than one syntactic shape (e.g. the same unsafe call reachable through a helper function, or
      several equivalent call forms), prefer `patterns`/`pattern-either` to cover them together,
      rather than only the one shape seen in this diff.
    - `patterns` (a list under one `pattern`-family key) means EVERY listed pattern must match the
      SAME code location -- it is for combining different CONDITIONS on one spot (e.g. a call plus
      a pattern-not exclusion), not for joining two separate statements that merely both need to be
      present. Two or more statements that occur together in sequence belong in ONE multi-line
      `pattern:` block (write them one after another, exactly like plain code), not as separate
      entries under `patterns`.{(
      "\n    - `pattern-either` with a SIBLING top-level `pattern-not` (both as direct keys of the "
      "rule, not nested together) does NOT exclude matches of one of the pattern-either alternatives "
      "-- verified empirically, this is a real gotcha, not a hypothetical one. If you need to exclude "
      "one alternative (e.g. the patched form) from a pattern-either match, put BOTH pattern-either "
      "AND pattern-not inside one `patterns:` list together: "
      "`patterns: [{pattern-either: [...]}, {pattern-not: ...}]` -- that is the only form that "
      "actually composes as an exclusion." if composition_guidance else "")}
    - For a mechanism that is really about untrusted data reaching a dangerous sink, consider a
      taint-mode rule instead: `mode: taint` with `pattern-sources` (where the untrusted data
      enters) and `pattern-sinks` (the dangerous use) -- this generalizes across refactors that a
      single structural pattern cannot, since it tracks the data, not the exact code shape.

    REQUIRED FIELDS:
    1. id: "{suggested_id}" (must be unique and descriptive)
    2. At least one of: pattern, patterns, pattern-either, pattern-regex, or (mode: taint with)
       pattern-sources and pattern-sinks
    3. languages: ["{language}"]
    4. message: Detailed description of what the vulnerability is, why it's dangerous, how to fix it
    5. severity: One of [ERROR, WARNING, INFO]

    RECOMMENDED FIELDS:
    - pattern-not: Pattern that should not match (e.g., fixed version)
    - pattern-inside / pattern-not-inside: Context pattern for where the rule should/should not match
    - metadata:
        source-url: github.com/{patch_info.repo_owner}/{patch_info.repo_name}/commit/{patch_info.commit_id}
        category: security
        cwe: [relevant CWE number]

    IMPORTANT GUIDELINES:
    1. Make patterns as specific as possible to minimize false positives on the patched/safe code
    2. Include pattern-not for the fixed version when possible
    3. Consider that the vulnerable mechanism may be reached through a renamed or restructured
       call site, not only the exact one shown in the diff
    4. Write clear, actionable messages explaining both the problem and solution
    {("5. YAML QUOTING: if a pattern, pattern-not, or message value itself contains a colon followed "
      "by a space (e.g. matching or describing an object literal like { escapeFormulae: true }), you "
      "MUST wrap that whole value in quotes (single or double), e.g. pattern-not: '$X.unparse(..., "
      "{ escapeFormulae: true })'. An unquoted value with an embedded \": \" breaks YAML parsing -- "
      "this is a real, common failure mode, not a hypothetical one.\n\n"
      "    6. EXACTLY ONE RULE: your response must contain exactly ONE rule under `rules:` -- never "
      "two or more, even if you think a second rule would also be useful." if quoting_guidance else "")}

    EXAMPLES OF HIGH-QUALITY RULES:
    {(examples or EXAMPLE_RULES).get(language, "")}

    FORMAT YOUR RESPONSE AS A SINGLE YAML DOCUMENT with exactly one rule under `rules:`. Do not
    include Markdown fences or prose before or after it."""

        if error_feedback:
            prompt += f"\n\nPREVIOUS ERROR TO FIX:\n{error_feedback}\nEnsure your next attempt addresses these issues."

        return prompt

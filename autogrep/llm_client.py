from typing import Optional, Tuple
from config import Config
import logging
import yaml
from patch_processor import PatchInfo
import re
from openai import OpenAI
from pathlib import Path


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
        required_fields = ['id', 'pattern', 'message', 'severity', 'languages']
        
        if not isinstance(rule, dict):
            return False, "Rule must be a dictionary"
            
        missing_fields = [field for field in required_fields if field not in rule]
        if missing_fields:
            return False, f"Missing required fields: {', '.join(missing_fields)}"
            
        # Validate severity
        valid_severities = ['ERROR', 'WARNING', 'INFO']
        if rule['severity'] not in valid_severities:
            return False, f"Invalid severity level. Must be one of: {', '.join(valid_severities)}"
            
        # Ensure id is properly formatted
        if not re.match(r'^[a-z0-9-]+$', rule['id']):
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
        """Generate a Semgrep rule using the LLM with improved validation."""
        prompt = self._build_prompt(patch_info, error_feedback)

        try:
            kwargs = {}
            if self.config.max_output_tokens is not None:
                kwargs["max_tokens"] = self.config.max_output_tokens
            response = self.client.chat.completions.create(
                model=self.config.model_name,
                messages=[
                    {"role": "system", "content": """You generate Semgrep rules in YAML format.
    Return only the raw YAML content without any markdown formatting or additional text.
    Always include these required fields: id, pattern, message, severity, languages"""},
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
        
    def _build_prompt(self, patch_info: PatchInfo, error_feedback: Optional[str] = None) -> str:
        """Dispatches to the configured prompt variant (Config.prompt_variant).
        Both variants are real, independently runnable options -- see
        Research_Log/Implementation_Log.md for why both exist."""
        variant = getattr(self.config, "prompt_variant", "autogrep_default")
        if variant == "design_v1":
            return self._build_prompt_design_v1(patch_info, error_feedback)
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
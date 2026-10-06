"""
Section 9 ground-truth test bundle: CASE-0001
(1Panel-dev/MaxKB, CVE-2026-39419, CWE-290/CWE-693/CWE-74).

Core detectable vulnerable mechanism: exec_code() generates a correlation
token with `uuid.uuid7()` (time-ordered, PREDICTABLE) and later trusts any
subprocess stdout line that starts with that token (`line.startswith(_id)`)
as authoritative execution output. Since the sandboxed/untrusted code being
executed can write its own arbitrary stdout, a predictable token lets it
guess/derive the token and spoof a fake success line -- CWE-290 (auth
bypass by spoofing).

Note: line 239 of the original file ALSO calls `uuid.uuid7()`, but for the
FastMCP server's display name -- not a security boundary. That is left
untouched in every variant below and doubles as evidence that "any call to
uuid.uuid7()" is not, by itself, the vulnerability signature.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0001"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_SNIPPET = '''    def exec_code(self, code_str, keywords, function_name=None):
        _id = str(uuid.uuid7())'''
assert VULNERABLE_SNIPPET in original

# --- Variant 1: renamed vulnerable variant ---
# Rename the token variable _id -> _token throughout exec_code() only (the
# unrelated execution_timer(id="") parameter, and the unrelated uuid.uuid7()
# call at line 239 in a different method, are untouched).
renamed_source = original
renamed_source = renamed_source.replace(
    '''    def exec_code(self, code_str, keywords, function_name=None):
        _id = str(uuid.uuid7())''',
    '''    def exec_code(self, code_str, keywords, function_name=None):
        _token = str(uuid.uuid7())''',
)
renamed_source = renamed_source.replace(
    '    sys.stdout.write("\\n{_id}:")\n    json.dump({{\'code\':200,\'msg\':\'success\',\'data\':exec_result}}, sys.stdout, default=str)',
    '    sys.stdout.write("\\n{_token}:")\n    json.dump({{\'code\':200,\'msg\':\'success\',\'data\':exec_result}}, sys.stdout, default=str)',
)
renamed_source = renamed_source.replace(
    '    sys.stdout.write("\\n{_id}:")\n    json.dump({{\'code\':500,\'msg\':str(e),\'data\':None}}, sys.stdout, default=str)',
    '    sys.stdout.write("\\n{_token}:")\n    json.dump({{\'code\':500,\'msg\':str(e),\'data\':None}}, sys.stdout, default=str)',
)
renamed_source = renamed_source.replace(
    'maxkb_logger.debug(f"Sandbox execute code: {_exec_code}")',
    'maxkb_logger.debug(f"Sandbox execute code: {_exec_code}")',  # unchanged, no _id reference here
)
renamed_source = renamed_source.replace(
    '            with execution_timer(_id):\n                subprocess_result = self._exec(f.name)',
    '            with execution_timer(_token):\n                subprocess_result = self._exec(f.name)',
)
renamed_source = renamed_source.replace(
    "        result_line = [line for line in lines if line.startswith(_id)]",
    "        result_line = [line for line in lines if line.startswith(_token)]",
)
assert "_token" in renamed_source
# Confirm the unrelated uuid.uuid7() call (line 239, FastMCP name) and the
# unrelated execution_timer(id="") parameter are both untouched.
assert 'mcp = FastMCP(\\"{uuid.uuid7()}\\")' in renamed_source
assert "def execution_timer(id=\"\"):" in renamed_source
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent rewriting of the
# list-comprehension trust check into an explicit loop. Same exact
# vulnerability (predictable token, prefix-trust of untrusted output).
structural_source = original.replace(
    '''    def exec_code(self, code_str, keywords, function_name=None):
        _id = str(uuid.uuid7())''',
    '''    def exec_code(self, code_str, keywords, function_name=None):
        raw_token = uuid.uuid7()
        _id = str(raw_token)''',
)
structural_source = structural_source.replace(
    '        lines = subprocess_result.stdout.splitlines()\n        result_line = [line for line in lines if line.startswith(_id)]\n        if not result_line:\n            maxkb_logger.error("\\n".join(lines))\n            raise Exception("No result found.")\n        result = json.loads(result_line[-1].split(":", 1)[1])',
    '''        lines = subprocess_result.stdout.splitlines()
        matching_lines = []
        for line in lines:
            if line.startswith(_id):
                matching_lines.append(line)
        if not matching_lines:
            maxkb_logger.error("\\n".join(lines))
            raise Exception("No result found.")
        result = json.loads(matching_lines[-1].split(":", 1)[1])''',
)
assert structural_source != original
assert "raw_token = uuid.uuid7()" in structural_source
assert "matching_lines" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core fix as upstream (predictable uuid7 -> CSPRNG token) but a
# different token function/length than the real patch's
# secrets.token_hex(32), so it isn't byte-identical to the known fix.
# Prefix-trust matching remains, which is fine once the token itself is
# unguessable -- that's the actual security property CVE-2026-39419 hinges
# on (CWE-290: predictability, not the matching mechanism itself).
safe_source = original.replace(
    '''    def exec_code(self, code_str, keywords, function_name=None):
        _id = str(uuid.uuid7())''',
    '''    def exec_code(self, code_str, keywords, function_name=None):
        _id = secrets.token_urlsafe(24)''',
)
# add the missing import, matching the real patch's approach of importing secrets
safe_source = safe_source.replace(
    "import subprocess\nimport sys\nimport tempfile\nimport time\n",
    "import secrets\nimport subprocess\nimport sys\nimport tempfile\nimport time\n",
)
assert "secrets.token_urlsafe(24)" in safe_source
assert "import secrets" in safe_source
assert "uuid.uuid7())" not in safe_source.split("def exec_code")[1].split("def _generate_mcp_server_code")[0]
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# A new method that also calls uuid.uuid7() (the same API surface as the
# vulnerable line) but for a non-security purpose: a temp-file-name suffix
# that is never used to authenticate or match untrusted subprocess output.
# A rule that fires on "any uuid.uuid7() call" would wrongly flag this.
BENIGN_ADDITION = '''
    def make_temp_file_suffix(self):
        """Returns a display-only suffix for naming scratch temp files.

        Not used for any security-sensitive matching or authentication --
        collisions or predictability here have no security consequence,
        unlike the correlation token used in exec_code().
        """
        return str(uuid.uuid7())
'''
anchor = "    def _generate_mcp_server_code(self, _code, params, name=None, description=None, tool_id=None):"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor)
assert "_id = str(uuid.uuid7())" not in benign_source, "benign_lookalike must not contain the real vulnerability"
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)

print("Wrote 4 new samples for CASE-0001.")

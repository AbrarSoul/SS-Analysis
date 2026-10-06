"""
Section 9 ground-truth test bundle: CASE-0042
(1Panel-dev/MaxKB, CVE-2025-32383, CWE-94 code/command injection).

Core vulnerable mechanism: `_exec_sandbox()` runs a user-submitted script by
invoking `su -c "<python_directory> <exec_python_file>" <user>`. `su -c`
takes a SINGLE STRING and has the target user's shell parse it as a full
command line -- so even though subprocess.run() itself is called with a
list (no shell=True), the string handed to `-c` is still shell-interpreted
one layer down, inside su. `exec_python_file` embeds `_id` via
f'{self.sandbox_path}/{_id}.py' with no escaping, so shell metacharacters
in `_id` reach a real shell.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0042"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''        subprocess_result = subprocess.run(
            ['su', '-c', python_directory + ' ' + exec_python_file, self.user],
            text=True,
            capture_output=True, **kwargs)'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename exec_python_file -> script_path, su_result -> proc_result. Same
# exact unescaped shell-string concatenation reaching su -c.
renamed_source = original.replace(
    "exec_python_file = f'{self.sandbox_path}/{_id}.py'",
    "script_path = f'{self.sandbox_path}/{_id}.py'",
)
renamed_source = renamed_source.replace(
    'os.system(f"chown {self.user}:{self.user} {exec_python_file}")',
    'os.system(f"chown {self.user}:{self.user} {script_path}")',
)
renamed_source = renamed_source.replace(
    VULNERABLE_BLOCK,
    '''        proc_result = subprocess.run(
            ['su', '-c', python_directory + ' ' + script_path, self.user],
            text=True,
            capture_output=True, **kwargs)''',
)
renamed_source = renamed_source.replace(
    "os.remove(exec_python_file)\n        return subprocess_result",
    "os.remove(script_path)\n        return proc_result",
)
assert "script_path" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the su -c command string. Same
# exact unescaped concatenation, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''        su_command_line = python_directory + ' ' + exec_python_file
        su_argv = ['su', '-c', su_command_line, self.user]
        subprocess_result = subprocess.run(su_argv, text=True, capture_output=True, **kwargs)''',
)
assert structural_source != original
assert "su_command_line = python_directory + ' ' + exec_python_file" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (still invokes via `su -c "<string>"`, unlike
# the real fix's `-s`+exec() approach) but neutralizes the injection by
# shell-quoting each component with shlex.quote() before concatenating --
# a materially different fix technique (proper escaping vs. switching
# interpreters) that is nonetheless genuinely safe: any shell metacharacter
# in exec_python_file (i.e. in attacker-controlled _id) is neutralized by
# quoting, not interpreted by the target shell.
SAFE_BLOCK = '''        import shlex
        quoted_command = shlex.quote(python_directory) + ' ' + shlex.quote(exec_python_file)
        subprocess_result = subprocess.run(
            ['su', '-c', quoted_command, self.user],
            text=True,
            capture_output=True, **kwargs)'''
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
assert safe_source != original
assert "shlex.quote" in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Same visible shape (subprocess.run(['su', '-c', <string>, user], ...))
# as the vulnerable sink, but this sibling method runs a fixed, hardcoded
# maintenance command with no dynamic/attacker-influenced component at
# all (no `_id`, no per-request file path) -- the command string is a
# compile-time constant, so no injection is reachable through it despite
# the structural resemblance to _exec_sandbox().
BENIGN_SOURCE = '''import subprocess


class SandboxMaintenance:
    """Periodic sandbox cleanup, run on a fixed schedule with no
    per-request or user-controlled input anywhere in the command."""

    def __init__(self, user: str):
        self.user = user

    def clear_temp_files(self):
        # Entirely hardcoded -- nothing here is derived from a request,
        # session id, or any other attacker-reachable value.
        fixed_command = "/usr/bin/find /opt/maxkb/app/sandbox -name '*.tmp' -delete"
        return subprocess.run(
            ["su", "-c", fixed_command, self.user],
            text=True,
            capture_output=True,
        )
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "_id" not in BENIGN_SOURCE
assert "exec_python_file" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0042.")

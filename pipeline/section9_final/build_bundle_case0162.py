"""
Section 9 ground-truth test bundle: CASE-0162
(fedora-selinux/setroubleshoot, framework/src/SetroubleshootFixit.py
RunFix.run_fix, CVE-2016-4989, CWE-77 command injection).

Core vulnerable mechanism: the D-Bus method `run_fix(local_id, analysis_id)`
(run as root behind a polkit rule) builds a shell command with string
formatting, `"sealert -f %s -P %s" % (local_id, analysis_id)`, and runs it with
`commands.getoutput`, which goes through `/bin/sh`. Shell metacharacters in
either id (`;`, `$(...)`, backticks, `|`) therefore run extra commands as
root. The upstream fix passes an argument list to
`subprocess.check_output`, so no shell is involved.

Sibling sites: none; this file has a single exported method.

Every variant is the FULL real file (Python 2). run_fix is the D-Bus method
clients call by name (it is also registered by the decorator), so the renamed
variant keeps the method name and renames its parameters and locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0162"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

BODY = '''    def run_fix(self, local_id, analysis_id):
        import commands
        command = "sealert -f %s -P %s" % ( local_id, analysis_id)
        return commands.getoutput(command)
'''
assert original.count(BODY) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, BODY, '''    def run_fix(self, alert_id, report_id):
        import commands
        shell_line = "sealert -f %s -P %s" % ( alert_id, report_id)
        return commands.getoutput(shell_line)
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BODY, '''    def run_fix(self, local_id, analysis_id):
        command = "sealert -f {0} -P {1}".format(local_id, analysis_id)
        pipe = os.popen(command)
        try:
            return pipe.read()
        finally:
            pipe.close()
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# No shell (argument list to subprocess.Popen, stderr merged into the
# returned text like commands.getoutput did) and ids that would be parsed as
# options are refused; upstream uses subprocess.check_output.
v3 = swap(original, BODY, '''    def run_fix(self, local_id, analysis_id):
        import subprocess
        for value in (local_id, analysis_id):
            if value.startswith("-"):
                raise ValueError("invalid id")
        proc = subprocess.Popen(["sealert", "-f", local_id, "-P", analysis_id],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True)
        output = proc.communicate()[0]
        return output.rstrip("\\n")
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import subprocess


def list_installed_policies():
    """Same "run a helper and return its text" shape as run_fix, but the
    command is a fixed argument list with no caller-supplied value in it, and
    no shell is involved."""
    proc = subprocess.Popen(["semodule", "-l"], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, universal_newlines=True)
    return proc.communicate()[0]
'''
assert '["semodule", "-l"]' in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0162.")

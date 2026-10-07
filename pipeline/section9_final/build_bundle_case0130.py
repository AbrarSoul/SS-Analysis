"""
Section 9 ground-truth test bundle: CASE-0130
(bit-team/backintime, qt4/plugins/notifyplugin.py NotifyPlugin.on_message,
CVE-2017-16667, CWE-78 OS command injection).

Core vulnerable mechanism: `on_message()` builds a shell command line by
string formatting,
`cmd = cmd + " \\"%s\\" \\"%s\\"" % (title, message)`, where `title` contains
the profile name and `message` is text produced by the backup process, and
runs it with `os.system(cmd)`. Only newlines are stripped, so a message or
profile name containing `"; some-command; "` (or `$(...)`, backticks) breaks
out of the double quotes and executes arbitrary commands. The upstream fix
builds an argument list and runs it with `subprocess.Popen(cmd).communicate()`.

Every variant is the FULL real file with on_message replaced. on_message is
the plugin hook the plugin manager calls by name (no in-file callers), so
the renamed variant renames its parameters and locals, not the method.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0130"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

HDR = "    def on_message( self, profile_id, profile_name, level, message, timeout ):\n"
s = original.index(HDR)
BLOCK = original[s:]
assert original.count(HDR) == 1 and original.count("on_message(") == 1
assert BLOCK.count("os.system(cmd)") == 1 and "subprocess" not in original
IMPORT = "import gettext\n"
assert original.count(IMPORT) == 1


def build(new_block, extra_import=None):
    assert new_block != BLOCK
    out = original[:s] + new_block
    if extra_import:
        out = out.replace(IMPORT, IMPORT + extra_import + "\n", 1)
    return out


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        parts = re.split(r"""('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")""", line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename_outside_strings(BLOCK, (("profile_id", "pid"), ("profile_name", "pname"), ("level", "severity"),
                                   ("message", "text"), ("timeout", "seconds"), ("cmd", "command_line"),
                                   ("title", "heading")))
assert "def on_message( self, pid, pname, severity, text, seconds ):" in b
assert 'command_line = command_line + " \\"%s\\" \\"%s\\"" % (heading, text)' in b and "os.system(command_line)" in b
(CASE_DIR / "variant_vulnerable_01.py").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace('''            cmd = "notify-send "
            if timeout > 0:
                cmd = cmd + " -t %s" % (1000 * timeout)
''', '''            option = " -t %s" % (1000 * timeout) if timeout > 0 else ""
''').replace('''            cmd = cmd + " \\"%s\\" \\"%s\\"" % (title, message)
''', '''            cmd = "notify-send%s \\"%s\\" \\"%s\\"" % (option, title, message)
''')
assert b != BLOCK and "os.system(cmd)" in b and "option" in b
(CASE_DIR / "variant_vulnerable_02.py").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Argument list executed with subprocess.call (no shell); the command is no
# longer printed (upstream: subprocess.Popen(cmd).communicate()).
b = BLOCK.replace('''            cmd = "notify-send "
            if timeout > 0:
                cmd = cmd + " -t %s" % (1000 * timeout)
''', '''            argv = ["notify-send"]
            if timeout > 0:
                argv += ["-t", str(1000 * timeout)]
''').replace('''            cmd = cmd + " \\"%s\\" \\"%s\\"" % (title, message)
            print(cmd)
            os.system(cmd)
''', '''            argv += [title, message]
            subprocess.call(argv)
''')
safe_source = build(b, extra_import="import subprocess")
assert "os.system" not in safe_source and "import subprocess" in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import os


def notify_finished(timeout):
    """Same "build a notify-send shell string and hand it to os.system"
    shape, but every part is constant except the timeout, which is forced
    through int() and formatted with %d, so it can hold only digits (or a
    sign); no text from the backup, the profile or the user reaches the shell."""
    cmd = "notify-send -t %d 'Back In Time' 'Backup finished'" % (1000 * int(timeout))
    return os.system(cmd)
'''
assert "%d" in benign_source and "int(timeout)" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0130.")

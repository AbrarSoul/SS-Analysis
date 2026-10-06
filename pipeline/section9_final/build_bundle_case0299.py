"""
Section 9 ground-truth test bundle: CASE-0299
(themoken/canto-curses, canto_curses/guibase.py GuiBase._fork,
CVE-2013-7416, CWE-77 command injection).

Core vulnerable mechanism: canto-curses is an ncurses RSS reader. When the
user opens a link (`_fork(path, href, text, fetch)`), the configured
"handler" command template (`path`, e.g. `firefox %u` or `less`) is combined
with the article link `href` and executed through a real shell:
`os.execv("/bin/sh", ["/bin/sh", "-c", path])`, after either substituting
`%u` with `href` or appending ` ` + `href`. `href` comes straight from the
feed's item link, i.e. from whoever controls a subscribed feed. Shell
metacharacters in it are interpreted: an item whose link is
`http://example.com & touch /tmp/pwned` (or `; rm -rf ~/`, `$(...)`,
backticks) runs the attacker's command with the reader's privileges as soon
as the user opens the article. The upstream fix wraps `href` in
`shlex.quote(href)` before it is combined into the shell command line.

Sibling sites: `_fork` is the single place that builds the shell command
from a link (the `fetch=True` branch replaces `href` with a local temp-file
path first, and is quoted by the same line).

Verification: each full file's `_fork` method is extracted verbatim into a
stand-in class and executed for real, with the process-level side effects
neutralized: `os.fork` returns 0 (take the child path in-process),
`os.execv`, `os.dup2`, `os.setpgid` are recorders/no-ops and `sys.exit`
raises. The recorded `/bin/sh -c <command>` argv is then really executed
with `subprocess.run(["/bin/sh","-c",command])`, exactly what `execv` would
do. `_fork("echo %u", "http://example.com & touch MARKER", text=True)` is
called with `fetch=False`: the injected `touch MARKER` running (the marker
file existing) is the measurement. A benign link
`http://example.com/a?b=1` must reach the shell as one intact argument
(echoed back verbatim) in every variant.

Every variant is the FULL real file. `_fork` is called by name from
`_goto`/`_edit`-style commands, so its name/signature are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0299"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


s = original.index("    def _fork(self, path, href, text, fetch=False):")
e = original.index("    def _edit(self, text):")
F = original[s:e]
CMD = '''        if "%u" in path:
            path = path.replace("%u", href)
        elif href:
            path = path + " " + href
'''
assert original.count(CMD) == 1

# --- Variant 1: renamed vulnerable variant ---
f1 = re.sub(r"\bhref\b", "link", F)
f1 = re.sub(r"\bpath\b", "handler_cmd", f1)
assert f1 != F
(CASE_DIR / "variant_vulnerable_01.py").write_text(original.replace(F, f1))

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CMD, '''        path = self._compose_command(path, href)
''')
v2 = swap(v2, "    def _edit(self, text):", '''    def _compose_command(self, path, href):
        if "%u" in path:
            return path.replace("%u", href)
        elif href:
            return path + " " + href
        return path

    def _edit(self, text):''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, CMD, '''        path = self._compose_command(path, href)
''')
v3 = swap(v3, "    def _edit(self, text):", '''    def _compose_command(self, path, href):
        # href is untrusted feed data and the command runs through /bin/sh -c
        quoted = shlex.quote(href) if href else href
        if "%u" in path:
            return path.replace("%u", quoted)
        elif quoted:
            return path + " " + quoted
        return path

    def _edit(self, text):''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''"""
Standalone example of the same shape: assemble a command from a template
and a value, but run it WITHOUT a shell (argument list), so the value is one
literal argv item and metacharacters are inert.
"""
import subprocess


def open_with(template_argv, url):
    return subprocess.run(list(template_argv) + [url], check=False)
''')

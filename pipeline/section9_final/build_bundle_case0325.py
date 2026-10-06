r"""
Section 9 ground-truth test bundle: CASE-0325
(web2py/web2py, gluon/messageboxhandler.py NotifySendHandler.emit,
CVE-2023-45158, CWE-78 OS command injection).

Core vulnerable mechanism: `NotifySendHandler` is a `logging.Handler` that
shows desktop notifications. `emit` formats the log record into `msg` and runs
`os.system("notify-send '%s'" % msg)`. The log message routinely contains
attacker-influenced text (request URLs, form values, exception text), and a
single quote in it closes the shell string: a message like
`x'; touch /tmp/pwned; echo '` runs arbitrary shell commands as the web2py
user. The upstream fix calls `subprocess.run(["notify-send", msg], ...)`
with an argument list (no shell) and a 2-second timeout.

Sibling sites: `MessageBoxHandler.emit` in the same file uses tkinter, not a
shell, and is unaffected.

Verification (REAL /bin/sh execution): each full file is imported (tkinter is
imported for real; if unavailable a stub module is inserted so the handler is
active), a fake `notify-send` executable that appends its argument count and
arguments to a log file is put first on PATH, and
`NotifySendHandler().emit(record)` is called with the message
`x'; touch <marker>; echo '`. Vulnerable variants create the marker file (the
injected command ran) and pass 1 mangled argument; patched/safe do not create
the marker and pass exactly 1 argument equal to the whole message. A plain
message is delivered as one argument in every file.

Every variant is the FULL real file; `emit` is the logging.Handler API and
keeps its name.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0325"
original = (CASE_DIR / "vulnerable_source.py").read_text()
patched = (CASE_DIR / "patched_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


SINK = '''            msg = self.format(record)
            os.system("notify-send '%s'" % msg)
'''

# --- Variant 1: renamed vulnerable variant (local renamed in NotifySendHandler.emit) ---
v1 = swap(original, SINK, '''            text = self.format(record)
            os.system("notify-send '%s'" % text)
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (shell call moved into a helper method) ---
v2 = swap(original, SINK, '''            msg = self.format(record)
            self._notify(msg)

    def _notify(self, text):
        os.system("notify-send '%s'" % text)
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the subprocess call moved into a helper method) ---
PS = '''            msg = self.format(record)
            subprocess.run(["notify-send", msg], check=False, timeout=2)
'''
v3 = swap(patched, PS, '''            msg = self.format(record)
            self._notify(msg)

    def _notify(self, text):
        subprocess.run(["notify-send", text], check=False, timeout=2)
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''import logging
import subprocess


class SoundAlertHandler(logging.Handler):
    """Plays a fixed alert sound for ERROR records; the log text never reaches a command."""

    def emit(self, record):
        if record.levelno >= logging.ERROR:
            subprocess.run(["aplay", "/usr/share/sounds/alert.wav"], check=False, timeout=2)
''')

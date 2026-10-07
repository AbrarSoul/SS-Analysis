r"""
Section 9 ground-truth test bundle: CASE-0308
(traccar/traccar, src/main/java/org/traccar/WindowsService.java install,
CVE-2021-21292, CWE-428 unquoted search path or element).

Core vulnerable mechanism: `install` registers Traccar as a Windows service
with `CreateService(..., binaryPathName = command, ...)` where `command`
begins with the Java executable path built as
the java.home directory plus bin/java.exe (backslash-separated) and is NOT quoted. When `java.home` contains a
space (the normal case: `C:\Program Files\Java\jdk-17`), Windows parses an
unquoted service path by trying each space-delimited prefix as an
executable: C:/Program.exe, then C:/Program Files/Java/jdk-17/bin/java.exe and so
on. A local unprivileged user who can write to `C:\` (or to a parent
directory earlier in the path) drops C:/Program.exe; the service runs it
as LocalSystem at every boot: local privilege escalation. The upstream fix
wraps the Java binary path in double quotes.

Sibling sites: the jar path and config arguments in the same command are
already quoted; the Java binary is the one unquoted token.

Verification: the command-construction span of each full file's `install`
(`String javaHome = ...` through the end of the `command` statement) is
extracted verbatim and compiled with javac into a harness with
`java.home` set to a directory under C:/Program Files and `WindowsService.class`
replaced by the harness class (for the jar location). The resulting command
line is analysed with Windows' documented unquoted-path rule: if the command
starts with a double quote there is exactly one candidate executable;
otherwise every space-delimited prefix ending at a token boundary is a
candidate. The number of candidate executables (and the first candidate) is
the measurement: more than one candidate, starting with C:/Program, is the
vulnerability.

Every variant is the FULL real file. `install` is a public method called
by name from the service entry point, so its name/signature are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0308"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


BIN = '        String javaBinary = javaHome + "\\\\bin\\\\java.exe";\n'
assert original.count(BIN) == 1, BIN
CMD = '''        String command = javaBinary
                + " -Duser.dir=\\"" + jar.getParentFile().getAbsolutePath() + "\\""
                + " -jar \\"" + jar.getAbsolutePath() + "\\""
                + " --service \\"" + config + "\\"";
'''
assert original.count(CMD) == 1, CMD

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, BIN, '        String javaExe = javaHome + "\\\\bin\\\\java.exe";\n')
v1 = swap(v1, CMD, CMD.replace("javaBinary", "javaExe").replace("String command", "String serviceCommand"))
v1 = re.sub(r"\bcommand,\n", "serviceCommand,\n", v1)
assert "serviceCommand," in v1
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BIN, ('        java.util.function.Function<String, String> binaryOf = home -> home + "\\\\bin\\\\java.exe";\n'
                          '        String javaBinary = binaryOf.apply(javaHome);\n'))
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file, quoting via String.format) ---
PBIN = '        String javaBinary = "\\"" + javaHome + "\\\\bin\\\\java.exe\\"";\n'
assert patched.count(PBIN) == 1, PBIN
v3 = swap(patched, PBIN, '        String javaBinary = String.format("\\"%s\\\\bin\\\\java.exe\\"", javaHome);\n')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package org.traccar;

/**
 * Standalone example of the same shape: build a display-only label from the
 * Java home path for a diagnostics page. The string is only shown to a
 * human, never handed to the operating system as a program path, so
 * quoting is irrelevant.
 */
class JavaHomeLabel {

    static String label(String javaHome) {
        return "Running on Java at " + javaHome + "\\\\bin\\\\java.exe";
    }
}
''')

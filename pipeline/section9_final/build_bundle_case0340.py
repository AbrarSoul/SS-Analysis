r"""
Section 9 ground-truth test bundle: CASE-0340
(zamotany/logkitty, src/android/adb.ts getApplicationPid,
CVE-2020-8149, CWE-94/CWE-78 command injection).

Core vulnerable mechanism: `getApplicationPid(applicationId, adbPath?)` runs
`execSync(`'${getAdbPath(adbPath)}' shell pidof -s ${applicationId}`)`: the
application id (taken from the CLI/API caller, e.g. from a CI config or a
project file) is interpolated UNQUOTED into a shell command line, so an id
such as `x; touch /tmp/pwned` runs an arbitrary command through `/bin/sh`.
`spawnLogcatProcess` has the same pattern with the adb path
(`execSync(`${adbPath} logcat -c`)`). The upstream fix switches both to
`execFileSync(program, [args...])` (no shell).

Sibling sites: `spawnLogcatProcess` in the same file (also changed by the
fix), whose adb path comes from `ANDROID_HOME` or the custom path option.

Verification (REAL /bin/sh execution): each full file is type-stripped with
node's `stripTypeScriptTypes` (the `../errors` import is pointed at a stub
module defining `CodeError` and the error constants) and imported with a
fake `adb` shell script that records its arguments and prints `4242`. Probes:
`getApplicationPid('x; touch <marker>; echo', <fake adb>)`. Vulnerable
variants create the marker file (the injected `touch` ran through `/bin/sh`)
and the fake adb receives only `shell pidof -s x`; patched/safe create no
marker and the fake adb receives the WHOLE application id (with its `;` and
`touch`) as one argument. A benign application id returns 4242 in every file.
(The `spawnLogcatProcess` sibling was not exercised: after its injected
`execSync` it spawns a long-lived adb child that the harness cannot safely
supervise.)

Every variant is the FULL real file; the exported function names are the
package API.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0340"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
patched = (CASE_DIR / "patched_source.ts").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


A = original.index("export function getApplicationPid(")
func = original[A:]

# --- Variant 1: renamed vulnerable variant (parameter and locals renamed inside getApplicationPid) ---
f1 = func
for old, new in [("applicationId", "appId"), ("output", "stdout"), ("pid", "processId"), ("error", "failure")]:
    f1 = re.sub(r"(?<![\w.'\"])%s(?![\w'\"])" % old, new, f1)
assert "(failure as Error)" in f1 and "parseInt(stdout.toString(), 10)" in f1 and "ERR_ANDROID_CANNOT_GET_APP_PID" in f1
v1 = original[:A] + f1
(CASE_DIR / "variant_vulnerable_01.ts").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (shell call moved into a helper; still one interpolated string) ---
CALL = '''    output = execSync(
      `'${getAdbPath(adbPath)}' shell pidof -s ${applicationId}`
    );
'''
v2 = swap(original, CALL, "    output = runPidof(getAdbPath(adbPath), applicationId);\n")
v2 = swap(v2, "export function getApplicationPid(",
          "function runPidof(adb: string, applicationId: string): Buffer {\n  return execSync(`'${adb}' shell pidof -s ${applicationId}`);\n}\n\nexport function getApplicationPid(")
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the argument-list call moved into a helper) ---
PCALL = '''    output = execFileSync(getAdbPath(adbPath), [
      'shell',
      'pidof',
      '-s',
      applicationId,
    ]);
'''
v3 = swap(patched, PCALL, "    output = runPidof(getAdbPath(adbPath), applicationId);\n")
v3 = swap(v3, "export function getApplicationPid(",
          "function runPidof(adb: string, applicationId: string): Buffer {\n  return execFileSync(adb, ['shell', 'pidof', '-s', applicationId]);\n}\n\nexport function getApplicationPid(")
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

(CASE_DIR / "benign_lookalike.ts").write_text('''import { execSync } from 'child_process';

// Prints the installed adb version. The command line is a constant string (no caller-controlled value is
// interpolated), so running it through the shell is safe.
export function getAdbVersion(): string {
  return execSync('adb version').toString().split('\\n')[0];
}
''')

"""
Section 9 ground-truth test bundle: CASE-0039
(genieacs/genieacs, CVE-2021-46704, CWE-78 -- OS command injection).

Core vulnerable mechanism: ping() interpolates the caller-supplied `host`
directly into a shell command string (e.g. `ping -w 1 -i 0.2 -c 3
${host}`) executed via exec(), with no validation of host's contents at
all. A crafted host value containing shell metacharacters (e.g.
"; rm -rf /" or a command substitution) achieves arbitrary command
execution. The real fix adds isValidHost(), which rejects any host not
matching a strict IPv4/IPv6/domain-name character set (with IDN/punycode
support) before it is ever used to build a command.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0039"
original = (CASE_DIR / "vulnerable_source.ts").read_text()

VULNERABLE_BLOCK = (
    "export function ping(\n"
    "  host: string,\n"
    "  callback: (err: Error, res?: PingResult, stdout?: string) => void\n"
    "): void {\n"
    "  let cmd: string, parseRegExp1: RegExp, parseRegExp2: RegExp;\n"
    "  host = host.replace(\"[\", \"\").replace(\"]\", \"\");\n"
    "  switch (platform()) {\n"
    "    case \"linux\":\n"
    "      cmd = `ping -w 1 -i 0.2 -c 3 ${host}`;\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"
assert "cmd = `ping -t 1 -c 3 ${host}`;" in original

# --- Variant 1: renamed vulnerable variant ---
# Rename the exported function ping -> pingHost and parameter host ->
# targetHost throughout the function (5 occurrences). Same exact
# vulnerability: still no validation before targetHost reaches the shell
# command.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    "export function pingHost(\n"
    "  targetHost: string,\n"
    "  callback: (err: Error, res?: PingResult, stdout?: string) => void\n"
    "): void {\n"
    "  let cmd: string, parseRegExp1: RegExp, parseRegExp2: RegExp;\n"
    "  targetHost = targetHost.replace(\"[\", \"\").replace(\"]\", \"\");\n"
    "  switch (platform()) {\n"
    "    case \"linux\":\n"
    "      cmd = `ping -w 1 -i 0.2 -c 3 ${targetHost}`;\n",
)
renamed_source = renamed_source.replace(
    "cmd = `ping -t 1 -c 3 ${host}`;", "cmd = `ping -t 1 -c 3 ${targetHost}`;"
)
assert renamed_source != original
assert "export function pingHost(" in renamed_source
assert "targetHost = targetHost.replace" in renamed_source
assert "${targetHost}" in renamed_source
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable -- the
# bracket-stripped value is captured under a new name instead of
# reassigning the parameter. Same exact vulnerability (still no
# validation), no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    "export function ping(\n"
    "  host: string,\n"
    "  callback: (err: Error, res?: PingResult, stdout?: string) => void\n"
    "): void {\n"
    "  let cmd: string, parseRegExp1: RegExp, parseRegExp2: RegExp;\n"
    "  const strippedHost = host.replace(\"[\", \"\").replace(\"]\", \"\");\n"
    "  switch (platform()) {\n"
    "    case \"linux\":\n"
    "      cmd = `ping -w 1 -i 0.2 -c 3 ${strippedHost}`;\n",
)
structural_source = structural_source.replace(
    "cmd = `ping -t 1 -c 3 ${host}`;", "cmd = `ping -t 1 -c 3 ${strippedHost}`;"
)
assert structural_source != original
assert "const strippedHost = host.replace" in structural_source
assert "${strippedHost}" in structural_source
(CASE_DIR / "variant_vulnerable_02.ts").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (host is rejected before being
# used to build any command unless it matches a strict safe character
# set) but validated inline with a single regex check and a differently-
# worded error, instead of the real patch's separate isValidHost() helper
# with its IDN/punycode fallback branch -- materially simpler, still
# injection-safe, not byte-identical to the known fix.
safe_source = original.replace(
    VULNERABLE_BLOCK,
    "export function ping(\n"
    "  host: string,\n"
    "  callback: (err: Error, res?: PingResult, stdout?: string) => void\n"
    "): void {\n"
    "  let cmd: string, parseRegExp1: RegExp, parseRegExp2: RegExp;\n"
    "  if (!/^[a-zA-Z0-9\\-.:[\\]]+$/.test(host)) {\n"
    "    return callback(new Error(\"Host contains invalid characters\"));\n"
    "  }\n"
    "  host = host.replace(\"[\", \"\").replace(\"]\", \"\");\n"
    "  switch (platform()) {\n"
    "    case \"linux\":\n"
    "      cmd = `ping -w 1 -i 0.2 -c 3 ${host}`;\n",
)
assert safe_source != original
assert 'if (!/^[a-zA-Z0-9\\-.:[\\]]+$/.test(host)) {' in safe_source
assert "Host contains invalid characters" in safe_source
(CASE_DIR / "variant_safe_01.ts").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a function that also
# builds and executes a shell command via exec() from a parameter -- the
# same superficial shape as ping() -- but the parameter's type is a
# TypeScript string-literal union restricted to three fixed, hardcoded
# command names, never an arbitrary caller-supplied string, so no shell
# metacharacter injection is possible here.
BENIGN_ADDITION = (
    "\n"
    "export function runDiagnostic(\n"
    "  diagnosticName: \"uptime\" | \"df\" | \"free\",\n"
    "  callback: (err: Error, stdout?: string) => void\n"
    "): void {\n"
    "  // diagnosticName is restricted by its own TypeScript union type to\n"
    "  // one of three fixed, hardcoded command names -- never an arbitrary\n"
    "  // caller-supplied string -- so there is no way to inject shell\n"
    "  // metacharacters here, unlike ping()'s host parameter.\n"
    "  const cmd = diagnosticName;\n"
    "  exec(cmd, (err, stdout) => {\n"
    "    callback(err, stdout);\n"
    "  });\n"
    "}\n"
)
anchor = "export function ping(\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "runDiagnostic" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)

print("Wrote 4 new samples for CASE-0039.")

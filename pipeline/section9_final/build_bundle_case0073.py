"""
Section 9 ground-truth test bundle: CASE-0073
(SignalK/set-system-time, CVE-2026-23515, CWE-78 OS command injection).

Core vulnerable mechanism: the `datetime` value received from a Signal K
data stream (network-influenced, not sanitized) is interpolated directly
into a shell command string: `` `date -u -s "${dateStr}"` ``, then run via
`spawn('sh', ['-c', setDate])` -- with a SUDO fallback path if the first
attempt fails. A `datetime` value containing a double-quote followed by
shell metacharacters (e.g. `2024-01-01T00:00:00Z"; rm -rf / #`) breaks out
of the quoted string and injects arbitrary shell commands, which can run
with root privileges via the sudo fallback. The fix validates `datetime`
against a strict ISO-8601-shaped regex BEFORE it's ever used to build the
command string, rejecting anything that doesn't match.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0073"
original = (CASE_DIR / "vulnerable_source.js").read_text()

ANCHOR = '''          if( ! plugin.useNetworkTime(options) ){
            const useSudoFallback = typeof options.sudo === 'undefined' || options.sudo
            // Convert ISO 8601 datetime to format compatible with both GNU date and BusyBox date
            // e.g., "2024-01-10T17:55:03.000Z" → "2024-01-10 17:55:03"
            const dateStr = datetime.replace('T', ' ').replace(/\\.\\d+Z?$|Z$/, '')
            const setDate = `date -u -s "${dateStr}"`'''
assert ANCHOR in original

# --- Variant 1: renamed vulnerable variant ---
# Rename dateStr -> normalizedDate, setDate -> dateCommand. Same exact
# unvalidated shell-string interpolation.
renamed_block = '''          if( ! plugin.useNetworkTime(options) ){
            const useSudoFallback = typeof options.sudo === 'undefined' || options.sudo
            // Convert ISO 8601 datetime to format compatible with both GNU date and BusyBox date
            // e.g., "2024-01-10T17:55:03.000Z" → "2024-01-10 17:55:03"
            const normalizedDate = datetime.replace('T', ' ').replace(/\\.\\d+Z?$|Z$/, '')
            const dateCommand = `date -u -s "${normalizedDate}"`'''
renamed_source = original.replace(ANCHOR, renamed_block)
renamed_source = renamed_source.replace(
    "child = require('child_process').spawn('sh', ['-c', setDate])",
    "child = require('child_process').spawn('sh', ['-c', dateCommand])",
)
renamed_source = renamed_source.replace(
    "const sudoCommand = `if sudo -n date &> /dev/null ; then sudo ${setDate} ; else exit 3 ; fi`",
    "const sudoCommand = `if sudo -n date &> /dev/null ; then sudo ${dateCommand} ; else exit 3 ; fi`",
)
assert "const normalizedDate = datetime.replace" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the raw datetime before the
# T/Z replacement. Same exact unvalidated shell-string interpolation, no
# renaming.
structural_block = '''          if( ! plugin.useNetworkTime(options) ){
            const useSudoFallback = typeof options.sudo === 'undefined' || options.sudo
            const rawDatetime = datetime
            // Convert ISO 8601 datetime to format compatible with both GNU date and BusyBox date
            // e.g., "2024-01-10T17:55:03.000Z" → "2024-01-10 17:55:03"
            const dateStr = rawDatetime.replace('T', ' ').replace(/\\.\\d+Z?$|Z$/, '')
            const setDate = `date -u -s "${dateStr}"`'''
structural_source = original.replace(ANCHOR, structural_block)
assert structural_source != original
assert "const rawDatetime = datetime" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (reject a datetime value before it's used to
# build a shell command) but a materially different technique: instead of
# a regex format check, parses the value with `new Date(datetime)` and
# rebuilds the shell-command date string entirely from the parsed
# NUMERIC components (never from the original string) -- so even if the
# original string somehow smuggled shell metacharacters, none of them
# ever reach the command, since the command is built purely from numbers.
SAFE_SOURCE = '''function buildSafeSetDateCommand(datetime) {
  const parsed = new Date(datetime)
  if (isNaN(parsed.getTime())) {
    throw new Error('Invalid datetime received: ' + String(datetime).substring(0, 50))
  }
  const pad = n => String(n).padStart(2, '0')
  const safeDateStr =
    `${parsed.getUTCFullYear()}-${pad(parsed.getUTCMonth() + 1)}-${pad(parsed.getUTCDate())} ` +
    `${pad(parsed.getUTCHours())}:${pad(parsed.getUTCMinutes())}:${pad(parsed.getUTCSeconds())}`
  // safeDateStr is built ENTIRELY from validated numeric fields -- no
  // substring of the original attacker-influenced string ever appears
  // in the returned command.
  return `date -u -s "${safeDateStr}"`
}

module.exports = { buildSafeSetDateCommand }
'''
(CASE_DIR / "variant_safe_01.js").write_text(SAFE_SOURCE)
assert "buildSafeSetDateCommand" in SAFE_SOURCE

# --- Verify the safe builder genuinely never lets injected shell syntax
# through, even for a maliciously-crafted datetime string ---
import subprocess

node_check = """
const { buildSafeSetDateCommand } = require('./variant_safe_01.js')
const malicious = '2024-01-01T00:00:00Z"; rm -rf / #'
let result;
try {
  result = buildSafeSetDateCommand(malicious)
} catch (e) {
  result = null
}
if (result !== null && result.includes(';')) {
  console.error('FAIL: malicious payload survived into the command:', result)
  process.exit(1)
}
console.log('OK: malicious datetime either rejected or fully neutralized:', result)
"""
proc = subprocess.run(
    ["node", "-e", node_check], capture_output=True, text=True, cwd=str(CASE_DIR)
)
assert proc.returncode == 0, f"safe variant failed live injection-resistance verification: {proc.stdout} {proc.stderr}"

# --- Variant 4: benign structural look-alike ---
# Same visible shape (interpolate a variable into a template-literal
# shell command string and spawn('sh', ['-c', ...])) but this sibling
# always builds its command from a FIXED, hard-coded string with no
# variable interpolation at all -- never anything derived from stream
# data -- so there is no injection surface regardless of validation,
# unlike the datetime-driven setDate command.
BENIGN_SOURCE = '''function restartNetworkTimeService() {
  // The entire command string is a fixed literal -- nothing here is
  // ever built from stream data or any other external input, so there
  // is no value an attacker could influence to reach this shell command.
  const command = `systemctl restart systemd-timesyncd`
  return require('child_process').spawn('sh', ['-c', command])
}

module.exports = { restartNetworkTimeService }
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN_SOURCE)
assert "datetime" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0073.")

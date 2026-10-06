"""
Section 9 ground-truth test bundle: CASE-0045
(AiondaDotCom/mcp-ssh, CVE-2025-9654, CWE-74/CWE-77 command injection).

Core vulnerable mechanism: `uploadFile()` builds a shell command string via
template-literal interpolation (`scp "${localPath}" "${hostAlias}:${remotePath}"`)
and runs it through `execAsync` (Node's `child_process.exec`, which always
goes through a shell). Wrapping values in double quotes does NOT neutralize
shell metacharacters -- a value containing a literal `"` (or `` ` ``, `$(...)`,
etc.) breaks out of the quoting and reaches the shell. The real fix switches
to `execFileAsync('scp', [args...], ...)`, which never invokes a shell at
all -- each array element is passed directly as a literal argv entry.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0045"
# Normalize trailing whitespace per line first -- the real file has a
# stray trailing-whitespace-only line inside uploadFile() that a hand-typed
# VULNERABLE_BLOCK literal (auto-stripped by this session's own editing
# tools) can never byte-match otherwise. Cosmetically irrelevant for JS
# syntax validity either way.
original = "\n".join(line.rstrip() for line in (CASE_DIR / "vulnerable_source.js").read_text().splitlines())
if not original.endswith("\n"):
    original += "\n"

VULNERABLE_BLOCK = '''  async uploadFile(hostAlias, localPath, remotePath) {
    try {
      const scpCommand = `scp "${localPath}" "${hostAlias}:${remotePath}"`;
      debugLog(`Executing: ${scpCommand}\\n`);

      await execAsync(scpCommand, { timeout: 60000 }); // 60 second timeout for file transfer
      return true;
    } catch (error) {
      debugLog(`Error uploading file to ${hostAlias}: ${error.message}\\n`);
      return false;
    }
  }'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename uploadFile -> pushFile, scpCommand -> transferCommand. Same exact
# shell-string interpolation reaching execAsync.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''  async pushFile(hostAlias, localPath, remotePath) {
    try {
      const transferCommand = `scp "${localPath}" "${hostAlias}:${remotePath}"`;
      debugLog(`Executing: ${transferCommand}\\n`);

      await execAsync(transferCommand, { timeout: 60000 }); // 60 second timeout for file transfer
      return true;
    } catch (error) {
      debugLog(`Error uploading file to ${hostAlias}: ${error.message}\\n`);
      return false;
    }
  }''',
)
assert "async pushFile(hostAlias, localPath, remotePath)" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variables + equivalent conditional rewriting
# (try/catch body restructured to an explicit success flag). Same exact
# vulnerability, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''  async uploadFile(hostAlias, localPath, remotePath) {
    const target = `${hostAlias}:${remotePath}`;
    const scpCommand = `scp "${localPath}" "${target}"`;
    let succeeded = false;
    try {
      debugLog(`Executing: ${scpCommand}\\n`);
      await execAsync(scpCommand, { timeout: 60000 });
      succeeded = true;
    } catch (error) {
      debugLog(`Error uploading file to ${hostAlias}: ${error.message}\\n`);
    }
    return succeeded;
  }''',
)
assert structural_source != original
assert "const target = `${hostAlias}:${remotePath}`;" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (avoid shell-string interpolation) but a
# materially different technique: instead of switching to execFile, keeps
# execAsync but properly shell-escapes each interpolated value first
# (wrapping in single quotes and escaping embedded single quotes) --
# genuinely neutralizes shell metacharacters, different implementation
# from the real patch's execFile-array approach.
SAFE_SOURCE = '''function shellEscape(value) {
  return "'" + String(value).replace(/'/g, "'\\\\''") + "'";
}

class SecureUploader {
  constructor(execAsync, debugLog) {
    this.execAsync = execAsync;
    this.debugLog = debugLog;
  }

  async uploadFile(hostAlias, localPath, remotePath) {
    try {
      const target = shellEscape(hostAlias) + ":" + shellEscape(remotePath);
      const scpCommand = `scp ${shellEscape(localPath)} ${target}`;
      this.debugLog(`Executing: ${scpCommand}\\n`);

      await this.execAsync(scpCommand, { timeout: 60000 });
      return true;
    } catch (error) {
      this.debugLog(`Error uploading file to ${hostAlias}: ${error.message}\\n`);
      return false;
    }
  }
}

module.exports = { SecureUploader, shellEscape };
'''
(CASE_DIR / "variant_safe_01.js").write_text(SAFE_SOURCE)
assert "shellEscape" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (build a command string via template-literal
# interpolation, run it, log it) but every interpolated value here comes
# from a fixed, hardcoded internal constant (a health-check ping to a
# well-known loopback target), never from a hostAlias/path supplied by an
# MCP client -- no attacker-controlled input reaches the shell despite the
# structural resemblance to uploadFile()/downloadFile().
BENIGN_SOURCE = '''const { exec } = require("child_process");
const { promisify } = require("util");
const execAsync = promisify(exec);

class HealthChecker {
  // Only ever pings a fixed, compile-time-constant loopback address --
  // never receives a remote host name or path from an MCP client request,
  // so there is no injectable value reaching the shell here.
  async pingLoopback() {
    const target = "127.0.0.1";
    const pingCommand = `ping -c 1 "${target}"`;
    try {
      await execAsync(pingCommand, { timeout: 5000 });
      return true;
    } catch (error) {
      return false;
    }
  }
}

module.exports = { HealthChecker };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN_SOURCE)
assert "hostAlias" not in BENIGN_SOURCE
assert "remotePath" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0045.")

"""
Section 9 ground-truth test bundle: CASE-0081
(YosefHayim/ebay-mcp, CVE-2026-27203, CWE-15/CWE-74 .env injection).

Core vulnerable mechanism: `updateEnvFile()` builds `KEY="value"` lines by
string interpolation with no escaping/validation of the value (or of the
key, which is also interpolated into a RegExp). A token value containing a
double quote or a newline can therefore terminate the quoted value and
inject arbitrary additional environment variables into the .env file. The
upstream fix parses the existing file with `dotenv` and serialises the
merged object with `dotenv-stringify`.

Every variant is the FULL real file with the updateEnvFile function
replaced. The renamed variant also renames the function's three call
sites elsewhere in the file (a missed call site would be a runtime
ReferenceError that a syntax check cannot see).
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0081"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.ts").read_text().splitlines()) + "\n"

START = "function updateEnvFile(updates: Record<string, string>): void {"
s = original.index(START)
e = original.index("\n}\n", s) + 3
BLOCK = original[s:e]
assert original.count(START) == 1
assert "writeFileSync(envPath, envContent, 'utf-8');" in BLOCK


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK
for old, new in (
    ("updateEnvFile", "persistEnvValues"),
    ("updates", "changes"),
    ("envContent", "fileText"),
    ("envPath", "dotenvPath"),
    ("newLine", "assignment"),
    ("regex", "keyPattern"),
):
    b = re.sub(r"\b%s\b" % old, new, b)
# `key`/`value` are only loop locals in this function
b = re.sub(r"\bkey\b", "name", b)
b = re.sub(r"\bvalue\b", "val", b)
renamed = build(b)
# rename every other reference (three call sites + one comment)
renamed = re.sub(r"\bupdateEnvFile\b", "persistEnvValues", renamed)
assert "updateEnvFile" not in renamed
assert renamed.count("persistEnvValues(") == 5  # declaration + 3 call sites + 1 comment
assert '${name}="${val}"' in renamed
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed)

# --- Variant 2: structurally changed vulnerable variant ---
STRUCT = """function updateEnvFile(updates: Record<string, string>): void {
  try {
    const envPath = join(process.cwd(), '.env');
    const currentText = existsSync(envPath) ? readFileSync(envPath, 'utf-8') : '';
    const entries = Object.entries(updates);

    const nextText = entries.reduce((acc, [key, value]) => {
      const pattern = new RegExp(`^(#\\\\s*)?${key}=.*$`, 'gm');
      const assignment = `${key}="${value}"`;
      const alreadyPresent = pattern.test(acc);
      return alreadyPresent ? acc.replace(pattern, assignment) : `${acc}\\n${assignment}`;
    }, currentText);

    writeFileSync(envPath, nextText, 'utf-8');
  } catch (_error) {
    // Silent failure - error logging interferes with MCP JSON protocol
    // If needed, check .env file manually
  }
}
"""
(CASE_DIR / "variant_vulnerable_02.ts").write_text(build(STRUCT))

# --- Variant 3: transformed safe variant ---
# Keeps the line-oriented update approach but validates the key against a
# strict identifier grammar (which also makes the RegExp safe), rejects
# values containing CR/LF/NUL, escapes backslash and double quote, and
# uses a replacer function so `$&`-style sequences in a value are inert.
# Different mechanism from the upstream dotenv parse/stringify fix.
SAFE = """function updateEnvFile(updates: Record<string, string>): void {
  try {
    const envPath = join(process.cwd(), '.env');
    let envContent = existsSync(envPath) ? readFileSync(envPath, 'utf-8') : '';

    for (const [key, value] of Object.entries(updates)) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
        throw new Error('invalid environment variable name');
      }
      if (/[\\r\\n\\0]/.test(value)) {
        throw new Error('environment variable value must not contain line breaks');
      }
      const escaped = value.replace(/\\\\/g, '\\\\\\\\').replace(/"/g, '\\\\"');
      const regex = new RegExp(`^(#\\\\s*)?${key}=.*$`, 'm');
      const newLine = `${key}="${escaped}"`;

      if (regex.test(envContent)) {
        envContent = envContent.replace(regex, () => newLine);
      } else {
        envContent += `\\n${newLine}`;
      }
    }

    writeFileSync(envPath, envContent, 'utf-8');
  } catch (_error) {
    // Silent failure - error logging interferes with MCP JSON protocol
    // If needed, check .env file manually
  }
}
"""
(CASE_DIR / "variant_safe_01.ts").write_text(build(SAFE))

# --- Variant 4: benign structural look-alike ---
BENIGN = """import { join } from 'path';

/**
 * Builds a human-readable summary of a configuration object for a debug
 * banner. Same `${key}="${value}"` interpolation shape as an env-file
 * writer, but the result is only ever printed to a log line, never
 * written to any file that is later parsed as configuration.
 */
export function describeSettings(settings: Record<string, string>): string {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(settings)) {
    lines.push(`${key}="${value}"`);
  }
  return `settings for ${join('config', 'debug')}: ${lines.join(', ')}`;
}
"""
(CASE_DIR / "benign_lookalike.ts").write_text(BENIGN)

print("Wrote 4 new samples for CASE-0081.")

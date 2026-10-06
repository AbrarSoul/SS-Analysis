"""
Section 9 ground-truth test bundle: CASE-0036
(awwaiid/mcp-server-taskwarrior, CVE-2026-5833, CWE-74/CWE-77 -- command
injection).

The real patch fixes three sites (get_next_tasks, mark_task_done, and the
add-task handler). This bundle targets mark_task_done as the
representative instance (Section 9.3); the other two are left untouched.

Core vulnerable mechanism: parsed.data.identifier (an MCP tool-call
argument, attacker-controlled) is interpolated directly into a shell
command string executed via execSync(), which runs it through `/bin/sh
-c`. A crafted identifier like "1; rm -rf ~" is interpreted by the shell,
achieving arbitrary command execution. The real fix switches to
execFileSync('task', [args...], ...), which passes arguments directly to
the binary with no shell involved.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0036"
original = (CASE_DIR / "vulnerable_source.ts").read_text()

VULNERABLE_BLOCK = (
    "      case \"mark_task_done\": {\n"
    "        const parsed = markTaskDoneRequest.safeParse(args);\n"
    "        if (!parsed.success) {\n"
    "          throw new Error(`Invalid arguments for mark_task_done: ${parsed.error}`);\n"
    "        }\n"
    "        const content = execSync(`task ${parsed.data.identifier} done`, { maxBuffer: 1024 * 1024 * 10 }).toString().trim();\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"
assert original.count("execSync(") == 3, "expected exactly 3 occurrences total"

# --- Variant 1: renamed vulnerable variant ---
# Rename the local content -> taskOutput within this case block (its
# declaration and its use as the `text:` value) -- but NOT the outer
# `content:` response-object key, which is a fixed MCP protocol field
# name, not a local identifier. Same exact vulnerability: still a shell
# command string built via template literal interpolation of
# attacker-controlled input.
FULL_CASE_BLOCK = (
    VULNERABLE_BLOCK
    + "        return {\n"
    + "          content: [{ type: \"text\", text: content }],\n"
    + "        };\n"
    + "      }\n"
)
assert FULL_CASE_BLOCK in original
renamed_case_block = FULL_CASE_BLOCK.replace(
    "const content = execSync(`task ${parsed.data.identifier} done`, { maxBuffer: 1024 * 1024 * 10 }).toString().trim();\n",
    "const taskOutput = execSync(`task ${parsed.data.identifier} done`, { maxBuffer: 1024 * 1024 * 10 }).toString().trim();\n",
).replace(
    "content: [{ type: \"text\", text: content }],\n",
    "content: [{ type: \"text\", text: taskOutput }],\n",
)
renamed_source = original.replace(FULL_CASE_BLOCK, renamed_case_block)
assert renamed_source != original
assert "const taskOutput = execSync(`task ${parsed.data.identifier} done`" in renamed_source
assert "text: taskOutput }" in renamed_source
assert "content: [{ type: \"text\", text: taskOutput }]" in renamed_source
assert renamed_source.count("execSync(") == 3
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable -- the command
# string is built separately before being passed to execSync(). Same
# exact vulnerability, no renaming.
STRUCTURAL_BLOCK = VULNERABLE_BLOCK.replace(
    "        const content = execSync(`task ${parsed.data.identifier} done`, { maxBuffer: 1024 * 1024 * 10 }).toString().trim();\n",
    "        const command = `task ${parsed.data.identifier} done`;\n"
    "        const content = execSync(command, { maxBuffer: 1024 * 1024 * 10 }).toString().trim();\n",
)
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "const command = `task ${parsed.data.identifier} done`;" in structural_source
assert structural_source.count("execSync(") == 3
(CASE_DIR / "variant_vulnerable_02.ts").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (arguments passed directly to
# the task binary, no shell involved) but the args array is built into a
# named taskArgs variable instead of the real patch's inline array
# literal -- materially different structure, not byte-identical to the
# known fix.
SAFE_BLOCK = VULNERABLE_BLOCK.replace(
    "        const content = execSync(`task ${parsed.data.identifier} done`, { maxBuffer: 1024 * 1024 * 10 }).toString().trim();\n",
    "        const taskArgs = [parsed.data.identifier, 'done'];\n"
    "        const content = execFileSync('task', taskArgs, { encoding: 'utf8', maxBuffer: 1024 * 1024 * 10 }).trim();\n",
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
safe_source = safe_source.replace(
    "import { execSync } from 'child_process';\n",
    "import { execSync, execFileSync } from 'child_process';\n",
    1,
)
assert safe_source != original
assert "const taskArgs = [parsed.data.identifier, 'done'];" in safe_source
assert "execFileSync('task', taskArgs" in safe_source
# the other two sibling vulnerable execSync() sites remain untouched
assert safe_source.count("execSync(`task limit:") == 1
assert safe_source.count("execSync(`task add") == 1
(CASE_DIR / "variant_safe_01.ts").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a function that also calls
# execSync() with a template literal -- the same superficial shape as the
# vulnerable line -- but the interpolated command is a hardcoded literal,
# never derived from MCP tool-call arguments, so it carries no
# command-injection risk.
BENIGN_ADDITION = (
    "\n"
    "function getTaskwarriorVersion(): string {\n"
    "  // \"task\" here is a fixed, hardcoded literal -- never derived from\n"
    "  // MCP tool-call arguments -- so execSync() here cannot be used for\n"
    "  // command injection, unlike the identifier-based commands above.\n"
    "  return execSync(`task --version`, { maxBuffer: 1024 * 1024 }).toString().trim();\n"
    "}\n"
)
anchor = "server.setRequestHandler(CallToolRequestSchema, async (request) => {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "getTaskwarriorVersion" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)

print("Wrote 4 new samples for CASE-0036.")

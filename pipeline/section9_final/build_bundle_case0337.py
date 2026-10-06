r"""
Section 9 ground-truth test bundle: CASE-0337
(yugabyte/yugabyte-db, managed/src/main/java/com/yugabyte/yw/common/NodeUniverseManager.java
executeNodeAction, CVE-2024-0006, CWE-532 insertion of sensitive information
into a log file; two backports of the same fix exist, this is the first).

Core vulnerable mechanism: `executeNodeAction` collects the secrets that must be
hidden from logs (`redactedVals`, filled by `addConnectionParams` with
tokens, keys and passwords) and then builds a NEW `ShellProcessContext` with
`context.toBuilder().redactedVals(redactedVals).build()`. That REPLACES the
redaction map the caller had already put on the incoming context (for example
the password embedded in `actionArgs`), so the shell process handler logs the
full command line with those caller-registered secrets in clear text. The fix
merges the incoming context's `getRedactedVals()` into the new map before
rebuilding.

Sibling sites: the second backport (CASE-0338) applies the identical change
to a different branch of the same file.

Verification: the `executeNodeAction` method (plus any helper a variant adds)
is sliced from each full file into a javac harness with stand-ins for
`ShellProcessContext` (immutable, with `toBuilder()`/`redactedVals(...)`/`build()`
and `getRedactedVals()`), `ShellProcessHandler` (records the context it is
given), `ShellResponse`, `Universe`, `NodeDetails`, `UniverseNodeAction`, an
`addConnectionParams` that registers `NODE_TOKEN`, and the REAL
commons-collections4 `MapUtils`. The incoming context already redacts
`ACTION_PASSWORD`. The context received by the shell handler is inspected:
vulnerable variants hand over only `NODE_TOKEN` (the caller's
`ACTION_PASSWORD` redaction is lost), patched/safe hand over both.
When the incoming context has no redactions both behave the same.

Every variant is the FULL real file; `executeNodeAction` is a private
method called by name within the class.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0337"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


def method_span(text):
    a = text.index("  private ShellResponse executeNodeAction(")
    b = text.index("\n  }\n", a) + len("\n  }\n")
    return a, b


a, b = method_span(original)
m = original[a:b]
TAIL = '''    if (MapUtils.isNotEmpty(redactedVals)) {
      // Create a new context as a context is immutable.
      context = context.toBuilder().redactedVals(redactedVals).build();
    }
'''
assert m.count(TAIL) == 1

# --- Variant 1: renamed vulnerable variant (locals renamed inside executeNodeAction) ---
m1 = m
for old, new in [("commandArgs", "argv"), ("redactedVals", "secretsToHide")]:
    m1 = re.sub(r"(?<![\w.])%s(?![\w(])" % old, new, m1)
assert ".redactedVals(secretsToHide)" in m1 and "secretsToHide" in m1
v1 = original.replace(m, m1)
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (context rebuilt by a helper that overwrites the map) ---
m2 = swap(m, TAIL, "    context = withRedactions(context, redactedVals);\n")
helper2 = '''
  private ShellProcessContext withRedactions(
      ShellProcessContext context, Map<String, String> redactedVals) {
    if (MapUtils.isNotEmpty(redactedVals)) {
      // Create a new context as a context is immutable.
      context = context.toBuilder().redactedVals(redactedVals).build();
    }
    return context;
  }
'''
v2 = original.replace(m, m2 + helper2)
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the merge lives in a helper) ---
pa, pb = method_span(patched)
pm = patched[pa:pb]
PTAIL = '''    if (MapUtils.isNotEmpty(redactedVals)) {
      // Create a new context as a context is immutable.
      if (MapUtils.isNotEmpty(context.getRedactedVals())) {
        redactedVals.putAll(context.getRedactedVals());
      }
      context = context.toBuilder().redactedVals(redactedVals).build();
    }
'''
pm3 = swap(pm, PTAIL, "    context = withRedactions(context, redactedVals);\n")
helper3 = '''
  private ShellProcessContext withRedactions(
      ShellProcessContext context, Map<String, String> redactedVals) {
    if (MapUtils.isNotEmpty(redactedVals)) {
      // Create a new context as a context is immutable.
      if (MapUtils.isNotEmpty(context.getRedactedVals())) {
        redactedVals.putAll(context.getRedactedVals());
      }
      context = context.toBuilder().redactedVals(redactedVals).build();
    }
    return context;
  }
'''
v3 = patched.replace(pm, pm3 + helper3)
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package com.yugabyte.yw.common;

import java.util.HashMap;
import java.util.Map;

/**
 * Standalone example of the same shape: builds a brand-new context for a command that has no earlier redactions
 * (there is nothing on a fresh command to lose), so setting the redaction map directly is correct.
 */
class FreshCommandContext {

    static final class Context {
        final Map<String, String> redactedVals;

        Context(Map<String, String> redactedVals) {
            this.redactedVals = redactedVals;
        }
    }

    static Context forNewCommand(String tokenName, String tokenValue) {
        Map<String, String> redactions = new HashMap<>();
        redactions.put(tokenName, tokenValue);
        return new Context(redactions);
    }
}
''')

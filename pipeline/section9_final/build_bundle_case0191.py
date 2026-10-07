"""
Section 9 ground-truth test bundle: CASE-0191
(jenkinsci/queue-cleanup-plugin, .../queuecleanup/QueueCleanup.java
DescriptorImpl.doCheckItemPattern, CVE-2020-2169, CWE-79 reflected/stored XSS).

Core vulnerable mechanism: the form-validation method compiles the
user-typed `itemPattern` and, on a syntax error, returns
`FormValidation.errorWithMarkup("Not a regular expression: <pre>" + ex.getMessage() + "</pre>")`.
`PatternSyntaxException.getMessage()` INCLUDES the offending pattern text, and
`errorWithMarkup` renders its argument as raw HTML, so a pattern such as
`[<img src=x onerror=alert(1)>` puts attacker-controlled markup into the admin's
configuration page. The upstream fix switches to `FormValidation.error(...)`,
whose message Jenkins HTML-escapes when rendering.

Modelling note (kept in the manifest notes): Jenkins' escaping happens when the
FormValidation is rendered; the harness reproduces that rule with a stand-in
FormValidation (`error` -> HTML-escaped on render, `errorWithMarkup` -> raw)
and the JDK's real Pattern/PatternSyntaxException.

Sibling sites: `doCheckTimeout` uses the plain `error(...)` with a constant
message; only the item-pattern check reflects user text.

Every variant is the FULL real file. doCheckItemPattern is bound by name by
Stapler and its `itemPattern` parameter by name, so the renamed variant keeps
both and renames the caught exception variable.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0191"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

ERR = '''                return FormValidation.errorWithMarkup("Not a regular expression: <pre>" + ex.getMessage() + "</pre>");
'''
assert original.count(ERR) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
CATCH = "            } catch (PatternSyntaxException ex) {\n"
IDX = original.index("public FormValidation doCheckItemPattern(")
assert original.count(CATCH, IDX) == 1
v1 = original[:IDX] + original[IDX:].replace(CATCH, "            } catch (PatternSyntaxException problem) {\n")
v1 = swap(v1, ERR, ERR.replace("ex.getMessage()", "problem.getMessage()"))
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, ERR, "                return FormValidation.errorWithMarkup(describe(ex));\n")
v2 = swap(v2, "        @Restricted(NoExternalUse.class)\n        public FormValidation doCheckTimeout(", '''        private static String describe(PatternSyntaxException ex) {
            return "Not a regular expression: <pre>" + ex.getMessage() + "</pre>";
        }

        @Restricted(NoExternalUse.class)
        public FormValidation doCheckTimeout(''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Keeps the monospace <pre> layout the comment asks for but HTML-escapes the
# exception text with hudson.Util.escape (already imported); upstream drops
# the markup and uses the escaping error().
v3 = swap(original, ERR, '''                return FormValidation.errorWithMarkup("Not a regular expression: <pre>" + Util.escape(ex.getMessage()) + "</pre>");
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import hudson.util.FormValidation;

public class StaticHelp {

    /**
     * Same errorWithMarkup(...) call shape as the pattern check, but the
     * markup is a developer-written constant and no user text is placed in it.
     */
    public FormValidation help() {
        return FormValidation.errorWithMarkup("Use a <b>Java regular expression</b>, for example <code>.*-nightly</code>");
    }
}
'''
assert "developer-written constant" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0191.")

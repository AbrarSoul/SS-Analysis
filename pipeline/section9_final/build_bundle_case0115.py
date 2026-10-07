"""
Section 9 ground-truth test bundle: CASE-0115
(apache/struts, REST plugin RestActionMapper, CVE-2016-4438 / S2-037,
CWE-20 improper input validation leading to OGNL/RCE).

Core vulnerable mechanism: `handleDynamicMethodInvocation()` splits the
request name at "!" and, when dynamic method calls are enabled, stores the
attacker-supplied text after the "!" verbatim with
`mapping.setMethod(actionMethod)`. That string is later evaluated as an
OGNL expression/method reference (e.g. `action!%{...}`), giving remote code
execution. The upstream fix sanitises it with the inherited
`cleanupActionName(actionMethod)` (strips characters outside the allowed
action-name pattern).

Every variant is the FULL real file with handleDynamicMethodInvocation
replaced. It is private with one in-file call site, which the renamed
variant also renames.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0115"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    private void handleDynamicMethodInvocation(ActionMapping mapping, String name) {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
CALL = "handleDynamicMethodInvocation(mapping, mapping.getName());"
SET_LINE = "                mapping.setMethod(actionMethod);\n"
assert original.count(HDR) == 1 and original.count(CALL) == 1 and BLOCK.count(SET_LINE) == 1
assert original.count("handleDynamicMethodInvocation(") == 2 and "cleanupActionName" not in original


def build(new_block, new_call=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + original[e:]
    if new_call:
        assert out.count(CALL) == 1
        out = out.replace(CALL, new_call)
    return out


def rename_outside_comments_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        st = line.lstrip()
        if st.startswith("//") or st.startswith("*") or st.startswith("/*"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for old, new in pairs:
                parts[i] = re.sub(r"\b%s\b" % old, new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("handleDynamicMethodInvocation(", "applyDynamicMethod(")
b = rename_outside_comments_strings(b, (("mapping", "target"), ("name", "rawName"), ("exclamation", "bangPos"),
                                        ("actionName", "nameOnly"), ("actionMethod", "methodPart"),
                                        ("scPos", "semiPos")))
assert "target.setMethod(methodPart);" in b and "applyDynamicMethod(ActionMapping target, String rawName)" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b, "applyDynamicMethod(mapping, mapping.getName());"))

# --- Variant 2: structurally changed vulnerable variant ---
b = '''    private void handleDynamicMethodInvocation(ActionMapping mapping, String name) {
        int exclamation = name.lastIndexOf("!");
        if (exclamation == -1) {
            return;
        }

        String actionName = name.substring(0, exclamation);
        String actionMethod = name.substring(exclamation + 1);

        // WW-4585
        // add any ; appendix to name, it will be handled later in getMapping method
        int scPos = actionMethod.indexOf(';');
        if (scPos != -1) {
            actionName = actionName + actionMethod.substring(scPos);
            actionMethod = actionMethod.substring(0, scPos);
        }

        mapping.setName(actionName);
        mapping.setMethod(allowDynamicMethodCalls ? actionMethod : null);
    }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# REJECT (null method) anything that is not a plain Java identifier, instead
# of upstream's clean-up via cleanupActionName.
b = BLOCK.replace(
    SET_LINE,
    '                mapping.setMethod(actionMethod.matches("[A-Za-z_][A-Za-z0-9_]*") ? actionMethod : null);\n')
safe_source = build(b)
assert "mapping.setMethod(actionMethod);" not in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''public class VerbMethodMapper {

    public interface Mapping {
        void setMethod(String method);
    }

    /**
     * Same "hand a method name to mapping.setMethod(...)" shape, but the name
     * comes from a fixed developer-written table keyed by the HTTP verb, so
     * request text never becomes the method name.
     */
    static String methodFor(String httpVerb) {
        switch (httpVerb) {
            case "GET":
                return "index";
            case "POST":
                return "create";
            case "PUT":
                return "update";
            case "DELETE":
                return "destroy";
            default:
                return null;
        }
    }

    public void apply(Mapping mapping, String httpVerb) {
        String actionMethod = methodFor(httpVerb);
        mapping.setMethod(actionMethod);
    }
}
'''
assert "switch (httpVerb)" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0115.")

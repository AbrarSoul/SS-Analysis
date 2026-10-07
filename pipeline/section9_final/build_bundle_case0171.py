"""
Section 9 ground-truth test bundle: CASE-0171
(graphhopper/graphhopper, navigation/.../NavigateResource.java
getPointsFromRequest, CVE-2021-29506, CWE-400 uncontrolled resource
consumption / regular-expression denial of service).

Core vulnerable mechanism: `getPointsFromRequest` strips the route prefix with
`url.replaceFirst("/navigate/directions/v5/gh/" + profile + "/", "")`.
`replaceFirst` treats its first argument as a REGEX, and `profile` is the
caller-supplied `@PathParam("profile")`, so a profile such as `(.+)+$` is
injected into the pattern. On older JDKs a catastrophic pattern makes the
regex engine backtrack exponentially (the classic ReDoS, hence CWE-400).
Measured on JDK 26 (whose regex engine memoises repeated loop states, so the
classic `(.+)+$`, `.*(a|aa)+$` forms tested here did NOT blow up), the
injection is still observable: a profile of `(` or `[` makes replaceFirst
throw PatternSyntaxException, so a crafted path segment turns into an
unhandled server error, and regex metacharacters change what is stripped. The
upstream fix replaces the regex with `startsWith` + `substring` (and rejects a
URI that does not start with the expected prefix).

Sibling sites: none in this file (`getBearing` and the other parsers split on
fixed string literals).

Every variant is the FULL real file. getPointsFromRequest is a private method
called once from the JAX-RS handler, so the renamed variant renames the
method, its parameters and locals and the call.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0171"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    private List<GHPoint> getPointsFromRequest(HttpServletRequest httpServletRequest, String profile) {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
REPL = '''        url = url.replaceFirst("/navigate/directions/v5/gh/" + profile + "/", "");
'''
CALL = "        List<GHPoint> requestPoints = getPointsFromRequest(httpReq, mapboxProfile);\n"
assert original.count(HDR) == 1 and BLOCK.count(REPL) == 1 and original.count(CALL) == 1


def build(new_block, extra_after=None, text=None):
    text = text or original
    assert new_block != BLOCK
    return text[:s] + new_block + (extra_after or "") + text[e:]


def rename(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith(("*", "//", "/*")):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename(BLOCK, (("getPointsFromRequest", "extractWaypoints"), ("httpServletRequest", "servletRequest"),
                   ("profile", "profileName"), ("url", "path"), ("pointStrings", "coordinates"), ("points", "waypoints")))
assert 'path = path.replaceFirst("/navigate/directions/v5/gh/" + profileName + "/", "");' in b
assert "List<GHPoint> waypoints = new ArrayList<>(coordinates.length);" in b and "return waypoints;" in b
v1 = build(b)
v1 = v1.replace(CALL, "        List<GHPoint> requestPoints = extractWaypoints(httpReq, mapboxProfile);\n")
assert "getPointsFromRequest" not in v1.replace("getPointsFromRequest(", "getPointsFromRequest(") or v1.count("getPointsFromRequest") <= 1
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(REPL, '        url = stripPrefix(url, profile);\n')
helper = '''
    private static String stripPrefix(String url, String profile) {
        return url.replaceFirst("/navigate/directions/v5/gh/" + profile + "/", "");
    }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# The route prefix is quoted with Pattern.quote so profile is matched
# literally; upstream replaces the regex with startsWith + substring.
b = BLOCK.replace(REPL, '''        url = url.replaceFirst(java.util.regex.Pattern.quote("/navigate/directions/v5/gh/" + profile + "/"), "");
''')
(CASE_DIR / "variant_safe_01.java").write_text(build(b))

# --- Variant 4: benign structural look-alike ---
benign_source = '''public class RoutePrefix {

    /**
     * Same replaceFirst call as the route parser, but the pattern is a
     * developer-written constant with a bounded character class for the
     * profile, so no caller-supplied text becomes part of the regex.
     */
    public static String stripPrefix(String requestUri) {
        return requestUri.replaceFirst("^/navigate/directions/v5/gh/[A-Za-z0-9_]{1,32}/", "");
    }
}
'''
assert "developer-written constant" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0171.")

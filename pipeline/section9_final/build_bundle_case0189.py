"""
Section 9 ground-truth test bundle: CASE-0189
(jenkinsci/monitoring-plugin, .../monitoring/HudsonMonitoringFilter.java
doFilter, CVE-2014-3678, CWE-79 / NVD-CWE-noinfo).

Core vulnerable mechanism: `doFilter` requires the Jenkins ADMINISTER
permission only when the request URI EQUALS `/monitoring` or
`/monitoring/nodes`, but later serves every URI that STARTS with
`/monitoring/nodes` (`/monitoring/nodes/<slave>`) through `doMonitoring`.
The per-node report URLs therefore skip the admin check (authorization
bypass), and the request parameters that JavaMelody reflects into that
report are not filtered, which is the reflected XSS in the advisory. The
upstream fix uses `startsWith` for the check and, for admin requests, answers
400 when any parameter value contains `"`, `'`, `<` or `&`.

Sibling sites: the equality check and the later startsWith dispatch are the
two halves of one decision; the safe variant makes the protected set equal the
served set (every URL under the monitoring URL) and also filters parameters.

Verification: the class is compiled against the real servlet API jar and small
stand-ins for Jenkins and the JavaMelody classes it extends/uses; the caller's
admin permission is modelled by a flag.

Every variant is the FULL real file. doFilter is the servlet Filter override,
so the renamed variant keeps its signature and renames the locals only.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0189"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

AUTH = '''		if (!PLUGIN_AUTHENTICATION_DISABLED
				&& (requestURI.equals(monitoringUrl) || requestURI.equals(monitoringSlavesUrl))) {
			// only the Hudson/Jenkins administrator can view the monitoring report
			Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
		}
'''
s = original.index("	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)\n")
e = original.index("\n	}\n", s) + len("\n	}\n")
BLOCK = original[s:e]
assert BLOCK.count(AUTH) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


# --- Variant 1: renamed vulnerable variant ---
parts = re.split(r'("(?:[^"\\]|\\.)*")', BLOCK)
for i in range(0, len(parts), 2):
    for old, new in (("httpRequest", "httpReq"), ("requestURI", "uri"), ("monitoringUrl", "baseUrl"),
                     ("monitoringSlavesUrl", "nodesUrl"), ("nodeName", "slaveName"), ("httpResponse", "httpResp")):
        parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, parts[i])
b = "".join(parts)
assert "uri.equals(baseUrl) || uri.equals(nodesUrl)" in b and "doMonitoring(httpReq, httpResp, slaveName);" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(AUTH, '''		if (!PLUGIN_AUTHENTICATION_DISABLED && isReportUrl(requestURI, monitoringUrl, monitoringSlavesUrl)) {
			// only the Hudson/Jenkins administrator can view the monitoring report
			Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
		}
''')
helper = '''
	private static boolean isReportUrl(String requestURI, String monitoringUrl, String monitoringSlavesUrl) {
		return requestURI.equals(monitoringUrl) || requestURI.equals(monitoringSlavesUrl);
	}
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
b = BLOCK.replace(AUTH, '''		if (!PLUGIN_AUTHENTICATION_DISABLED
				&& (requestURI.equals(monitoringUrl) || requestURI.startsWith(monitoringUrl + "/"))) {
			// only the Hudson/Jenkins administrator can view the monitoring report,
			// including every per-node report below /monitoring/nodes
			Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
			if (hasUnsafeParameter(httpRequest)) {
				((HttpServletResponse) response).sendError(HttpServletResponse.SC_BAD_REQUEST);
				return;
			}
		}
''')
helper = '''
	private static boolean hasUnsafeParameter(HttpServletRequest httpRequest) {
		final java.util.regex.Pattern unsafe = java.util.regex.Pattern.compile("[\\"'<&]");
		final java.util.Enumeration<?> names = httpRequest.getParameterNames();
		while (names.hasMoreElements()) {
			final String[] values = httpRequest.getParameterValues((String) names.nextElement());
			if (values != null) {
				for (String value : values) {
					if (value != null && unsafe.matcher(value).find()) {
						return true;
					}
				}
			}
		}
		return false;
	}
'''
(CASE_DIR / "variant_safe_01.java").write_text(build(b, extra_after=helper))

# --- Variant 4: benign structural look-alike ---
benign_source = '''public class AdminAreaGuard {

    /**
     * Same "URL equals the page OR is under the page" access decision as the
     * monitoring filter's fix: the protected set is defined with a prefix
     * test that includes every sub-path, so a URL that is served can never
     * be one that skipped the check.
     */
    public static boolean requiresAdmin(String requestUri, String adminUrl) {
        return requestUri.equals(adminUrl) || requestUri.startsWith(adminUrl + "/");
    }
}
'''
assert "every sub-path" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0189.")

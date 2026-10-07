"""
Section 9 ground-truth test bundle: CASE-0183
(jenkinsci/dynatrace-plugin, .../dashboard/TAGlobalConfiguration.java
doTestDynatraceConnection, CVE-2019-10463, CWE-276 as recorded; in substance a
missing permission check on a form-validation endpoint).

Core vulnerable mechanism: `doTestDynatraceConnection` is a Stapler web method
(`@RequirePOST` only protects against CSRF) that opens a connection to a
Dynatrace server whose host, port and credentials come straight from the
request (`@QueryParameter`). It never checks that the caller is an
administrator, so any user with Overall/Read (or any anonymous user on a
permissive instance) can make the Jenkins server connect to an arbitrary
host and port with attacker-chosen credentials (connection probing / SSRF,
credential validation). The upstream fix fetches `Jenkins.getInstance()`,
throws if it is null and calls `checkPermission(Jenkins.ADMINISTER)`.

Sibling sites: the other `doCheck*` methods only validate the SYNTAX of a
field (port number, delay, retry count) and cause no side effects; the
connection test is the only method that acts on the network.

Verification: the whole file is compiled and run against small stand-ins for
Jenkins core, Stapler, the Dynatrace SDK and Apache commons (names and
signatures as the file uses them); the real Jenkins security layer was not
run.

Every variant is the FULL real file. doTestDynatraceConnection is bound by
name by Stapler, and its parameters carry explicit @QueryParameter names, so
the renamed variant keeps the method name and the query-parameter names and
renames the Java parameters and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0183"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = '''	@RequirePOST
	public FormValidation doTestDynatraceConnection(
			@QueryParameter("protocol") final String protocol,
			@QueryParameter("host") final String host,
			@QueryParameter("port") final String port,
			@QueryParameter("username") final String username,
			@QueryParameter("validateCerts") final boolean validateCerts,
			@QueryParameter("password") final String password) {

		try {
'''
s = original.index(HDR)
e = original.index("\n\t}\n", s) + len("\n\t}\n")
BLOCK = original[s:e]
assert original.count(HDR) == 1
CONN = "\t\t\tfinal SystemProfiles connection = new SystemProfiles(new DynatraceClient(new BasicServerConfiguration(username, password, protocol.startsWith(\"https\"), host, Integer.parseInt(port), validateCerts, 10000)));\n"
assert BLOCK.count(CONN) == 1


def build(new_block, extra_after=None, text=None):
    text = text or original
    assert new_block != BLOCK
    return text[:s] + new_block + (extra_after or "") + text[e:]


# --- Variant 1: renamed vulnerable variant ---
parts = re.split(r'("(?:[^"\\]|\\.)*")', BLOCK)
for i in range(0, len(parts), 2):
    for old, new in (("protocol", "scheme"), ("host", "hostname"), ("port", "portText"), ("username", "user"),
                     ("validateCerts", "verifyCerts"), ("password", "pwd"), ("connection", "profiles")):
        parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, parts[i])
b = "".join(parts)
assert '@QueryParameter("protocol") final String scheme,' in b and '@QueryParameter("validateCerts") final boolean verifyCerts,' in b
assert "new BasicServerConfiguration(user, pwd, scheme.startsWith(\"https\"), hostname, Integer.parseInt(portText), verifyCerts, 10000)" in b
assert "profiles.getSystemProfiles();" in b and "if (scheme.equals(\"http\"))" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(CONN, "\t\t\tfinal SystemProfiles connection = openConnection(username, password, protocol, host, port, validateCerts);\n")
helper = '''
	private static SystemProfiles openConnection(String username, String password, String protocol, String host, String port, boolean validateCerts) {
		return new SystemProfiles(new DynatraceClient(new BasicServerConfiguration(username, password, protocol.startsWith("https"), host, Integer.parseInt(port), validateCerts, 10000)));
	}
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# Administrator permission is required before anything is read from the
# request, through the non-null Jenkins.get() accessor; upstream uses
# getInstance() with an explicit null check.
b = BLOCK
b = b.replace("final String password) {\n\n\t\ttry {\n", "final String password) {\n\t\tJenkins.get().checkPermission(Jenkins.ADMINISTER);\n\n\t\ttry {\n")
assert b != BLOCK
v3 = build(b)
v3 = v3.replace("import jenkins.model.GlobalConfiguration;\n", "import jenkins.model.GlobalConfiguration;\nimport jenkins.model.Jenkins;\n")
assert v3.count("import jenkins.model.Jenkins;") == 1
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import hudson.util.FormValidation;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

public class HostFormatValidator {

    /**
     * Same Stapler form-validation endpoint shape as the connection test, but
     * it only checks the SYNTAX of the host string and never opens a
     * connection or reads any credential, so it has no side effect that would
     * need an administrator permission check.
     */
    @RequirePOST
    public FormValidation doCheckHostFormat(@QueryParameter("host") final String host) {
        if (host == null || !host.matches("[A-Za-z0-9.-]{1,253}")) {
            return FormValidation.error("Invalid host name");
        }
        return FormValidation.ok();
    }
}
'''
assert "SYNTAX of the host string" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0183.")

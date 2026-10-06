"""
Section 9 ground-truth test bundle: CASE-0190
(jenkinsci/openid-plugin, .../openid/OpenIdSsoSecurityRealm.java
DescriptorImpl.doValidate, CVE-2019-1003098, CWE-352 / CWE-862).

Core vulnerable mechanism: `doValidate(@QueryParameter String endpoint)` is a
Stapler web method that runs an OpenID DISCOVERY request against the
caller-supplied `endpoint` (`new Discovery().discover(endpoint)`). It has no
`@RequirePOST` (so it can be triggered by a cross-site GET) and no permission
check (so any user can make the Jenkins server contact an arbitrary URL and
read the success/error message back: SSRF and CSRF). The upstream fix adds
`@RequirePOST` and, for non-administrators, returns `FormValidation.ok()`
without contacting the endpoint.

Sibling sites: none in this file (doValidate is the only form-validation
method that acts on the network).

Verification: the method is extracted into a harness with stand-ins for
Discovery, FormValidation and Jenkins; the presence of @RequirePOST is read by
reflection on the extracted method (the stand-in annotation has runtime
retention), and the caller's admin permission is modelled by a flag.

Every variant is the FULL real file. doValidate is bound by name by Stapler and
its `endpoint` parameter is bound by name, so the renamed variant keeps both
and renames the caught exception variable.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0190"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

METHOD = '''        public FormValidation doValidate(@QueryParameter String endpoint) {
            try {
                new Discovery().discover(endpoint);
                return FormValidation.ok("OK");
            } catch (DiscoveryException e) {
                return FormValidation.error(e, "Invalid provider URL: " + endpoint);
            }
        }
'''
assert original.count(METHOD) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, METHOD, '''        public FormValidation doValidate(@QueryParameter String endpoint) {
            try {
                new Discovery().discover(endpoint);
                return FormValidation.ok("OK");
            } catch (DiscoveryException failure) {
                return FormValidation.error(failure, "Invalid provider URL: " + endpoint);
            }
        }
''')
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, METHOD, '''        public FormValidation doValidate(@QueryParameter String endpoint) {
            return probeProvider(endpoint);
        }

        private static FormValidation probeProvider(String endpoint) {
            try {
                new Discovery().discover(endpoint);
                return FormValidation.ok("OK");
            } catch (DiscoveryException e) {
                return FormValidation.error(e, "Invalid provider URL: " + endpoint);
            }
        }
''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
# POST only, and the administrator permission is REQUIRED (an AccessDenied is
# raised for anyone else) before any network access; upstream silently returns
# ok() for a non-administrator.
v3 = swap(original, METHOD, '''        @RequirePOST
        public FormValidation doValidate(@QueryParameter String endpoint) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            try {
                new Discovery().discover(endpoint);
                return FormValidation.ok("OK");
            } catch (DiscoveryException e) {
                return FormValidation.error(e, "Invalid provider URL: " + endpoint);
            }
        }
''')
v3 = swap(v3, "import org.kohsuke.stapler.StaplerRequest;\n", "import org.kohsuke.stapler.StaplerRequest;\nimport org.kohsuke.stapler.interceptor.RequirePOST;\n")
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import hudson.util.FormValidation;
import java.net.URI;
import java.net.URISyntaxException;
import org.kohsuke.stapler.QueryParameter;

public class EndpointSyntaxCheck {

    /**
     * Same form-validation method shape as doValidate, but it only PARSES the
     * text as a URI and never opens a connection, so it makes no outbound
     * request and needs no POST or permission protection.
     */
    public FormValidation doCheckEndpoint(@QueryParameter String endpoint) {
        try {
            URI uri = new URI(endpoint);
            return uri.getScheme() == null ? FormValidation.error("Missing scheme") : FormValidation.ok();
        } catch (URISyntaxException e) {
            return FormValidation.error("Invalid URL");
        }
    }
}
'''
assert "never opens a connection" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0190.")

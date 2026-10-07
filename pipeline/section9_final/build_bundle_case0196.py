"""
Section 9 ground-truth test bundle: CASE-0196
(jenkinsci/warnings-ng-plugin, .../warnings/axivion/AxivionSuite.java
withValidCredentials, CVE-2023-46651, CWE-522 insufficiently protected
credentials).

Core vulnerable mechanism: when the Axivion tool runs, `withValidCredentials()`
looks the configured `credentialsId` up with
`CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class,
(Item) null, null, emptyList())`. A null Item context and a null authentication
mean the lookup runs in GLOBAL scope as the system, so ANY username/password
credential known to Jenkins can be selected by id, including credentials
scoped to folders or jobs the current job's owner cannot use. Someone who can
configure a job can point `credentialsId` at another team's credential and
`projectUrl` at a server they control, and the plugin sends the credential
there. The upstream fix passes the job (`run.getParent()`) as the context.

Sibling sites: the file's two form-fill/validation methods (around lines 362 and
401) already check `item.hasPermission(CredentialsProvider.USE_ITEM)` and look
credentials up with the item; only the build-time lookup used the null context.

Verification: the method is extracted into a harness with stand-ins for the
credentials-plugin API (a credential store where each credential has a scope,
`lookupCredentials(cls, item, auth, reqs)` returning global-scope credentials for a
null item and only the item's visible ones otherwise, and `findCredentialById(id,
cls, run, reqs)` doing the same for a run); the Jenkins runtime itself was not run.

Every variant is the FULL real file. withValidCredentials is a private
method with one call in `scan`, so the renamed variant renames its locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0196"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

METHOD = '''    private UsernamePasswordCredentials withValidCredentials() {
        final List<StandardUsernamePasswordCredentials> all =
                CredentialsProvider.lookupCredentials(
                        StandardUsernamePasswordCredentials.class,
                        (Item) null,
                        null,
                        Collections.emptyList());

        final StandardUsernamePasswordCredentials jenkinsCredentials =
                CredentialsMatchers.firstOrNull(all,
                        CredentialsMatchers.withId(credentialsId));

        if (jenkinsCredentials == null) {
            throw new ParsingException("Could not find the credentials for " + credentialsId);
        }

        return new UsernamePasswordCredentials(
                jenkinsCredentials.getUsername(),
                Secret.toString(jenkinsCredentials.getPassword()));
    }
'''
CALL = "        final AxivionDashboard dashboard = new RemoteAxivionDashboard(projectUrl, withValidCredentials(), namedFilter);\n"
assert original.count(METHOD) == 1 and original.count(CALL) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
m = METHOD.replace("all", "candidates").replace("jenkinsCredentials", "selected")
m = m.replace("List<StandardUsernamePasswordCredentials> candidates =", "List<StandardUsernamePasswordCredentials> candidates =")
assert "candidates" in m and "selected.getUsername()" in m and "Collections.emptyList()" in m
v1 = swap(original, METHOD, m)
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, METHOD, '''    private UsernamePasswordCredentials withValidCredentials() {
        final StandardUsernamePasswordCredentials jenkinsCredentials =
                CredentialsMatchers.firstOrNull(allCredentials(),
                        CredentialsMatchers.withId(credentialsId));

        if (jenkinsCredentials == null) {
            throw new ParsingException("Could not find the credentials for " + credentialsId);
        }

        return new UsernamePasswordCredentials(
                jenkinsCredentials.getUsername(),
                Secret.toString(jenkinsCredentials.getPassword()));
    }

    private static List<StandardUsernamePasswordCredentials> allCredentials() {
        return CredentialsProvider.lookupCredentials(
                StandardUsernamePasswordCredentials.class,
                (Item) null,
                null,
                Collections.emptyList());
    }
''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The run is passed in and the credential is resolved with
# findCredentialById(id, type, run, ...), the API that scopes the lookup to the
# job and to the build's authentication; upstream keeps lookupCredentials but
# passes run.getParent() as the context.
v3 = swap(original, CALL, "        final AxivionDashboard dashboard = new RemoteAxivionDashboard(projectUrl, withValidCredentials(run), namedFilter);\n")
v3 = swap(v3, METHOD, '''    private UsernamePasswordCredentials withValidCredentials(final Run<?, ?> run) {
        final StandardUsernamePasswordCredentials jenkinsCredentials =
                CredentialsProvider.findCredentialById(
                        credentialsId,
                        StandardUsernamePasswordCredentials.class,
                        run,
                        Collections.emptyList());

        if (jenkinsCredentials == null) {
            throw new ParsingException("Could not find the credentials for " + credentialsId);
        }

        return new UsernamePasswordCredentials(
                jenkinsCredentials.getUsername(),
                Secret.toString(jenkinsCredentials.getPassword()));
    }
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import hudson.model.Item;
import java.util.Collections;
import java.util.List;

public class ScopedLookup {

    /**
     * Same lookupCredentials(...) + withId(...) shape as the tool's credential
     * resolution, but the lookup is made in the scope of the JOB passed in, so
     * only credentials that job may use can be found.
     */
    public StandardUsernamePasswordCredentials find(Item job, String credentialsId) {
        List<StandardUsernamePasswordCredentials> visible = CredentialsProvider.lookupCredentials(
                StandardUsernamePasswordCredentials.class, job, null, Collections.emptyList());
        return CredentialsMatchers.firstOrNull(visible, CredentialsMatchers.withId(credentialsId));
    }
}
'''
assert "scope of the JOB" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0196.")

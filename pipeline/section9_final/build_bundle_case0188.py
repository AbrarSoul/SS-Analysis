"""
Section 9 ground-truth test bundle: CASE-0188
(jenkinsci/mercurial-plugin, .../traits/MercurialInstallationSCMSourceTrait.java
DescriptorImpl.doFillInstallationItems, CVE-2020-2306, NVD-CWE-noinfo; missing
permission check on a form-fill endpoint).

Located target: the `@Restricted(NoExternalUse.class) // stapler` annotated
`doFillInstallationItems` method.

Core vulnerable mechanism: `doFillInstallationItems()` is a Stapler web method
(`@Restricted(NoExternalUse.class)` is only a code-level annotation, it does
not restrict HTTP access) that returns the NAMES of all globally configured
Mercurial installations that use caches. It performs no permission check, so
any user who can reach the form-fill URL (Overall/Read is enough) can enumerate
the installations configured by the administrators. The upstream fix adds an
`@AncestorInPath Item context` parameter and returns an empty list unless the
caller has EXTENDED_READ on the item (or ADMINISTER when there is no item).

Sibling sites: the descriptor's isApplicableTo* methods also iterate the
installations but return only booleans; only the form-fill endpoint returns
the names.

Verification: the method is extracted into a small harness (the class needs
Jenkins core and the SCM API): stand-ins for Jenkins, Item, ListBoxModel and
the installation list are used and the caller's permissions are modelled with
flags.

Every variant is the FULL real file. doFillInstallationItems is bound by name
by Stapler, so the renamed variant keeps the name and renames its locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0188"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

METHOD = '''        @Restricted(NoExternalUse.class) // stapler
        public ListBoxModel doFillInstallationItems() {
            ListBoxModel result = new ListBoxModel();
            for (MercurialInstallation i: MercurialInstallation.allInstallations()) {
                if (i.isUseCaches()) {
                    result.add(i.getName());
                }
            }
            return result;
        }
'''
assert original.count(METHOD) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, METHOD, '''        @Restricted(NoExternalUse.class) // stapler
        public ListBoxModel doFillInstallationItems() {
            ListBoxModel items = new ListBoxModel();
            for (MercurialInstallation inst: MercurialInstallation.allInstallations()) {
                if (inst.isUseCaches()) {
                    items.add(inst.getName());
                }
            }
            return items;
        }
''')
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, METHOD, '''        @Restricted(NoExternalUse.class) // stapler
        public ListBoxModel doFillInstallationItems() {
            ListBoxModel result = new ListBoxModel();
            addCacheEnabledNames(result);
            return result;
        }

        private static void addCacheEnabledNames(ListBoxModel target) {
            for (MercurialInstallation i: MercurialInstallation.allInstallations()) {
                if (i.isUseCaches()) {
                    target.add(i.getName());
                }
            }
        }
''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The permission decision is a separate helper and the method takes the
# ancestor Item like upstream, returning an empty list when it fails.
v3 = swap(original, METHOD, '''        @Restricted(NoExternalUse.class) // stapler
        public ListBoxModel doFillInstallationItems(@AncestorInPath Item context) {
            ListBoxModel result = new ListBoxModel();
            if (!mayListInstallations(context)) {
                return result;
            }
            for (MercurialInstallation i: MercurialInstallation.allInstallations()) {
                if (i.isUseCaches()) {
                    result.add(i.getName());
                }
            }
            return result;
        }

        private static boolean mayListInstallations(Item context) {
            return context == null
                    ? Jenkins.get().hasPermission(Jenkins.ADMINISTER)
                    : context.hasPermission(Item.EXTENDED_READ);
        }
''')
v3 = swap(v3, "import hudson.Util;\n", "import hudson.Util;\nimport hudson.model.Item;\n")
v3 = swap(v3, "import jenkins.scm.api.SCMSource;\n", "import jenkins.model.Jenkins;\nimport jenkins.scm.api.SCMSource;\n")
v3 = swap(v3, "import org.kohsuke.stapler.DataBoundConstructor;\n", "import org.kohsuke.stapler.AncestorInPath;\nimport org.kohsuke.stapler.DataBoundConstructor;\n")
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import hudson.util.ListBoxModel;

public class ProtocolChoices {

    /**
     * Same ListBoxModel-returning form-fill shape as the installation list,
     * but the items are two fixed protocol names built into the plugin (not
     * administrator-configured data), so listing them to any caller discloses
     * nothing.
     */
    public ListBoxModel doFillProtocolItems() {
        ListBoxModel model = new ListBoxModel();
        model.add("http");
        model.add("https");
        return model;
    }
}
'''
assert "fixed protocol names" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0188.")

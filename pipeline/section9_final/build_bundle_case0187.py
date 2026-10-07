"""
Section 9 ground-truth test bundle: CASE-0187
(jenkinsci/mercurial-plugin, .../mercurial/MercurialStatus.java getSearchUrl,
CVE-2018-1000112, CWE-863 incorrect authorization).

Located target: `public String getSearchUrl() {`.

Core vulnerable mechanism: MercurialStatus is an UnprotectedRootAction (reachable
without authentication) that ALSO extends `AbstractModelObject` and defines
`getSearchUrl()`, which makes it a SearchableModelObject. Jenkins' search
index therefore treats the unauthenticated action as an item and offers
it in search results; through the search machinery the request reaches
the model object without the permission checks that guard real items. The
upstream fix removes `extends AbstractModelObject` and the `getSearchUrl()`
override, leaving the class an UnprotectedRootAction only.

Verification: syntax-only (pipeline/check_java_syntax.sh). The Jenkins search
index and its authorization filtering cannot be run without Jenkins core, so
the vulnerable/safe distinction is a structural property of the class
declaration (does it participate in search or not), not an observed request
outcome. This is the weakest verification level used in Section 9.

Sibling sites: none; getSearchUrl exists only for the AbstractModelObject
contract and is the single search hook.

Every variant is the FULL real file. getSearchUrl is a one-line override of the
AbstractModelObject contract, so the renamed variant renames a private helper
and its parameter (isUnexpandedEnvVar) instead.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0187"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def swap(text, old, new, count=1):
    assert text.count(old) == count and new != old
    return text.replace(old, new)


SEARCH = '''    public String getSearchUrl() {
        return getUrlName();
    }

'''
DECL = "public class MercurialStatus extends AbstractModelObject implements UnprotectedRootAction {\n"
IMPORT = "import hudson.model.AbstractModelObject;\n"
assert original.count(SEARCH) == 1 and original.count(DECL) == 1 and original.count(IMPORT) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, "    static private boolean isUnexpandedEnvVar(String str) {\n        return str.startsWith(\"$\");\n",
          "    static private boolean isUnresolvedVariable(String text) {\n        return text.startsWith(\"$\");\n")
v1 = swap(v1, "if (!isUnexpandedEnvVar(repository)) {", "if (!isUnresolvedVariable(repository)) {")
assert "isUnexpandedEnvVar" not in v1 and "extends AbstractModelObject" in v1 and "getSearchUrl()" in v1
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, SEARCH, '''    public String getSearchUrl() {
        return URL_NAME;
    }

''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The class stops being a searchable model object (no AbstractModelObject, no
# getSearchUrl), exactly the property the upstream fix establishes, with the
# reason recorded next to the declaration.
v3 = swap(original, SEARCH, "")
v3 = swap(v3, IMPORT, "")
v3 = swap(v3, DECL, '''// Deliberately NOT an AbstractModelObject: an unauthenticated root action must not be a searchable model object.
public class MercurialStatus implements UnprotectedRootAction {
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''package hudson.plugins.mercurial;

import hudson.Extension;
import hudson.model.UnprotectedRootAction;

/**
 * Same UnprotectedRootAction declaration and URL name/display-name methods as
 * the status screen, but it does not extend AbstractModelObject and has no
 * getSearchUrl(), so it never appears in the Jenkins search index.
 */
@Extension
public class HealthProbeAction implements UnprotectedRootAction {

    public String getDisplayName() {
        return "Mercurial health";
    }

    public String getIconFileName() {
        return null;
    }

    public String getUrlName() {
        return "mercurial-health";
    }
}
'''
assert "never appears in the Jenkins search index" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0187.")

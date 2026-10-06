"""
Section 9 ground-truth test bundle: CASE-0194
(jenkinsci/sidebar-link-plugin, .../sidebar_link/SidebarLinkPlugin.java
doCheckLinkIcon, CVE-2023-32985, CWE-22 path traversal). This case is the
replacement added by top-up 10 after CASE-0141 was excluded.

Core vulnerable mechanism: `doCheckLinkIcon(@QueryParameter String value)`
resolves the caller's icon path with
`Jenkins.get().getRootPath().child(value)` and answers
`Image does not exist:  <full path>` or ok depending on `exists()`. `value`
is not confined to `userContent/`, so `../../etc/passwd`, `config.xml` or
`secrets/master.key` turn the endpoint into a file-existence oracle for the
whole controller file system, and the error message also discloses the
absolute path of the Jenkins home. The upstream fix (a large rewrite of the
method) accepts plain icon names, canonicalises the path and requires it to
start with `<JENKINS_HOME>/userContent`.

Measured caveat, kept in the manifest notes: upstream builds
`userContentDirectory = <home canonical path> + File.separatorChar + "userContent"`
and checks `canonicalPath.startsWith(userContentDirectory)` WITHOUT a trailing
separator, so a sibling such as `userContent2/x.png` or `userContentBackup/...`
passes the check. The safe variant compares path COMPONENTS
(`Path.startsWith`), which does not have that hole, and does not echo the
absolute path.

Sibling sites: `doUploadLinkImage` sanitises the uploaded file name (strips
any directory part and disallowed characters) and only writes under
`userContent/`; it is left unchanged. The unrelated cleanup hunks of the
upstream patch (removing the logger, `<tt>` -> `<code>`) are not part of the
vulnerability and are not reproduced in the safe variant.

Verification: doCheckLinkIcon (and, for the patched file, isAcceptedIconName) is
extracted into a harness with stand-ins for Jenkins, FilePath, FormValidation and
StringUtils, run on a real temporary JENKINS_HOME.

Every variant is the FULL real file. doCheckLinkIcon is bound by name by
Stapler and `value` by name, so the renamed variant keeps both and renames the
locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0194"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

s = original.index("    @Restricted(NoExternalUse.class)\n    public FormValidation doCheckLinkIcon(")
e = original.index("\n    }\n", s) + len("\n    }\n")
METHOD = original[s:e]
assert original.count("doCheckLinkIcon(") == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


def build(new_method, extra_after=None):
    return original[:s] + new_method + (extra_after or "") + original[e:]


# --- Variant 1: renamed vulnerable variant ---
m = swap(METHOD, "            FilePath imageFile = Jenkins.get().getRootPath().child(value);\n", "            FilePath iconFile = Jenkins.get().getRootPath().child(value);\n")
m = swap(m, "                if (!imageFile.exists()) {\n                    return FormValidation.error(\"Image does not exist:  \" + imageFile);\n",
         "                if (!iconFile.exists()) {\n                    return FormValidation.error(\"Image does not exist:  \" + iconFile);\n")
m = swap(m, "            } catch (Exception e) {\n                return FormValidation.error(e, ", "            } catch (Exception problem) {\n                return FormValidation.error(problem, ")
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(m))

# --- Variant 2: structurally changed vulnerable variant ---
m = '''    @Restricted(NoExternalUse.class)
    public FormValidation doCheckLinkIcon(@QueryParameter String value) {
        if (StringUtils.isBlank(value)) {
            return FormValidation.warning("The provided icon is blank or empty. Default will be used.");
        }
        if (value.equals(LinkAction.DEFAULT_ICON_NAME)) {
            return FormValidation.ok();
        }
        return checkIconExists(value);
    }
'''
helper = '''
    private static FormValidation checkIconExists(String value) {
        FilePath imageFile = Jenkins.get().getRootPath().child(value);
        try {
            if (!imageFile.exists()) {
                return FormValidation.error("Image does not exist:  " + imageFile);
            }
        } catch (Exception e) {
            return FormValidation.error(e, "Problem with link icon:  " + value);
        }
        return FormValidation.ok();
    }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(m, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# The resolved icon must lie INSIDE $JENKINS_HOME/userContent, decided by
# comparing path components (Path.startsWith), so `userContent2/...` and
# `userContentBackup/...` are outside; the error text does not include any
# absolute path. Upstream also accepts bare built-in icon names.
m = '''    @Restricted(NoExternalUse.class)
    public FormValidation doCheckLinkIcon(@QueryParameter String value) {
        if (StringUtils.isBlank(value)) {
            return FormValidation.warning("The provided icon is blank or empty. Default will be used.");
        }
        if (value.equals(LinkAction.DEFAULT_ICON_NAME)) {
            return FormValidation.ok();
        }
        try {
            File userContent = new File(Jenkins.get().getRootDir(), "userContent").getCanonicalFile();
            File imageFile = new File(Jenkins.get().getRootDir(), value).getCanonicalFile();
            if (!imageFile.toPath().startsWith(userContent.toPath())) {
                return FormValidation.error("Use a path inside userContent, e.g. userContent/myIcon.png");
            }
            if (!imageFile.exists()) {
                return FormValidation.error("Image does not exist");
            }
        } catch (IOException e) {
            return FormValidation.error("Problem with link icon");
        }
        return FormValidation.ok();
    }
'''
v3 = build(m)
v3 = swap(v3, "import java.io.IOException;\n", "import java.io.File;\nimport java.io.IOException;\n")
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.File;
import java.io.IOException;

public class ContainedFile {

    private final File base;

    public ContainedFile(File base) {
        this.base = base;
    }

    /**
     * Same "resolve a user-supplied relative path under a base directory and
     * test exists()" shape as the icon check, but the canonical result must be
     * INSIDE the base (compared by path components) or the answer is simply
     * false, so a traversal cannot probe files outside it.
     */
    public boolean existsInside(String relative) throws IOException {
        File target = new File(base, relative).getCanonicalFile();
        return target.toPath().startsWith(base.getCanonicalFile().toPath()) && target.exists();
    }
}
'''
assert "compared by path components" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0194.")

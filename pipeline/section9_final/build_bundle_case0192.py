"""
Section 9 ground-truth test bundle: CASE-0192
(jenkinsci/rhnpush-plugin, jenkins/plugins/rhnpush/RhnPush.java
DescriptorImpl.doCheckIncludes, CVE-2022-36892, CWE-862 missing authorization).

Core vulnerable mechanism: `doCheckIncludes(@AncestorInPath AbstractProject
project, @QueryParameter String value)` is a Stapler form-validation method that
runs `project.getWorkspace().validateAntFileMask(value)`. That call inspects the
job's WORKSPACE and its error message tells the caller which files match
(or what similar paths exist). The method never checks that the caller may
read the workspace (`Item.WORKSPACE`), so any user with access to the form URL
can probe the file names in the workspace of a job they cannot otherwise
see into. The upstream fix adds `project.checkPermission(Item.WORKSPACE)`.

Measured caveat, kept in the manifest notes: upstream places the check AFTER
`project.getWorkspace()`; the safe variant checks before touching the
workspace at all.

Sibling sites: `doCheckChannels` only validates that a value is present (no
workspace access), so it needs no check.

Verification: the method is extracted into a harness with stand-ins for
AbstractProject, FilePath, Item and FormValidation; the caller's permission is
a flag and validateAntFileMask returns a message that names a matching file
(as the real one does when a mask matches nothing but a similar path exists).

Every variant is the FULL real file. doCheckIncludes is bound by name by
Stapler and its parameters are bound by name, so the renamed variant keeps
them and renames the locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0192"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

METHOD = '''    public FormValidation doCheckIncludes(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException, InterruptedException {
      FilePath workspace = project.getWorkspace();
      if (workspace == null) {
        throw new IllegalStateException("Could not get a workspace.");
      }
      String msg = workspace.validateAntFileMask(value);
      if (msg != null) {
        return FormValidation.error(msg);
      }
      return FormValidation.ok();
    }
'''
assert original.count(METHOD) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, METHOD, '''    public FormValidation doCheckIncludes(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException, InterruptedException {
      FilePath ws = project.getWorkspace();
      if (ws == null) {
        throw new IllegalStateException("Could not get a workspace.");
      }
      String problem = ws.validateAntFileMask(value);
      if (problem != null) {
        return FormValidation.error(problem);
      }
      return FormValidation.ok();
    }
''')
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, METHOD, '''    public FormValidation doCheckIncludes(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException, InterruptedException {
      String msg = maskProblem(project.getWorkspace(), value);
      return msg == null ? FormValidation.ok() : FormValidation.error(msg);
    }

    private static String maskProblem(FilePath workspace, String value) throws IOException, InterruptedException {
      if (workspace == null) {
        throw new IllegalStateException("Could not get a workspace.");
      }
      return workspace.validateAntFileMask(value);
    }
''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The workspace permission is required BEFORE the workspace is even fetched
# (upstream checks after project.getWorkspace()).
v3 = swap(original, METHOD, METHOD.replace("      FilePath workspace = project.getWorkspace();\n", "      project.checkPermission(Item.WORKSPACE);\n      FilePath workspace = project.getWorkspace();\n"))
v3 = swap(v3, "import hudson.model.BuildListener;\n", "import hudson.model.BuildListener;\nimport hudson.model.Item;\n")
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import hudson.util.FormValidation;
import org.kohsuke.stapler.QueryParameter;

public class MaskSyntaxCheck {

    /**
     * Same form-validation shape as doCheckIncludes, but it only checks that
     * the pattern text is non-blank and has no absolute path, without touching
     * any workspace or file, so there is no data for a caller to probe.
     */
    public FormValidation doCheckIncludesSyntax(@QueryParameter String value) {
        if (value == null || value.trim().isEmpty()) {
            return FormValidation.error("Pattern required");
        }
        if (value.startsWith("/")) {
            return FormValidation.error("Use a relative pattern");
        }
        return FormValidation.ok();
    }
}
'''
assert "without touching" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0192.")

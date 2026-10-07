"""
Section 9 ground-truth test bundle: CASE-0186
(jenkinsci/jenkins, core/src/main/java/hudson/cli/CreateJobCommand.java run,
CVE-2014-2059, CWE-22 path traversal).

Core vulnerable mechanism: the `create-job` CLI command takes the job NAME
from the command line and, after splitting off a folder prefix at the last
`/`, passes the rest straight to `ig.createProjectFromXML(name, stdin)`.
Jenkins creates the job's directory from that name, so a name whose
last segment is `..` (or that otherwise contains path elements once the
prefix was stripped) makes the job directory land outside the jobs directory.
The upstream fix calls `Jenkins.checkGoodName(name)` before creating the job.

Modelling note (kept in the manifest notes): the job-creation step
(`createProjectFromXML`) is a stand-in that makes `new File(jobsDir, name)`
the way Jenkins core maps a job name to a directory; `Jenkins.checkGoodName`
is a stand-in that rejects the same class of names (empty, `.`, `..`, path
separators and control characters) as the real one.

Sibling sites: none in this file (the folder-prefix branch is part of the same
`run`; the name is validated once after it).

Every variant is the FULL real file. `run` is the CLI command entry point
(an override), so the renamed variant renames its locals only.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0186"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

s = original.index("    protected int run() throws Exception {\n")
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
CREATE = "        ig.createProjectFromXML(name, stdin);\n"
assert BLOCK.count(CREATE) == 1


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


# --- Variant 1: renamed vulnerable variant ---
parts = re.split(r'("(?:[^"\\]|\\.)*")', BLOCK)
for i in range(0, len(parts), 2):
    for old, new in (("h", "jenkins"), ("ig", "target"), ("i", "slash"), ("group", "parentPath"), ("item", "found")):
        parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, parts[i])
b = "".join(parts)
assert "Jenkins jenkins = Jenkins.getInstance();" in b and "ModifiableTopLevelItemGroup target = jenkins;" in b
assert "target.createProjectFromXML(name, stdin);" in b and "int slash = name.lastIndexOf('/');" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace('''        ModifiableTopLevelItemGroup ig = h;
        int i = name.lastIndexOf('/');
        if (i > 0) {
            String group = name.substring(0, i);
            Item item = h.getItemByFullName(group);
            if (item == null) {
                throw new IllegalArgumentException("Unknown ItemGroup " + group);
            }

            if (item instanceof ModifiableTopLevelItemGroup) {
                ig = (ModifiableTopLevelItemGroup) item;
            } else {
                throw new IllegalArgumentException("Can't create job from CLI in " + group);
            }
            name = name.substring(i + 1);
        }
''', '''        ModifiableTopLevelItemGroup ig = resolveGroup(h);
''')
helper = '''
    private ModifiableTopLevelItemGroup resolveGroup(Jenkins h) {
        ModifiableTopLevelItemGroup ig = h;
        int i = name.lastIndexOf('/');
        if (i > 0) {
            String group = name.substring(0, i);
            Item item = h.getItemByFullName(group);
            if (item == null) {
                throw new IllegalArgumentException("Unknown ItemGroup " + group);
            }

            if (item instanceof ModifiableTopLevelItemGroup) {
                ig = (ModifiableTopLevelItemGroup) item;
            } else {
                throw new IllegalArgumentException("Can't create job from CLI in " + group);
            }
            name = name.substring(i + 1);
        }
        return ig;
    }
'''
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# A local allow-list style check on the final name segment (non-empty, not
# `.`/`..`, no path separators, drive colon or control characters); upstream
# calls Jenkins.checkGoodName.
b = BLOCK.replace(CREATE, "        requireSimpleJobName(name);\n" + CREATE)
helper = '''
    private static void requireSimpleJobName(String jobName) {
        if (jobName == null || jobName.isEmpty() || jobName.equals(".") || jobName.equals("..")
                || jobName.matches(".*[/\\\\\\\\:\\\\p{Cntrl}].*")) {
            throw new IllegalArgumentException("Invalid job name: " + jobName);
        }
    }
'''
(CASE_DIR / "variant_safe_01.java").write_text(build(b, extra_after=helper))

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.File;

public class FixedJobDirs {

    private final File jobsDir;

    public FixedJobDirs(File jobsDir) {
        this.jobsDir = jobsDir;
    }

    /**
     * Same "new File(jobsDir, name).mkdirs()" mapping as job creation, but the
     * name is chosen from a fixed list of built-in template names, never from
     * the command line, so it cannot contain path elements.
     */
    public File createTemplateDir(int templateIndex) {
        String[] templates = {"freestyle", "pipeline", "folder"};
        File dir = new File(jobsDir, templates[templateIndex]);
        dir.mkdirs();
        return dir;
    }
}
'''
assert "fixed list of built-in template names" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0186.")

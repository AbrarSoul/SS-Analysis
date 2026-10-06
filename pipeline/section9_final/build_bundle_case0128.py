"""
Section 9 ground-truth test bundle: CASE-0128
(bcgit/bc-java, XMSSUtil.CheckingStream.resolveClass, CVE-2018-1000613,
CWE-470 unsafe reflection / deserialization of untrusted data).

Core vulnerable mechanism: `CheckingStream.resolveClass()` only checks that
the FIRST class in the serialized stream is the expected main class
(`if (!found) { must equal mainClass; found = true; }`). Once `found` is
true, EVERY other class descriptor is resolved unchecked through
`super.resolveClass`, so a crafted stream that starts with the expected
class but embeds any Serializable class on the classpath (a
"gadget") has that class deserialized and its readObject logic run,
enabling gadget-chain attacks. The upstream fix adds a static allow-list of
the component classes an XMSS object legitimately contains and rejects any
other class with InvalidClassException.

Every variant is the FULL real file with resolveClass replaced. resolveClass
overrides ObjectInputStream.resolveClass, so it is NOT renamed; the renamed
variant renames its parameter and the nested class's fields instead.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0128"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "        protected Class<?> resolveClass(ObjectStreamClass desc)\n"
s = original.index(HDR)
e = original.index("\n        }\n", s) + len("\n        }\n")
BLOCK = original[s:e]
CLS_HDR = "    private static class CheckingStream\n"
c0 = original.index(CLS_HDR)
CLS = original[c0:]
assert original.count(HDR) == 1 and original.count(CLS_HDR) == 1 and BLOCK.count("super.resolveClass(desc)") == 1
FOUND_ELSE = '''                else
                {
                    found = true;
                }
            }
'''
assert BLOCK.count(FOUND_ELSE) == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
cls1 = CLS.replace("this.mainClass", "this.expectedRoot")   # `.name` is skipped by the identifier regex below
for old, new in (("mainClass", "expectedRoot"), ("found", "rootSeen"), ("desc", "streamClass")):
    cls1 = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, cls1)
assert "rootSeen" in cls1 and "streamClass.getName()" in cls1 and "this.expectedRoot = expectedRoot;" in cls1
assert "protected Class<?> resolveClass(ObjectStreamClass streamClass)" in cls1
(CASE_DIR / "variant_vulnerable_01.java").write_text(original[:c0] + cls1)

# --- Variant 2: structurally changed vulnerable variant ---
b = '''        protected Class<?> resolveClass(ObjectStreamClass desc)
            throws IOException,
            ClassNotFoundException
        {
            if (!found && !desc.getName().equals(mainClass.getName()))
            {
                throw new InvalidClassException(
                    "unexpected class: ", desc.getName());
            }
            found = true;
            return super.resolveClass(desc);
        }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# After the main class, every further class must be one of the component
# types of an XMSS object; a string switch (upstream: a static HashSet).
ALLOWED = ["java.util.TreeMap", "java.lang.Integer", "java.lang.Number", "org.bouncycastle.pqc.crypto.xmss.BDS",
           "java.util.ArrayList", "org.bouncycastle.pqc.crypto.xmss.XMSSNode", "[B", "java.util.LinkedList",
           "java.util.Stack", "java.util.Vector", "[Ljava.lang.Object;", "org.bouncycastle.pqc.crypto.xmss.BDSTreeHash"]
cases = "".join(f'                    case "{n}":\n' for n in ALLOWED)
b = BLOCK.replace(FOUND_ELSE, '''                else
                {
                    found = true;
                }
            }
            else
            {
                switch (desc.getName())
                {
''' + cases + '''                    break;
                default:
                    throw new InvalidClassException(
                        "unexpected class: ", desc.getName());
                }
            }
''')
assert b != BLOCK
safe_source = build(b)
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class AllowListObjectInputStream
    extends ObjectInputStream
{
    private static final Set<String> ALLOWED = new HashSet<>(Arrays.asList(
        "java.util.ArrayList", "java.lang.Integer", "java.lang.Number", "[B"));

    public AllowListObjectInputStream(InputStream in)
        throws IOException
    {
        super(in);
    }

    /**
     * Same ObjectInputStream.resolveClass override as a "checking stream", but
     * EVERY class descriptor -- including the first -- must be on a fixed
     * allow-list before super.resolveClass is called, so no arbitrary class is
     * ever resolved or its deserialization logic run.
     */
    protected Class<?> resolveClass(ObjectStreamClass desc)
        throws IOException,
        ClassNotFoundException
    {
        if (!ALLOWED.contains(desc.getName()))
        {
            throw new InvalidClassException("unexpected class: ", desc.getName());
        }
        return super.resolveClass(desc);
    }
}
'''
assert "ALLOWED.contains(desc.getName())" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0128.")

"""
Section 9 ground-truth test bundle: CASE-0111
(apache/santuario-java, DOMCanonicalizationMethod, CVE-2013-2172, CWE-310
improper restriction of the CanonicalizationMethod algorithm).

Core vulnerable mechanism: `DOMCanonicalizationMethod(TransformService spi)`
(and the Element-based constructor used when UNMARSHALLING a signature)
accepts ANY TransformService as a "canonicalization method" without
checking that the algorithm is actually a canonicalization algorithm. An
attacker-supplied <CanonicalizationMethod Algorithm="...xslt...">
therefore lets a signature-validation flow run an arbitrary Transform
(e.g. XSLT) on SignedInfo, which permits signature bypass. The upstream fix
adds, to BOTH constructors,
`if (!(spi instanceof ApacheCanonicalizer) && !isC14Nalg(spi.getAlgorithm())) throw ...`
plus the isC14Nalg() helper.

Every variant is the FULL real file. The located target is the
TransformService constructor; because the fix ALSO guards the sibling
Element constructor, the safe variant fixes both (otherwise a "safe" file
would keep the real, unfixed weakness). The renamed variant renames the
class itself (constructors are named after it) and the parameter.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0111"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

CTOR1 = '''    public DOMCanonicalizationMethod(TransformService spi)
\tthrows InvalidAlgorithmParameterException {
\tsuper(spi);
    }
'''
CTOR2 = '''    public DOMCanonicalizationMethod(Element cmElem, XMLCryptoContext context,
\tProvider provider) throws MarshalException {
\tsuper(cmElem, context, provider);
    }
'''
assert original.count(CTOR1) == 1 and original.count(CTOR2) == 1
assert "ApacheCanonicalizer" not in original and original.rstrip().endswith("}")


def swap(src, old, new):
    assert src.count(old) == 1 and new != old
    return src.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
out = []
for line in original.split("\n"):
    st = line.lstrip()
    if not (st.startswith("*") or st.startswith("/*") or st.startswith("//")):
        line = re.sub(r"\bDOMCanonicalizationMethod\b", "DOMC14nMethod", line)
        line = re.sub(r"\bspi\b", "service", line)
    out.append(line)
v1 = "\n".join(out)
assert "public class DOMC14nMethod extends DOMTransform" in v1 and "super(service);" in v1
assert "public DOMC14nMethod(TransformService service)" in v1 and "public DOMC14nMethod(Element cmElem" in v1
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
# A null check that LOOKS like validation but does not restrict the
# algorithm to canonicalization methods (any non-null algorithm passes).
c1 = '''    public DOMCanonicalizationMethod(TransformService spi)
\tthrows InvalidAlgorithmParameterException {
\tsuper(spi);
\tString algorithm = spi.getAlgorithm();
\tif (algorithm == null) {
\t    throw new InvalidAlgorithmParameterException("Missing algorithm");
\t}
    }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(swap(original, CTOR1, c1))

# --- Variant 3: transformed safe variant ---
# Allow-list via a list lookup in a helper (upstream: chained equals in
# isC14Nalg), applied to BOTH constructors, with the same ApacheCanonicalizer
# exemption as upstream.
c1 = '''    public DOMCanonicalizationMethod(TransformService spi)
\tthrows InvalidAlgorithmParameterException {
\tsuper(spi);
\tif (!isApprovedCanonicalizer(spi)) {
\t    throw new InvalidAlgorithmParameterException("Illegal CanonicalizationMethod");
\t}
    }
'''
c2 = '''    public DOMCanonicalizationMethod(Element cmElem, XMLCryptoContext context,
\tProvider provider) throws MarshalException {
\tsuper(cmElem, context, provider);
\tif (!isApprovedCanonicalizer(spi)) {
\t    throw new MarshalException("Illegal CanonicalizationMethod");
\t}
    }
'''
HELPER = '''
    private static boolean isApprovedCanonicalizer(TransformService svc) {
\tif (svc instanceof ApacheCanonicalizer) {
\t    return true;
\t}
\treturn java.util.Arrays.asList(
\t    CanonicalizationMethod.INCLUSIVE,
\t    CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
\t    CanonicalizationMethod.EXCLUSIVE,
\t    CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
\t    DOMCanonicalXMLC14N11Method.C14N_11,
\t    DOMCanonicalXMLC14N11Method.C14N_11_WITH_COMMENTS).contains(svc.getAlgorithm());
    }
'''
safe = swap(swap(original, CTOR1, c1), CTOR2, c2)
idx = safe.rstrip().rfind("}")
safe = safe[:idx] + HELPER + safe[idx:]
assert "isApprovedCanonicalizer" in safe and safe.count("Illegal CanonicalizationMethod") == 2
(CASE_DIR / "variant_safe_01.java").write_text(safe)

# --- Variant 4: benign structural look-alike ---
benign_source = '''package org.jcp.xml.dsig.internal.dom;

import java.security.InvalidAlgorithmParameterException;

import javax.xml.crypto.dsig.TransformService;

/**
 * Same "constructor that just hands a TransformService to DOMTransform"
 * shape, but this class models a generic ds:Transform, which is DESIGNED to
 * accept any transform algorithm (XPath, XSLT, base64, ...). Unlike a
 * CanonicalizationMethod there is no narrower algorithm family to enforce
 * here, so passing the service straight through is correct.
 */
public class DOMGenericTransform extends DOMTransform {

    public DOMGenericTransform(TransformService spi)
        throws InvalidAlgorithmParameterException {
        super(spi);
    }
}
'''
assert "super(spi);" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0111.")

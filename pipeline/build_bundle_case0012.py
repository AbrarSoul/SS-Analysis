"""
Section 9 ground-truth test bundle: CASE-0012
(HtmlUnit/htmlunit, CVE-2023-2798, CWE-400/CWE-787 -- uncontrolled
resource consumption via unbounded recursion).

Core vulnerable mechanism: getNextElementUpwards() recurses into itself
(return getNextElementUpwards(parent);) once per ancestor level with no
depth bound. A deeply nested/crafted DOM tree drives unbounded recursion
depth, causing a StackOverflowError (DoS). The real fix rewrites this as
an iterative loop with identical traversal semantics.

Note: this same commit also touches fireCharacterDataChanged() (a
`safeGetCharacterDataListeners()` -> `toInform.safeGetCharacterDataListeners()`
qualifier fix), which reads as an unrelated correctness fix bundled into
the same commit, not the CWE-400/CWE-787 mechanism -- left untouched in
every variant below, per Section 9.3's requirement to represent only the
verified vulnerability mechanism.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0012"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = (
    "        private DomNode getNextElementUpwards(final DomNode startingNode) {\n"
    "            if (startingNode == DomNode.this) {\n"
    "                return null;\n"
    "            }\n"
    "            final DomNode parent = startingNode.getParentNode();\n"
    "            if (parent == null || parent == DomNode.this) {\n"
    "                return null;\n"
    "            }\n"
    "            DomNode next = parent.getNextSibling();\n"
    "            while (next != null && !isAccepted(next)) {\n"
    "                next = next.getNextSibling();\n"
    "            }\n"
    "            if (next == null) {\n"
    "                return getNextElementUpwards(parent);\n"
    "            }\n"
    "            return next;\n"
    "        }\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"
CALL_SITE = "                next = getNextElementUpwards(nextNode_);\n"
assert CALL_SITE in original

# --- Variant 1: renamed vulnerable variant ---
# Rename the method getNextElementUpwards -> findNextElementUpwards
# (definition + both call sites, including the outer caller), and local
# vars startingNode/parent/next -> fromNode/ancestor/sibling. Same exact
# vulnerability: unbounded self-recursion, no depth bound.
RENAMED_BLOCK = (
    "        private DomNode findNextElementUpwards(final DomNode fromNode) {\n"
    "            if (fromNode == DomNode.this) {\n"
    "                return null;\n"
    "            }\n"
    "            final DomNode ancestor = fromNode.getParentNode();\n"
    "            if (ancestor == null || ancestor == DomNode.this) {\n"
    "                return null;\n"
    "            }\n"
    "            DomNode sibling = ancestor.getNextSibling();\n"
    "            while (sibling != null && !isAccepted(sibling)) {\n"
    "                sibling = sibling.getNextSibling();\n"
    "            }\n"
    "            if (sibling == null) {\n"
    "                return findNextElementUpwards(ancestor);\n"
    "            }\n"
    "            return sibling;\n"
    "        }\n"
)
renamed_source = original.replace(VULNERABLE_BLOCK, RENAMED_BLOCK)
renamed_source = renamed_source.replace(CALL_SITE, "                next = findNextElementUpwards(nextNode_);\n")
assert renamed_source != original
assert "getNextElementUpwards" not in renamed_source
assert renamed_source.count("findNextElementUpwards") == 3
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: equivalent conditional rewriting -- the trailing if/return
# is collapsed into a ternary. Same exact vulnerability (still an
# unbounded self-recursive call), no renaming.
STRUCTURAL_BLOCK = (
    "        private DomNode getNextElementUpwards(final DomNode startingNode) {\n"
    "            if (startingNode == DomNode.this) {\n"
    "                return null;\n"
    "            }\n"
    "            final DomNode parent = startingNode.getParentNode();\n"
    "            if (parent == null || parent == DomNode.this) {\n"
    "                return null;\n"
    "            }\n"
    "            DomNode next = parent.getNextSibling();\n"
    "            while (next != null && !isAccepted(next)) {\n"
    "                next = next.getNextSibling();\n"
    "            }\n"
    "            return (next != null) ? next : getNextElementUpwards(parent);\n"
    "        }\n"
)
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "return (next != null) ? next : getNextElementUpwards(parent);" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same fix idea as upstream (recursion -> iteration, no stack growth with
# DOM depth) but via a for(;;) infinite loop with an explicit null/root
# check inside, instead of the real patch's `while (parent != null &&
# parent != DomNode.this)` guard -- materially different loop construct,
# not byte-identical to the known fix.
SAFE_BLOCK = (
    "        private DomNode getNextElementUpwards(final DomNode startingNode) {\n"
    "            if (startingNode == DomNode.this) {\n"
    "                return null;\n"
    "            }\n"
    "            DomNode ancestor = startingNode.getParentNode();\n"
    "            for (;;) {\n"
    "                if (ancestor == null || ancestor == DomNode.this) {\n"
    "                    return null;\n"
    "                }\n"
    "                DomNode next = ancestor.getNextSibling();\n"
    "                while (next != null && !isAccepted(next)) {\n"
    "                    next = next.getNextSibling();\n"
    "                }\n"
    "                if (next != null) {\n"
    "                    return next;\n"
    "                }\n"
    "                ancestor = ancestor.getParentNode();\n"
    "            }\n"
    "        }\n"
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
assert safe_source != original
assert "for (;;) {" in safe_source
assert "getNextElementUpwards(parent)" not in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a second private method,
# also recursive and also walking DomNode ancestors (same superficial
# shape as the vulnerable method), but bounded by an explicit maxDepth
# parameter that strictly caps recursion depth regardless of actual DOM
# depth -- genuinely safe from stack overflow.
BENIGN_ADDITION = (
    "\n"
    "        /**\n"
    "         * Counts ancestors up to a caller-supplied bound. Unlike\n"
    "         * getNextElementUpwards(), maxDepth strictly caps the recursion\n"
    "         * depth regardless of how deep the actual DOM tree is, so this\n"
    "         * cannot StackOverflow no matter how the document is crafted.\n"
    "         */\n"
    "        private int countAncestorsUpTo(final DomNode startingNode, final int maxDepth) {\n"
    "            if (maxDepth <= 0 || startingNode == null || startingNode == DomNode.this) {\n"
    "                return 0;\n"
    "            }\n"
    "            return 1 + countAncestorsUpTo(startingNode.getParentNode(), maxDepth - 1);\n"
    "        }\n"
)
anchor = "        private DomNode getNextElementUpwards(final DomNode startingNode) {\n"
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "countAncestorsUpTo" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)

print("Wrote 4 new samples for CASE-0012.")

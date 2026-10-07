"""
Section 9 ground-truth test bundle: CASE-0053
(HtmlUnit/htmlunit, CVE-2023-2798, CWE-400 uncontrolled resource
consumption via unbounded recursion).

Core vulnerable mechanism: `getNextElementUpwards()` walks up the DOM tree
by calling ITSELF once per ancestor level whenever the current level has
no accepted next sibling. For a maliciously deeply-nested HTML document
(attacker-controlled input parsed by HtmlUnit), this recursion depth is
bounded only by the document's own nesting depth -- a document nested deep
enough exhausts the JVM call stack (StackOverflowError), a denial of
service. The fix replaces the self-recursion with an explicit while-loop
that walks the SAME ancestor chain iteratively, using constant stack space
regardless of nesting depth.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0053"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = '''        private DomNode getNextElementUpwards(final DomNode startingNode) {
            if (startingNode == DomNode.this) {
                return null;
            }
            final DomNode parent = startingNode.getParentNode();
            if (parent == null || parent == DomNode.this) {
                return null;
            }
            DomNode next = parent.getNextSibling();
            while (next != null && !isAccepted(next)) {
                next = next.getNextSibling();
            }
            if (next == null) {
                return getNextElementUpwards(parent);
            }
            return next;
        }'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename getNextElementUpwards -> findNextAncestorSibling, parent ->
# ancestorNode, next -> candidate. Same exact self-recursive ancestor walk.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''        private DomNode findNextAncestorSibling(final DomNode startingNode) {
            if (startingNode == DomNode.this) {
                return null;
            }
            final DomNode ancestorNode = startingNode.getParentNode();
            if (ancestorNode == null || ancestorNode == DomNode.this) {
                return null;
            }
            DomNode candidate = ancestorNode.getNextSibling();
            while (candidate != null && !isAccepted(candidate)) {
                candidate = candidate.getNextSibling();
            }
            if (candidate == null) {
                return findNextAncestorSibling(ancestorNode);
            }
            return candidate;
        }''',
)
assert "private DomNode findNextAncestorSibling(" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting
# (early-return restructured as if/else). Same exact unbounded self-
# recursion, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''        private DomNode getNextElementUpwards(final DomNode startingNode) {
            if (startingNode == DomNode.this) {
                return null;
            }
            final DomNode parent = startingNode.getParentNode();
            final boolean reachedRoot = (parent == null || parent == DomNode.this);
            if (reachedRoot) {
                return null;
            }
            DomNode next = parent.getNextSibling();
            while (next != null && !isAccepted(next)) {
                next = next.getNextSibling();
            }
            final boolean foundSibling = (next != null);
            if (foundSibling) {
                return next;
            }
            else {
                return getNextElementUpwards(parent);
            }
        }''',
)
assert structural_source != original
assert "final boolean reachedRoot" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (walk ancestors without growing the call
# stack per level) but a materially different technique: an explicit
# java.util.ArrayDeque used as a manual work-stack instead of the real
# patch's plain while-loop with a reassigned local variable -- genuinely
# uses constant native call-stack depth regardless of DOM nesting depth,
# different code shape from the real patch.
SAFE_SOURCE = '''import java.util.ArrayDeque;
import java.util.Deque;

public class DomNodeAncestorWalker
{
    private final DomNode root;

    public DomNodeAncestorWalker(final DomNode root)
    {
        this.root = root;
    }

    private boolean isAccepted(final DomNode node)
    {
        return true;
    }

    private DomNode getNextElementUpwards(final DomNode startingNode)
    {
        if (startingNode == root) {
            return null;
        }

        final Deque<DomNode> pending = new ArrayDeque<DomNode>();
        pending.push(startingNode.getParentNode());

        while (!pending.isEmpty()) {
            final DomNode parent = pending.pop();
            if (parent == null || parent == root) {
                continue;
            }
            DomNode next = parent.getNextSibling();
            while (next != null && !isAccepted(next)) {
                next = next.getNextSibling();
            }
            if (next != null) {
                return next;
            }
            pending.push(parent.getParentNode());
        }
        return null;
    }
}
'''
(CASE_DIR / "variant_safe_01.java").write_text(SAFE_SOURCE)
assert "ArrayDeque" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (a method that recurses upward through a parent
# chain, calling itself again when the current level yields nothing) but
# this sibling walks a fixed, server-side CONFIGURATION tree with a
# hard-coded maximum depth of 8 levels, enforced by an explicit counter --
# never operates on attacker-supplied HTML, so its recursion depth is
# bounded by construction and can never be driven arbitrarily deep,
# unlike getNextElementUpwards() walking an attacker-controlled DOM.
BENIGN_SOURCE = '''public class ConfigNode
{
    private static final int MAX_CONFIG_DEPTH = 8;

    private final ConfigNode parent;
    private final String key;

    public ConfigNode(final ConfigNode parent, final String key)
    {
        this.parent = parent;
        this.key = key;
    }

    /** Fixed, hand-authored config tree only -- never built from
     * untrusted input, and never deeper than MAX_CONFIG_DEPTH by
     * construction, so this recursion is inherently bounded. */
    public String resolveEffectiveValue(final int depth)
    {
        if (depth > MAX_CONFIG_DEPTH) {
            throw new IllegalStateException("config tree deeper than expected");
        }
        if (parent == null) {
            return key;
        }
        return parent.resolveEffectiveValue(depth + 1) + "." + key;
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN_SOURCE)
assert "DomNode" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0053.")

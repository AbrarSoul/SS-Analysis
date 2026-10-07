import java.util.ArrayDeque;
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

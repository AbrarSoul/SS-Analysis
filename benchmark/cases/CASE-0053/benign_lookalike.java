public class ConfigNode
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

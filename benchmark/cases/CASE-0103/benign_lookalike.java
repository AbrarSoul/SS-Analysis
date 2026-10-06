import org.apache.wss4j.dom.WSConstants;
import org.w3c.dom.Element;

public final class TokenDebugLabel {

    private TokenDebugLabel() {}

    /**
     * Same wsu:Id / ID / AssertionID attribute chain, but the value is only
     * embedded in a human-readable debug label. It is never used as a cache
     * key or any other security identity, so a token that declares someone
     * else's Id gains nothing.
     */
    public static String labelFor(Element token) {
        if (token == null) {
            return "token[none]";
        }
        String declared = "unnamed";
        if (token.hasAttributeNS(WSConstants.WSU_NS, "Id")) {
            declared = token.getAttributeNS(WSConstants.WSU_NS, "Id");
        } else if (token.hasAttributeNS(null, "ID")) {
            declared = token.getAttributeNS(null, "ID");
        } else if (token.hasAttributeNS(null, "AssertionID")) {
            declared = token.getAttributeNS(null, "AssertionID");
        }
        return "token[" + declared + "]";
    }
}

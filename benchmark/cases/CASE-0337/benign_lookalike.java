package com.yugabyte.yw.common;

import java.util.HashMap;
import java.util.Map;

/**
 * Standalone example of the same shape: builds a brand-new context for a command that has no earlier redactions
 * (there is nothing on a fresh command to lose), so setting the redaction map directly is correct.
 */
class FreshCommandContext {

    static final class Context {
        final Map<String, String> redactedVals;

        Context(Map<String, String> redactedVals) {
            this.redactedVals = redactedVals;
        }
    }

    static Context forNewCommand(String tokenName, String tokenValue) {
        Map<String, String> redactions = new HashMap<>();
        redactions.put(tokenName, tokenValue);
        return new Context(redactions);
    }
}

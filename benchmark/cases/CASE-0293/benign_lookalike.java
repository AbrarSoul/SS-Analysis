package org.springframework.messaging.simp.broker;

/**
 * Standalone example of the same shape: match a destination against a fixed
 * comparison operator chosen from an enum (never a caller-supplied
 * expression), so nothing is interpreted as code.
 */
class DestinationMatcher {

    enum Op { EQUALS, PREFIX }

    static boolean matches(Op op, String destination, String pattern) {
        return op == Op.EQUALS ? destination.equals(pattern) : destination.startsWith(pattern);
    }
}

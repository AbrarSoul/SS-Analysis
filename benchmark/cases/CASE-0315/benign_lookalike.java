package io.undertow.server.protocol.ajp;

/**
 * Standalone example of the same shape: a lazily created shared StringBuilder
 * that is only ever used inside a synchronized method, so two callers can
 * never interleave their writes into it.
 */
class LockedJoiner {

    private StringBuilder buffer;

    synchronized String join(String a, String b) {
        if (buffer == null) {
            buffer = new StringBuilder();
        }
        buffer.setLength(0);
        buffer.append(a).append('/').append(b);
        return buffer.toString();
    }
}

package io.undertow.protocols.ssl;

import java.nio.ByteBuffer;

/**
 * Standalone example of the same shape: keep asking a source for more bytes
 * while it reports "more available", bounded by a hard iteration limit so the
 * loop always terminates even if the source misbehaves.
 */
class BoundedDrain {

    interface Source {
        boolean hasMore();
        void readInto(ByteBuffer target);
    }

    static int drain(Source source, ByteBuffer target) {
        int rounds = 0;
        while (source.hasMore() && rounds < 64 && target.hasRemaining()) {
            source.readInto(target);
            rounds++;
        }
        return rounds;
    }
}

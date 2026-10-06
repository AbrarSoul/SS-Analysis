package org.jboss.netty.handler.ssl;

import java.nio.ByteBuffer;

/**
 * Standalone example of the same shape: a retry loop that copes with a
 * "destination too small" answer by choosing a bigger destination, and gives up
 * after a fixed number of tries instead of looping forever.
 */
public class BoundedRetryCopy {

    public static ByteBuffer copyWithGrowth(ByteBuffer source, int startCapacity) {
        int capacity = Math.max(1, startCapacity);
        for (int attempt = 0; attempt < 32; attempt++) {
            ByteBuffer target = ByteBuffer.allocate(capacity);
            if (target.remaining() >= source.remaining()) {
                target.put(source.duplicate());
                target.flip();
                return target;
            }
            capacity *= 2;
        }
        throw new IllegalStateException("payload too large");
    }
}

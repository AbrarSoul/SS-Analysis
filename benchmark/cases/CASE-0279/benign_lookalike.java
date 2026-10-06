package io.quarkus.resteasy.runtime.standalone;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Standalone example of the same shape: a flag-guarded early return in a
 * writer that owns nothing needing release (the stream is owned and closed
 * by its creator), so skipping the close on the early path leaks nothing.
 */
class BorrowedStreamWriter {
    private final OutputStream borrowed;
    private boolean done;

    BorrowedStreamWriter(OutputStream borrowed) {
        this.borrowed = borrowed;
    }

    void finish() throws IOException {
        if (done)
            return;
        borrowed.flush();
        done = true;
    }
}

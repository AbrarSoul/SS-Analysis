"""
Section 9 ground-truth test bundle: CASE-0279
(quarkusio/quarkus, extensions/resteasy-classic/resteasy/runtime/src/main/
java/io/quarkus/resteasy/runtime/standalone/VertxHttpResponse.java finish,
CVE-2025-1634, CWE-401 missing release of memory after effective lifetime).

Core vulnerable mechanism: `finish()` ends a RESTEasy response on Vert.x.
When the underlying Vert.x response is ALREADY ended or closed (client
disconnected mid-request, timeout, an earlier error path), it returns
immediately -- without closing `os`, the response's OutputStream, which
wraps a pooled/reference-counted Netty buffer. That stream is only released
by `os.close()` on the normal path, so every request whose response was
already ended leaks its output-stream buffer. An unauthenticated client can
repeatedly open requests and drop the connection (or trigger errors) to
make the server leak buffers until it runs out of memory (remote DoS). The
upstream fix closes and nulls `os` on that early-return path too.

Sibling sites: the normal path already closes `os`; `flushBuffer` only
flushes; the early return in `finish()` is the single leaking path.

Verification: each full file's `finish()` method (plus any helper method a
variant adds up to `flushBuffer`) is extracted verbatim and compiled with
javac into a harness class with stand-ins for the Vert.x types it touches
(`HttpServerResponse`, `RoutingContext`, `HttpHeaders`). The harness sets
the response as already ended and `os` as an OutputStream that records
`close()`, calls `finish()`, and reports whether `os` was closed.

Every variant is the FULL real file. `finish()` is called by name by the
RESTEasy runtime, so its signature is kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0279"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


HEAD = '''    public void finish() throws IOException {
        checkException();
        if (finished || response.ended() || response.closed())
            return;
'''
assert original.count(HEAD) == 1

v1 = swap(original, HEAD, HEAD)  if False else None
v1 = swap(original, "                routingContext.addHeadersEndHandler(h -> {\n                    response.headers().remove(HttpHeaders.CONTENT_LENGTH);\n                    response.headers().set(HttpHeaders.CONNECTION, HttpHeaders.KEEP_ALIVE);\n                });",
          "                routingContext.addHeadersEndHandler(endHeaders -> {\n                    response.headers().remove(HttpHeaders.CONTENT_LENGTH);\n                    response.headers().set(HttpHeaders.CONNECTION, HttpHeaders.KEEP_ALIVE);\n                });")
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

v2 = swap(original, HEAD, '''    private boolean responseAlreadyDone() {
        return finished || response.ended() || response.closed();
    }

    public void finish() throws IOException {
        checkException();
        if (responseAlreadyDone())
            return;
''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

v3 = swap(original, HEAD, '''    private void releaseOutputStream() {
        if (os != null) {
            try {
                os.close();
            } catch (Exception ignored) {
                // best effort: the response is already ended
            } finally {
                os = null;
            }
        }
    }

    public void finish() throws IOException {
        checkException();
        if (finished || response.ended() || response.closed()) {
            releaseOutputStream();
            return;
        }
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package io.quarkus.resteasy.runtime.standalone;

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
''')

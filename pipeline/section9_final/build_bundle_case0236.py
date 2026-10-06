"""
Section 9 ground-truth test bundle: CASE-0236
(netty/netty, src/main/java/org/jboss/netty/handler/ssl/SslHandler.java
unwrap, CVE-2014-3488, CWE-119 / resource exhaustion in the SSL record
decoder).

Core vulnerable mechanism: `unwrap` decrypts each inbound record into a pooled
`ByteBuffer` (`nioOutAppBuf`, 18,816 bytes from `SslBufferPool`) with
`engine.unwrap(nioInNetBuf, nioOutAppBuf)` and, on `BUFFER_OVERFLOW`, just
`continue`s, on the stated assumption that emptying the buffer always lets a
retry succeed. When the SSLEngine needs an application buffer larger than the pooled
one (`engine.getSession().getApplicationBufferSize()` above 18,816, for example with
some engines or compressed records that inflate), emptying the SAME small buffer
never helps: `unwrap` returns `BUFFER_OVERFLOW` on every retry, so the `for (;;)`
spins forever on the I/O thread with the handshake lock held. The upstream fix
asks the session for the size and, if the pooled buffer is too small, allocates a
temporary heap buffer of that size for the call.

Measured caveat, kept in the manifest notes: with a stand-in SSLEngine whose
plaintext record (20,000 bytes) is far larger than the 35-byte ciphertext, the
upstream-patched code no longer spins but fails with an IndexOutOfBoundsException at
`nettyOutAppBuf.writeBytes(outAppBuf)`, because the Netty output buffer is
still created with `initialNettyOutAppBufCapacity` (the ciphertext length) and is
not grown. The safe variant sizes that buffer with
`Math.max(initialNettyOutAppBufCapacity, outAppBuf.remaining())` so the record is
delivered.

Sibling sites: `nioOutAppBuf` is used in this one loop; `wrap` has its own separate
buffer handling and is not part of this bug.

Verification: each full SslHandler.java is compiled with javac against the REAL
netty 3.9.2.Final jar (the source file shadows the jar's class) together with a
harness that puts the handler in a DecoderEmbedder and feeds one TLS record to a
stand-in SSLEngine (real SSLEngine interface, mock behaviour) whose `unwrap` returns
BUFFER_OVERFLOW unless the destination has at least 20,000 bytes and which reports
20,000 as its session application buffer size. The engine throws after 2,000
unwrap calls so a spin is visible.

Every variant is the FULL real file. `unwrap` is private and called by `decode`, so
its name and signature are kept; the renamed variant renames a local.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0236"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
s = original.index("    private ChannelBuffer unwrap(")
e = original.index("\n    }\n", s) + 7
body = original[s:e]
assert body.count("nioOutAppBuf") == 7
v1 = original[:s] + body.replace("nioOutAppBuf", "pooledPlainBuf") + original[e:]
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, "        final ByteBuffer nioOutAppBuf = bufferPool.acquireBuffer();\n",
          "        final ByteBuffer nioOutAppBuf = acquirePlainBuffer();\n")
v2 = swap(v2, "    private ChannelBuffer unwrap(", '''    private ByteBuffer acquirePlainBuffer() {
        return bufferPool.acquireBuffer();
    }

    private ChannelBuffer unwrap(''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, '''                    for (;;) {
                        try {
                            result = engine.unwrap(nioInNetBuf, nioOutAppBuf);
''', '''                    for (;;) {
                        // The pooled buffer may be smaller than what the engine needs for one record.
                        final ByteBuffer outAppBuf =
                                engine.getSession().getApplicationBufferSize() > nioOutAppBuf.capacity()
                                        ? ByteBuffer.allocate(engine.getSession().getApplicationBufferSize())
                                        : nioOutAppBuf;
                        try {
                            result = engine.unwrap(nioInNetBuf, outAppBuf);
''')
v3 = swap(v3, '''                        } finally {
                            nioOutAppBuf.flip();
''', '''                        } finally {
                            outAppBuf.flip();
''')
v3 = swap(v3, '''                            if (nioOutAppBuf.hasRemaining()) {
                                if (nettyOutAppBuf == null) {
                                    ChannelBufferFactory factory = ctx.getChannel().getConfig().getBufferFactory();
                                    nettyOutAppBuf = factory.getBuffer(initialNettyOutAppBufCapacity);
                                }
                                nettyOutAppBuf.writeBytes(nioOutAppBuf);
                            }
                            nioOutAppBuf.clear();
''', '''                            if (outAppBuf.hasRemaining()) {
                                if (nettyOutAppBuf == null) {
                                    ChannelBufferFactory factory = ctx.getChannel().getConfig().getBufferFactory();
                                    nettyOutAppBuf = factory.getBuffer(
                                            Math.max(initialNettyOutAppBufCapacity, outAppBuf.remaining()));
                                }
                                nettyOutAppBuf.writeBytes(outAppBuf);
                            }
                            outAppBuf.clear();
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

BENIGN = '''package org.jboss.netty.handler.ssl;

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
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN)

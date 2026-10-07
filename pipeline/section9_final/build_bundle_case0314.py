r"""
Section 9 ground-truth test bundle: CASE-0314
(undertow-io/undertow, core/src/main/java/io/undertow/protocols/ssl/SslConduit.java
wrapAndFlip, CVE-2023-1108, CWE-835 loop with unreachable exit condition).

Core vulnerable mechanism: `wrapAndFlip` repeatedly calls `engine.wrap(...)`
for as long as the handshake status is NEED_WRAP and the last result was not
BUFFER_OVERFLOW. When the peer has closed the connection during the
handshake (the SSLEngine's inbound side is done) the engine keeps reporting
NEED_WRAP without making progress, so the loop never terminates: an
unauthenticated remote client can pin an XNIO worker thread at 100% CPU per
connection (denial of service). The upstream fix adds
`&& !engine.isInboundDone()` to the loop condition.

Sibling sites: none; the other wrap/unwrap loops in the class terminate on
different statuses.

Verification: the method (plus any helper the variant adds next to it) is
sliced from each full file into a javac harness class that has the same
`engine`, `wrappedData` and `EMPTY_BUFFER` members (the engine is a concrete
javax.net.ssl.SSLEngine subclass that counts wrap() calls and throws after
1,000 calls to catch a non-terminating loop). Scenarios: peer closed (inbound
done, engine stuck reporting NEED_WRAP) and a normal handshake (three NEED_WRAP
results then NOT_HANDSHAKING). Vulnerable variants hit the 1,000-call cap
on the peer-closed scenario, patched/safe stop after one wrap; the normal
scenario makes exactly 3 wrap calls in every file.

Every variant is the FULL real file; `wrapAndFlip` keeps its name and
signature because handshake code calls it.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0314"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


METHOD = '''    private SSLEngineResult wrapAndFlip(ByteBuffer[] userBuffers, int off, int len) throws IOException {
        SSLEngineResult result = null;
        while (result == null || (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP && result.getStatus() != SSLEngineResult.Status.BUFFER_OVERFLOW)) {
            if (userBuffers == null) {
                result = engine.wrap(EMPTY_BUFFER, wrappedData.getBuffer());
            } else {
                result = engine.wrap(userBuffers, off, len, wrappedData.getBuffer());
            }
        }
        wrappedData.getBuffer().flip();
        return result;
    }
'''
assert original.count(METHOD) == 1

# --- Variant 1: renamed vulnerable variant (parameters and local renamed inside wrapAndFlip) ---
m1 = METHOD
for old, new in [("userBuffers", "sources"), ("off", "offset"), ("len", "length"), ("result", "wrapResult")]:
    m1 = re.sub(r"\b%s\b" % old, new, m1)
v1 = swap(original, METHOD, m1)
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (single wrap step extracted into a helper) ---
m2 = '''    private SSLEngineResult wrapAndFlip(ByteBuffer[] userBuffers, int off, int len) throws IOException {
        SSLEngineResult result = wrapOnce(userBuffers, off, len);
        while (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP && result.getStatus() != SSLEngineResult.Status.BUFFER_OVERFLOW) {
            result = wrapOnce(userBuffers, off, len);
        }
        wrappedData.getBuffer().flip();
        return result;
    }

    private SSLEngineResult wrapOnce(ByteBuffer[] userBuffers, int off, int len) throws IOException {
        if (userBuffers == null) {
            return engine.wrap(EMPTY_BUFFER, wrappedData.getBuffer());
        }
        return engine.wrap(userBuffers, off, len, wrappedData.getBuffer());
    }
'''
v2 = swap(original, METHOD, m2)
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the loop test moves into a helper method) ---
COND = '''        while (result == null || (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP
                && result.getStatus() != SSLEngineResult.Status.BUFFER_OVERFLOW && !engine.isInboundDone())) {
'''
v3 = swap(patched, COND, "        while (result == null || shouldWrapAgain(result)) {\n")
v3 = swap(v3, "    private SSLEngineResult wrapAndFlip(", '''    private boolean shouldWrapAgain(SSLEngineResult result) {
        return result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP
                && result.getStatus() != SSLEngineResult.Status.BUFFER_OVERFLOW
                && !engine.isInboundDone();
    }

    private SSLEngineResult wrapAndFlip(''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package io.undertow.protocols.ssl;

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
''')

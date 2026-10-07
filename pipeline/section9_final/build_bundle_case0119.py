"""
Section 9 ground-truth test bundle: CASE-0119
(apache/tomcat, Http2UpgradeHandler.close, CVE-2017-5650, CWE-404 improper
resource shutdown/release).

Core vulnerable mechanism: `close()` marks the connection CLOSED and closes
the socket, but never cancels the connection's still-open HTTP/2 streams.
Each of those streams keeps its processing thread/state waiting on a
connection that no longer exists, so a client can open many streams and
drop the connection to leak threads and memory (denial of service). The
upstream fix loops over `streams.values()` and calls
`stream.receiveReset(Http2Error.CANCEL.getCode())` before closing the socket.

Every variant is the FULL real file with close() replaced. close() is
private with four in-file call sites (bare `close();`), which the renamed
variant also renames; `socketWrapper.close()` inside it is a different
method and is NOT renamed.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0119"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    private void close() {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
assert original.count(HDR) == 1 and "receiveReset(Http2Error.CANCEL" not in BLOCK
CALL_RE = re.compile(r"^(\s+)close\(\);$", re.M)
calls = CALL_RE.findall(original)
assert len(calls) == 4, len(calls)
STATE = "        connectionState.set(ConnectionState.CLOSED);\n"
SOCK = '''        try {
            socketWrapper.close();
        } catch (IOException ioe) {
            log.debug(sm.getString("upgradeHandler.socketCloseFailed"), ioe);
        }
'''
assert BLOCK == HDR + STATE + SOCK + "    }\n"


def build(new_block, extra_after=None, rename_calls_to=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + (extra_after or "") + original[e:]
    if rename_calls_to:
        out, n = CALL_RE.subn(lambda m: f"{m.group(1)}{rename_calls_to}();", out)
        assert n == 4
    return out


# --- Variant 1: renamed vulnerable variant ---
b = ('    private void shutdownConnection() {\n' + STATE +
     SOCK.replace("IOException ioe", "IOException closeFailure").replace(", ioe);", ", closeFailure);") + "    }\n")
assert "shutdownConnection" in b and "closeFailure" in b and "socketWrapper.close();" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b, rename_calls_to="shutdownConnection"))

# --- Variant 2: structurally changed vulnerable variant ---
b = HDR + STATE + "        closeSocketQuietly();\n    }\n"
helper = '''

    private void closeSocketQuietly() {
        try {
            socketWrapper.close();
        } catch (IOException ioe) {
            log.debug(sm.getString("upgradeHandler.socketCloseFailed"), ioe);
        }
    }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# Cancels every stream from a SNAPSHOT of the ids and shields the socket
# close from a failing reset (upstream iterates streams.values() directly).
b = HDR + STATE + '''        for (Integer streamId : new java.util.ArrayList<>(streams.keySet())) {
            Stream stream = streams.get(streamId);
            if (stream != null) {
                try {
                    stream.receiveReset(Http2Error.CANCEL.getCode());
                } catch (RuntimeException re) {
                    log.debug(sm.getString("upgradeHandler.socketCloseFailed"), re);
                }
            }
        }
''' + SOCK + "    }\n"
safe_source = build(b)
assert "receiveReset(Http2Error.CANCEL.getCode())" in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicReference;

public class SingleRequestConnection {

    private enum State { OPEN, CLOSED }

    private final AtomicReference<State> state = new AtomicReference<>(State.OPEN);
    private final Socket socket;

    public SingleRequestConnection(Socket socket) {
        this.socket = socket;
    }

    /**
     * Same "mark CLOSED, then close the socket" shape as a multiplexed
     * connection's close(), but this connection carries exactly one
     * request/response at a time on the socket itself: there are no child
     * streams or per-stream threads that could outlive it, so closing the
     * socket is the complete shutdown.
     */
    private void close() {
        state.set(State.CLOSED);
        try {
            socket.close();
        } catch (IOException ioe) {
            // nothing else to release
        }
    }
}
'''
assert "no child" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0119.")

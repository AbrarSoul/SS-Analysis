"""
Section 9 ground-truth test bundle: CASE-0089
(aio-libs/aiosmtpd, CVE-2024-34083, CWE-349 STARTTLS plaintext injection).

Core vulnerable mechanism: when the SMTP server upgrades a connection with
STARTTLS, `connection_made()` swaps in the TLS transport but never discards
data the client sent in PLAINTEXT before the handshake and that is still
sitting in the stream reader's buffer. An attacker (or a man in the middle)
can pipeline commands after STARTTLS; they are then processed as if they
had arrived over the encrypted channel ("response/command injection",
RFC 3207 section 4.2 requires such data to be discarded). The upstream fix
clears the reader buffer after switching transports.

Note: `connection_made` is the asyncio protocol callback, so the METHOD
NAME cannot be renamed without breaking the framework contract; the
renamed variant therefore renames the parameter and locals only.

Every variant is the FULL real file with SMTP.connection_made replaced.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0089"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.py").read_text().splitlines()) + "\n"

START = "    def connection_made(self, transport: asyncio.BaseTransport) -> None:\n        # Reset state due to rfc3207 part 4.2."
s = original.index(START)
END_MARK = "                self._handle_client())\n"
e = original.index(END_MARK, s) + len(END_MARK)
BLOCK = original[s:e]
assert original.count(START) == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK
b = b.replace("transport: asyncio.BaseTransport", "new_transport: asyncio.BaseTransport")
b = b.replace("transport.get_extra_info", "new_transport.get_extra_info")
b = b.replace("= transport  # type", "= new_transport  # type")
b = b.replace("self.transport = transport\n", "self.transport = new_transport\n")
b = b.replace("super().connection_made(transport)", "super().connection_made(new_transport)")
import re
b = re.sub(r"\bseen_starttls\b", "is_upgrade", b)
b = re.sub(r"\bhook\b", "starttls_hook", b)
assert "_handle_hooks" in b
assert "(transport)" not in b and "= transport" not in b
assert b.count("new_transport") == 7, b.count("new_transport")
(CASE_DIR / "variant_vulnerable_01.py").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_02.py").write_text(build('''    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        # Reset state due to rfc3207 part 4.2.
        self._set_rset_state()
        self.session = self._create_session()
        self.session.peer = transport.get_extra_info('peername')
        self._reset_timeout()
        upgrading = self.transport is not None and self._original_transport is not None
        if not upgrading:
            super().connection_made(transport)
            self.transport = transport
            log.info('Peer: %r', self.session.peer)
            # Process the client's requests.
            self._handler_coroutine = self.loop.create_task(
                self._handle_client())
            return
        # It is STARTTLS connection over normal connection.
        self._reader._transport = transport  # type: ignore[attr-defined]
        self._writer._transport = transport  # type: ignore[attr-defined]
        self.transport = transport
        # Do SSL certificate checking as rfc3207 part 4.1 says.  Why is
        # _extra a protected attribute?
        assert self._tls_protocol is not None
        self.session.ssl = self._tls_protocol._extra
        hook = self._handle_hooks.get("STARTTLS")
        if hook is None:
            self._tls_handshake_okay = True
        else:
            self._tls_handshake_okay = hook(
                self, self.session, self.envelope)
'''))

# --- Variant 3: transformed safe variant ---
# Fail closed instead of silently discarding: if ANY plaintext is still
# buffered when the TLS transport takes over, log it and close the
# connection. (Upstream clears the buffer and carries on.)
safe = BLOCK.replace(
    "            self.transport = transport\n            # Do SSL certificate checking",
    "            self.transport = transport\n"
    "            if self._reader._buffer:  # type: ignore[attr-defined]\n"
    "                # Data pipelined in the clear before the handshake finished: rfc3207\n"
    "                # part 4.2 forbids acting on it, so refuse to continue at all.\n"
    "                log.warning('%r plaintext data pipelined before STARTTLS handshake; closing',\n"
    "                            self.session.peer)\n"
    "                transport.close()\n"
    "                return\n"
    "            # Do SSL certificate checking",
)
assert safe != BLOCK and "transport.close()" in safe
(CASE_DIR / "variant_safe_01.py").write_text(build(safe))

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.py").write_text('''import asyncio


class LineEchoProtocol(asyncio.Protocol):
    """Same connection_made()/transport-swap shape, but a plain (non-TLS)
    protocol: there is no security-relevant transport upgrade, so there is
    no earlier plaintext phase whose leftover buffered data could be
    mistaken for authenticated/encrypted input."""

    def __init__(self) -> None:
        self.transport = None
        self._buffer = bytearray()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport
        self._buffer.clear()

    def data_received(self, data: bytes) -> None:
        self._buffer.extend(data)
        while b"\\n" in self._buffer:
            line, _, rest = self._buffer.partition(b"\\n")
            self._buffer = bytearray(rest)
            self.transport.write(line + b"\\n")
''')
print("Wrote 4 new samples for CASE-0089.")

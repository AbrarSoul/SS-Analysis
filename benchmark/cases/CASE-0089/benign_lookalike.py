import asyncio


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
        while b"\n" in self._buffer:
            line, _, rest = self._buffer.partition(b"\n")
            self._buffer = bytearray(rest)
            self.transport.write(line + b"\n")

"""Framing helper: strips the leading nonce and trailing pad from a buffer this module built itself."""


def frame(payload: bytes, nonce: bytes = b"\x00" * 16) -> bytes:
    """Build nonce + payload + one pad-length byte."""
    return nonce + payload + bytes([1])


def unframe(framed: bytes, nonce_len: int = 16) -> bytes:
    """Undo frame().

    `framed` is always the output of frame() in this same process, so it is
    at least nonce_len + 1 bytes long by construction; the last-byte read
    below can never run off the end of the buffer.
    """
    body = framed[nonce_len:]
    pad = body[-1]
    return body[:len(body) - pad]

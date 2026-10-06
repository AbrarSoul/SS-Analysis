from .utils import _warnmsg


def check_key_type(kind):
    """Same "warn about an unknown attacker-supplied key type" shape, but the
    only thing put into the message is the LENGTH of the value (an int), never
    its text, so no escape or control sequence can reach the terminal."""
    if kind in ("rsa", "ed25519"):
        return True
    _warnmsg(f"Unknown DKIM key type (length {len(kind)})")
    return False

import base64
import binascii

from .utils import _warnmsg

PUBPRE = "-----BEGIN PUBLIC KEY-----\n"
PUBPOST = "\n-----END PUBLIC KEY-----"
EDASN1 = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"


def parse_dkim_record(record):
    if '"' in record:
        toggle = 0
        joined = ""
        for part in record.split('"'):
            toggle ^= 1
            if toggle == 0:
                joined += part
    else:
        joined = record

    fields = {}
    for part in joined.split(";"):
        pair = part.split("=", 1)
        if len(pair) != 2:
            continue
        name = pair[0].strip()
        val = pair[1].strip()
        fields[name] = val
    if "p" not in fields:
        return False
    if fields["p"] == "":
        return False
    if "k" not in fields:
        fields["k"] = "rsa"

    if fields["k"] == "rsa":
        return PUBPRE + fields["p"] + PUBPOST
    if fields["k"] == "ed25519":
        try:
            raw = base64.b64decode(fields["p"].encode("ascii"))
        except (binascii.Error, UnicodeEncodeError):
            return False
        if len(raw) != 32:
            return False
        spki = EDASN1 + raw
        return PUBPRE + base64.b64encode(spki).decode() + PUBPOST
    _warnmsg(f"Unknown DKIM key type {fields['k']}")
    return False

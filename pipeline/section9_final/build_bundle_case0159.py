"""
Section 9 ground-truth test bundle: CASE-0159
(eventlet/eventlet, eventlet/support/greendns.py udp, CVE-2023-29483,
CWE-292 / DNS response forgery, "TuDoor").

Core vulnerable mechanism: `udp()` (eventlet's replacement for
dns.query.udp) receives datagrams in a loop and `break`s out of it on the FIRST
datagram whose source address equals the server's, then parses it and raises
BadResponse if it is not a valid reply to the query. A forged or malformed
datagram that reaches the socket first (same source address, wrong
transaction id / bad wire format) therefore ends the lookup with an exception
instead of being ignored while the real answer is still on its way, letting an
off-path attacker knock out or race DNS resolution. The upstream fix moves
parsing and the is_response check INSIDE the loop, adds an `ignore_errors`
parameter, and on an invalid packet continues listening when it is True.

Measured caveat, kept in the manifest notes: upstream keeps `ignore_errors`
defaulting to False, so callers that do not pass it (including the
dnspython resolver path) keep the old behaviour. The safe variant instead
treats an invalid packet from the expected server as ignorable by default
and only a genuine (valid) truncated reply still raises.

Sibling sites: `tcp()` is a stream protocol (no forged-datagram race) and is
unchanged in all variants.

Every variant is the FULL real file. udp is a module-level function that
callers (and the dns.query monkeypatch) use by name and keyword, so the renamed
variant keeps the name and parameter names and renames locals only.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0159"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

s = original.index("def udp(q, where, timeout=DNS_QUERY_TIMEOUT, port=53,\n")
e = original.index("\n\ndef tcp(", s)
BLOCK = original[s:e]
DOC_END = '    @type sock: socket.socket | None"""\n'
assert BLOCK.count(DOC_END) == 1

LOOP_TAIL = '''            if from_address == destination:
                break
            if not ignore_unexpected:
                raise dns.query.UnexpectedSource(
                    'got a response from %s instead of %s'
                    % (from_address, destination))
    finally:
        s.close()

    if _handle_raise_on_truncation:
        r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                                  one_rr_per_rrset=one_rr_per_rrset,
                                  ignore_trailing=ignore_trailing,
                                  raise_on_truncation=raise_on_truncation)
    else:
        r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                                  one_rr_per_rrset=one_rr_per_rrset,
                                  ignore_trailing=ignore_trailing)
    if not q.is_response(r):
        raise dns.query.BadResponse()
    return r
'''
assert BLOCK.count(LOOP_TAIL) == 1


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


# --- Variant 1: renamed vulnerable variant ---
head, code = BLOCK.split(DOC_END)
for old, new in (("wire", "packet"), ("from_address", "peer"), ("destination", "target"), ("expiration", "deadline"),
                 ("tried", "retried"), ("addr", "ip"), ("s", "udp_sock"), ("r", "resp")):
    code = re.sub(r"(?<![.\w$'])%s(?![\w$'=])" % re.escape(old), new, code)
b = head + DOC_END + code
assert "udp_sock.settimeout(timeout)" in b and "(packet, peer) = udp_sock.recvfrom(65535)" in b
assert "if peer == target:" in b and "if not q.is_response(resp):" in b and "return resp" in b
assert "ignore_unexpected" in b and "raise_on_truncation=raise_on_truncation" in b
(CASE_DIR / "variant_vulnerable_01.py").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace('''    if _handle_raise_on_truncation:
        r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                                  one_rr_per_rrset=one_rr_per_rrset,
                                  ignore_trailing=ignore_trailing,
                                  raise_on_truncation=raise_on_truncation)
    else:
        r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                                  one_rr_per_rrset=one_rr_per_rrset,
                                  ignore_trailing=ignore_trailing)
    if not q.is_response(r):
        raise dns.query.BadResponse()
    return r
''', '''    return _parse_reply(q, wire, one_rr_per_rrset, ignore_trailing, raise_on_truncation)
''')
helper = '''

def _parse_reply(q, wire, one_rr_per_rrset, ignore_trailing, raise_on_truncation):
    if _handle_raise_on_truncation:
        r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                                  one_rr_per_rrset=one_rr_per_rrset,
                                  ignore_trailing=ignore_trailing,
                                  raise_on_truncation=raise_on_truncation)
    else:
        r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                                  one_rr_per_rrset=one_rr_per_rrset,
                                  ignore_trailing=ignore_trailing)
    if not q.is_response(r):
        raise dns.query.BadResponse()
    return r
'''
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.py").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# Every datagram from the expected server is parsed and validated INSIDE the
# loop; an invalid one is skipped (listening continues until the deadline)
# by default, and only a valid truncated reply is raised; upstream adds an
# `ignore_errors` flag that defaults to False.
b = BLOCK.replace(LOOP_TAIL, '''            if from_address != destination:
                if ignore_unexpected:
                    continue
                raise dns.query.UnexpectedSource(
                    'got a response from %s instead of %s'
                    % (from_address, destination))
            try:
                if _handle_raise_on_truncation:
                    r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                                              one_rr_per_rrset=one_rr_per_rrset,
                                              ignore_trailing=ignore_trailing,
                                              raise_on_truncation=raise_on_truncation)
                else:
                    r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                                              one_rr_per_rrset=one_rr_per_rrset,
                                              ignore_trailing=ignore_trailing)
            except dns.message.Truncated as e:
                if q.is_response(e.message()):
                    raise
                continue
            except Exception:
                continue
            if q.is_response(r):
                return r
    finally:
        s.close()
''')
assert b != BLOCK
(CASE_DIR / "variant_safe_01.py").write_text(build(b))

# --- Variant 4: benign structural look-alike ---
benign_source = '''import socket
import time


def send_datagram(wire, destination, timeout=2.0):
    """Same sendto-with-retry loop as the DNS client, but fire-and-forget: it
    never reads a reply, so there is no response to validate, spoof or race."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    deadline = time.time() + timeout
    try:
        while True:
            try:
                s.sendto(wire, destination)
                return
            except socket.timeout:
                if deadline - time.time() <= 0.0:
                    raise
                time.sleep(0.01)
    finally:
        s.close()
'''
assert "fire-and-forget" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0159.")

"""
Section 9 ground-truth test bundle: CASE-0133
(bsv-blockchain/ts-sdk, src/auth/Peer.ts processInitialRequest,
CVE-2025-69287, CWE-573 improper following of specification by caller).

Core vulnerable mechanism: the handshake signature is computed over
`Peer.base64ToBytes(message.initialNonce + sessionNonce)`, i.e. the two
base64 STRINGS are concatenated and then decoded ONCE. For nonces generated
by this SDK (48 bytes = 64 base64 characters, no padding) that happens to
equal decoding each and joining the bytes (96 bytes; measured). But
`message.initialNonce` is CHOSEN BY THE PEER: a value with '=' padding (e.g.
32 bytes -> 44 characters) makes the decoder stop at the padding, so the
result is only the peer's own bytes and the responder's freshly generated
`sessionNonce` is silently DROPPED from the signed data (measured: 32 bytes
signed instead of 32 + 48 = 80). The signature then does not commit to the
responder's session nonce. The upstream fix decodes each nonce separately
and concatenates the BYTES.

Sibling site (unchanged in the upstream-patched file, verified):
`processInitialResponse` builds `dataToVerify` with the same string
concatenation. There the first part is the local, SDK-generated (unpadded)
nonce, so it is not independently exploitable the same way, and honest
handshakes with the upstream-patched signing side still complete (measured);
the SAFE variant nonetheless uses byte concatenation on both sides so no
string-concatenation-then-decode remains in a file labeled safe.

Every variant is the FULL real file. processInitialRequest is a private
method with one in-file call site (the message dispatch switch), which the
renamed variant also renames.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0133"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
assert "\r" not in original

HDR = "  private async processInitialRequest (message: AuthMessage): Promise<void> {\n"
s = original.index(HDR)
e = original.index("\n  }\n", s) + len("\n  }\n")
BLOCK = original[s:e]
CALL = "await this.processInitialRequest(message)"
SIGN = "      data: Peer.base64ToBytes(message.initialNonce + sessionNonce),\n"
VERIFY = '''    const dataToVerify = Peer.base64ToBytes(
      (peerSession.sessionNonce ?? '') + (message.initialNonce ?? '')
    )
'''
assert original.count(HDR) == 1 and original.count(CALL) == 1 and original.count("processInitialRequest") == 2
assert BLOCK.count(SIGN) == 1 and original.count(VERIFY) == 1


def build(new_block, extra=None, new_call=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + (extra or "") + original[e:]
    if new_call:
        assert out.count(CALL) == 1
        out = out.replace(CALL, new_call)
    return out


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r"""('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`)""", line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])(?!\s*:)" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
# (`sessionNonce` and `signature` are used as object-literal SHORTHAND
# properties here, so they are deliberately not renamed.)
b = BLOCK.replace("private async processInitialRequest (message: AuthMessage)",
                  "private async handleHandshakeInit (incoming: AuthMessage)")
b = rename_outside_strings(b, (("message", "incoming"), ("now", "timestamp"), ("certificatesToInclude", "certsToSend"),
                               ("initialResponseMessage", "replyMessage"), ("cb", "handler")))
b = b.replace("const initialResponseMessage:", "const replyMessage:")
b = b.replace("let certificatesToInclude:", "let certsToSend:")   # a TS type annotation after the name looks like an object key to the rename rule
b = b.replace("${message.", "${incoming.")   # template-literal interpolations are code, the string-protecting rename skips them
assert "${message." not in b, "unrenamed template-literal interpolation left in the renamed method"
assert "incoming.initialNonce + sessionNonce" in b and "certificates: certsToSend," in b
assert "lastUpdate: timestamp" in b and "await this.transport.send(replyMessage)" in b
compile_ok = build(b, new_call="await this.handleHandshakeInit(message)")
(CASE_DIR / "variant_vulnerable_01.ts").write_text(compile_ok)

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(SIGN, "      data: await this.handshakeData(message.initialNonce, sessionNonce),\n")
helper = '''
  private async handshakeData (initialNonce: string, sessionNonce: string): Promise<number[]> {
    return Peer.base64ToBytes(initialNonce + sessionNonce)
  }
'''
assert b != BLOCK and "handshakeData(" in b
(CASE_DIR / "variant_vulnerable_02.ts").write_text(build(b, extra=helper))

# --- Variant 3: transformed safe variant ---
# Decode each nonce on its own and join the BYTES with Array.concat (upstream:
# spread of two decoded arrays) -- on BOTH the signing side and the sibling
# verifying side (processInitialResponse), which upstream left unchanged.
b = BLOCK.replace(SIGN, "      data: Peer.base64ToBytes(message.initialNonce).concat(Peer.base64ToBytes(sessionNonce)),\n")
safe = build(b)
safe = safe.replace(VERIFY, '''    const dataToVerify = Peer.base64ToBytes(peerSession.sessionNonce ?? '').concat(
      Peer.base64ToBytes(message.initialNonce ?? '')
    )
''')
assert "base64ToBytes(message.initialNonce + sessionNonce)" not in safe and safe.count(".concat(") == 2
(CASE_DIR / "variant_safe_01.ts").write_text(safe)

# --- Variant 4: benign structural look-alike ---
benign_source = '''// 30-byte values encode to exactly 40 base64 characters with NO '=' padding.
const NONCE_BYTES = 30
const NONCE_BASE64_LENGTH = 40

/**
 * Same "concatenate two base64 strings, then decode once" pattern as the
 * handshake code, but it is only ever applied to fixed-length, padding-free
 * values (and refuses anything else), so decoding the concatenation is
 * byte-for-byte identical to decoding each value and joining the bytes: no
 * input is dropped.
 */
export function joinFixedLengthNonces (first: string, second: string): number[] {
  for (const value of [first, second]) {
    if (value.length !== NONCE_BASE64_LENGTH || value.includes('=')) {
      throw new Error('Nonce must be exactly ' + NONCE_BYTES + ' bytes of unpadded base64')
    }
  }
  return Array.from(Buffer.from(first + second, 'base64'))
}
'''
assert "NONCE_BASE64_LENGTH" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)
print("Wrote 4 new samples for CASE-0133.")

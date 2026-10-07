"""
Section 9 ground-truth test bundle: CASE-0032
(Eugeny/tabby, CVE-2024-48460, CWE-295 -- improper host key validation
race condition).

Core vulnerable mechanism: authHandler submits authentication credentials
(via this.handleAuth(methodsLeft)) without first awaiting
hostVerifiedPromise, which resolves only once the SSH host key has been
verified/accepted. Because authHandler can fire before that promise
settles, credentials can be sent to a server whose host key has not yet
been confirmed -- a MITM presenting a spoofed key could receive them.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0032"
original = (CASE_DIR / "vulnerable_source.ts").read_text()

VULNERABLE_BLOCK = (
    "                authHandler: (methodsLeft, partialSuccess, callback) => {\n"
    "                    this.zone.run(async () => {\n"
    "                        callback(await this.handleAuth(methodsLeft))\n"
    "                    })\n"
    "                },\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# Rename the local callback parameters methodsLeft/partialSuccess/callback
# -> remainingMethods/didPartialSucceed/finishAuth (authHandler itself is
# a fixed ssh2 library option name and must not be renamed). Same exact
# vulnerability: still no await of hostVerifiedPromise before submitting
# credentials.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    "                authHandler: (remainingMethods, didPartialSucceed, finishAuth) => {\n"
    "                    this.zone.run(async () => {\n"
    "                        finishAuth(await this.handleAuth(remainingMethods))\n"
    "                    })\n"
    "                },\n",
)
assert renamed_source != original
assert "remainingMethods, didPartialSucceed, finishAuth" in renamed_source
assert "finishAuth(await this.handleAuth(remainingMethods))" in renamed_source
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable. Same exact
# vulnerability (still no await of hostVerifiedPromise), no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    "                authHandler: (methodsLeft, partialSuccess, callback) => {\n"
    "                    this.zone.run(async () => {\n"
    "                        const authResult = await this.handleAuth(methodsLeft)\n"
    "                        callback(authResult)\n"
    "                    })\n"
    "                },\n",
)
assert structural_source != original
assert "const authResult = await this.handleAuth(methodsLeft)" in structural_source
(CASE_DIR / "variant_vulnerable_02.ts").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (credentials are only submitted
# after host verification settles, and a rejection still propagates and
# blocks auth) but via a small wrapper method instead of the real patch's
# direct one-line `await hostVerifiedPromise` -- materially different
# structure, not byte-identical to the known fix.
safe_source = original.replace(
    VULNERABLE_BLOCK,
    "                authHandler: (methodsLeft, partialSuccess, callback) => {\n"
    "                    this.zone.run(async () => {\n"
    "                        await this.waitForHostVerification(hostVerifiedPromise)\n"
    "                        callback(await this.handleAuth(methodsLeft))\n"
    "                    })\n"
    "                },\n",
)
helper_method = (
    "\n"
    "    private async waitForHostVerification (promise: Promise<void>): Promise<void> {\n"
    "        await promise\n"
    "    }\n"
)
anchor = "export class SSHSession {\n"
assert anchor in safe_source
safe_source = safe_source.replace(anchor, anchor + helper_method, 1)
assert safe_source != original
assert "waitForHostVerification" in safe_source
(CASE_DIR / "variant_safe_01.ts").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a keepaliveHandler that
# also fires a this.zone.run(async () => {...}) callback without awaiting
# hostVerifiedPromise -- the same superficial shape as the vulnerable
# pattern -- but it only sends a transport-level keepalive ping, carrying
# no credentials, so racing ahead of host-key verification here has no
# security consequence.
BENIGN_ADDITION = (
    "\n"
    "    private registerKeepalive (): void {\n"
    "        this.zone.run(async () => {\n"
    "            // Sends only a transport-level keepalive ping -- carries no\n"
    "            // credentials and has no security consequence if it races\n"
    "            // ahead of host-key verification, unlike authHandler above.\n"
    "            this.notifyKeepalive()\n"
    "        })\n"
    "    }\n"
)
anchor2 = "    private async waitForHostVerification (promise: Promise<void>): Promise<void> {\n"
assert anchor2 in safe_source
benign_source = safe_source.replace(anchor2, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor2, 1)
assert benign_source != safe_source
assert "registerKeepalive" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)

print("Wrote 4 new samples for CASE-0032.")

"""
Section 9 ground-truth test bundle: CASE-0022
(GSConnect/gnome-shell-extension-gsconnect, CVE-2025-66270, CWE-290 --
authentication bypass by spoofing).

The real patch touches two near-identical post-TLS identity re-exchange
sites (in accept() and its outgoing-connection counterpart). This bundle
targets the accept() site as the representative instance (Section 9.3);
the second occurrence is left untouched in every variant.

Core vulnerable mechanism: after TLS negotiation, the device re-exchanges
identity packets, but the code unconditionally overwrites this.identity
with whatever packet comes back (this.identity = await this.readPacket())
with no check that the post-TLS identity (protocolVersion, deviceId)
matches the pre-TLS identity established during the initial handshake --
letting an attacker who completed the outer TLS handshake claim a
different device identity afterward.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0022"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = (
    "    async accept(connection) {\n"
)
# We match on the full method signature plus the specific vulnerable
# 3-line block within it (protocolVersion check + 2-line re-exchange),
# not the whole method body, to avoid re-typing unrelated lines.
VULNERABLE_INNER = (
    "            // Starting with protocol version 8, the devices are expected to\n"
    "            // exchange identity packets again after TLS negotiation\n"
    "            if (this.identity.body.protocolVersion >= 8) {\n"
    "                await this.sendPacket(this.backend.identity);\n"
    "                this.identity = await this.readPacket();\n"
    "            }\n"
    "        } catch (e) {\n"
    "            this.close();\n"
    "            throw e;\n"
    "        }\n"
)
assert VULNERABLE_BLOCK in original
assert original.count(VULNERABLE_INNER) == 2, "expected exactly 2 occurrences (accept() and its counterpart)"
# Locate the FIRST occurrence only (the one inside accept()) by anchoring
# on the accept() method definition and taking everything up to and
# including the first VULNERABLE_INNER after it.
accept_start = original.index(VULNERABLE_BLOCK)
first_inner_start = original.index(VULNERABLE_INNER, accept_start)
first_inner_end = first_inner_start + len(VULNERABLE_INNER)

CALL_SITE = "            await channel.accept(connection);\n"
assert CALL_SITE in original

# --- Variant 1: renamed vulnerable variant ---
# Rename the method accept -> acceptIncomingConnection (definition + its
# one call site). Same exact vulnerability: still no validation of the
# post-TLS identity before overwriting this.identity.
renamed_source = (
    original[:accept_start]
    + "    async acceptIncomingConnection(connection) {\n"
    + original[accept_start + len(VULNERABLE_BLOCK):]
)
renamed_source = renamed_source.replace(CALL_SITE, "            await channel.acceptIncomingConnection(connection);\n")
assert renamed_source != original
assert "async acceptIncomingConnection(connection) {" in renamed_source
assert "channel.acceptIncomingConnection(connection)" in renamed_source
# the second occurrence's enclosing method (not accept()) must be untouched
assert renamed_source.count(VULNERABLE_INNER) == 2
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable. Same exact
# vulnerability (still no validation before overwriting this.identity),
# no renaming. Applied only to the FIRST occurrence (inside accept()).
STRUCTURAL_REPLACEMENT = (
    "            // Starting with protocol version 8, the devices are expected to\n"
    "            // exchange identity packets again after TLS negotiation\n"
    "            if (this.identity.body.protocolVersion >= 8) {\n"
    "                await this.sendPacket(this.backend.identity);\n"
    "                const newIdentity = await this.readPacket();\n"
    "                this.identity = newIdentity;\n"
    "            }\n"
    "        } catch (e) {\n"
    "            this.close();\n"
    "            throw e;\n"
    "        }\n"
)
structural_source = original[:first_inner_start] + STRUCTURAL_REPLACEMENT + original[first_inner_end:]
assert structural_source != original
assert "const newIdentity = await this.readPacket();" in structural_source
# the second occurrence must remain exactly as-is (still the original 2-liner)
assert structural_source.count(VULNERABLE_INNER) == 1
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (post-TLS identity must match
# protocolVersion and deviceId of the pre-TLS identity) but validated
# inline within accept(), instead of the real patch's separate
# _exchangeIdentities() method shared by both call sites -- materially
# different structure, not byte-identical to the known fix. Applied only
# to the FIRST occurrence.
SAFE_REPLACEMENT = (
    "            // Starting with protocol version 8, the devices are expected to\n"
    "            // exchange identity packets again after TLS negotiation\n"
    "            if (this.identity.body.protocolVersion >= 8) {\n"
    "                await this.sendPacket(this.backend.identity);\n"
    "                const reExchangedIdentity = await this.readPacket();\n"
    "\n"
    "                if (this.identity.body.protocolVersion !== reExchangedIdentity.body.protocolVersion ||\n"
    "                    this.identity.body.deviceId !== reExchangedIdentity.body.deviceId) {\n"
    "                    this.identity = null;\n"
    "                    throw new Error('Identity mismatch after TLS re-exchange');\n"
    "                }\n"
    "\n"
    "                this.identity = reExchangedIdentity;\n"
    "            }\n"
    "        } catch (e) {\n"
    "            this.close();\n"
    "            throw e;\n"
    "        }\n"
)
safe_source = original[:first_inner_start] + SAFE_REPLACEMENT + original[first_inner_end:]
assert safe_source != original
assert "Identity mismatch after TLS re-exchange" in safe_source
assert safe_source.count(VULNERABLE_INNER) == 1
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a method that also does
# `this.X = await this.readPacket();` with no validation -- the same
# superficial shape as the vulnerable line -- but for a heartbeat packet
# that carries no identity claims and is never used to authenticate or
# authorize anything, so accepting it unconditionally has no security
# consequence.
BENIGN_ADDITION = (
    "\n"
    "    async _updateHeartbeat() {\n"
    "        // Heartbeat packets carry no identity claims and are never used\n"
    "        // to authenticate or authorize anything, unlike the identity\n"
    "        // re-exchange in accept() -- accepting whatever comes back here\n"
    "        // has no security consequence.\n"
    "        this._lastHeartbeat = await this.readPacket();\n"
    "    }\n"
)
anchor = "    async accept(connection) {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "_updateHeartbeat" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)

print("Wrote 4 new samples for CASE-0022.")

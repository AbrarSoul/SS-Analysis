"""
Section 9 ground-truth test bundle: CASE-0021
(Countly/countly-server, CVE-2022-29174, CWE-640 -- weak password recovery
mechanism).

Core vulnerable mechanism: the password-reset token (prid) is derived from
predictable, semi-public data (member.username + member.full_name +
timestamp) via a hash, not a cryptographically random secret. An attacker
who knows a user's username/full name and roughly when a reset was
requested can recompute the same token and hijack the password reset.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0021"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = (
    "        membersUtility.db.collection('members').findOne({\"email\": email}, function(err, member) {\n"
    "            if (member) {\n"
    "                var timestamp = Math.round(new Date().getTime() / 1000),\n"
    "                    prid = sha512Hash(member.username + member.full_name, timestamp);\n"
    "                member.lang = member.lang || req.body.lang || \"en\";\n"
    "                membersUtility.db.collection('password_reset').insert({\"prid\": prid, \"user_id\": member._id, \"timestamp\": timestamp}, {safe: true}, function() {\n"
    "                    countlyMail.sendPasswordResetInfo(member, prid);\n"
    "                    plugins.callMethod(\"passwordRequest\", {req: req, data: req.body}); //used in systemlogs\n"
    "                    callback(member);\n"
    "                });\n"
    "            }\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# Rename prid -> resetToken throughout this callback scope (4 uses). Same
# exact vulnerability: still a predictable hash-based token.
renamed_block = VULNERABLE_BLOCK.replace("prid", "resetToken")
assert "resetToken = sha512Hash" in renamed_block
renamed_source = original.replace(VULNERABLE_BLOCK, renamed_block)
assert renamed_source != original
assert renamed_source.count("resetToken") == 4
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable. Same exact
# vulnerability (still a predictable, non-random token), no renaming.
structural_block = VULNERABLE_BLOCK.replace(
    "                var timestamp = Math.round(new Date().getTime() / 1000),\n"
    "                    prid = sha512Hash(member.username + member.full_name, timestamp);\n",
    "                var timestamp = Math.round(new Date().getTime() / 1000);\n"
    "                var tokenSeed = member.username + member.full_name;\n"
    "                var prid = sha512Hash(tokenSeed, timestamp);\n",
)
assert structural_block != VULNERABLE_BLOCK
structural_source = original.replace(VULNERABLE_BLOCK, structural_block)
assert structural_source != original
assert "var tokenSeed = member.username + member.full_name;" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same fix idea as upstream (CSPRNG-based token) but a different length
# and encoding than the real patch's crypto.randomBytes(32).toString('hex')
# -- still genuinely unpredictable, not byte-identical to the known fix.
safe_block = VULNERABLE_BLOCK.replace(
    "                var timestamp = Math.round(new Date().getTime() / 1000),\n"
    "                    prid = sha512Hash(member.username + member.full_name, timestamp);\n",
    "                var timestamp = Math.round(new Date().getTime() / 1000),\n"
    "                    prid = crypto.randomBytes(24).toString('base64');\n",
)
assert safe_block != VULNERABLE_BLOCK
safe_source = original.replace(VULNERABLE_BLOCK, safe_block)
assert safe_source != original
assert "crypto.randomBytes(24).toString('base64')" in safe_source
assert "sha512Hash(member.username + member.full_name, timestamp)" not in safe_source
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a function that also calls
# sha512Hash(member.username + member.full_name, ...) -- the same
# superficial shape as the vulnerable line -- but the result is used only
# as a cache key for a non-sensitive rendered asset, never to authorize
# any action, so predictability here has no security consequence.
BENIGN_ADDITION = (
    "\n"
    "function buildAvatarCacheKey(member) {\n"
    "    // Only used as a cache key for the user's rendered avatar image;\n"
    "    // guessing or recomputing this value grants no capability, unlike\n"
    "    // prid, which authorizes a password reset.\n"
    "    return sha512Hash(member.username + member.full_name, \"avatar\");\n"
    "}\n"
)
anchor = "membersUtility.forgot = function(req, callback) {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "buildAvatarCacheKey" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)

print("Wrote 4 new samples for CASE-0021.")

"""
Section 9 ground-truth test bundle: CASE-0080
(Yonle/bostr, CVE-2024-41962, CWE-285 improper authorization).

Core vulnerable mechanism: the NIP-42 auth handler rejects a pubkey only
when `!authorized_keys?.includes(pk) && !private_keys[pk] && !noscraper`.
The trailing `&& !noscraper` means that whenever the `noscraper` option
is enabled the "unauthorized" rejection can never fire, so ANY validly
signed challenge response is accepted, even from a pubkey that is not in
the configured allow-lists. The upstream fix drops `noscraper` from the
authorization decision and gates purely on the configured key list.

Every variant is the FULL real file with the exported handler replaced.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0080"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.js").read_text().splitlines()) + "\n"

START = "module.exports = (authKey, data, ws, req) => {"
s = original.index(START)
BLOCK = original[s:]
assert original.count(START) == 1

AUTH_ORIG = """  if (!authorized_keys?.includes(data.pubkey) && !private_keys[data.pubkey] && !noscraper) {
    ws.send(JSON.stringify(["OK", data.id, false, "unauthorized."]));
    return false;
  }
"""
assert AUTH_ORIG in BLOCK


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK
b = b.replace("const tags = Object.fromEntries(data.tags);", "const eventTags = Object.fromEntries(data.tags);")
b = b.replace("tags.relay?.includes", "eventTags.relay?.includes").replace("tags.challenge !==", "eventTags.challenge !==")
for old, new in (("authKey", "challengeToken"), ("data", "authEvent"), ("ws", "socket"), ("req", "request")):
    b = re.sub(r"(?<![.\w])%s\b" % old, new, b)
# `.tags` on the event object is a property access and was skipped by the lookbehind
b = b.replace("authEvent.tags", "authEvent.tags")
assert "!noscraper" in b and "Object.fromEntries(authEvent.tags)" in b
assert not re.search(r"(?<![.\w])(authKey|data|ws|req)\b", b)
(CASE_DIR / "variant_vulnerable_01.js").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
AUTH_STRUCT = """  const isListed = authorized_keys?.includes(data.pubkey) || Boolean(private_keys[data.pubkey]);
  const isPermitted = isListed || noscraper;
  if (!isPermitted) {
    ws.send(JSON.stringify(["OK", data.id, false, "unauthorized."]));
    return false;
  }
"""
(CASE_DIR / "variant_vulnerable_02.js").write_text(build(BLOCK.replace(AUTH_ORIG, AUTH_STRUCT)))

# --- Variant 3: transformed safe variant ---
# The `noscraper` option no longer participates in the authorization
# decision. Whenever ANY allow-list is configured, a pubkey must be in one
# of them (own-property lookup on private_keys). Different formulation from
# the upstream `authorized_keys?.length && !pubkeyInConfig` check.
AUTH_SAFE = """  const anyListConfigured = Boolean(authorized_keys?.length) || Object.keys(private_keys).length > 0;
  const pubkeyListed = Boolean(authorized_keys?.includes(data.pubkey)) ||
    Object.prototype.hasOwnProperty.call(private_keys, data.pubkey);
  if (anyListConfigured && !pubkeyListed) {
    ws.send(JSON.stringify(["OK", data.id, false, "unauthorized."]));
    return false;
  }
"""
(CASE_DIR / "variant_safe_01.js").write_text(build(BLOCK.replace(AUTH_ORIG, AUTH_SAFE)))

# --- Variant 4: benign structural look-alike ---
BENIGN = """"use strict";
const seenPubkeys = new Set();
const pubkeyCache = Object.create(null);

// Same `!a.includes(x) && !b[x] && !flag` shape, but the result only
// decides whether a debug log line is printed. No access-control
// decision depends on it.
function shouldSkipDebugLog(watchedKeys, pubkey, verbose) {
  return !watchedKeys?.includes(pubkey) && !pubkeyCache[pubkey] && !verbose;
}

module.exports = (watchedKeys, pubkey, verbose) => {
  if (shouldSkipDebugLog(watchedKeys, pubkey, verbose)) return;
  seenPubkeys.add(pubkey);
  console.debug("watching pubkey", pubkey);
};
"""
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)

print("Wrote 4 new samples for CASE-0080.")

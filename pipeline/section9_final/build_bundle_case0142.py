"""
Section 9 ground-truth test bundle: CASE-0142
(decolua/9router, src/dashboardGuard.js isLocalRequest, CVE-2026-10269,
CWE-290 authentication bypass by spoofing).

Core vulnerable mechanism: `isLocalRequest(request)` decides "the caller is on
localhost" from the client-supplied `Host` header alone
(`hostname === "localhost" || "127.0.0.1" || "::1"`). Any remote client can
send `Host: localhost` and `proxy()` then waves it through the routes that are
supposed to need a JWT: the always-protected `/api/shutdown` and
`/api/settings/database`, and the settings/keys/provider paths. The upstream
fix deletes isLocalRequest and requires either a valid JWT or a local CLI
token (`x-9r-cli-token`, derived from the machine id).

Sibling site: `proxy()` calls `isLocal` in BOTH protected branches (the
always-protected list and PROTECTED_API_PATHS), so the safe variant removes
the Host trust from both and the vulnerable variants keep both.

Every variant is the FULL real file. isLocalRequest is a module-private
function with one in-file caller (proxy), so the renamed variant renames the
function, its locals and the `isLocal` variable consistently.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0142"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

FN = '''function isLocalRequest(request) {
  const host = request.headers.get("host") || "";
  const hostname = host.split(":")[0];
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}
'''
CALL = "  const isLocal = isLocalRequest(request);\n"
SITE1 = "    if (isLocal || await hasValidToken(request))\n"
SITE2 = "    if (isLocal || await isAuthenticated(request))\n"
IMPORTS = 'import { getSettings } from "@/lib/localDb";\n'
for x in (FN, CALL, SITE1, SITE2, IMPORTS):
    assert original.count(x) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, FN, '''function isLoopbackHost(request) {
  const hostHeader = request.headers.get("host") || "";
  const name = hostHeader.split(":")[0];
  return name === "localhost" || name === "127.0.0.1" || name === "::1";
}
''')
v1 = swap(v1, CALL, "  const fromLoopback = isLoopbackHost(request);\n")
v1 = swap(v1, SITE1, "    if (fromLoopback || await hasValidToken(request))\n")
v1 = swap(v1, SITE2, "    if (fromLoopback || await isAuthenticated(request))\n")
assert "isLocal" not in v1 and v1.count("fromLoopback") == 3
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, FN, '''const LOOPBACK_NAMES = ["localhost", "127.0.0.1", "::1"];

function isLocalRequest(request) {
  const [hostname] = (request.headers.get("host") || "").split(":");
  return LOOPBACK_NAMES.includes(hostname);
}
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The Host header is no longer trusted at either site. A caller must present
# the shared secret from the environment in `x-9r-cli-token` (compared in
# constant time) or a valid JWT; upstream derives the token from the machine id.
v3 = swap(original, IMPORTS, IMPORTS + 'import { timingSafeEqual } from "node:crypto";\n')
v3 = swap(v3, FN, '''function hasValidCliToken(request) {
  const expected = process.env.CLI_AUTH_TOKEN || "";
  const supplied = request.headers.get("x-9r-cli-token") || "";
  if (!expected || supplied.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
}
''')
v3 = swap(v3, CALL, "")
v3 = swap(v3, SITE1, "    if (hasValidCliToken(request) || await hasValidToken(request))\n")
v3 = swap(v3, SITE2, "    if (hasValidCliToken(request) || await isAuthenticated(request))\n")
assert "isLocal" not in v3 and 'get("host")' in v3
(CASE_DIR / "variant_safe_01.js").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''/**
 * Same "read the Host header and compare it to a fixed list" shape as a
 * localhost check, but the result is only ever used to DENY (redirect a
 * request that arrived through a disabled tunnel host); it never grants
 * access to anything, so a spoofed Host header can only make things stricter
 * for the spoofer.
 */
export function arrivedViaBlockedTunnel(request, settings) {
  const host = (request.headers.get("host") || "").split(":")[0].toLowerCase();
  const blocked = [settings.tunnelHost, settings.tailscaleHost]
    .filter(Boolean)
    .map((h) => h.toLowerCase());
  return settings.tunnelDashboardAccess !== true && blocked.includes(host);
}
'''
assert "never grants" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0142.")

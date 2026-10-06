"""
Section 9 ground-truth test bundle: CASE-0284
(seerr-team/seerr, server/routes/auth.ts POST /auth/jellyfin handler,
CVE-2026-27707, CWE-288/CWE-807 authentication bypass via a wrong
"is login enabled" guard).

Core vulnerable mechanism: the Jellyfin login route begins with a guard
meant to refuse Jellyfin logins unless the server is (a) not configured
yet (setup) or (b) configured for Jellyfin/Emby with media-server login
enabled. The guard's second branch,
`mediaServerType !== JELLYFIN && mediaServerType !== EMBY &&
settings.jellyfin.ip !== ''`, only blocks when a Jellyfin IP is ALSO
configured. On an instance configured for Plex (or any other non-Jellyfin
type) that has never had a Jellyfin host set (`jellyfin.ip === ''`), the
guard evaluates false and the request proceeds, even though Jellyfin login
is not meant to be available. The handler then accepts a
`hostname`/credentials from the request body and authenticates against
whatever Jellyfin server the caller names, creating/logging in a local user
-- an unauthenticated attacker can point it at a Jellyfin server they
control and obtain a session on a Plex-only Seerr instance. The upstream fix
drops the `&& settings.jellyfin.ip !== ''` term so a non-Jellyfin/Emby
server always refuses.

Sibling sites: the same "is X login enabled" guard shape exists for Plex at
line ~62 with different (correct) semantics; this Jellyfin guard is the one
site.

Verification: the guard's boolean expression is extracted verbatim from
each full file's `authRoutes.post('/jellyfin', ...)` handler (for the
helper-extracted variant, from the helper function, with TypeScript types
stripped via Node's stripTypeScriptTypes) and evaluated in Node for the
attack configuration `{mediaServerType: PLEX, mediaServerLogin: true,
jellyfin.ip: ''}` (plus two controls: a Jellyfin-configured server with
login enabled must NOT be blocked; a Plex server that HAS a Jellyfin ip
must be blocked in every variant).

Every variant is the FULL real file. The route path/handler shape is kept;
the renamed variant renames the handler-local `settings`.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0284"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


GUARD = '''  if (
    // media server not configured, allow login for setup
    settings.main.mediaServerType != MediaServerType.NOT_CONFIGURED &&
    (settings.main.mediaServerLogin === false ||
      // media server is neither jellyfin or emby
      (settings.main.mediaServerType !== MediaServerType.JELLYFIN &&
        settings.main.mediaServerType !== MediaServerType.EMBY &&
        settings.jellyfin.ip !== ''))
  ) {
    return res.status(500).json({ error: 'Jellyfin login is disabled' });
  }
'''
assert original.count(GUARD) == 1

# --- Variant 1: renamed vulnerable variant (handler-local `settings`) ---
hs = original.index("authRoutes.post('/jellyfin', async (req, res, next) => {")
he = original.index("\nauthRoutes.", hs + 10)
region = original[hs:he]
new_region = re.sub(r"\bsettings\b", "appSettings", region)
assert new_region != region
(CASE_DIR / "variant_vulnerable_01.ts").write_text(original[:hs] + new_region + original[he:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, GUARD, '''  if (isJellyfinLoginDisabled(settings)) {
    return res.status(500).json({ error: 'Jellyfin login is disabled' });
  }
''')
v2 = swap(v2, "authRoutes.post('/jellyfin', async (req, res, next) => {", '''// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isJellyfinLoginDisabled(settings: any): boolean {
  return (
    // media server not configured, allow login for setup
    settings.main.mediaServerType != MediaServerType.NOT_CONFIGURED &&
    (settings.main.mediaServerLogin === false ||
      // media server is neither jellyfin or emby
      (settings.main.mediaServerType !== MediaServerType.JELLYFIN &&
        settings.main.mediaServerType !== MediaServerType.EMBY &&
        settings.jellyfin.ip !== ''))
  );
}

authRoutes.post('/jellyfin', async (req, res, next) => {''')
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, GUARD, '''  const isSetupMode =
    settings.main.mediaServerType == MediaServerType.NOT_CONFIGURED;
  const isJellyfinOrEmby =
    settings.main.mediaServerType === MediaServerType.JELLYFIN ||
    settings.main.mediaServerType === MediaServerType.EMBY;
  if (
    !isSetupMode &&
    (settings.main.mediaServerLogin === false || !isJellyfinOrEmby)
  ) {
    return res.status(500).json({ error: 'Jellyfin login is disabled' });
  }
''')
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

(CASE_DIR / "benign_lookalike.ts").write_text('''// Standalone example of the same shape: decide whether to show a "connect
// your account" hint in the UI based on the configured server type and
// whether a host is set -- purely presentational; the actual login route is
// guarded separately.
export function shouldShowConnectHint(
  serverType: 'plex' | 'jellyfin' | 'none',
  hostConfigured: boolean
): boolean {
  return serverType !== 'none' && !hostConfigured;
}
''')

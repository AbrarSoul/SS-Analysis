r"""
Section 9 ground-truth test bundle: CASE-0332
(whyour/qinglong, back/loaders/express.ts init-guard middleware,
CVE-2026-3965, CWE-693 protection mechanism failure).

Core vulnerable mechanism: Qinglong protects its one-time setup endpoints
(`/api/user/init`, `/api/user/notification/init`, which set the admin
credentials on a fresh install) with a middleware that answers `450` once the
panel is initialised. The middleware only recognises the `/api/...` spelling.
Requests to the equivalent `/open/user/init` and
`/open/user/notification/init` (the "open API" alias) pass straight through the
guard, are rewritten to `/api/...` by `app.use(rewrite('/open/*', '/api/$1'))`
further down, and reach the real init handlers on an ALREADY initialised
panel: an attacker can re-run initialisation and overwrite the administrator
credentials (account takeover). The fix lists the `/open/...` spellings in
the guard as well.

Sibling sites: the earlier auth middleware has a matching `/open/` branch; the
init guard did not.

Verification (REAL express + express-urlrewrite): the guard middleware is
sliced from each full file (from `app.use(async (req, res, next) => {` before
the `user/init` list through its closing `});`), type-stripped with node's
`stripTypeScriptTypes`, and mounted in a real express 4 app configured like
the loader (case-sensitive and strict routing) with a stub `shareStore` and
the same `rewrite('/open/*', '/api/$1')` and an `/api/user/init` handler that
answers `HANDLER-REACHED`. With the panel initialised (auth info holds a real
user), `GET /open/user/init` and `/open/user/notification/init` reach the
handler for vulnerable variants and get `450` for patched/safe;
`/api/user/init` gets `450` in every file; with the panel NOT initialised
(default `admin/admin`) `/api/user/init` reaches the handler in every file.

Every variant is the FULL real file; the loader is a default export that the
server calls, and stays.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0332"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
patched = (CASE_DIR / "patched_source.ts").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


def guard(text):
    k = text.index("'/api/user/init'")
    a = text.rindex("  app.use(async (req, res, next) => {\n", 0, k)
    b = text.index("\n  });\n", a) + len("\n  });\n")
    return text[a:b]


g = guard(original)
assert "authInfo" in g and g.count("pathLower") == 2

# --- Variant 1: renamed vulnerable variant (locals of the guard renamed) ---
g1 = g
for old, new in [("pathLower", "lowered"), ("authInfo", "storedAuth"), ("isInitialized", "alreadySetUp")]:
    g1 = re.sub(r"(?<![\w.'\"])%s(?![\w'\"])" % old, new, g1)
assert "alreadySetUp" in g1 and "storedAuth.username" in g1
v1 = original.replace(g, g1)
(CASE_DIR / "variant_vulnerable_01.ts").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (guarded list hoisted to a constant before the middleware) ---
LIST = "    if (!['/api/user/init', '/api/user/notification/init'].includes(pathLower)) {\n"
g2 = swap(g, LIST, "    if (!INIT_PATHS.includes(pathLower)) {\n")
v2 = original.replace(g, "  const INIT_PATHS = ['/api/user/init', '/api/user/notification/init'];\n" + g2)
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the list becomes a Set constant) ---
pg = guard(patched)
PLIST = '''    if (
      ![
        '/api/user/init',
        '/api/user/notification/init',
        '/open/user/init',
        '/open/user/notification/init',
      ].includes(req.path)
    ) {
'''
pg3 = swap(pg, PLIST, "    if (!INIT_GUARDED_PATHS.has(req.path)) {\n")
set_decl = '''  const INIT_GUARDED_PATHS = new Set([
    '/api/user/init',
    '/api/user/notification/init',
    '/open/user/init',
    '/open/user/notification/init',
  ]);
'''
v3 = patched.replace(pg, set_decl + pg3)
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

(CASE_DIR / "benign_lookalike.ts").write_text('''import { Application, Request, Response, NextFunction } from 'express';

// Setup-endpoint guard for a panel that exposes ONLY the /api prefix (no /open alias and no rewrite),
// so listing the /api spellings is a complete guard.
export function guardSetup(app: Application, isInitialized: () => Promise<boolean>) {
  app.use(async (req: Request, res: Response, next: NextFunction) => {
    if (!['/api/setup', '/api/setup/notification'].includes(req.path)) {
      return next();
    }
    if (await isInitialized()) {
      return res.send({ code: 450, message: 'unknown error' });
    }
    return next();
  });
}
''')

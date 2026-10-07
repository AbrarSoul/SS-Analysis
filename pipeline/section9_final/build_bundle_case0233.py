"""
Section 9 ground-truth test bundle: CASE-0233
(mrvautin/expressCart, routes/user.js POST /admin/user/insert,
CVE-2018-12457, CWE-732 incorrect permission assignment / privilege
escalation).

Core vulnerable mechanism: the route decides whether the new account is an
administrator from the HTTP Referer header:
`if (url.parse(req.header('Referer')).path === '/admin/setup') isAdmin = true`.
The header is chosen by the client, so any logged-in user, including a
non-admin, can POST `/admin/user/insert` with `Referer: http://shop/admin/setup`
and create a new account with `isAdmin: true`. The upstream fix counts existing
users and grants admin only when there are none (`userCount === 0`).

Measured caveat, kept in the manifest notes: both versions still call
`url.parse(req.header('Referer'))` before anything else, so a request with no
Referer header at all makes `url.parse(undefined)` throw and the handler fails,
and the upstream patch still uses the Referer to decide whether to log the new
user in (`session.user = ...`) after insert.

Sibling sites: the same Referer test appears twice in this handler (the isAdmin
decision and the post-insert "from setup" redirect). The safe variant
derives both from the user count instead of the header.

Verification: the route is extracted verbatim from each full file and mounted on
a REAL Express 4 app (real `url`, real Router) with stand-ins for `common.restrict`
(requires a logged-in session user), `bcryptjs` and an in-memory `db.users`
(count / findOne / insert). A logged-in NON-admin user posts with a forged
`Referer: http://shop.example/admin/setup` while one user already exists; a
first-run request (no users) is posted as the control.

Every variant is the FULL real file. `router.post('/admin/user/insert', ...)` is
registered on the exported router, so nothing but the handler body changes.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0233"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


s = original.index("// insert a user\nrouter.post('/admin/user/insert'")
e = original.index("\nmodule.exports = router;")
ROUTE = original[s:e]
assert original.count(ROUTE) == 1

# --- Variant 1: renamed vulnerable variant ---
r1 = ROUTE.replace("urlParts", "refererParts")
r1 = swap(r1, "    let doc = {\n", "    let newUser = {\n")
r1 = swap(r1, "db.users.insert(doc, (err, doc) => {", "db.users.insert(newUser, (err, doc) => {")
assert "urlParts" not in r1
(CASE_DIR / "variant_vulnerable_01.js").write_text(original[:s] + r1 + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
r2 = swap(ROUTE, '''    let urlParts = url.parse(req.header('Referer'));

    let isAdmin = false;
    if(urlParts.path === '/admin/setup'){
        isAdmin = true;
    }
''', '''    let urlParts = url.parse(req.header('Referer'));

    const isAdmin = isSetupPage(urlParts);
''')
r2 = swap(r2, "            if(urlParts.path === '/admin/setup'){\n                req.session.user", "            if(isSetupPage(urlParts)){\n                req.session.user")
r2 = swap(r2, "// insert a user\n", '''const isSetupPage = (urlParts) => urlParts.path === '/admin/setup';

// insert a user
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(original[:s] + r2 + original[e:])

# --- Variant 3: transformed safe variant ---
r3 = swap(ROUTE, '''    // set the account to admin if using the setup form. Eg: First user account
    let urlParts = url.parse(req.header('Referer'));

    let isAdmin = false;
    if(urlParts.path === '/admin/setup'){
        isAdmin = true;
    }

    let doc = {''', '''    db.users.count({}, (countErr, userCount) => {
        // only the very first account becomes an administrator; the Referer header is not consulted
        const isAdmin = !countErr && userCount === 0;
        insertUser(req, res, db, isAdmin);
    });
});

function insertUser(req, res, db, isAdmin){
    let doc = {''')
r3 = swap(r3, "            if(urlParts.path === '/admin/setup'){\n                req.session.user", "            if(isAdmin){\n                req.session.user")
# the handler body that followed is now the body of insertUser; its closing "});" becomes "}"
assert r3.rstrip().endswith("});\n    });\n});") or r3.rstrip().endswith("});")
r3 = r3.rstrip()
assert r3.endswith("    });\n});")
r3 = r3[: -len("});")] + "}\n"
(CASE_DIR / "variant_safe_01.js").write_text(original[:s] + r3 + original[e:])

BENIGN = '''// Standalone example of the same shape: the role of a newly created account
// is derived from server-side state (how many accounts exist), never from a
// client-controlled header.
function isFirstAccount(userCount) {
    return userCount === 0;
}

function roleForNewAccount(userCount) {
    return isFirstAccount(userCount) ? 'owner' : 'member';
}

module.exports = { roleForNewAccount };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)

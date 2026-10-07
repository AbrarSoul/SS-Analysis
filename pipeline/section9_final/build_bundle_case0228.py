"""
Section 9 ground-truth test bundle: CASE-0228
(misskey-dev/misskey, packages/frontend/src/account.ts login / fetchAccount,
CVE-2025-24897, CWE-614 / CWE-352 sensitive cookie without the Secure /
SameSite attributes).

Core vulnerable mechanism: after a login `login()` stores the user's API token
in a long-lived cookie for the queue dashboard:
`document.cookie = \\`token=${token}; path=/; max-age=31536000\\``. The cookie is
scoped to the whole site (`path=/`), has no `SameSite` and no `Secure`
attribute and lives a year. The browser therefore attaches the bearer token to
EVERY request to the origin, including cross-site requests forged by another
page and plain-HTTP requests, so a request the server authenticates from the
cookie (the dashboard does) can be triggered by any site the user visits.
The upstream fix (i) deletes the old cookie, (ii) sets it only for
`path=/queue` with `SameSite=Strict; Secure` and a one-day lifetime, and moves
that into `fetchAccount` so it also runs on refresh, and removes the line from
`login()`.

Sibling sites: the single `document.cookie =` in the file is the one in login();
`fetchAccount` is where the fix adds the replacement, which is why the
auto-located target function is fetchAccount.

Verification: from each full file the statements that touch `document.cookie`
(the prelude of `fetchAccount`, the line in `login`, and the safe variant's
`setQueueCookie` helper) are evaluated in the order a login performs them against a
fake `document`, and every cookie string written is fed to the REAL `tough-cookie`
package; the jar is then asked which requests would carry the token:
cross-site `https://misskey.example/api/i`, same-site `/queue` and plain-HTTP `/api/i`.

Every variant is the FULL real file. `login` and `fetchAccount` are called by name
from the rest of the frontend, so their names and signatures are kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0228"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


LOGIN_LINE = "\tdocument.cookie = `token=${token}; path=/; max-age=31536000`; // bull dashboardの認証とかで使う\n"
assert original.count(LOGIN_LINE) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, LOGIN_LINE, "\tconst dashboardCookie = `token=${token}; path=/; max-age=31536000`; // bull dashboardの認証とかで使う\n\tdocument.cookie = dashboardCookie;\n")
(CASE_DIR / "variant_vulnerable_01.ts").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, LOGIN_LINE, "\twriteDashboardCookie(token); // bull dashboardの認証とかで使う\n")
v2 = swap(v2, "export async function login(", '''function writeDashboardCookie(token: string) {
	document.cookie = `token=${token}; path=/; max-age=31536000`;
}

export async function login(''')
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, LOGIN_LINE, "")
v3 = swap(v3, "function fetchAccount(token: string, id?: string, forceShowDialog?: boolean): Promise<Account> {\n",
          "function fetchAccount(token: string, id?: string, forceShowDialog?: boolean): Promise<Account> {\n\tsetQueueCookie(token);\n")
v3 = swap(v3, "function fetchAccount(", '''// The queue dashboard authenticates from this cookie: scope it to /queue, never send it
// cross-site or over plain HTTP, and keep it for a day. Also drop the old site-wide cookie.
function setQueueCookie(token: string) {
	document.cookie = 'token=; path=/; max-age=0';
	document.cookie = `token=${token}; path=/queue; max-age=86400; SameSite=Strict; Secure`;
}

function fetchAccount(''')
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

BENIGN = '''// Standalone example of the same shape: a UI preference cookie that carries
// no credential, so a site-wide path and a long lifetime are fine.
export function rememberTheme(theme: 'light' | 'dark') {
	document.cookie = `theme=${theme}; path=/; max-age=31536000; SameSite=Lax`;
}
'''
(CASE_DIR / "benign_lookalike.ts").write_text(BENIGN)

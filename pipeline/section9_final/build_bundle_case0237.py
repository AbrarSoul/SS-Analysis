"""
Section 9 ground-truth test bundle: CASE-0237
(new-usemame/Calibre-Web-NextGen, cps/kobo_auth.py generate_auth_token,
CVE-2026-7713, CWE-266 / CWE-285 insecure direct object reference).

Core vulnerable mechanism: `GET /kobo_auth/generate_auth_token/<int:user_id>` is
protected only by `@user_login_required`, and the numeric `user_id` in the URL
is used directly to look up (or create) that user's Kobo sync token and to
return it in the rendered page. Any logged-in user can request another
user's id and walk away with a token that authorises Kobo sync as that user.
The upstream fix adds `if current_user.id != user_id and not
current_user.role_admin(): abort(403)`.

Sibling sites: `POST /kobo_auth/deleteauthtoken/<int:user_id>` in the same file
has the same unchecked id and deletes the Kobo token of whichever user is named,
which locks the victim out of sync. The upstream patch guards both routes; the
auto-located target is only generate_auth_token, so the vulnerable variants leave
both unchanged and the safe variant guards both.

Verification: the two routes are extracted verbatim from each full file and
registered on a REAL Flask 3 blueprint with stand-ins for `user_login_required`
(needs an X-User header), `current_user` (a proxy to the request's user with
`role_admin()`), and an in-memory `ub` (a tiny query/filter/first/delete layer
over a list of RemoteAuthToken rows). Requests are made with Flask's test client
as alice (id 1, owner of a token), bob (id 2, non-admin) and an admin (id 3).

Every variant is the FULL real file. The route functions are registered by Flask
under their names (endpoint names), so their names are kept; the renamed
variant renames locals of generate_auth_token.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0237"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


GEN_HEAD = '''def generate_auth_token(user_id):
    warning = False
'''
DEL_HEAD = '''def delete_auth_token(user_id):
    # Invalidate any previously generated Kobo Auth token for this user
'''
assert original.count(GEN_HEAD) == 1 and original.count(DEL_HEAD) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("def generate_auth_token(user_id):")
e = original.index('@kobo_auth.route("/deleteauthtoken')
seg = original[s:e]
seg = seg.replace("warning = False", "localhost_warning = False").replace("warning = _(", "localhost_warning = _(").replace("warning=warning", "warning=localhost_warning")
seg = re.sub(r"\bhost_list\b", "host_parts", seg)
assert "localhost_warning" in seg and "host_parts" in seg and "host_list" not in seg
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + seg + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
TOKEN = '''    # Generate auth token if none is existing for this user
    auth_token = ub.session.query(ub.RemoteAuthToken).filter(
        ub.RemoteAuthToken.user_id == user_id
    ).filter(ub.RemoteAuthToken.token_type==1).first()

    if not auth_token:
        auth_token = ub.RemoteAuthToken()
        auth_token.user_id = user_id
        auth_token.expiration = datetime.max
        auth_token.auth_token = (hexlify(urandom(16))).decode("utf-8")
        auth_token.token_type = 1

        ub.session.add(auth_token)
        ub.session_commit()
'''
assert original.count(TOKEN) == 1
v2 = swap(original, TOKEN, "    auth_token = _get_or_create_kobo_token(user_id)\n")
v2 = swap(v2, '@kobo_auth.route("/generate_auth_token/<int:user_id>")', '''def _get_or_create_kobo_token(user_id):
    auth_token = ub.session.query(ub.RemoteAuthToken).filter(
        ub.RemoteAuthToken.user_id == user_id
    ).filter(ub.RemoteAuthToken.token_type==1).first()

    if not auth_token:
        auth_token = ub.RemoteAuthToken()
        auth_token.user_id = user_id
        auth_token.expiration = datetime.max
        auth_token.auth_token = (hexlify(urandom(16))).decode("utf-8")
        auth_token.token_type = 1

        ub.session.add(auth_token)
        ub.session_commit()
    return auth_token


@kobo_auth.route("/generate_auth_token/<int:user_id>")''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, GEN_HEAD, '''def generate_auth_token(user_id):
    _require_self_or_admin(user_id)
    warning = False
''')
v3 = swap(v3, DEL_HEAD, '''def delete_auth_token(user_id):
    _require_self_or_admin(user_id)
    # Invalidate any previously generated Kobo Auth token for this user
''')
v3 = swap(v3, '@kobo_auth.route("/generate_auth_token/<int:user_id>")', '''def _require_self_or_admin(user_id):
    """A Kobo token may only be minted or revoked by its owner or by an administrator."""
    if current_user.id != user_id and not current_user.role_admin():
        abort(403)


@kobo_auth.route("/generate_auth_token/<int:user_id>")''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: a per-user route that takes an id from
the URL but compares it with the logged-in user before doing anything."""
from flask import abort


def read_own_preferences(user_id, current_user, store):
    if current_user.id != user_id:
        abort(403)
    return store.get(user_id, {})
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)

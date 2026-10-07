"""
Section 9 ground-truth test bundle: CASE-0274
(pyload/pyload, src/pyload/webui/app/blueprints/json_blueprint.py
update_users, CVE-2026-41133, CWE-613 insufficient session expiration).

Core vulnerable mechanism: `update_users` lets an admin change another
user's role (promote/demote admin) and permission set, and
`change_password` lets an admin force-change a user's password (e.g.
because the account looks compromised) -- but neither function
invalidates that user's EXISTING, already-logged-in sessions. A user
whose admin role was just revoked keeps acting as an admin in their
current browser session until it naturally expires; a user whose password
was changed specifically to lock out a suspected attacker leaves that
attacker's already-established session fully valid, defeating the whole
point of the password change. The upstream fix calls a new
`clear_all_user_sessions(name)` helper (imported from `..helpers`)
whenever a user's password changes, is deleted, or their role/permission
set actually changes (`update_users` tracks this with a `was_changed`
flag so it only clears sessions on a REAL change, not a no-op update).

Sibling sites: `change_password` has the identical missing-invalidation
defect and is fixed in the same commit; the safe variant fixes both,
matching upstream's scope. `update_users`'s own delete branch is a THIRD
site within the same function.

Verification: each full file's `update_users` and `change_password`
function bodies (decorators stripped, since `login_required`/
`expect_json`/route registration are unrelated to the session-invalidation
defect) are extracted verbatim and run as real Python with stand-ins for
`flask.current_app`/`flask.session`, `get_permission`/`set_permission`/
`permlist`, and a recording `clear_all_user_sessions` stub. `update_users`
is called with data that promotes a non-self user to admin (a real role
change); `change_password` is called for a successful password change.
The recorder shows whether `clear_all_user_sessions` was invoked for the
affected user in each case.

Every variant is the FULL real file. `update_users`/`change_password` are
registered as Flask routes by the app's blueprint system
(`bp.route("/json/update_users", ...)`), so their names and signatures are
kept; the renamed variant renames their own locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0274"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


CHANGE_PW = '''def change_password(user_login, user_curpw, user_newpw):
    api = flask.current_app.config["PYLOAD_API"]
    done = api.change_password(user_login, user_curpw, user_newpw)
    if not done:
        return jsonify(False), 403  #: Wrong password

    return jsonify(True)'''
assert original.count(CHANGE_PW) == 1

UPDATE_USERS = '''def update_users(update_data):
    api = flask.current_app.config["PYLOAD_API"]

    all_users = api.get_all_userdata()

    users = {}

    # NOTE: messy code...
    for userdata in all_users.values():
        name = userdata.name
        users[name] = {"perms": get_permission(userdata.permission)}
        users[name]["perms"]["admin"] = userdata.role == 0
        users[name]["role"] = userdata.role

    s = flask.session
    for name in list(users):
        data = users[name]
        if update_data.get(f"{name}|delete"):
            if name != s["name"]:
                api.remove_user(name)
                del users[name]
            continue
        if update_data.get(f"{name}|admin"):
            data["role"] = 0
            data["perms"]["admin"] = True
        elif name != s["name"]:
            data["role"] = 1
            data["perms"]["admin"] = False

        # set all perms to false
        for perm in permlist():
            data["perms"][perm] = False

        for perm in update_data.get(f"{name}|perms", []):
            data["perms"][perm] = True

        data["permission"] = set_permission(data["perms"])

        api.set_user_permission(name, data["permission"], data["role"])

    return jsonify(True)'''
assert original.count(UPDATE_USERS) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, CHANGE_PW, '''def change_password(user_login, user_curpw, user_newpw):
    pyload_api = flask.current_app.config["PYLOAD_API"]
    ok = pyload_api.change_password(user_login, user_curpw, user_newpw)
    if not ok:
        return jsonify(False), 403  #: Wrong password

    return jsonify(True)''')
v1 = swap(v1, UPDATE_USERS, '''def update_users(update_data):
    api = flask.current_app.config["PYLOAD_API"]

    all_users = api.get_all_userdata()

    user_table = {}

    # NOTE: messy code...
    for userdata in all_users.values():
        uname = userdata.name
        user_table[uname] = {"perms": get_permission(userdata.permission)}
        user_table[uname]["perms"]["admin"] = userdata.role == 0
        user_table[uname]["role"] = userdata.role

    s = flask.session
    for uname in list(user_table):
        entry = user_table[uname]
        if update_data.get(f"{uname}|delete"):
            if uname != s["name"]:
                api.remove_user(uname)
                del user_table[uname]
            continue
        if update_data.get(f"{uname}|admin"):
            entry["role"] = 0
            entry["perms"]["admin"] = True
        elif uname != s["name"]:
            entry["role"] = 1
            entry["perms"]["admin"] = False

        # set all perms to false
        for perm in permlist():
            entry["perms"][perm] = False

        for perm in update_data.get(f"{uname}|perms", []):
            entry["perms"][perm] = True

        entry["permission"] = set_permission(entry["perms"])

        api.set_user_permission(uname, entry["permission"], entry["role"])

    return jsonify(True)''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CHANGE_PW, '''def _apply_password_change(api, user_login, user_curpw, user_newpw):
    return api.change_password(user_login, user_curpw, user_newpw)


def change_password(user_login, user_curpw, user_newpw):
    api = flask.current_app.config["PYLOAD_API"]
    done = _apply_password_change(api, user_login, user_curpw, user_newpw)
    if not done:
        return jsonify(False), 403  #: Wrong password

    return jsonify(True)''')
v2 = swap(v2, UPDATE_USERS, '''def _apply_role_update(api, s, name, data, update_data):
    if update_data.get(f"{name}|admin"):
        data["role"] = 0
        data["perms"]["admin"] = True
    elif name != s["name"]:
        data["role"] = 1
        data["perms"]["admin"] = False


def update_users(update_data):
    api = flask.current_app.config["PYLOAD_API"]

    all_users = api.get_all_userdata()

    users = {}

    # NOTE: messy code...
    for userdata in all_users.values():
        name = userdata.name
        users[name] = {"perms": get_permission(userdata.permission)}
        users[name]["perms"]["admin"] = userdata.role == 0
        users[name]["role"] = userdata.role

    s = flask.session
    for name in list(users):
        data = users[name]
        if update_data.get(f"{name}|delete"):
            if name != s["name"]:
                api.remove_user(name)
                del users[name]
            continue
        _apply_role_update(api, s, name, data, update_data)

        # set all perms to false
        for perm in permlist():
            data["perms"][perm] = False

        for perm in update_data.get(f"{name}|perms", []):
            data["perms"][perm] = True

        data["permission"] = set_permission(data["perms"])

        api.set_user_permission(name, data["permission"], data["role"])

    return jsonify(True)''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (clear the affected user's sessions on a
# real password change, deletion, or role/permission change) but the
# "did anything actually change" tracking is computed via a before/after
# tuple comparison instead of upstream's was_changed boolean flag.
v3 = swap(original, CHANGE_PW, '''def change_password(user_login, user_curpw, user_newpw):
    api = flask.current_app.config["PYLOAD_API"]
    done = api.change_password(user_login, user_curpw, user_newpw)
    if not done:
        return jsonify(False), 403  #: Wrong password

    clear_all_user_sessions(user_login)
    return jsonify(True)''')
v3 = swap(v3, UPDATE_USERS, '''def update_users(update_data):
    api = flask.current_app.config["PYLOAD_API"]

    all_users = api.get_all_userdata()

    users = {}

    # NOTE: messy code...
    for userdata in all_users.values():
        name = userdata.name
        users[name] = {
            "permission": userdata.permission,
            "perms": get_permission(userdata.permission)
        }
        users[name]["perms"]["admin"] = userdata.role == 0
        users[name]["role"] = userdata.role

    s = flask.session
    for name in list(users):
        data = users[name]
        before = (data["role"], data["permission"])
        if update_data.get(f"{name}|delete"):
            if name != s["name"]:
                api.remove_user(name)
                del users[name]
                clear_all_user_sessions(name)
            continue
        if update_data.get(f"{name}|admin"):
            data["role"] = 0
            data["perms"]["admin"] = True
        elif name != s["name"]:  #: deny removing 'self' admin role
            data["role"] = 1
            data["perms"]["admin"] = False

        # set all perms to false
        for perm in permlist():
            data["perms"][perm] = False

        for perm in update_data.get(f"{name}|perms", []):
            data["perms"][perm] = True

        data["permission"] = set_permission(data["perms"])

        api.set_user_permission(name, data["permission"], data["role"])
        after = (data["role"], data["permission"])
        if after != before:
            clear_all_user_sessions(name)

    return jsonify(True)''')
v3 = swap(v3, "from ..helpers import get_permission, login_required, permlist, render_template, set_permission",
          "from ..helpers import clear_all_user_sessions, get_permission, login_required, permlist, render_template, set_permission")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""
Standalone example of the same shape: after updating a user's DISPLAY
preferences (timezone, locale), invalidate a purely cosmetic cached
render of their dashboard so it regenerates with the new settings on
next view -- a UX freshness concern, not a security boundary, unlike
invalidating a session after a privilege change.
"""


def update_display_prefs(cache, user, timezone, locale):
    user.timezone = timezone
    user.locale = locale
    cache.pop(f"dashboard:{user.name}", None)
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)

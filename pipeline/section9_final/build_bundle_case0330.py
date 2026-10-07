r"""
Section 9 ground-truth test bundle: CASE-0330
(wekan/wekan, models/boards.js POST /api/boards route and the Boards
allow/deny rules, CVE-2026-25568, CWE-863 incorrect authorization).

Core vulnerable mechanism: Wekan has an admin setting
`tableVisibilityMode-allowPrivateOnly` meaning "users may only create private
boards". The setting was only enforced in the web UI. On the server, the
`POST /api/boards` REST route stores `permission: req.body.permission ||
'private'` (so a client sending `permission: 'public'` creates a public
board), the `Boards.allow({ insert: Meteor.userId })` rule accepts any logged-in
user's insert (including permission 'public'), and no deny rule blocks a
later `$set: { permission: 'public' }` update. Any authenticated user can
therefore create or expose public boards even when the administrator forbade
it. The upstream fix reads the setting and forces `private` in the REST route,
adds an insert allow rule that rejects public boards when the setting is on,
and adds a `Boards.deny` update rule for changes to `public`.

Sibling sites: the three enforcement points (REST insert, Meteor allow insert,
deny update) are the same policy applied to three write paths.

Verification: the full 2,540-line file is evaluated with node's `vm`-style
`with` scope under a permissive ambient global (unknown Meteor/Mongo/
SimpleSchema globals are no-op stand-ins; `Mongo.Collection` records
`insert`, `allow` and `deny` calls). `TableVisibilityModeSettings.findOne`
returns `{ booleanValue: true }` (allow-private-only ON). Probes: (a) `POST
/api/boards` with `permission: 'public'` and the recorded permission of the
inserted board; (b) the recorded `allow` rule's `insert(userId, {permission:
'public'})` result; (c) whether any recorded `deny.update` rule blocks
`$set: { permission: 'public' }`. Vulnerable variants insert `public`, allow
the insert and block nothing; patched/safe insert `private`, refuse the
insert and block the update. With the setting OFF a public board is created
in every file.

Every variant is the FULL real file; the REST route path and the collection
rules are the API and stay.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0330"
original = (CASE_DIR / "vulnerable_source.js").read_text()
patched = (CASE_DIR / "patched_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


ROUTE_START = "  JsonRoutes.add('POST', '/api/boards', function(req, res) {\n"
a = original.index(ROUTE_START)
b = original.index("  /**\n   * @operation delete_board", a)
route = original[a:b]

# --- Variant 1: renamed vulnerable variant (locals of the POST route renamed) ---
r1 = route.replace("const id = Boards.insert(", "const newBoardId = Boards.insert(").replace("const swimlaneId =", "const defaultLaneId =")
r1 = r1.replace("boardId: id,", "boardId: newBoardId,").replace("_id: id,", "_id: newBoardId,").replace("defaultSwimlaneId: swimlaneId,", "defaultSwimlaneId: defaultLaneId,")
assert "swimlaneId," not in r1.replace("defaultSwimlaneId", "") and "newBoardId" in r1
v1 = original.replace(route, r1)
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (requested permission computed by a helper; no setting check) ---
v2 = swap(original, "        permission: req.body.permission || 'private',\n", "        permission: requestedPermission(req),\n")
v2 = swap(v2, "Boards.labelColors = () => {\n  return ALLOWED_COLORS;\n};\n",
          "Boards.labelColors = () => {\n  return ALLOWED_COLORS;\n};\n\nfunction requestedPermission(req) {\n  return req.body.permission || 'private';\n}\n")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the permission computation moves into a helper) ---
PP = '''      const allowPrivateOnly = TableVisibilityModeSettings.findOne('tableVisibilityMode-allowPrivateOnly')?.booleanValue;
      const permission = allowPrivateOnly ? 'private' : (req.body.permission || 'private');
'''
v3 = swap(patched, PP, "      const permission = effectivePermission(req);\n")
v3 = swap(v3, "Boards.labelColors = () => {\n  return ALLOWED_COLORS;\n};\n",
          "Boards.labelColors = () => {\n  return ALLOWED_COLORS;\n};\n\nfunction effectivePermission(req) {\n  const allowPrivateOnly = TableVisibilityModeSettings.findOne('tableVisibilityMode-allowPrivateOnly')?.booleanValue;\n  return allowPrivateOnly ? 'private' : (req.body.permission || 'private');\n}\n")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''// Board-template creation: the permission is fixed by the server, never taken from the request.
if (Meteor.isServer) {
  JsonRoutes.add('POST', '/api/board-templates', function(req, res) {
    Authentication.checkLoggedIn(req.userId);
    const id = Boards.insert({
      title: req.body.title,
      members: [{ userId: req.userId, isAdmin: true, isActive: true }],
      permission: 'private',
      type: 'template-board',
    });
    JsonRoutes.sendResult(res, { code: 200, data: { _id: id } });
  });
}
''')

r"""
Section 9 ground-truth test bundle: CASE-0329
(wekan/wekan, models/customFields.js REST custom-field routes,
CVE-2026-30843, CWE-639 authorization bypass through user-controlled key).

Core vulnerable mechanism: the `/api/boards/:boardId/custom-fields/:customFieldId`
routes (PUT edit, POST/PUT/DELETE dropdown items) authorise the caller for the
board in the URL (`Authentication.checkBoardAccess(req.userId, boardId)`), but
then update the custom field by `_id` ALONE (`CustomFields.direct.update({ _id:
customFieldId }, ...)`). A user with access to any board (their own) can
put another board's custom-field id in the URL and modify or delete
dropdown items of custom fields on boards they cannot access (insecure direct
object reference). The upstream fix scopes every update selector to the
authorised board (`boardIds: { $in: [boardId] }`), and also declares the
implicit-global `paramCustomFieldId`/`paramDropdownItemId` in the delete
route with `const`.

Sibling sites: the file's delete-field route already scopes by board
(`CustomFields.remove({ _id: id, boardIds: { $in: [paramBoardId] } })`);
the four update/dropdown routes did not.

Verification (REAL query/update engine): the full file is evaluated with
node's `vm` under a permissive ambient global (unknown globals such as
`SimpleSchema`, `Meteor`, `Mongo` are no-op stand-ins), with `JsonRoutes.add`
captured, `Authentication.checkBoardAccess` allowing user u1 only on board B1,
and `CustomFields.direct.update` implemented with the real `mingo`
MongoDB query/update library over two custom fields (f1 on B1, f2 on B2).
Calls: PUT `/api/boards/B1/custom-fields/f2` with `{name: 'HACKED'}` and DELETE
`/api/boards/B1/custom-fields/f2/dropdown-items/d2` as u1. Vulnerable
variants rename f2 and delete its item d2 (cross-board write); patched/safe
leave f2 unchanged; the same operations on the caller's own field f1 succeed
in every file.

Every variant is the FULL real file; the routes' paths and handler names are
the REST API and stay.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0329"
original = (CASE_DIR / "vulnerable_source.js").read_text()
patched = (CASE_DIR / "patched_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant (the PUT route's field-id local renamed) ---
assert original.count("paramFieldId") == 10
v1 = original.replace("paramFieldId", "targetFieldId")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (repeated id-only selector hoisted into one local) ---
SEL = "          { _id: paramFieldId },\n"
assert original.count(SEL) == 8
v2 = original.replace(SEL, "          fieldFilter,\n")
v2 = swap(v2, "      const paramFieldId = req.params.customFieldId;\n      Authentication.checkBoardAccess(req.userId, paramBoardId);\n",
          "      const paramFieldId = req.params.customFieldId;\n      Authentication.checkBoardAccess(req.userId, paramBoardId);\n      const fieldFilter = { _id: paramFieldId };\n")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the board-scoped selector comes from a helper) ---
BSF = '''      const boardScopedField = {
        _id: paramFieldId,
        boardIds: { $in: [paramBoardId] },
      };
'''
v3 = swap(patched, BSF, "      const boardScopedField = scopeToBoard(paramFieldId, paramBoardId);\n")
v3 = swap(v3, "CustomFields = new Mongo.Collection('customFields');\n",
          "function scopeToBoard(fieldId, boardId) {\n  return { _id: fieldId, boardIds: { $in: [boardId] } };\n}\n\nCustomFields = new Mongo.Collection('customFields');\n")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''// Site-administrator maintenance route: may edit ANY custom field by id, but only for site admins
// (the caller's privilege, not a board in the URL, is what is checked).
if (Meteor.isServer) {
  JsonRoutes.add('PUT', '/api/admin/custom-fields/:customFieldId', (req, res) => {
    Authentication.checkAdmin(req.userId);
    const paramFieldId = req.params.customFieldId;
    CustomFields.direct.update({ _id: paramFieldId }, { $set: { name: req.body.name } });
    JsonRoutes.sendResult(res, { code: 200, data: { _id: paramFieldId } });
  });
}
''')

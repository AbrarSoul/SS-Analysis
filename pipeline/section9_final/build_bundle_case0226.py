"""
Section 9 ground-truth test bundle: CASE-0226
(mintplex-labs/anything-llm, server/endpoints/system.js
GET /system/local-files, CVE-2024-0798, CWE-272 least privilege violation).

Core vulnerable mechanism: in multi-user mode four document-management routes
are registered with `[validatedRequest]` only, which proves the caller is
logged in but not what role they hold: `GET /system/local-files` (lists every
uploaded document), `GET /system/system-vectors` (vector counts),
`DELETE /system/remove-document` and `DELETE /system/remove-folder`. Any
`default`-role user can therefore list all documents and delete documents and
folders that belong to the whole instance. The upstream fix adds
`flexUserRoleValid([ROLES.admin, ROLES.manager])` to all four.

Sibling sites: the auto-located target is only `/system/local-files`; the
other three routes are changed by the same upstream patch and carry the same
missing role check, so the safe variant gates all four with one shared
middleware list and the vulnerable variants leave all four unchanged.

Verification: the four routes are extracted verbatim from each full file and
registered on a REAL Express 4 app with the real `flexUserRoleValid` (copied from
server/utils/middleware/multiUserProtected.js at the vulnerable commit), a
stand-in `validatedRequest` (multi-user mode, role taken from an x-role header)
and stand-in handlers that count calls to purgeDocument / purgeFolder. Real HTTP
requests are made as a `default` user and as an `admin`.

Every variant is the FULL real file. `systemEndpoints` is exported and called by
the server, so only route registration text inside it is altered.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0226"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


LOCAL = '''  app.get("/system/local-files", [validatedRequest], async (_, response) => {
    try {
      const localFiles = await viewLocalFiles();
      response.status(200).json({ localFiles });
    } catch (e) {
      console.log(e.message, e);
      response.sendStatus(500).end();
    }
  });
'''
assert original.count(LOCAL) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, LOCAL, '''  app.get("/system/local-files", [validatedRequest], async (request, response) => {
    try {
      const availableFiles = await viewLocalFiles();
      response.status(200).json({ localFiles: availableFiles });
    } catch (e) {
      console.log(e.message, e);
      response.sendStatus(500).end();
    }
  });
''')
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, LOCAL, '''  async function listLocalFiles(_, response) {
    try {
      const localFiles = await viewLocalFiles();
      response.status(200).json({ localFiles });
    } catch (e) {
      console.log(e.message, e);
      response.sendStatus(500).end();
    }
  }

  app.get("/system/local-files", [validatedRequest], listLocalFiles);
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, '''  app.get(
    "/system/system-vectors",
    [validatedRequest],''', '''  // Document management is limited to administrators and managers.
  const documentAdmins = [
    validatedRequest,
    flexUserRoleValid([ROLES.admin, ROLES.manager]),
  ];

  app.get(
    "/system/system-vectors",
    documentAdmins,''')
v3 = swap(v3, '''  app.delete(
    "/system/remove-document",
    [validatedRequest],''', '''  app.delete(
    "/system/remove-document",
    documentAdmins,''')
v3 = swap(v3, '''  app.delete(
    "/system/remove-folder",
    [validatedRequest],''', '''  app.delete(
    "/system/remove-folder",
    documentAdmins,''')
v3 = swap(v3, '  app.get("/system/local-files", [validatedRequest], async (_, response) => {',
          '  app.get("/system/local-files", documentAdmins, async (_, response) => {')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = '''// Standalone example of the same shape: a read-only route that intentionally
// uses only the login check because every logged-in user may see the same
// public list (release notes), with no per-role data.
function releaseNotesEndpoints(app, validatedRequest, loadNotes) {
  app.get("/notes/latest", [validatedRequest], async (_, response) => {
    response.status(200).json({ notes: await loadNotes() });
  });
}

module.exports = { releaseNotesEndpoints };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)

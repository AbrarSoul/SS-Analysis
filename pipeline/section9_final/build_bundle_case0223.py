"""
Section 9 ground-truth test bundle: CASE-0223
(mintplex-labs/anything-llm, server/endpoints/system.js
GET /system/data-export, CVE-2024-0551, CWE-284 improper access control).

Core vulnerable mechanism: in multi-user mode the export route is
`app.get("/system/data-export", [validatedRequest], ...)`. `validatedRequest`
only proves that the caller is logged in; nothing checks the caller's role, so
any authenticated `default` (non-admin) user can call it, have the whole
workspace exported (`exportData()` bundles all documents, chats and settings)
and then fetch the archive. The other administrative routes in the file use
`[validatedRequest, flexUserRoleValid]`. The upstream fix adds
`flexUserRoleValid` to this route.

Sibling sites (kept in the manifest notes): in the vulnerable file
`POST /system/data-import`, which overwrites the whole instance from an
uploaded archive, has NO auth middleware at all, and
`GET /system/data-exports/:filename` is deliberately unauthenticated (it deletes
the file after download). The upstream fix changes neither. The safe variant
applies the same role gate to data-export AND data-import (the same
missing-authorization weakness on an admin-only data operation) and leaves the
one-time download route and the api-key routes unchanged.

Verification: the three data routes (`/system/data-export`, `/system/data-exports/:filename`
and `/system/data-import`) are extracted verbatim from each full file and
registered on a REAL Express 4 app with stand-in `validatedRequest` (requires
an `x-role` header, else 401), `flexUserRoleValid` (allows admin and manager
only, else 401), `exportData`, `handleImports.single` and
`unpackAndOverwriteImport`. Real HTTP requests are made as an admin, as a
`default` user and with no login.

Every variant is the FULL real file. `systemEndpoints` is exported and called by
the server, so nothing outside the route block is renamed.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0223"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


EXPORT = '''  app.get("/system/data-export", [validatedRequest], async (_, response) => {
    try {
      const { filename, error } = await exportData();
      response.status(200).json({ filename, error });
    } catch (e) {
      console.log(e.message, e);
      response.sendStatus(500).end();
    }
  });
'''
IMPORT = '''  app.post(
    "/system/data-import",
    handleImports.single("file"),
    async function (request, response) {
      const { originalname } = request.file;
      const { success, error } = await unpackAndOverwriteImport(originalname);
      response.status(200).json({ success, error });
    }
  );
'''
assert original.count(EXPORT) == 1 and original.count(IMPORT) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, EXPORT, '''  app.get("/system/data-export", [validatedRequest], async (_, res) => {
    try {
      const { filename: archiveName, error: exportError } = await exportData();
      res.status(200).json({ filename: archiveName, error: exportError });
    } catch (e) {
      console.log(e.message, e);
      res.sendStatus(500).end();
    }
  });
''')
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, EXPORT, '''  async function handleDataExport(_, response) {
    try {
      const { filename, error } = await exportData();
      response.status(200).json({ filename, error });
    } catch (e) {
      console.log(e.message, e);
      response.sendStatus(500).end();
    }
  }

  app.get("/system/data-export", [validatedRequest], handleDataExport);
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, EXPORT, '''  // Whole-instance data operations are administrator-only.
  const adminOnly = [validatedRequest, flexUserRoleValid];

  app.get("/system/data-export", adminOnly, async (_, response) => {
    try {
      const { filename, error } = await exportData();
      response.status(200).json({ filename, error });
    } catch (e) {
      console.log(e.message, e);
      response.sendStatus(500).end();
    }
  });
''')
v3 = swap(v3, IMPORT, '''  app.post(
    "/system/data-import",
    adminOnly,
    handleImports.single("file"),
    async function (request, response) {
      const { originalname } = request.file;
      const { success, error } = await unpackAndOverwriteImport(originalname);
      response.status(200).json({ success, error });
    }
  );
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = '''// Standalone example of the same shape: an Express route for a public,
// read-only status document, deliberately without an auth middleware because
// it exposes nothing but a static build number.
function statusEndpoints(app) {
  app.get("/status/version", async (_, response) => {
    response.status(200).json({ version: process.env.BUILD_NUMBER || "dev" });
  });
}

module.exports = { statusEndpoints };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)

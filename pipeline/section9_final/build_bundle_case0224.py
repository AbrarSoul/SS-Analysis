"""
Section 9 ground-truth test bundle: CASE-0224
(mintplex-labs/anything-llm, server/endpoints/system.js
POST /system/enable-multi-user, CVE-2024-3029, CWE-20 improper input
validation).

Core vulnerable mechanism: the handler parses the body first
(`reqBody(request)` is `JSON.parse(request.body)` when the body is a string) and
only then checks whether multi-user mode is already on. `validatedRequest` lets
ANY logged-in user through once multi-user mode is enabled, so a low-privilege
user can POST a `text/plain` body that is not valid JSON: `JSON.parse` throws
before the "already enabled" check, and the route's `catch` block, written to
roll back a half-finished first-time setup, runs `User.delete({})` and sets
`multi_user_mode: false`. One request deletes every account and turns the
instance back into single-user mode. The upstream fix moves the check first
(using `response.locals.multiUserMode`, which `validatedRequest` already
computed) and parses the body afterwards.

Measured caveat, kept in the manifest notes: the fix only reorders the two
statements; the `catch` block still deletes all users on ANY exception, so a
failure in the first-time setup itself (for example `User.create` throwing on a
duplicate name once mode is off) still triggers the same destructive rollback,
and an exception from the guard itself is not distinguished. The safe variant
runs the rollback only if this request actually began enabling.

Sibling sites: no other route in the file has this parse-then-check ordering
with a destructive catch; `/system/multi-user-mode` only reads the flag.

Verification: the route is extracted verbatim from each full file and registered
on a REAL Express 4 app with the real `reqBody` (copied from
server/utils/http/index.js at the vulnerable commit), a stand-in
`validatedRequest` (needs an x-user header, sets response.locals.multiUserMode
from the stored flag) and in-memory SystemSettings / User stand-ins. With
multi-user mode on and users [admin, alice], alice POSTs a text/plain body
`not json{`, then a valid JSON body.

Every variant is the FULL real file. systemEndpoints is exported and called by
the server, so nothing outside the route handler is renamed.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0224"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


HEAD = '''        const { username, password } = reqBody(request);
        const multiUserModeEnabled = await SystemSettings.isMultiUserMode();
        if (multiUserModeEnabled) {
          response.status(200).json({
            success: false,
            error: "Multi-user mode is already enabled.",
          });
          return;
        }

        const { user, error } = await User.create({
'''
assert original.count(HEAD) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, HEAD, '''        const { username: newUsername, password: newPassword } = reqBody(request);
        const alreadyEnabled = await SystemSettings.isMultiUserMode();
        if (alreadyEnabled) {
          response.status(200).json({
            success: false,
            error: "Multi-user mode is already enabled.",
          });
          return;
        }

        const { user, error } = await User.create({
''')
v1 = swap(v1, '''          username,
          password,
          role: ROLES.admin,''', '''          username: newUsername,
          password: newPassword,
          role: ROLES.admin,''')
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, HEAD, '''        const { username, password } = reqBody(request);
        const alreadyEnabled = () => SystemSettings.isMultiUserMode();
        if (await alreadyEnabled()) {
          response.status(200).json({
            success: false,
            error: "Multi-user mode is already enabled.",
          });
          return;
        }

        const { user, error } = await User.create({
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, HEAD, '''        // Check the current mode BEFORE touching the request body.
        const multiUserModeEnabled = await SystemSettings.isMultiUserMode();
        if (multiUserModeEnabled) {
          response.status(200).json({
            success: false,
            error: "Multi-user mode is already enabled.",
          });
          return;
        }

        enabling = true;
        const { username, password } = reqBody(request);
        const { user, error } = await User.create({
''')
v3 = swap(v3, '''    async (request, response) => {
      try {
        // Check the current mode BEFORE''', '''    async (request, response) => {
      let enabling = false;
      try {
        // Check the current mode BEFORE''')
v3 = swap(v3, '''      } catch (e) {
        await User.delete({});
        await SystemSettings.updateSettings({
          multi_user_mode: false,
        });

        console.log(e.message, e);
        response.sendStatus(500).end();
      }
    }
  );

  app.get("/system/multi-user-mode"''', '''      } catch (e) {
        // Roll back only a first-time setup that this request itself started.
        if (enabling) {
          await User.delete({});
          await SystemSettings.updateSettings({
            multi_user_mode: false,
          });
        }

        console.log(e.message, e);
        response.sendStatus(500).end();
      }
    }
  );

  app.get("/system/multi-user-mode"''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = '''// Standalone example of the same shape: an Express handler that parses its
// body inside try/catch and, on failure, undoes only work that this same
// request performed (a temp file it created), never shared data.
const fs = require("fs");

function uploadEndpoints(app) {
  app.post("/upload/preview", async (request, response) => {
    let tmpPath = null;
    try {
      const { name } = typeof request.body === "string" ? JSON.parse(request.body) : request.body;
      tmpPath = `/tmp/preview-${Date.now()}.txt`;
      fs.writeFileSync(tmpPath, String(name));
      response.status(200).json({ ok: true });
    } catch (e) {
      if (tmpPath) fs.rmSync(tmpPath, { force: true });
      response.sendStatus(400).end();
    }
  });
}

module.exports = { uploadEndpoints };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)

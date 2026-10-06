r"""
Section 9 ground-truth test bundle: CASE-0327
(wekan/wekan, server/publications/notifications.js notificationUsers,
CVE-2026-30847, CWE-200 exposure of sensitive information / CWE-285 improper
authorization).

Core vulnerable mechanism: the `notificationUsers` Meteor publication sends
the client every user document referenced by the current user's
notification activities: `ReactiveCache.getUsers({_id: {$in: ...}}, {}, true)`
with an EMPTY options object, i.e. no field projection. A full Wekan user
document contains private fields (email addresses, `services.password.bcrypt`
password hash, `services.resume.loginTokens`, per-user profile settings), so
any logged-in user who shares a notification with another user receives that
user's hashed password and login tokens. The upstream fix adds
`fields: { username, profile.fullname, profile.avatarUrl, profile.initials }`.

Sibling sites: the other `notification*` publications in the same file
publish cards, swimlanes and attachments (no credential-bearing documents).

Verification (REAL query engine): the full file is evaluated with node's `vm`
with the `import` line removed and `Meteor.publish` captured; `ReactiveCache`
is a stand-in whose `getUsers(selector, options)` runs the query and the
options' `fields` projection with the real `mingo` MongoDB-query library over
an in-memory user collection (current user u1 has one notification whose
activity was performed by u2). The published users' JSON is inspected:
vulnerable variants return u2 with `services.password.bcrypt`,
`services.resume.loginTokens` and `emails`; patched/safe return only
`_id`, `username` and `profile.{fullname,avatarUrl,initials}`.

Every variant is the FULL real file; the publication name `notificationUsers`
is the client-facing API and stays.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0327"
original = (CASE_DIR / "vulnerable_source.js").read_text()
patched = (CASE_DIR / "patched_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


FUNC = '''Meteor.publish('notificationUsers', async function() {
  const ret = await ReactiveCache.getUsers(
    {
      _id: {
        $in: (await activities())
          .map(v => v.userId)
          .filter(v => !!v),
      },
    },
    {},
    true,
  );
  return ret;
});
'''
assert original.count(FUNC) == 1

# --- Variant 1: renamed vulnerable variant (local and arrow parameters renamed) ---
f1 = (FUNC.replace("const ret =", "const publishedUsers =").replace("return ret;", "return publishedUsers;")
      .replace("v => v.userId", "act => act.userId").replace("v => !!v", "id => !!id"))
v1 = swap(original, FUNC, f1)
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (activity user ids computed by a helper; still no projection) ---
f2 = FUNC.replace('''        $in: (await activities())
          .map(v => v.userId)
          .filter(v => !!v),
''', "        $in: await activityUserIds(),\n")
helper = '''async function activityUserIds() {
  return (await activities())
    .map(v => v.userId)
    .filter(v => !!v);
}

'''
v2 = swap(original, FUNC, f2)
v2 = swap(v2, "async function activities() {\n", helper + "async function activities() {\n")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the projection moves into a module constant) ---
PROJ = '''    {
      fields: {
        username: 1,
        'profile.fullname': 1,
        'profile.avatarUrl': 1,
        'profile.initials': 1,
      },
    },
    true,
'''
assert patched.count(PROJ) == 1
v3 = swap(patched, PROJ, "    PUBLIC_USER_PROJECTION,\n    true,\n")
v3 = swap(v3, "// We use these when displaying notifications in the notificationsDrawer\n",
          "// We use these when displaying notifications in the notificationsDrawer\n\nconst PUBLIC_USER_PROJECTION = {\n  fields: {\n    username: 1,\n    'profile.fullname': 1,\n    'profile.avatarUrl': 1,\n    'profile.initials': 1,\n  },\n};\n")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''import { ReactiveCache } from '/imports/reactiveCache';

// gets all labels associated with the notifications of the current user.
// Labels only carry a name and a colour (no credentials or personal data), so
// publishing the whole document with an empty projection exposes nothing private.
Meteor.publish('notificationLabels', async function() {
  const ret = await ReactiveCache.getLabels(
    {
      _id: { $in: await labelIdsForCurrentUser() },
    },
    {},
    true,
  );
  return ret;
});

async function labelIdsForCurrentUser() {
  const user = await ReactiveCache.getCurrentUser();
  return user?.profile?.pinnedLabels || [];
}
''')

"""
Section 9 ground-truth test bundle: CASE-0264
(polonel/trudesk, src/controllers/api/v2/routes.js module.exports,
CVE-2022-1770, CWE-269 improper privilege management).

Core vulnerable mechanism: every API v2 route is wired with `apiv2Auth` (an
authentication check: is this a valid, logged-in session/token?) but most
resource routes -- account creation/update, ticket create/update/delete,
group/team/department create/update/delete -- have NO authorization check
at all: no `canUser('<resource>:<action>')` in their middleware chain. Since
`middleware.canUser` already exists and IS used for the Notices routes in
this very file, its absence elsewhere is not a missing feature but a gap:
authentication alone (`apiv2Auth`) only proves a request carries SOME valid
session, not that the session's role is permitted to perform that specific
action -- so any authenticated user, including a low-privilege agent
account, can call `POST /api/v2/accounts` and create a new (potentially
admin) account, or delete another team's tickets/groups, bypassing the
role-based access control the rest of the app enforces. The upstream fix
adds a `canUser('<resource>:<action>')` middleware to every one of these
routes (accounts, tickets, groups, teams, departments), matching the
pattern the Notices routes already used.

Sibling sites: this file registers ~20 routes across 5 resources
(accounts/tickets/groups/teams/departments) that are missing the check; the
upstream fix addresses all of them, and so does this bundle's safe variant.
The clearest, highest-impact single example -- used for the pass/fail
measurement below -- is `POST /api/v2/accounts` (creating a new account,
i.e. potential privilege escalation to a fresh admin-capable account).

Verification: each full file is `require()`d as the real, unmodified
module and invoked with a stand-in `router` that RECORDS, per HTTP verb and
path, the exact middleware chain array passed to it (no real Express
needed -- routing itself is not what's being tested), plus a stand-in
`middleware` object whose `canUser(permission)` is a real factory: it
returns a tagged middleware function carrying `.permission = permission`,
mirroring the real function's call contract. After requiring the module,
the recorded chain for `POST /api/v2/accounts` is inspected for a
middleware whose `.permission === 'accounts:create'`.

Every variant is the FULL real file. `module.exports` is the module's only
export, invoked by the app's route-bootstrap code as
`require('./routes')(middleware, router, controllers)`, so its signature is
kept; the renamed variant renames its local shorthand bindings.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0264"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
# Rename only the LOCAL shorthand bindings; `middleware.apiv2` / `.canUser`
# on the RHS are the external contract with the injected `middleware`
# object and must be left untouched, same pitfall as renaming self.field.
v1 = original
v1 = v1.replace("const apiv2Auth = middleware.apiv2", "const requireAuth = middleware.apiv2")
v1 = v1.replace("apiv2Auth", "requireAuth")
v1 = v1.replace("const apiv2 = controllers.api.v2", "const apiV2Controllers = controllers.api.v2")
v1 = v1.replace("apiv2.", "apiV2Controllers.")
v1 = v1.replace("const canUser = middleware.canUser", "const hasPermission = middleware.canUser")
v1 = v1.replace("canUser(", "hasPermission(")
assert "requireAuth" in v1 and "apiV2Controllers.accounts.get" in v1 and "hasPermission('notices:update')" in v1
assert "middleware.canUser" in v1  # external contract preserved
assert "apiv2Auth" not in v1 and "canUser(" not in v1 and "= canUser" not in v1
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
OLD_ACCOUNTS = """  // Accounts
  router.get('/api/v2/accounts', apiv2Auth, apiv2.accounts.get)
  router.post('/api/v2/accounts', apiv2Auth, apiv2.accounts.create)
  router.put('/api/v2/accounts/:username', apiv2Auth, apiv2.accounts.update)
"""
assert original.count(OLD_ACCOUNTS) == 1
NEW_ACCOUNTS_CALL = """  // Accounts
  registerAccountRoutes(router, apiv2Auth, apiv2)
"""
v2 = swap(original, OLD_ACCOUNTS, NEW_ACCOUNTS_CALL)
HELPER = """function registerAccountRoutes (router, apiv2Auth, apiv2) {
  router.get('/api/v2/accounts', apiv2Auth, apiv2.accounts.get)
  router.post('/api/v2/accounts', apiv2Auth, apiv2.accounts.create)
  router.put('/api/v2/accounts/:username', apiv2Auth, apiv2.accounts.update)
}

module.exports = function (middleware, router, controllers) {"""
v2 = swap(v2, "module.exports = function (middleware, router, controllers) {", HELPER)
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (canUser('accounts:create') etc. added to
# every account/ticket/group/team/department route) but expressed as a
# declarative route table registered in a loop, instead of upstream's
# individual literal router.verb() edits.
OLD_ACCOUNTS_2 = OLD_ACCOUNTS
NEW_ACCOUNTS_TABLE = """  // Accounts
  const accountRoutes = [
    ['get', '/api/v2/accounts', [apiv2Auth, canUser('accounts:view')], apiv2.accounts.get],
    ['post', '/api/v2/accounts', [apiv2Auth, canUser('accounts:create')], apiv2.accounts.create],
    ['put', '/api/v2/accounts/:username', [apiv2Auth, canUser('accounts:update')], apiv2.accounts.update],
  ]
  for (const [verb, routePath, guards, handler] of accountRoutes) {
    router[verb](routePath, ...guards, handler)
  }
"""
v3 = swap(original, OLD_ACCOUNTS_2, NEW_ACCOUNTS_TABLE)

# Sibling sites: Tickets/Groups/Teams/Departments have the identical missing
# canUser() defect and must be closed too, or this "safe" variant would
# still contain a real privilege-escalation gap.
OLD_TICKETS = """  // Tickets
  router.get('/api/v2/tickets', apiv2Auth, apiv2.tickets.get)
  router.post('/api/v2/tickets', apiv2Auth, apiv2.tickets.create)
  router.post('/api/v2/tickets/transfer/:uid', apiv2Auth, isAdmin, apiv2.tickets.transferToThirdParty)
  router.get('/api/v2/tickets/:uid', apiv2Auth, apiv2.tickets.single)
  router.put('/api/v2/tickets/batch', apiv2Auth, apiv2.tickets.batchUpdate)
  router.put('/api/v2/tickets/:uid', apiv2Auth, apiv2.tickets.update)
  router.delete('/api/v2/tickets/:uid', apiv2Auth, apiv2.tickets.delete)
  router.delete('/api/v2/tickets/deleted/:id', apiv2Auth, isAdmin, apiv2.tickets.permDelete)
"""
assert original.count(OLD_TICKETS) == 1
NEW_TICKETS = """  // Tickets
  router.get('/api/v2/tickets', apiv2Auth, canUser('tickets:view'), apiv2.tickets.get)
  router.post('/api/v2/tickets', apiv2Auth, canUser('tickets:create'), apiv2.tickets.create)
  router.post('/api/v2/tickets/transfer/:uid', apiv2Auth, isAdmin, apiv2.tickets.transferToThirdParty)
  router.get('/api/v2/tickets/:uid', apiv2Auth, canUser('tickets:view'), apiv2.tickets.single)
  router.put('/api/v2/tickets/batch', apiv2Auth, canUser('tickets:update'), apiv2.tickets.batchUpdate)
  router.put('/api/v2/tickets/:uid', apiv2Auth, canUser('tickets:update'), apiv2.tickets.update)
  router.delete('/api/v2/tickets/:uid', apiv2Auth, canUser('tickets:delete'), apiv2.tickets.delete)
  router.delete('/api/v2/tickets/deleted/:id', apiv2Auth, isAdmin, apiv2.tickets.permDelete)
"""
v3 = swap(v3, OLD_TICKETS, NEW_TICKETS)

OLD_GROUPS = """  // Groups
  router.get('/api/v2/groups', apiv2Auth, apiv2.groups.get)
  router.post('/api/v2/groups', apiv2Auth, apiv2.groups.create)
  router.put('/api/v2/groups/:id', apiv2Auth, apiv2.groups.update)
  router.delete('/api/v2/groups/:id', apiv2Auth, apiv2.groups.delete)
"""
assert original.count(OLD_GROUPS) == 1
NEW_GROUPS = """  // Groups
  router.get('/api/v2/groups', apiv2Auth, apiv2.groups.get)
  router.post('/api/v2/groups', apiv2Auth, canUser('groups:create'), apiv2.groups.create)
  router.put('/api/v2/groups/:id', apiv2Auth, canUser('groups:update'), apiv2.groups.update)
  router.delete('/api/v2/groups/:id', apiv2Auth, canUser('groups:delete'), apiv2.groups.delete)
"""
v3 = swap(v3, OLD_GROUPS, NEW_GROUPS)

OLD_TEAMS = """  // Teams
  router.get('/api/v2/teams', apiv2Auth, apiv2.teams.get)
  router.post('/api/v2/teams', apiv2Auth, apiv2.teams.create)
  router.put('/api/v2/teams/:id', apiv2Auth, apiv2.teams.update)
  router.delete('/api/v2/teams/:id', apiv2Auth, apiv2.teams.delete)
"""
assert original.count(OLD_TEAMS) == 1
NEW_TEAMS = """  // Teams
  router.get('/api/v2/teams', apiv2Auth, canUser('teams:view'), apiv2.teams.get)
  router.post('/api/v2/teams', apiv2Auth, canUser('teams:create'), apiv2.teams.create)
  router.put('/api/v2/teams/:id', apiv2Auth, canUser('teams:update'), apiv2.teams.update)
  router.delete('/api/v2/teams/:id', apiv2Auth, canUser('teams:delete'), apiv2.teams.delete)
"""
v3 = swap(v3, OLD_TEAMS, NEW_TEAMS)

OLD_DEPTS = """  // Departments
  router.get('/api/v2/departments', apiv2Auth, apiv2.departments.get)
  router.post('/api/v2/departments', apiv2Auth, apiv2.departments.create)
  router.put('/api/v2/departments/:id', apiv2Auth, apiv2.departments.update)
  router.delete('/api/v2/departments/:id', apiv2Auth, apiv2.departments.delete)
"""
assert original.count(OLD_DEPTS) == 1
NEW_DEPTS = """  // Departments
  router.get('/api/v2/departments', apiv2Auth, canUser('departments:view'), apiv2.departments.get)
  router.post('/api/v2/departments', apiv2Auth, canUser('departments:create'), apiv2.departments.create)
  router.put('/api/v2/departments/:id', apiv2Auth, canUser('departments:update'), apiv2.departments.update)
  router.delete('/api/v2/departments/:id', apiv2Auth, canUser('departments:delete'), apiv2.departments.delete)
"""
v3 = swap(v3, OLD_DEPTS, NEW_DEPTS)

(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = """// Standalone example of the same shape: a route table where one entry is
// missing an extra middleware, but the missing one (requestId) just tags
// each request with a correlation id for logs, a non-security nicety.
function registerHealthRoutes (router, requestId) {
  router.get('/api/v2/health', requestId, (req, res) => res.sendStatus(200))
  router.get('/api/v2/health/deep', (req, res) => res.sendStatus(200))
}

module.exports = { registerHealthRoutes }
"""
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)

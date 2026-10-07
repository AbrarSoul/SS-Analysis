"""
Section 9 ground-truth test bundle: CASE-0031
(Dokploy/dokploy, CVE-2025-53374, CWE-359/CWE-862 -- missing authorization
/ IDOR).

Core vulnerable mechanism: the `one` tRPC procedure looks up a member+user
record by a caller-supplied input.userId, scoped only to the caller's
active organization, and returns it directly -- with no check that a
record was actually found, and no check that the CALLER is either the
target user or an org owner. Any authenticated member of the organization
can enumerate other members' full user records by supplying arbitrary
userIds.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0031"
original = (CASE_DIR / "vulnerable_source.ts").read_text()

VULNERABLE_BLOCK = (
    "\tone: protectedProcedure\n"
    "\t\t.input(\n"
    "\t\t\tz.object({\n"
    "\t\t\t\tuserId: z.string(),\n"
    "\t\t\t}),\n"
    "\t\t)\n"
    "\t\t.query(async ({ input, ctx }) => {\n"
    "\t\t\tconst memberResult = await db.query.member.findFirst({\n"
    "\t\t\t\twhere: and(\n"
    "\t\t\t\t\teq(member.userId, input.userId),\n"
    "\t\t\t\t\teq(member.organizationId, ctx.session?.activeOrganizationId || \"\"),\n"
    "\t\t\t\t),\n"
    "\t\t\t\twith: {\n"
    "\t\t\t\t\tuser: true,\n"
    "\t\t\t\t},\n"
    "\t\t\t});\n"
    "\n"
    "\t\t\treturn memberResult;\n"
    "\t\t}),\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# Rename the procedure key one -> getUserById and the local memberResult
# -> targetMember. Same exact vulnerability: still no not-found check or
# authorization check before returning the record.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    VULNERABLE_BLOCK.replace("one: protectedProcedure", "getUserById: protectedProcedure").replace(
        "memberResult", "targetMember"
    ),
)
assert renamed_source != original
assert "getUserById: protectedProcedure" in renamed_source
assert "const targetMember = await db.query.member.findFirst" in renamed_source
assert "return targetMember;" in renamed_source
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable -- the organization
# ID expression is extracted before the query. Same exact vulnerability
# (still no not-found/authorization check), no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    "\tone: protectedProcedure\n"
    "\t\t.input(\n"
    "\t\t\tz.object({\n"
    "\t\t\t\tuserId: z.string(),\n"
    "\t\t\t}),\n"
    "\t\t)\n"
    "\t\t.query(async ({ input, ctx }) => {\n"
    "\t\t\tconst organizationId = ctx.session?.activeOrganizationId || \"\";\n"
    "\t\t\tconst memberResult = await db.query.member.findFirst({\n"
    "\t\t\t\twhere: and(\n"
    "\t\t\t\t\teq(member.userId, input.userId),\n"
    "\t\t\t\t\teq(member.organizationId, organizationId),\n"
    "\t\t\t\t),\n"
    "\t\t\t\twith: {\n"
    "\t\t\t\t\tuser: true,\n"
    "\t\t\t\t},\n"
    "\t\t\t});\n"
    "\n"
    "\t\t\treturn memberResult;\n"
    "\t\t}),\n",
)
assert structural_source != original
assert "const organizationId = ctx.session?.activeOrganizationId || \"\";" in structural_source
(CASE_DIR / "variant_vulnerable_02.ts").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (only the target user themself
# or an org owner may view the record; a missing record is also
# rejected) but combined into a single isSelfOrOwner boolean check with
# one TRPCError, instead of the real patch's two separate if/throw
# blocks with different error codes -- materially different structure,
# not byte-identical to the known fix.
safe_source = original.replace(
    VULNERABLE_BLOCK,
    "\tone: protectedProcedure\n"
    "\t\t.input(\n"
    "\t\t\tz.object({\n"
    "\t\t\t\tuserId: z.string(),\n"
    "\t\t\t}),\n"
    "\t\t)\n"
    "\t\t.query(async ({ input, ctx }) => {\n"
    "\t\t\tconst memberResult = await db.query.member.findFirst({\n"
    "\t\t\t\twhere: and(\n"
    "\t\t\t\t\teq(member.userId, input.userId),\n"
    "\t\t\t\t\teq(member.organizationId, ctx.session?.activeOrganizationId || \"\"),\n"
    "\t\t\t\t),\n"
    "\t\t\t\twith: {\n"
    "\t\t\t\t\tuser: true,\n"
    "\t\t\t\t},\n"
    "\t\t\t});\n"
    "\n"
    "\t\t\tconst isSelfOrOwner =\n"
    "\t\t\t\t!!memberResult && (memberResult.userId === ctx.user.id || ctx.user.role === \"owner\");\n"
    "\t\t\tif (!isSelfOrOwner) {\n"
    "\t\t\t\tthrow new TRPCError({\n"
    "\t\t\t\t\tcode: \"FORBIDDEN\",\n"
    "\t\t\t\t\tmessage: \"Access denied\",\n"
    "\t\t\t\t});\n"
    "\t\t\t}\n"
    "\n"
    "\t\t\treturn memberResult;\n"
    "\t\t}),\n",
)
assert safe_source != original
assert "const isSelfOrOwner =" in safe_source
assert '"FORBIDDEN"' in safe_source
(CASE_DIR / "variant_safe_01.ts").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a memberExists procedure
# that also queries by input.userId with no per-caller authorization
# check -- the same superficial shape as the vulnerable procedure -- but
# returns only a boolean, never the member's actual profile data (name,
# email, role), so an unauthorized caller learns nothing sensitive by
# probing arbitrary userIds.
BENIGN_ADDITION = (
    "\tmemberExists: protectedProcedure\n"
    "\t\t.input(\n"
    "\t\t\tz.object({\n"
    "\t\t\t\tuserId: z.string(),\n"
    "\t\t\t}),\n"
    "\t\t)\n"
    "\t\t.query(async ({ input, ctx }) => {\n"
    "\t\t\t// Returns only a boolean -- never the member's actual profile\n"
    "\t\t\t// data (name, email, role) -- so unlike the `one` procedure\n"
    "\t\t\t// above, an unauthorized caller learns nothing sensitive about\n"
    "\t\t\t// the target user by probing arbitrary userIds here.\n"
    "\t\t\tconst memberResult = await db.query.member.findFirst({\n"
    "\t\t\t\twhere: and(\n"
    "\t\t\t\t\teq(member.userId, input.userId),\n"
    "\t\t\t\t\teq(member.organizationId, ctx.session?.activeOrganizationId || \"\"),\n"
    "\t\t\t\t),\n"
    "\t\t\t});\n"
    "\n"
    "\t\t\treturn !!memberResult;\n"
    "\t\t}),\n"
    "\n"
)
anchor = "\tone: protectedProcedure\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION + anchor, 1)
assert benign_source != safe_source
assert "memberExists" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)

print("Wrote 4 new samples for CASE-0031.")

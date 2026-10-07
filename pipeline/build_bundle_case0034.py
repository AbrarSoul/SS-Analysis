"""
Section 9 ground-truth test bundle: CASE-0034
(OneUptime/oneuptime, CVE-2025-65966, CWE-285 -- improper authorization).

The real patch touches only the table-level @TableAccessControl decorator
on the User entity itself. Several column-level create:[Permission.Public]
entries elsewhere in this file are untouched by the real patch and are
left untouched in every variant below (Section 9.3).

Core vulnerable mechanism: the User entity's table-level access control
declares create: [Permission.Public], allowing any unauthenticated caller
to create User records directly through this generic ORM path, bypassing
whatever validation a proper registration flow would apply. read/update/
delete are correctly restricted to [Permission.CurrentUser].
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0034"
original = (CASE_DIR / "vulnerable_source.ts").read_text()

VULNERABLE_BLOCK = (
    "@TableAccessControl({\n"
    "  create: [Permission.Public],\n"
    "  read: [Permission.CurrentUser],\n"
    "  delete: [Permission.CurrentUser],\n"
    "  update: [Permission.CurrentUser],\n"
    "})\n"
    "@CrudApiEndpoint(new Route(\"/user\"))\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"
assert original.count(VULNERABLE_BLOCK) == 1

# --- Variant 1: renamed vulnerable variant ---
# TableAccessControl/Permission are fixed framework imports and cannot be
# renamed without breaking the decorator's real behavior. Instead, the
# create permission list is referenced through a new named constant
# instead of an inline array literal -- a rule keyed on the literal token
# "[Permission.Public]" appearing directly inside create: would miss
# this. Same exact vulnerability: the User table's create permission is
# still Permission.Public.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    "const USER_TABLE_CREATE_PERMISSIONS: Array<Permission> = [Permission.Public];\n\n"
    "@TableAccessControl({\n"
    "  create: USER_TABLE_CREATE_PERMISSIONS,\n"
    "  read: [Permission.CurrentUser],\n"
    "  delete: [Permission.CurrentUser],\n"
    "  update: [Permission.CurrentUser],\n"
    "})\n"
    "@CrudApiEndpoint(new Route(\"/user\"))\n",
)
assert renamed_source != original
assert "USER_TABLE_CREATE_PERMISSIONS" in renamed_source
assert "create: USER_TABLE_CREATE_PERMISSIONS," in renamed_source
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: safe statement reordering -- the decorator's object
# properties are reordered (property order is semantically irrelevant).
# Same exact vulnerability (create is still Permission.Public), no
# renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    "@TableAccessControl({\n"
    "  read: [Permission.CurrentUser],\n"
    "  update: [Permission.CurrentUser],\n"
    "  delete: [Permission.CurrentUser],\n"
    "  create: [Permission.Public],\n"
    "})\n"
    "@CrudApiEndpoint(new Route(\"/user\"))\n",
)
assert structural_source != original
assert "  create: [Permission.Public],\n})" in structural_source
(CASE_DIR / "variant_vulnerable_02.ts").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (nobody can create User records
# through this generic table-level path) but expressed via a named empty
# constant instead of the real patch's inline `[]` literal -- not
# byte-identical to the known fix.
safe_source = original.replace(
    VULNERABLE_BLOCK,
    "const NO_ONE_CAN_CREATE_DIRECTLY: Array<Permission> = [];\n\n"
    "@TableAccessControl({\n"
    "  create: NO_ONE_CAN_CREATE_DIRECTLY,\n"
    "  read: [Permission.CurrentUser],\n"
    "  delete: [Permission.CurrentUser],\n"
    "  update: [Permission.CurrentUser],\n"
    "})\n"
    "@CrudApiEndpoint(new Route(\"/user\"))\n",
)
assert safe_source != original
assert "NO_ONE_CAN_CREATE_DIRECTLY" in safe_source
assert "create: [Permission.Public]" not in safe_source.split("class User extends UserModel")[0]
(CASE_DIR / "variant_safe_01.ts").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a new, unrelated entity
# with the same superficial pattern (create: [Permission.Public]) but for
# a contact-form-style submission where public, unauthenticated creation
# is the intended, legitimate behavior -- not an identity/account record,
# so no privileged capability is granted by allowing it.
BENIGN_ADDITION = (
    "\n"
    "@TableAccessControl({\n"
    "  // Public users should legitimately be able to submit contact form\n"
    "  // entries with no account required -- unlike User, this entity\n"
    "  // grants no account/identity capability, so public creation is the\n"
    "  // intended behavior here.\n"
    "  create: [Permission.Public],\n"
    "  read: [Permission.CurrentUser],\n"
    "  delete: [Permission.CurrentUser],\n"
    "  update: [Permission.CurrentUser],\n"
    "})\n"
    "@Entity({\n"
    "  name: \"PublicContactMessage\",\n"
    "})\n"
    "class PublicContactMessage extends UserModel {}\n"
)
anchor = "@TableAccessControl({\n  create: NO_ONE_CAN_CREATE_DIRECTLY,\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "PublicContactMessage" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)

print("Wrote 4 new samples for CASE-0034.")

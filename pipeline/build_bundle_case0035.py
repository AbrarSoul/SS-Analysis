"""
Section 9 ground-truth test bundle: CASE-0035
(OpenSlides/openslides-auth-service, CVE-2026-25519, CWE-284 -- improper
access control / passwordless-account authentication bypass).

Core vulnerable mechanism: when thisUser.password is falsy (e.g. an
account provisioned without ever setting a local password), the code
compares the caller-supplied password against a fixed `dummyPassword`
constant instead (a timing-attack mitigation) but never explicitly
rejects the login just because there was no real password to check
against. If isPasswordCorrect(password, dummyPassword) can ever return
true for some input, any account with no password set becomes
authenticatable without knowing a real credential. The real fix adds an
explicit `!thisUser.password` rejection.

Renaming is scoped to readUserFromDatastoreByCredentials() only --
`thisUser` is reused as an unrelated local variable name in two other,
separate functions in this file.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0035"
original = (CASE_DIR / "vulnerable_source.ts").read_text()

FUNCTION_START = "    private async readUserFromDatastoreByCredentials(username: string, password: string): Promise<User> {\n"
FUNCTION_END_MARKER = "        return thisUser;\n    }\n"
assert FUNCTION_START in original
start_idx = original.index(FUNCTION_START)
end_idx = original.index(FUNCTION_END_MARKER, start_idx) + len(FUNCTION_END_MARKER)
function_body = original[start_idx:end_idx]
assert function_body.count("thisUser") == 7
assert "const passwordCorrect = await this.isPasswordCorrect(password, thisUser?.password || dummyPassword);" in function_body
assert "if (!thisUser.isExisting() || !passwordCorrect) {" in function_body


def rebuild(new_function_body):
    return original[:start_idx] + new_function_body + original[end_idx:]


# --- Variant 1: renamed vulnerable variant ---
# Rename thisUser -> authenticatedUser, passwordCorrect -> isValidPassword
# throughout this function only (the other two functions' own unrelated
# local thisUser variables are untouched). Same exact vulnerability: still
# no explicit rejection when authenticatedUser.password is falsy.
renamed_body = function_body.replace("thisUser", "authenticatedUser").replace("passwordCorrect", "isValidPassword")
renamed_source = rebuild(renamed_body)
assert renamed_source != original
assert "const authenticatedUser: User = new User(users[0]);" in renamed_source
assert "if (!authenticatedUser.isExisting() || !isValidPassword) {" in renamed_source
# the other two functions' own local thisUser variables must be untouched
assert renamed_source.count("thisUser") == original.count("thisUser") - 7
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable -- the fallback
# value is computed separately before being passed to
# isPasswordCorrect(). Same exact vulnerability (still no explicit
# no-password rejection), no renaming.
structural_body = function_body.replace(
    "        const passwordCorrect = await this.isPasswordCorrect(password, thisUser?.password || dummyPassword);\n",
    "        const passwordToCompare = thisUser?.password || dummyPassword;\n"
    "        const passwordCorrect = await this.isPasswordCorrect(password, passwordToCompare);\n",
)
assert structural_body != function_body
structural_source = rebuild(structural_body)
assert structural_source != original
assert "const passwordToCompare = thisUser?.password || dummyPassword;" in structural_source
(CASE_DIR / "variant_vulnerable_02.ts").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (an account with no password
# set can never authenticate, regardless of what isPasswordCorrect
# returns for the dummy comparison) but via a separate named hasPassword
# boolean instead of the real patch's inline `!thisUser.password ||`
# condition -- materially different structure, not byte-identical to the
# known fix.
safe_body = function_body.replace(
    "        const passwordCorrect = await this.isPasswordCorrect(password, thisUser?.password || dummyPassword);\n"
    "        if (!thisUser.isExisting() || !passwordCorrect) {\n",
    "        const hasPassword = Boolean(thisUser.password);\n"
    "        const passwordCorrect = await this.isPasswordCorrect(password, thisUser.password || dummyPassword);\n"
    "        if (!hasPassword || !thisUser.isExisting() || !passwordCorrect) {\n",
)
assert safe_body != function_body
safe_source = rebuild(safe_body)
assert safe_source != original
assert "const hasPassword = Boolean(thisUser.password);" in safe_source
assert "if (!hasPassword || !thisUser.isExisting() || !passwordCorrect) {" in safe_source
(CASE_DIR / "variant_safe_01.ts").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a method with the same
# superficial "value-or-fallback-default, then conditional" shape, but
# for a feature-flag decision, not authentication -- using the fallback
# here never grants unauthorized access, it only decides whether a UI
# feature is shown.
BENIGN_ADDITION = (
    "\n"
    "    private isFeatureEnabledForUser(thisUser: User): boolean {\n"
    "        // If no per-user override is set, falls back to the global\n"
    "        // default setting. Unlike the password/dummyPassword fallback\n"
    "        // above, using this fallback never grants unauthorized access --\n"
    "        // it only decides whether a UI feature is shown.\n"
    "        const settingValue = thisUser.featureOverride || globalDefaultFeatureFlag;\n"
    "        return settingValue === 'enabled';\n"
    "    }\n"
)
anchor = "    private async readUserFromDatastoreByCredentials(username: string, password: string): Promise<User> {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "isFeatureEnabledForUser" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)

print("Wrote 4 new samples for CASE-0035.")

"""
Section 9 ground-truth test bundle: CASE-0069
(OpenNMS/opennms, CVE-2023-0872, CWE-269 improper privilege management).

Core vulnerable mechanism: `hasEditRights()` grants edit/write access to
user records to anyone holding EITHER `ROLE_ADMIN` OR `ROLE_REST`.
`ROLE_REST` is intended as a limited API-access role, not a full
administrative role -- granting it the same edit rights as `ROLE_ADMIN`
lets a REST-API-scoped credential modify arbitrary user accounts
(including, transitively, granting itself further privileges), well
beyond its intended scope. The fix removes the `ROLE_REST` branch
entirely, so only `ROLE_ADMIN` passes this check.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0069"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = '''    private static boolean hasEditRights(SecurityContext securityContext) {
        if (securityContext.isUserInRole(Authentication.ROLE_ADMIN) || securityContext.isUserInRole(Authentication.ROLE_REST)) {
            return true;
        } else {
            return false;
        }
    }'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename hasEditRights -> canEditUsers, securityContext -> secCtx. Same
# exact over-broad ROLE_ADMIN-or-ROLE_REST check.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''    private static boolean canEditUsers(SecurityContext secCtx) {
        if (secCtx.isUserInRole(Authentication.ROLE_ADMIN) || secCtx.isUserInRole(Authentication.ROLE_REST)) {
            return true;
        } else {
            return false;
        }
    }''',
)
assert "private static boolean canEditUsers(SecurityContext secCtx) {" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting
# (ternary instead of if/else). Same exact over-broad role check, no
# renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    private static boolean hasEditRights(SecurityContext securityContext) {
        boolean isAdmin = securityContext.isUserInRole(Authentication.ROLE_ADMIN);
        boolean isRestRole = securityContext.isUserInRole(Authentication.ROLE_REST);
        return isAdmin || isRestRole ? true : false;
    }''',
)
assert structural_source != original
assert "boolean isRestRole = securityContext.isUserInRole(Authentication.ROLE_REST);" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (only ROLE_ADMIN grants edit rights) but a
# materially different technique: checks membership against a static
# single-element allowlist Set of roles instead of the real patch's
# direct single isUserInRole() call -- genuinely restricts edit rights to
# ROLE_ADMIN alone, different implementation shape (extensible to more
# roles later without an if/else rewrite).
SAFE_SOURCE = '''import java.util.Collections;
import java.util.Set;

public final class UserEditAuthorization {

    private static final Set<String> EDIT_ALLOWED_ROLES = Collections.singleton(Authentication.ROLE_ADMIN);

    private static boolean hasEditRights(SecurityContext securityContext) {
        for (String role : EDIT_ALLOWED_ROLES) {
            if (securityContext.isUserInRole(role)) {
                return true;
            }
        }
        return false;
    }
}
'''
(CASE_DIR / "variant_safe_01.java").write_text(SAFE_SOURCE)
assert "EDIT_ALLOWED_ROLES" in SAFE_SOURCE
assert "ROLE_REST" not in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (isUserInRole(ROLE_ADMIN) || isUserInRole(ROLE_REST))
# but this sibling method gates READ-ONLY access to user records, where
# granting ROLE_REST the same access as ROLE_ADMIN is the CORRECT,
# intended design -- a REST-API-scoped credential is meant to be able to
# read user data, just not edit it. Genuinely safe/correct despite the
# identical-looking role check, unlike hasEditRights()'s use of the same
# check for a write operation.
BENIGN_SOURCE = '''public final class UserViewAuthorization {

    // ROLE_REST is intentionally included here: REST-API credentials are
    // meant to be able to VIEW user records, just not edit them -- this
    // is the intended read-only privilege boundary, not the same mistake
    // the write-side edit-rights check made by using this combined test
    // for a write operation instead of a read one.
    private static boolean hasViewRights(SecurityContext securityContext) {
        if (securityContext.isUserInRole(Authentication.ROLE_ADMIN) || securityContext.isUserInRole(Authentication.ROLE_REST)) {
            return true;
        } else {
            return false;
        }
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN_SOURCE)
assert "hasEditRights" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0069.")

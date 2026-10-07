public final class UserViewAuthorization {

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

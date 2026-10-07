import java.util.Collections;
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

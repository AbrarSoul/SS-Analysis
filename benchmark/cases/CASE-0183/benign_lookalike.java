import hudson.util.FormValidation;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

public class HostFormatValidator {

    /**
     * Same Stapler form-validation endpoint shape as the connection test, but
     * it only checks the SYNTAX of the host string and never opens a
     * connection or reads any credential, so it has no side effect that would
     * need an administrator permission check.
     */
    @RequirePOST
    public FormValidation doCheckHostFormat(@QueryParameter("host") final String host) {
        if (host == null || !host.matches("[A-Za-z0-9.-]{1,253}")) {
            return FormValidation.error("Invalid host name");
        }
        return FormValidation.ok();
    }
}

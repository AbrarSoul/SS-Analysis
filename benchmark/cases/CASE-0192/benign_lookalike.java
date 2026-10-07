import hudson.util.FormValidation;
import org.kohsuke.stapler.QueryParameter;

public class MaskSyntaxCheck {

    /**
     * Same form-validation shape as doCheckIncludes, but it only checks that
     * the pattern text is non-blank and has no absolute path, without touching
     * any workspace or file, so there is no data for a caller to probe.
     */
    public FormValidation doCheckIncludesSyntax(@QueryParameter String value) {
        if (value == null || value.trim().isEmpty()) {
            return FormValidation.error("Pattern required");
        }
        if (value.startsWith("/")) {
            return FormValidation.error("Use a relative pattern");
        }
        return FormValidation.ok();
    }
}

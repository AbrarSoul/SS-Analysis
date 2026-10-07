import hudson.util.FormValidation;
import java.net.URI;
import java.net.URISyntaxException;
import org.kohsuke.stapler.QueryParameter;

public class EndpointSyntaxCheck {

    /**
     * Same form-validation method shape as doValidate, but it only PARSES the
     * text as a URI and never opens a connection, so it makes no outbound
     * request and needs no POST or permission protection.
     */
    public FormValidation doCheckEndpoint(@QueryParameter String endpoint) {
        try {
            URI uri = new URI(endpoint);
            return uri.getScheme() == null ? FormValidation.error("Missing scheme") : FormValidation.ok();
        } catch (URISyntaxException e) {
            return FormValidation.error("Invalid URL");
        }
    }
}

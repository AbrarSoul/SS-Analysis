import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import hudson.model.Item;
import java.util.Collections;
import java.util.List;

public class ScopedLookup {

    /**
     * Same lookupCredentials(...) + withId(...) shape as the tool's credential
     * resolution, but the lookup is made in the scope of the JOB passed in, so
     * only credentials that job may use can be found.
     */
    public StandardUsernamePasswordCredentials find(Item job, String credentialsId) {
        List<StandardUsernamePasswordCredentials> visible = CredentialsProvider.lookupCredentials(
                StandardUsernamePasswordCredentials.class, job, null, Collections.emptyList());
        return CredentialsMatchers.firstOrNull(visible, CredentialsMatchers.withId(credentialsId));
    }
}

package hudson.plugins.mercurial;

import hudson.Extension;
import hudson.model.UnprotectedRootAction;

/**
 * Same UnprotectedRootAction declaration and URL name/display-name methods as
 * the status screen, but it does not extend AbstractModelObject and has no
 * getSearchUrl(), so it never appears in the Jenkins search index.
 */
@Extension
public class HealthProbeAction implements UnprotectedRootAction {

    public String getDisplayName() {
        return "Mercurial health";
    }

    public String getIconFileName() {
        return null;
    }

    public String getUrlName() {
        return "mercurial-health";
    }
}

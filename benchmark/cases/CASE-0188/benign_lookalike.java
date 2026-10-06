import hudson.util.ListBoxModel;

public class ProtocolChoices {

    /**
     * Same ListBoxModel-returning form-fill shape as the installation list,
     * but the items are two fixed protocol names built into the plugin (not
     * administrator-configured data), so listing them to any caller discloses
     * nothing.
     */
    public ListBoxModel doFillProtocolItems() {
        ListBoxModel model = new ListBoxModel();
        model.add("http");
        model.add("https");
        return model;
    }
}

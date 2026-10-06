import hudson.util.FormValidation;

public class StaticHelp {

    /**
     * Same errorWithMarkup(...) call shape as the pattern check, but the
     * markup is a developer-written constant and no user text is placed in it.
     */
    public FormValidation help() {
        return FormValidation.errorWithMarkup("Use a <b>Java regular expression</b>, for example <code>.*-nightly</code>");
    }
}

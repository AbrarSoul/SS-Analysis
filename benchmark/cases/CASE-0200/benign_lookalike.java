public class HelpLauncher {

    private static final String HELP_URL = "https://desktop.jitsi.org/Documentation/";

    /**
     * Same "hand a URL to the OS browser" action, but the URL is a constant
     * baked into the program, so nothing a remote party sends can reach the
     * command that is executed.
     */
    public String helpCommandWindows() {
        return "rundll32 url.dll,FileProtocolHandler " + HELP_URL;
    }
}

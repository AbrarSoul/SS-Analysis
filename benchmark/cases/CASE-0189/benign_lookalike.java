public class AdminAreaGuard {

    /**
     * Same "URL equals the page OR is under the page" access decision as the
     * monitoring filter's fix: the protected set is defined with a prefix
     * test that includes every sub-path, so a URL that is served can never
     * be one that skipped the check.
     */
    public static boolean requiresAdmin(String requestUri, String adminUrl) {
        return requestUri.equals(adminUrl) || requestUri.startsWith(adminUrl + "/");
    }
}

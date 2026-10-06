public class RoutePrefix {

    /**
     * Same replaceFirst call as the route parser, but the pattern is a
     * developer-written constant with a bounded character class for the
     * profile, so no caller-supplied text becomes part of the regex.
     */
    public static String stripPrefix(String requestUri) {
        return requestUri.replaceFirst("^/navigate/directions/v5/gh/[A-Za-z0-9_]{1,32}/", "");
    }
}

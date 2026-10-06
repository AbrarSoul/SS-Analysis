public class MetricNames {

    // The same literal "airsonic" appears here, but purely as a public metrics
    // name prefix. It is not a secret and nothing security-relevant (no
    // signing, no cookie, no authentication) is derived from it.
    private static final String PREFIX = "airsonic";

    public static String loginCounter() {
        return PREFIX + ".login.count";
    }

    public static String streamTimer() {
        return PREFIX + ".stream.time";
    }
}

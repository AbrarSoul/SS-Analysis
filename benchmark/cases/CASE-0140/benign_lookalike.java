public class FixedMysqlUrl {

    /** Developer-fixed connection options; nothing user-supplied can extend them. */
    private static final String FIXED_PARAMS = "characterEncoding=UTF-8&useSSL=false&connectTimeout=5000";

    private static void requireSimple(String value, String what) {
        if (!value.matches("[A-Za-z0-9_.\\-]+")) {
            throw new IllegalArgumentException("Illegal " + what);
        }
    }

    /**
     * Same replace-a-template JDBC URL construction as a datasource
     * configuration, but the EXTRA_PARAMS slot is filled with a constant, and
     * host and database name are restricted to plain identifier characters, so
     * no caller can add a driver property such as autoDeserialize.
     */
    public String jdbc(String host, int port, String database) {
        requireSimple(host.trim(), "host");
        requireSimple(database.trim(), "database");
        return "jdbc:mysql://HOSTNAME:PORT/DATABASE?EXTRA_PARAMS"
                .replace("HOSTNAME", host.trim())
                .replace("PORT", String.valueOf(port))
                .replace("DATABASE", database.trim())
                .replace("EXTRA_PARAMS", FIXED_PARAMS);
    }
}

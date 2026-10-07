public class AuditIndexProbe {

    /** The only indices this probe may ever query: fixed, developer-defined names. */
    public enum AuditIndex {
        LOGIN("audit-login"),
        EXPORT("audit-export");

        private final String indexName;

        AuditIndex(String indexName) {
            this.indexName = indexName;
        }

        public String indexName() {
            return indexName;
        }
    }

    /**
     * Same `"select * from \"" + <name> + "\" limit 0"` concatenation, but the
     * name comes from a fixed enum constant, never from request text, so it
     * cannot contain a quote or any injected SQL.
     */
    public String probeSql(AuditIndex index) {
        return "select * from \"" + index.indexName() + "\" limit 0";
    }
}

import org.apache.ibatis.jdbc.SQL;

public class AuditKindQueries {

    public enum AuditKind { PROXY, AGENT, SORT }

    /**
     * Same SQL-builder shape with a value concatenated into a quoted literal,
     * but the value is an enum constant's name(): a fixed, developer-defined
     * set of identifiers, never request text.
     */
    public String toKindSql(AuditKind kind) {
        return new SQL()
                .SELECT("log_ts", "sum(count) as total")
                .FROM("audit_data")
                .WHERE("audit_kind = '" + kind.name() + "'")
                .GROUP_BY("log_ts")
                .ORDER_BY("log_ts")
                .toString();
    }
}

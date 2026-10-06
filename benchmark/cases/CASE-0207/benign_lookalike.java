package org.keycloak.quarkus.runtime.storage.legacy.infinispan;

/**
 * Standalone example of the same shape as configureTransportStack's flag
 * check (read one boolean option, gate a piece of setup on it), but reading
 * the SAME option it means to read, for an unrelated, non-security setting.
 */
public class AuditLogSetup {

    public static boolean shouldEnableVerboseAuditLog(java.util.Map<String, String> config) {
        return "true".equalsIgnoreCase(config.get("kc.audit-verbose"));
    }

    public static void configureAuditLog(java.util.Map<String, String> config, StringBuilder log) {
        if (shouldEnableVerboseAuditLog(config)) {
            log.append("verbose audit logging enabled\n");
        }
    }
}

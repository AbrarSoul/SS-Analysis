"""
Section 9 ground-truth test bundle: CASE-0207
(keycloak/keycloak, .../storage/legacy/infinispan/CacheManagerFactory.java
configureTransportStack, CVE-2024-10973, CWE-319 cleartext transmission of
sensitive information).

Core vulnerable mechanism: `configureTransportStack` decides whether to set up
mTLS for the embedded (JGroups) cache cluster transport by checking
`Configuration.isTrue(CachingOptions.CACHE_REMOTE_TLS_ENABLED)` -- the flag for
TLS to the *remote* Infinispan store, not `CACHE_EMBEDDED_MTLS_ENABLED_PROPERTY`,
the flag documented and intended for the *embedded* cluster transport. An
operator who sets only the embedded-mTLS option (and its keystore/truststore
properties) gets a cluster transport with mTLS silently NOT configured, so
inter-node cache traffic (which carries session tokens) goes out in the clear.
The upstream fix swaps the checked constant to `CACHE_EMBEDDED_MTLS_ENABLED_PROPERTY`.

Sibling sites: `CACHE_REMOTE_TLS_ENABLED` is also read (correctly, for its own
purpose) by `isRemoteTLSEnabled()` a few lines above, which gates TLS to the
*remote* store -- a different transport with its own flag. That call is not a
sibling of the bug and must NOT change in the safe variant, since flipping it
would break remote-store TLS and correctly-configured deployments.

Verification: `configureTransportStack` and its two callees
(`validateTlsAvailable`, `requiredStringProperty`) are extracted verbatim into a
small harness compiled with `javac`/run with `java`, against minimal stand-in
classes for `ConfigurationBuilderHolder`, `GlobalConfigurationBuilder`, `TLS`,
`TLSClientAuth`, `JGroupsTransport`, `Configuration`, `CachingOptions` and
`Logger`. `kc.cache-stack` is left unset in every run, so
`validateTlsAvailable` takes its early `stack == null` return and no real
JGroups protocol classes are needed. The harness records whether
`transportConfig.addProperty(JGroupsTransport.SOCKET_FACTORY, ...)` -- the
actual act of turning on mTLS -- was reached, for the case where only the
embedded-mTLS option (and required keystore/truststore properties) is set.

Every variant is the FULL real file. configureTransportStack is a private
method (not called by name from outside the class), so the renamed variant may
rename both the method and its locals as long as the internal call site is
updated too.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0207"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

s = original.index("    private void configureTransportStack(ConfigurationBuilderHolder builder) {")
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
assert original.count("configureTransportStack(builder)") == 1
assert original.count(BLOCK) == 1


def build(new_block, extra_replacements=()):
    assert new_block != BLOCK
    text = original[:s] + new_block + original[e:]
    for old, new in extra_replacements:
        assert text.count(old) == 1
        text = text.replace(old, new)
    return text


# --- Variant 1: renamed vulnerable variant ---
# Renames the method itself (private, single internal call site updated) and
# its locals; the wrong-flag check is untouched.
V1 = '''    private void setupTransportStack(ConfigurationBuilderHolder holder) {
        String stackName = Configuration.getRawValue("kc.cache-stack");

        var transportCfg = holder.getGlobalConfigurationBuilder().transport();
        if (stackName != null && !stackName.isBlank()) {
            transportCfg.defaultTransport().stack(stackName);
        }

        if (Configuration.isTrue(CachingOptions.CACHE_REMOTE_TLS_ENABLED)) {
            validateTlsAvailable(transportCfg.build());
            var tlsConfig = new TLS()
                    .enabled(true)
                    .setKeystorePath(requiredStringProperty(CACHE_EMBEDDED_MTLS_KEYSTORE_FILE_PROPERTY))
                    .setKeystorePassword(requiredStringProperty(CACHE_EMBEDDED_MTLS_KEYSTORE_PASSWORD_PROPERTY))
                    .setKeystoreType("pkcs12")
                    .setTruststorePath(requiredStringProperty(CACHE_EMBEDDED_MTLS_TRUSTSTORE_FILE_PROPERTY))
                    .setTruststorePassword(requiredStringProperty(CACHE_EMBEDDED_MTLS_TRUSTSTORE_PASSWORD_PROPERTY))
                    .setTruststoreType("pkcs12")
                    .setClientAuth(TLSClientAuth.NEED)
                    .setProtocols(new String[]{"TLSv1.3"});
            transportCfg.addProperty(JGroupsTransport.SOCKET_FACTORY, tlsConfig.createSocketFactory());
            Logger.getLogger(CacheManagerFactory.class).info("MTLS enabled for communications for embedded caches");
        }
    }
'''
v1 = build(V1, extra_replacements=[("configureTransportStack(builder)", "setupTransportStack(builder)")])
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
# The mTLS setup is extracted into a helper invoked from inside the same
# (still-wrong) condition; behavior unchanged.
V2 = '''    private void configureTransportStack(ConfigurationBuilderHolder builder) {
        String transportStack = Configuration.getRawValue("kc.cache-stack");

        var transportConfig = builder.getGlobalConfigurationBuilder().transport();
        if (transportStack != null && !transportStack.isBlank()) {
            transportConfig.defaultTransport().stack(transportStack);
        }

        if (Configuration.isTrue(CachingOptions.CACHE_REMOTE_TLS_ENABLED)) {
            enableEmbeddedMtls(transportConfig);
        }
    }

    private void enableEmbeddedMtls(org.infinispan.configuration.global.TransportConfigurationBuilder transportConfig) {
        validateTlsAvailable(transportConfig.build());
        var tls = new TLS()
                .enabled(true)
                .setKeystorePath(requiredStringProperty(CACHE_EMBEDDED_MTLS_KEYSTORE_FILE_PROPERTY))
                .setKeystorePassword(requiredStringProperty(CACHE_EMBEDDED_MTLS_KEYSTORE_PASSWORD_PROPERTY))
                .setKeystoreType("pkcs12")
                .setTruststorePath(requiredStringProperty(CACHE_EMBEDDED_MTLS_TRUSTSTORE_FILE_PROPERTY))
                .setTruststorePassword(requiredStringProperty(CACHE_EMBEDDED_MTLS_TRUSTSTORE_PASSWORD_PROPERTY))
                .setTruststoreType("pkcs12")
                .setClientAuth(TLSClientAuth.NEED)
                .setProtocols(new String[]{"TLSv1.3"});
        transportConfig.addProperty(JGroupsTransport.SOCKET_FACTORY, tls.createSocketFactory());
        Logger.getLogger(CacheManagerFactory.class).info("MTLS enabled for communications for embedded caches");
    }
'''
v2 = build(V2)
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Reads the correct (embedded-mTLS) flag into a named boolean instead of
# inlining the check, and gates on that; CACHE_REMOTE_TLS_ENABLED is left
# alone everywhere else (it still correctly gates the *remote*-store TLS in
# isRemoteTLSEnabled(), a non-sibling site).
V3 = '''    private void configureTransportStack(ConfigurationBuilderHolder builder) {
        String transportStack = Configuration.getRawValue("kc.cache-stack");

        var transportConfig = builder.getGlobalConfigurationBuilder().transport();
        if (transportStack != null && !transportStack.isBlank()) {
            transportConfig.defaultTransport().stack(transportStack);
        }

        boolean embeddedMtlsEnabled = Configuration.isTrue(CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED_PROPERTY);
        if (embeddedMtlsEnabled) {
            validateTlsAvailable(transportConfig.build());
            var tls = new TLS()
                    .enabled(true)
                    .setKeystorePath(requiredStringProperty(CACHE_EMBEDDED_MTLS_KEYSTORE_FILE_PROPERTY))
                    .setKeystorePassword(requiredStringProperty(CACHE_EMBEDDED_MTLS_KEYSTORE_PASSWORD_PROPERTY))
                    .setKeystoreType("pkcs12")
                    .setTruststorePath(requiredStringProperty(CACHE_EMBEDDED_MTLS_TRUSTSTORE_FILE_PROPERTY))
                    .setTruststorePassword(requiredStringProperty(CACHE_EMBEDDED_MTLS_TRUSTSTORE_PASSWORD_PROPERTY))
                    .setTruststoreType("pkcs12")
                    .setClientAuth(TLSClientAuth.NEED)
                    .setProtocols(new String[]{"TLSv1.3"});
            transportConfig.addProperty(JGroupsTransport.SOCKET_FACTORY, tls.createSocketFactory());
            Logger.getLogger(CacheManagerFactory.class).info("MTLS enabled for communications for embedded caches");
        }
    }
'''
v3 = build(V3)
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign look-alike ---
BENIGN = '''package org.keycloak.quarkus.runtime.storage.legacy.infinispan;

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
            log.append("verbose audit logging enabled\\n");
        }
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN)

package io.onedev.server.plugin.authenticator.ldap;

/**
 * Standalone example of the same shape: substitute a value into a template,
 * but the template is a plain log line (never an LDAP filter or any
 * query language), so no escaping is needed.
 */
class LogLineTemplate {

    static String render(String template, String user) {
        return template.replace("{0}", user);
    }
}

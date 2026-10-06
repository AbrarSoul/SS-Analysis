package org.springframework.ldap.core.support;

import java.util.Map;

/**
 * Standalone example of the same shape: set display-only properties on a
 * settings map (a UI theme and title) with no need to re-open any
 * connection for them to take effect.
 */
class DisplaySettings {

    static void apply(Map<String, String> settings, String theme, String title) {
        settings.put("theme", theme);
        settings.put("title", title);
    }
}

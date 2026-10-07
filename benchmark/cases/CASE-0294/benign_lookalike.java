package org.springframework.web.util;

/**
 * Standalone example of the same shape: pull the file extension out of a path
 * with a permissive regex for a MIME-type hint; the value is only used for a
 * content-type guess, never for an allow-list or redirect decision.
 */
final class ExtensionHint {

    private ExtensionHint() {
    }

    static String of(String path) {
        int dot = path.lastIndexOf('.');
        return dot < 0 ? "" : path.substring(dot + 1);
    }
}

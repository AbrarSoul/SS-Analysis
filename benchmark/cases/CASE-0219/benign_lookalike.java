package io.metersphere.gateway.service;

/**
 * Standalone example of the same shape (blank check, then a length check on a
 * short, server-defined value) for a display-name field that is never hashed or
 * used in a query.
 */
public class DisplayNameCheck {

    public static boolean isAcceptable(String displayName) {
        if (displayName == null || displayName.trim().isEmpty()) {
            return false;
        }
        return displayName.length() <= 64;
    }
}

package io.micronaut.http.netty;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Standalone example of the same shape (a constructor choosing a strictness
 * flag for an internal collection) where the flag only controls whether
 * duplicate keys are tolerated in a locally built settings map.
 */
public class SettingsMap {

    private final Map<String, String> values = new LinkedHashMap<>();
    private final boolean allowDuplicates;

    public SettingsMap() {
        this.allowDuplicates = false;
    }

    public void put(String key, String value) {
        if (!allowDuplicates && values.containsKey(key)) {
            throw new IllegalArgumentException("duplicate key " + key);
        }
        values.put(key, value);
    }
}

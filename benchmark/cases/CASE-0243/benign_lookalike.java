package org.opencastproject.ingest.impl;

import java.net.URI;
import java.util.Set;

/**
 * Standalone example of the same shape: decide whether a URL belongs to a
 * server list, for a log message only (no credentials are attached because of
 * the answer).
 */
public class UrlLabel {

    public static String label(Set<String> ownServers, URI uri) {
        String origin = uri.getScheme() + "://" + uri.getHost();
        return ownServers.contains(origin) ? "own" : "external";
    }
}

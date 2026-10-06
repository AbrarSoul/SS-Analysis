package org.springframework.session.web.http;

/**
 * Standalone example of the same shape: print the (public) application
 * version to standard output once at startup, a value that is not a
 * credential and is meant to appear in logs.
 */
class StartupBanner {

    static void printVersion(String version) {
        System.out.println("Application version " + version);
    }
}

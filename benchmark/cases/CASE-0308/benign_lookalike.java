package org.traccar;

/**
 * Standalone example of the same shape: build a display-only label from the
 * Java home path for a diagnostics page. The string is only shown to a
 * human, never handed to the operating system as a program path, so
 * quoting is irrelevant.
 */
class JavaHomeLabel {

    static String label(String javaHome) {
        return "Running on Java at " + javaHome + "\\bin\\java.exe";
    }
}

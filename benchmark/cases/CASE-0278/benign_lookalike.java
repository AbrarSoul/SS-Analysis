package io.quarkus.kubernetes.deployment;

/**
 * Standalone example of the same shape: stamp a manifest annotation with the
 * build tool version string, a public, non-sensitive value that needs no
 * sanitization.
 */
public class BuildToolAnnotation {

    public static String annotationValue(String buildToolVersion) {
        return buildToolVersion == null ? null : buildToolVersion.trim();
    }
}

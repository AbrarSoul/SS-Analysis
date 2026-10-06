package io.onedev.server.web.resource;

/**
 * Standalone example of the same shape: pick a Content-Type from the file
 * extension for a static, application-owned icon set (files shipped in the
 * jar, never user-supplied), which is safe to render inline.
 */
class BundledIconTypes {

    static String contentTypeOf(String iconName) {
        return iconName.endsWith(".svg") ? "image/svg+xml" : "image/png";
    }
}

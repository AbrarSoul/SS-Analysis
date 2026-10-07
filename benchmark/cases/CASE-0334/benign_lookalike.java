package org.xwiki.skinx.internal;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Standalone example of the same shape: build an output directory from page-name parts, but every part must
 * match a strict allow-list and the resulting canonical path must stay inside the export root.
 */
class SafeExportPaths {

    private static final Pattern SAFE_PART = Pattern.compile("[A-Za-z0-9_-]+");

    static File outputDirectory(File exportRoot, List<String> parts) throws IOException {
        File dir = exportRoot;
        for (String part : parts) {
            if (!SAFE_PART.matcher(part).matches()) {
                throw new IOException("Unsafe path part: " + part);
            }
            dir = new File(dir, part);
        }
        String root = exportRoot.getCanonicalPath() + File.separator;
        if (!(dir.getCanonicalPath() + File.separator).startsWith(root)) {
            throw new IOException("Path escapes the export directory");
        }
        return dir;
    }
}

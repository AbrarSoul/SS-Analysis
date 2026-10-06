package apoc.log;

import java.io.File;
import java.io.IOException;

/**
 * Standalone example of the same shape: decide whether a cache file that the
 * SERVER names lives under the cache directory, for a housekeeping job that only
 * deletes files the server itself created.
 */
public class CacheHousekeeping {

    public static boolean isServerCacheFile(File cacheDir, String serverGeneratedName) throws IOException {
        File candidate = new File(cacheDir, serverGeneratedName);
        return candidate.getCanonicalPath().startsWith(cacheDir.getCanonicalPath() + File.separator);
    }
}

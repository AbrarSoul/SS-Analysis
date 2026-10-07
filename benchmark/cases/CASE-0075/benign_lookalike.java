import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class BundledDefaultsExtractor {

    // BUNDLED_DEFAULTS_ZIP is packaged inside this application's own jar
    // at build time -- its entries were never supplied by an untrusted
    // download, unlike extractZip()'s user-selected resource pack.
    private static final String BUNDLED_DEFAULTS_ZIP = "/defaults/builtin-resources.zip";

    public static void extractBuiltinDefaults(File destDirectory) throws IOException {
        try (InputStream zipStream = BundledDefaultsExtractor.class.getResourceAsStream(BUNDLED_DEFAULTS_ZIP)) {
            // extraction logic omitted for this bundle
        }
    }
}

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public final class DefaultResourceInstaller {

    private static final String[] FIXED_RESOURCE_NAMES = {
        "defaults.xml", "schema.xsd", "README.txt"
    };

    /** Only ever installs files whose names come from the fixed array
     * above, compiled into this class -- never derived from any
     * external archive entry, so there is no traversal-capable input
     * this could ever receive. */
    public static void installDefaults(File outDir) throws IOException {
        for (String name : FIXED_RESOURCE_NAMES) {
            File target = new File(outDir, name);
            InputStream is = DefaultResourceInstaller.class.getResourceAsStream("/" + name);
            FileOutputStream fos = new FileOutputStream(target);
            while (is.available() > 0) {
                fos.write(is.read());
            }
            fos.close();
            is.close();
        }
    }
}

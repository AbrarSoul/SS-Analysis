import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class FlatUnzipper {

    /**
     * Same ZipFile-entries -> new File(dir, name) loop as a war deployer, but
     * every entry is flattened to its bare file name (new File(name).getName()),
     * so no entry name can carry a path component out of the directory.
     */
    public static void unpackFlat(File archive, File dir) throws IOException {
        try (ZipFile zip = new ZipFile(archive)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry ze = entries.nextElement();
                if (ze.isDirectory()) {
                    continue;
                }
                File outFile = new File(dir, new File(ze.getName()).getName());
                try (InputStream is = zip.getInputStream(ze); FileOutputStream os = new FileOutputStream(outFile)) {
                    byte[] buf = new byte[4096];
                    for (int n; (n = is.read(buf)) > 0; ) {
                        os.write(buf, 0, n);
                    }
                }
            }
        }
    }
}

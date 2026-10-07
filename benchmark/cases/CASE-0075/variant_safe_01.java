import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class SafeZipExtractor {

    public static void extractZip(File file, File destDirectory, ExtractTaskListener listener) throws IOException {
        if (!destDirectory.exists()) {
            destDirectory.mkdir();
        }
        String destCanonicalPath = destDirectory.getCanonicalPath();

        try (ZipFile zipFile = new ZipFile(file)) {
            Enumeration<? extends ZipEntry> zipEntries = zipFile.entries();
            int elementCount = 0;
            while (zipEntries.hasMoreElements()) {
                ZipEntry zipEntry = zipEntries.nextElement();
                File candidateFile = new File(destDirectory, zipEntry.getName());
                String candidateCanonicalPath = candidateFile.getCanonicalPath();
                if (!candidateCanonicalPath.startsWith(destCanonicalPath + File.separator)) {
                    listener.onMessage("Skipping " + zipEntry.getName() + ": resolves outside destination directory");
                    continue;
                }
                try (InputStream entryInputStream = zipFile.getInputStream(zipEntry)) {
                    candidateFile.getParentFile().mkdirs();
                    listener.fileProcessed(entryInputStream.available());
                    extractFile(entryInputStream, candidateFile);
                    elementCount++;
                }
            }
            listener.onMessage("Successfully extracted " + elementCount + " elements");
            listener.taskCompleted();
        }
    }

    private static void extractFile(InputStream in, File out) throws IOException {
        // implementation omitted for this bundle
    }
}

import java.io.File;
import java.io.IOException;
import java.util.StringTokenizer;

public class ContentFileLocator {

    private final File contentRoot;

    public ContentFileLocator(File contentRoot) throws IOException {
        this.contentRoot = contentRoot.getCanonicalFile();
    }

    /**
     * Same "walk the path segments until something matches" shape as a CGI
     * script search, but it only stops at a regular FILE, and it hands back
     * the CANONICAL path after checking it is still inside the content root,
     * so neither a directory, a differently-cased spelling, nor "../" can
     * change what is served. Nothing found is reported as null.
     */
    public File find(String pathInfo) throws IOException {
        File current = contentRoot;
        StringTokenizer walker = new StringTokenizer(pathInfo, "/");
        while (walker.hasMoreElements()) {
            current = new File(current, walker.nextToken());
            if (current.isFile()) {
                File canonical = current.getCanonicalFile();
                return canonical.getPath().startsWith(contentRoot.getPath() + File.separator) ? canonical : null;
            }
        }
        return null;
    }
}

import java.util.Set;
import java.util.Arrays;
import java.util.HashSet;

public class ContentTypeResolver {

    private static final Set<String> SAFE_OVERRIDE_CONTENT_TYPES = new HashSet<>(Arrays.asList(
        "text/csv", "text/tab-separated-values", "application/json", "application/octet-stream"
    ));

    public static String resolveContentType(String requestedContentType, String exporterDefaultType) {
        if (requestedContentType != null && SAFE_OVERRIDE_CONTENT_TYPES.contains(requestedContentType)) {
            return requestedContentType;
        }
        return exporterDefaultType;
    }
}

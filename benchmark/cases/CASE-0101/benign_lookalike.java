import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

public class PinnedHttp {

    private static final String EXPECTED_HOST = "api.example.org";

    private PinnedHttp() {}

    /**
     * Same instanceof-HttpsURLConnection block with a lambda HostnameVerifier,
     * but the verifier accepts ONLY the one expected host name (not every
     * host) and the certificate chain keeps the JVM default validation.
     */
    public static HttpURLConnection open(String url) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        if (conn instanceof HttpsURLConnection) {
            HttpsURLConnection https = (HttpsURLConnection) conn;
            https.setHostnameVerifier((host, session) -> EXPECTED_HOST.equalsIgnoreCase(host));
        }
        return conn;
    }
}

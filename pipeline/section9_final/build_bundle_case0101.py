"""
Section 9 ground-truth test bundle: CASE-0101
(apache/calcite, CVE-2020-13955, CWE-295 improper certificate validation).

Core vulnerable mechanism: `HttpUtils.getURLConnection()` configures every
HTTPS connection with `TrustAllSslSocketFactory.createSSLSocketFactory()`
(accepts ANY certificate chain) and `setHostnameVerifier((a, b) -> true)`
(accepts ANY host name), so a man-in-the-middle can present a self-signed
certificate for any host and read/alter the traffic (including the
credentials the Splunk adapter sends). The upstream fix deletes the whole
customisation and returns the default connection.

Every variant is the FULL real file with getURLConnection replaced.
getURLConnection has one in-file call site (executeMethod), which the
renamed variant also renames.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0101"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "  public static HttpURLConnection getURLConnection(String url)\n"
s = original.index(HDR)
e = original.index("\n  }\n", s) + len("\n  }\n")
BLOCK = original[s:e]
CALL = "final HttpURLConnection conn = getURLConnection(url);"
TRUST = '''      httpsConn.setSSLSocketFactory(
          TrustAllSslSocketFactory.createSSLSocketFactory());
      httpsConn.setHostnameVerifier((arg0, arg1) -> true);
'''
assert original.count(HDR) == 1 and BLOCK.count(TRUST) == 1
assert original.count("getURLConnection(") == 2 and original.count(CALL) == 1


def build(new_block, new_call=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + original[e:]
    if new_call:
        assert out.count(CALL) == 1
        out = out.replace(CALL, new_call)
    return out


# --- Variant 1: renamed vulnerable variant ---
def rename_outside_comments(text, pairs):
    out = []
    for line in text.split("\n"):
        if not line.lstrip().startswith("//"):
            for old, new in pairs:
                line = re.sub(r"\b%s\b" % old, new, line)
        out.append(line)
    return "\n".join(out)


b = BLOCK.replace("getURLConnection(", "openConnectionTo(")
b = rename_outside_comments(b, (("url", "endpoint"), ("conn", "rawConnection"), ("httpConn", "plainConn"), ("httpsConn", "tlsConn")))
assert "tlsConn.setHostnameVerifier((arg0, arg1) -> true);" in b and "openConnectionTo(String endpoint)" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(
    build(b, "final HttpURLConnection conn = openConnectionTo(url);"))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(
    '''    if (httpConn instanceof HttpsURLConnection) {
      HttpsURLConnection httpsConn = (HttpsURLConnection) httpConn;
''' + TRUST + '''    }

    return httpConn;
''',
    '''    if (!(httpConn instanceof HttpsURLConnection)) {
      return httpConn;
    }

    HttpsURLConnection httpsConn = (HttpsURLConnection) httpConn;
''' + TRUST + '''    return httpsConn;
''')
assert b != BLOCK and "TrustAllSslSocketFactory" in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Keeps the HTTPS branch but explicitly installs the JVM's default socket
# factory and default hostname verifier (full chain + host validation),
# instead of upstream's removal of the branch.
b = BLOCK.replace(
    TRUST,
    '''      httpsConn.setSSLSocketFactory(
          (javax.net.ssl.SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault());
      httpsConn.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
''')
b = b.replace('''    // take care of https stuff - most of the time it's only needed to
    // secure client/server comm
    // not to establish the identity of the server
''', '''    // https: use the JVM defaults so the server certificate chain and host
    // name are both validated
''')
safe_source = build(b)
assert "TrustAllSslSocketFactory" not in safe_source and "-> true" not in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.IOException;
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
'''
assert "-> true" not in benign_source and "TrustAll" not in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0101.")

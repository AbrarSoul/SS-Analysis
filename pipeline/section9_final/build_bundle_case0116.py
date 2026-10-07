"""
Section 9 ground-truth test bundle: CASE-0116
(apache/thrift, TSSLTransportFactory, CVE-2026-43869, CWE-297 improper
validation of certificate with host mismatch).

Core vulnerable mechanism: `createClient()` makes the TLS client socket
with `factory.createSocket(host, port)` and never enables endpoint
identification, so a raw SSLSocket only validates the certificate CHAIN,
not that the certificate belongs to `host`. A man-in-the-middle holding any
certificate that chains to a trusted CA can impersonate the server. The
upstream fix sets `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")`
on the socket before use.

Every variant is the FULL real file with createClient replaced.
createClient is private static with two in-file call sites
(getClientSocket overloads), which the renamed variant also renames.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0116"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "  private static TSocket createClient(SSLSocketFactory factory, String host, int port, int timeout)\n      throws TTransportException {\n"
s = original.index(HDR)
e = original.index("\n  }\n", s) + len("\n  }\n")
BLOCK = original[s:e]
CALL1 = "    return createClient(factory, host, port, timeout);\n"
CALL2 = "    return createClient(ctx.getSocketFactory(), host, port, timeout);\n"
SET_TIMEOUT = "      socket.setSoTimeout(timeout);\n"
assert original.count(HDR) == 1 and original.count(CALL1) == 1 and original.count(CALL2) == 1
assert original.count("createClient(") == 3 and BLOCK.count(SET_TIMEOUT) == 1
assert "setEndpointIdentificationAlgorithm" not in original


def build(new_block, calls=()):
    assert new_block != BLOCK
    out = original[:s] + new_block + original[e:]
    for old, new in calls:
        assert out.count(old) == 1
        out = out.replace(old, new)
    return out


def rename_outside_comments_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        st = line.lstrip()
        if st.startswith("//") or st.startswith("*") or st.startswith("/*"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for old, new in pairs:
                parts[i] = re.sub(r"\b%s\b" % old, new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("createClient(", "openSecureClient(")
b = rename_outside_comments_strings(b, (("factory", "socketFactory"), ("host", "remoteHost"), ("port", "remotePort"),
                                        ("timeout", "readTimeoutMs"), ("socket", "sslSocket"),
                                        ("tte", "transportEx"), ("e", "ex")))
assert "socketFactory.createSocket(remoteHost, remotePort)" in b and "sslSocket.setSoTimeout(readTimeoutMs);" in b
assert '"Could not connect to " + remoteHost + " on port " + remotePort' in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b, (
    (CALL1, "    return openSecureClient(factory, host, port, timeout);\n"),
    (CALL2, "    return openSecureClient(ctx.getSocketFactory(), host, port, timeout);\n"))))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(
    "      SSLSocket socket = (SSLSocket) factory.createSocket(host, port);\n",
    "      java.net.Socket raw = factory.createSocket(host, port);\n      SSLSocket socket = (SSLSocket) raw;\n")
assert b != BLOCK and "setSSLParameters" not in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Explicit post-handshake check that the server certificate names the host
# (DNS SAN with single-label wildcard, or IP SAN); upstream instead enables
# the JDK's HTTPS endpoint identification through SSLParameters.
b = BLOCK.replace(
    SET_TIMEOUT,
    SET_TIMEOUT + '''      socket.startHandshake();
      if (!certificateNamesHost(socket.getSession(), host)) {
        socket.close();
        throw new TTransportException(
            TTransportException.NOT_OPEN, "Server certificate does not match host " + host);
      }
''')
b += '''
  private static boolean certificateNamesHost(javax.net.ssl.SSLSession session, String host)
      throws Exception {
    java.security.cert.Certificate[] chain = session.getPeerCertificates();
    if (chain.length == 0 || !(chain[0] instanceof java.security.cert.X509Certificate)) {
      return false;
    }
    java.util.Collection<java.util.List<?>> names =
        ((java.security.cert.X509Certificate) chain[0]).getSubjectAlternativeNames();
    if (names == null) {
      return false;
    }
    for (java.util.List<?> entry : names) {
      int type = (Integer) entry.get(0);
      String value = (String) entry.get(1);
      if (type == 2 && dnsNameMatches(value, host)) {
        return true;
      }
      if (type == 7 && value.equals(host)) {
        return true;
      }
    }
    return false;
  }

  private static boolean dnsNameMatches(String pattern, String host) {
    if (pattern.startsWith("*.")) {
      int dot = host.indexOf('.');
      return dot > 0 && host.substring(dot).equalsIgnoreCase(pattern.substring(1));
    }
    return pattern.equalsIgnoreCase(host);
  }
'''
safe_source = build(b)
assert "startHandshake" in safe_source and safe_source.count("createClient(") == 3
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class PinnedTlsClient {

    private final SSLSocketFactory factory;

    /**
     * The trust store holds ONLY the one pinned server certificate, so the
     * only peer that can complete a handshake is the holder of that
     * certificate's private key. A separate host-name check adds nothing.
     */
    public PinnedTlsClient(InputStream pinnedServerCertificate) throws Exception {
        Certificate pinned = CertificateFactory.getInstance("X.509").generateCertificate(pinnedServerCertificate);
        KeyStore trustOnlyPinned = KeyStore.getInstance(KeyStore.getDefaultType());
        trustOnlyPinned.load(null, null);
        trustOnlyPinned.setCertificateEntry("pinned", pinned);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustOnlyPinned);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        this.factory = ctx.getSocketFactory();
    }

    public Socket connect(String host, int port, int timeout) throws IOException {
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(timeout);
        return socket;
    }
}
'''
assert "trustOnlyPinned" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0116.")

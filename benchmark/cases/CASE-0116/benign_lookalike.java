import java.io.IOException;
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

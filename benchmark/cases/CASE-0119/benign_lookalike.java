import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicReference;

public class SingleRequestConnection {

    private enum State { OPEN, CLOSED }

    private final AtomicReference<State> state = new AtomicReference<>(State.OPEN);
    private final Socket socket;

    public SingleRequestConnection(Socket socket) {
        this.socket = socket;
    }

    /**
     * Same "mark CLOSED, then close the socket" shape as a multiplexed
     * connection's close(), but this connection carries exactly one
     * request/response at a time on the socket itself: there are no child
     * streams or per-stream threads that could outlive it, so closing the
     * socket is the complete shutdown.
     */
    private void close() {
        state.set(State.CLOSED);
        try {
            socket.close();
        } catch (IOException ioe) {
            // nothing else to release
        }
    }
}

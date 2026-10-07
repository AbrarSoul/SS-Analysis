"""
Section 9 ground-truth test bundle: CASE-0209
(keylime/keylime, keylime/revocation_notifier.py start_broker.worker,
CVE-2022-23950, CWE-379 / CWE-668).

Core vulnerable mechanism: the revocation broker binds its ZeroMQ IPC socket
at a hardcoded path in the shared, world-writable `/tmp` directory
(`ipc:///tmp/keylime.verifier.ipc`) with no check of what is already there.
Any local user can pre-create a file or socket at that exact path before the
verifier starts (a classic predictable-shared-directory race), and once the
broker binds, any local user can connect to it and receive revocation events
(agent identifiers, timing, key material context) meant only for local
notification subscribers -- `frontend`/`backend` proxy every message with no
authentication. The upstream fix adds a `_SOCKET_PATH` check before bind: if
its parent directory does not exist, create it `0o700`; if something is
already there, verify its permission bits are exactly `0o700` and refuse
(raise) otherwise.

Measured caveat, kept in the manifest notes: upstream's own `stop_broker` fix
has a latent bug -- `os.path.exists(f"ipc://{_SOCKET_PATH}")` and
`os.remove(f"ipc://{_SOCKET_PATH}")` bake the `ipc://` URI scheme prefix into
a literal filesystem path (`os.path` functions do not parse URIs), so cleanup
silently never finds the real socket file and never removes it. This is
orthogonal to the exploited permission-check vulnerability itself (it is a
cleanup regression, not a new exposure) and is not reproduced in the safe
variant here, which uses the raw path for filesystem operations.

Sibling sites: `stop_broker` and `notify`'s inner `worker(tosend)` both
reference the same hardcoded socket path literal for cleanup/connect; the
safe variant repoints all three at the new, permission-checked location
(fixing the `ipc://`-prefix mistake along the way) so cleanup and publishing
still work. The vulnerable variants leave all three untouched.

Verification: `start_broker`'s inner `worker` is extracted (with a harness-
local text substitution of the literal socket-path string to a scratch
directory under Python's real `tempfile`, done only in the verification
harness, never in the shipped bundle files) and exec'd with a minimal
stand-in `zmq` module (`Context`/`socket`/`bind`/`setsockopt`/`device` all
no-ops that just record calls -- pyzmq is not installed and the bind/connect
mechanics are orthogonal to the permission-check bug) plus stand-in `config`
and `logger`. Two scenarios are run against the real filesystem (`os`,
`os.stat`, real permission bits): (1) the socket directory does not exist yet
-- does the code create it, and with what mode; (2) a file already exists at
the socket path with mode `0o777` (simulating a locally-planted, world-
writable pre-existing socket) -- does the code detect it and raise before
`zmq.Context/bind` is ever reached.

Every variant is the FULL real file. `start_broker`, `stop_broker` and
`notify` are module-level functions called by name from
`cloud_verifier_tornado.py`, so none of the three are renamed; the inner
`worker` closures are private to their enclosing function and may be renamed.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0209"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

s = original.index("def start_broker():")
e = original.index("\n\n\ndef notify(tosend):")
BLOCK = original[s:e]
assert original.count(BLOCK) == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
# Renames the inner worker (private to start_broker) and its locals; the
# module-level start_broker/stop_broker/notify names, called by name from
# cloud_verifier_tornado.py, are untouched. The insecure shared-/tmp path
# with no permission check is untouched.
V1 = '''def start_broker():
    def broker_worker():
        zmq_ctx = zmq.Context(1)
        sub_sock = zmq_ctx.socket(zmq.SUB)
        sub_sock.bind("ipc:///tmp/keylime.verifier.ipc")

        sub_sock.setsockopt(zmq.SUBSCRIBE, b'')

        # Socket facing services
        pub_sock = zmq_ctx.socket(zmq.PUB)
        pub_sock.bind(
            f"tcp://{config.get('cloud_verifier', 'revocation_notifier_ip')}:"
            f"{config.getint('cloud_verifier', 'revocation_notifier_port')}"
        )
        try:
            zmq.device(zmq.FORWARDER, sub_sock, pub_sock)
        except (KeyboardInterrupt, SystemExit):
            zmq_ctx.destroy()

    global broker_proc
    broker_proc = Process(target=broker_worker)
    broker_proc.start()


def stop_broker():
    global broker_proc
    if broker_proc is not None:
        # Remove the socket file before  we kill the process
        if os.path.exists("/tmp/keylime.verifier.ipc"):
            os.remove("/tmp/keylime.verifier.ipc")
        logger.info("Stopping revocation notifier...")
        broker_proc.terminate()
        broker_proc.join()'''
v1 = build(V1)
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
# The socket-opening steps are extracted into a helper, still with no
# permission check anywhere on the path.
V2 = '''def _open_broker_sockets():
    context = zmq.Context(1)
    frontend = context.socket(zmq.SUB)
    frontend.bind("ipc:///tmp/keylime.verifier.ipc")

    frontend.setsockopt(zmq.SUBSCRIBE, b'')

    # Socket facing services
    backend = context.socket(zmq.PUB)
    backend.bind(
        f"tcp://{config.get('cloud_verifier', 'revocation_notifier_ip')}:"
        f"{config.getint('cloud_verifier', 'revocation_notifier_port')}"
    )
    return context, frontend, backend


def start_broker():
    def worker():
        context, frontend, backend = _open_broker_sockets()
        try:
            zmq.device(zmq.FORWARDER, frontend, backend)
        except (KeyboardInterrupt, SystemExit):
            context.destroy()

    global broker_proc
    broker_proc = Process(target=worker)
    broker_proc.start()


def stop_broker():
    global broker_proc
    if broker_proc is not None:
        # Remove the socket file before  we kill the process
        if os.path.exists("/tmp/keylime.verifier.ipc"):
            os.remove("/tmp/keylime.verifier.ipc")
        logger.info("Stopping revocation notifier...")
        broker_proc.terminate()
        broker_proc.join()'''
v2 = build(V2)
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Moves the socket under a dedicated directory and verifies/creates its
# permissions before bind, structured as its own helper (upstream inlines the
# check directly in worker()); also fixes stop_broker/notify's sibling uses
# of the path, without reproducing upstream's "ipc://" literal-prefix bug.
V3 = '''_SOCKET_DIR = "/var/lib/keylime/ipc"
_SOCKET_PATH = os.path.join(_SOCKET_DIR, "keylime.verifier.ipc")


def _ensure_secure_socket_path():
    if not os.path.isdir(_SOCKET_DIR):
        os.makedirs(_SOCKET_DIR, 0o700)
    elif os.path.exists(_SOCKET_PATH):
        existing_mode = os.stat(_SOCKET_PATH).st_mode & 0o777
        if existing_mode != 0o700:
            msg = f"{_SOCKET_PATH} present with insecure permissions {oct(existing_mode)}"
            logger.error(msg)
            raise Exception(msg)


def start_broker():
    def worker():
        _ensure_secure_socket_path()

        context = zmq.Context(1)
        frontend = context.socket(zmq.SUB)
        frontend.bind(f"ipc://{_SOCKET_PATH}")

        frontend.setsockopt(zmq.SUBSCRIBE, b'')

        # Socket facing services
        backend = context.socket(zmq.PUB)
        backend.bind(
            f"tcp://{config.get('cloud_verifier', 'revocation_notifier_ip')}:"
            f"{config.getint('cloud_verifier', 'revocation_notifier_port')}"
        )
        try:
            zmq.device(zmq.FORWARDER, frontend, backend)
        except (KeyboardInterrupt, SystemExit):
            context.destroy()

    global broker_proc
    broker_proc = Process(target=worker)
    broker_proc.start()


def stop_broker():
    global broker_proc
    if broker_proc is not None:
        # Remove the socket file before  we kill the process
        if os.path.exists(_SOCKET_PATH):
            os.remove(_SOCKET_PATH)
        logger.info("Stopping revocation notifier...")
        broker_proc.terminate()
        broker_proc.join()'''
v3 = build(V3)
assert v3.count('mysock.connect("ipc:///tmp/keylime.verifier.ipc")') == 1
v3 = v3.replace('mysock.connect("ipc:///tmp/keylime.verifier.ipc")', 'mysock.connect(f"ipc://{_SOCKET_PATH}")')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign look-alike ---
BENIGN = '''"""Standalone example of the same shape as the fixed socket-path check
(create a dedicated directory with restrictive permissions if missing, verify
an existing path's permissions before reuse) but for a purely local,
non-sensitive scratch directory: there is nothing confidential or
authoritative behind it, so even skipping the check costs nothing."""
import os


_SCRATCH_DIR = "/var/tmp/example-app/render-cache"


def ensure_render_cache_dir():
    if not os.path.isdir(_SCRATCH_DIR):
        os.makedirs(_SCRATCH_DIR, 0o700)
    elif os.stat(_SCRATCH_DIR).st_mode & 0o777 != 0o700:
        # Hygiene only: tighten permissions on a plain thumbnail cache that
        # holds no secrets and is fully regenerable from public inputs.
        os.chmod(_SCRATCH_DIR, 0o700)
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)

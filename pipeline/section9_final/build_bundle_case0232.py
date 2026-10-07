"""
Section 9 ground-truth test bundle: CASE-0232
(modular/modular, max/serve/kvcache_agent/kvcache_agent.py
KVCacheAgentServer.__init__, CVE-2025-60455, CWE-502 deserialisation of
untrusted data).

Core vulnerable mechanism: the KV-cache agent listens on a ZeroMQ pull socket
for `KVCacheChangeMessage` events and builds the socket with
`ZmqPullSocket[KVCacheChangeMessage](zmq_endpoint=..., deserialize=pickle.loads)`.
Every frame that arrives on that endpoint is passed to `pickle.loads`, and a
pickle stream can name any importable callable (`os.system`, `subprocess.Popen`,
...) through `__reduce__`, so anyone who can send a frame to the endpoint runs
code in the agent process. The upstream fix replaces `pickle.loads` with
`msgpack_numpy_decoder(KVCacheChangeMessage)`.

Measured caveat, kept in the manifest notes: the upstream change carries the
comment "GENAI-233: This is currently non-functional": the original comment says
the message contains protobuf enums that msgspec/msgpack cannot serialise, so the
fix removes the code-execution path by giving up the feature (the pull socket no
longer decodes what the sender produces). The safe variant keeps the feature
working with a restricted unpickler that only resolves the one dataclass.

Sibling sites: `pickle.loads` appears only at this call site (the source comment
says it is the only use of pickle in the codebase).

Verification: each full file is imported as a module with the `max.*`, `grpc`
and pb2 imports stubbed; `KVCacheAgentServer(...)` is constructed with a
`ZmqPullSocket` stub that records the `deserialize` callable it was given. That
callable is fed (a) a pickle whose `__reduce__` runs `os.system('touch <marker>')`,
(b) a legitimate pickled KVCacheChangeMessage and (c) the same message encoded
with the REAL `msgspec` msgpack. For the patched file, `msgpack_numpy_decoder` is
stood in by `msgspec.msgpack.Decoder(cls).decode` (the real max.interfaces
function is not available here).

Every variant is the FULL real file. `KVCacheAgentServer.__init__` keeps its
name and signature; the renamed variant introduces a local for the callable.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0232"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


CALL = '''        self._kv_cache_events_pull_socket = ZmqPullSocket[KVCacheChangeMessage](
            zmq_endpoint=kv_cache_events_zmq_endpoint,
            deserialize=pickle.loads,
        )
'''
assert original.count(CALL) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, CALL, '''        decode_event = pickle.loads
        self._kv_cache_events_pull_socket = ZmqPullSocket[KVCacheChangeMessage](
            zmq_endpoint=kv_cache_events_zmq_endpoint,
            deserialize=decode_event,
        )
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CALL, '''        self._kv_cache_events_pull_socket = ZmqPullSocket[KVCacheChangeMessage](
            zmq_endpoint=kv_cache_events_zmq_endpoint,
            deserialize=_load_change_message,
        )
''')
v2 = swap(v2, "@dataclass\nclass KVCacheAgentServerConfig:", '''def _load_change_message(raw: bytes) -> Any:
    return pickle.loads(raw)


@dataclass
class KVCacheAgentServerConfig:''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, "import concurrent.futures\nimport logging\nimport pickle\n", "import concurrent.futures\nimport io\nimport logging\nimport pickle\n")
v3 = swap(v3, CALL, '''        self._kv_cache_events_pull_socket = ZmqPullSocket[KVCacheChangeMessage](
            zmq_endpoint=kv_cache_events_zmq_endpoint,
            deserialize=_load_change_message,
        )
''')
v3 = swap(v3, "@dataclass\nclass KVCacheAgentServerConfig:", '''class _ChangeMessageUnpickler(pickle.Unpickler):
    """Resolves exactly one global, the KVCacheChangeMessage dataclass."""

    def find_class(self, module: str, name: str) -> Any:
        if module == __name__ and name == "KVCacheChangeMessage":
            return KVCacheChangeMessage
        raise pickle.UnpicklingError(f"forbidden global {module}.{name}")


def _load_change_message(raw: bytes) -> "KVCacheChangeMessage":
    message = _ChangeMessageUnpickler(io.BytesIO(raw)).load()
    if not isinstance(message, KVCacheChangeMessage):
        raise pickle.UnpicklingError("unexpected message type")
    return message


@dataclass
class KVCacheAgentServerConfig:''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: a ZeroMQ-style receiver that decodes each
frame with json.loads, so a frame can only ever produce plain data."""
import json


class EventReceiver:
    def __init__(self, socket_factory, endpoint):
        self._socket = socket_factory(zmq_endpoint=endpoint, deserialize=json.loads)
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)

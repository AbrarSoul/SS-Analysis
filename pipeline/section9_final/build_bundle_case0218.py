"""
Section 9 ground-truth test bundle: CASE-0218
(mesop-dev/mesop, mesop/server/server.py handle_websocket (inside
configure_flask_app), CVE-2026-34824, CWE-125 / CWE-770 allocation of
resources without limits).

Core vulnerable mechanism: the WebSocket endpoint starts a brand-new OS thread
(`threading.Thread(...).start()`) for EVERY valid message it receives, so that
several updates on one connection can run concurrently. Nothing limits how
many are alive: a client (or many clients) that sends a stream of small valid
messages while the handlers are slow creates as many threads as messages,
exhausting threads and memory. The upstream fix creates a global
`ThreadPoolExecutor(max_workers=100)` and a non-blocking
`BoundedSemaphore(500)`; a message is dropped when 500 tasks are already in
flight, and the semaphore slot is released in a `finally`.

Measured caveat, kept in the manifest notes: the upstream cap is global (all
connections share the pool and the 500 slots), so one flooding client can use
up every slot and starve other clients' messages, which are then dropped.

Sibling sites: the SSE endpoint above (`/__ui__` POST) handles one request per
HTTP request and is not affected; this is the only per-message thread spawn.

Verification: the `if MESOP_WEBSOCKETS_ENABLED:` block of `configure_flask_app`
is extracted verbatim from each full file into a function body and exec'd with
stub `flask_sock.Sock` / `simple_websocket.Server`, a stub protobuf `UiRequest`,
and a `generate_data` that blocks on an Event. The registered handler is run
with a fake websocket that delivers 1200 valid messages and then raises; the
peak number of concurrently running generate_data calls and the number of
messages that got a worker are recorded.

Every variant is the FULL real file. handle_websocket is registered with
flask-sock under its function name (the endpoint name), so it keeps its name;
the renamed variant renames the inner helper and locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0218"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


THREAD = '''          # Start a new thread so we can handle multiple
          # concurrent updates for the same websocket connection.
          #
          # Note: we do copy_current_request_context at the callsite
          # to ensure that the request context is copied over for each new thread.
          thread = threading.Thread(
            target=copy_current_request_context(ws_generate_data),
            args=(ws, ui_request),
            daemon=True,
          )
          thread.start()
'''
assert original.count(THREAD) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, THREAD, '''          # Start a new thread so we can handle multiple
          # concurrent updates for the same websocket connection.
          #
          # Note: we do copy_current_request_context at the callsite
          # to ensure that the request context is copied over for each new thread.
          update_thread = threading.Thread(
            target=copy_current_request_context(stream_updates),
            args=(ws, ui_request),
            daemon=True,
          )
          update_thread.start()
''')
v1 = swap(v1, "      def ws_generate_data(ws, ui_request):", "      def stream_updates(ws, ui_request):")
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, THREAD, '''          start_update_thread(ws, ui_request)
''')
v2 = swap(v2, "      # Generate a unique session ID for the WebSocket connection\n", '''      def start_update_thread(ws, ui_request):
        # One thread per message so several updates on a connection can run at once.
        thread = threading.Thread(
          target=copy_current_request_context(ws_generate_data),
          args=(ws, ui_request),
          daemon=True,
        )
        thread.start()

      # Generate a unique session ID for the WebSocket connection
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Bounds the number of live update threads with one non-blocking semaphore
# (threads are still spawned, but never more than the cap; upstream uses a
# 100-worker ThreadPoolExecutor plus a 500-slot semaphore).
v3 = swap(original, "    sock = Sock(flask_app)\n", '''    sock = Sock(flask_app)

    # Never more than this many update threads alive across all connections.
    _WS_MAX_ACTIVE_UPDATES = 100
    _ws_slots = threading.BoundedSemaphore(_WS_MAX_ACTIVE_UPDATES)
''')
v3 = swap(v3, '''      def ws_generate_data(ws, ui_request):
        for data_chunk in generate_data(ui_request):
          if not ws.connected:
            break
          ws.send(data_chunk)
''', '''      def ws_generate_data(ws, ui_request):
        try:
          for data_chunk in generate_data(ui_request):
            if not ws.connected:
              break
            ws.send(data_chunk)
        finally:
          _ws_slots.release()
''')
v3 = swap(v3, THREAD, '''          if not _ws_slots.acquire(blocking=False):
            logging.warning(
              "Too many concurrent WebSocket updates (%d), dropping message.",
              _WS_MAX_ACTIVE_UPDATES,
            )
            continue

          thread = threading.Thread(
            target=copy_current_request_context(ws_generate_data),
            args=(ws, ui_request),
            daemon=True,
          )
          try:
            thread.start()
          except BaseException:
            _ws_slots.release()
            raise
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: one worker thread per queued job, for
a fixed list of nightly jobs read from configuration (a handful, chosen by the
operator, never by remote clients)."""
import threading


def run_nightly(jobs, run_job):
    threads = []
    for job in jobs:
        t = threading.Thread(target=run_job, args=(job,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)

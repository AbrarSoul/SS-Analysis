"""
Section 9 ground-truth test bundle: CASE-0067
(OSC/ondemand, CVE-2025-53636, CWE-400/CWE-779 uncontrolled resource
consumption via unbounded logging).

Core vulnerable mechanism: the callback passed to `ws.send(data, ...)`
logs every single send failure via a plain, unthrottled `console.log()`.
Once a client's WebSocket has gone away but the server-side terminal
process keeps producing output, EVERY data chunk from that terminal
triggers another failed `send()` and another log line -- with no
deduplication or rate limit, a single abandoned terminal session can
write an effectively unbounded number of near-identical log lines in a
short time, consuming disk space and log-processing resources
(CWE-779: logging of excessive data) for as long as the orphaned process
keeps running. The fix introduces a small windowed logger that combines
repeated identical messages into one line plus a skipped-count, instead
of writing one line per occurrence.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0067"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = '''      ws.send(data, function (error) {
        if (error) console.log('Send error: ' + error.message);
      });'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename the callback parameter error -> sendErr. Same exact unthrottled
# console.log() per occurrence.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''      ws.send(data, function (sendErr) {
        if (sendErr) console.log('Send error: ' + sendErr.message);
      });''',
)
assert "function (sendErr) {" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the formatted message before
# logging. Same exact unthrottled per-occurrence logging, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''      ws.send(data, function (error) {
        if (error) {
          const errorMessage = 'Send error: ' + error.message;
          console.log(errorMessage);
        }
      });''',
)
assert structural_source != original
assert "const errorMessage = 'Send error: ' + error.message;" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (bound the volume of near-identical log
# lines a single abandoned connection can produce) but a materially
# different technique: a simple per-message occurrence COUNTER that only
# logs on the 1st, 10th, 100th, ... occurrence (geometric backoff),
# instead of the real patch's time-windowed combine-and-flush logger --
# genuinely bounds log growth to O(log n) lines for n occurrences of the
# same message, different implementation shape.
SAFE_SOURCE = '''function createBackoffLogger() {
  const counts = new Map();

  return {
    log(message) {
      const count = (counts.get(message) || 0) + 1;
      counts.set(message, count);
      // Only log on powers of 10: 1st, 10th, 100th, ... occurrence.
      if (count === 1 || count % Math.pow(10, Math.floor(Math.log10(count))) === 0) {
        console.log(`${message} (occurrence #${count})`);
      }
    },
  };
}

function attachSendHandler(ws, term, data) {
  ws.errorLogger = ws.errorLogger || createBackoffLogger();
  ws.send(data, function (error) {
    if (error) {
      ws.errorLogger.log('Send error: ' + error.message);
    }
  });
}

module.exports = { createBackoffLogger, attachSendHandler };
'''
(CASE_DIR / "variant_safe_01.js").write_text(SAFE_SOURCE)
assert "createBackoffLogger" in SAFE_SOURCE

# --- Verify the backoff logger genuinely bounds log volume: for 1000
# occurrences of the same message, it should log only a handful of
# times, not 1000 ---
import subprocess

node_check = """
function createBackoffLogger() {
  const counts = new Map();
  let logCount = 0;
  return {
    log(message) {
      const count = (counts.get(message) || 0) + 1;
      counts.set(message, count);
      if (count === 1 || count % Math.pow(10, Math.floor(Math.log10(count))) === 0) {
        logCount++;
      }
    },
    getLogCount() { return logCount; },
  };
}
const logger = createBackoffLogger();
for (let i = 0; i < 1000; i++) {
  logger.log('Send error: socket closed');
}
const total = logger.getLogCount();
if (total >= 1000) {
  console.error('FAIL: logged', total, 'times for 1000 occurrences -- not bounded');
  process.exit(1);
}
console.log('OK: 1000 occurrences produced only', total, 'log lines');
"""
proc = subprocess.run(["node", "-e", node_check], capture_output=True, text=True)
assert proc.returncode == 0, f"safe variant failed live bounding verification: {proc.stdout} {proc.stderr}"

# --- Variant 4: benign structural look-alike ---
# Same visible shape (a send-style callback that logs unconditionally on
# error) but this sibling is the completion callback for a ONE-SHOT HTTP
# health-check request that fires AT MOST ONCE per server startup --
# never a per-data-chunk stream callback that can fire repeatedly for a
# single abandoned connection -- so even fully unthrottled logging here
# can never flood anything, unlike the ws.send() callback which fires
# once per terminal output chunk for as long as the process lives.
BENIGN_SOURCE = '''function pingHealthEndpointOnce(client, url) {
  // Fires exactly once, at server startup -- never attached to a
  // repeating stream of events, so there is no way this callback could
  // ever be invoked more than a handful of times in a process lifetime.
  client.get(url, function (error) {
    if (error) console.log('Health check failed: ' + error.message);
  });
}

module.exports = { pingHealthEndpointOnce };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN_SOURCE)
assert "ws.send" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0067.")

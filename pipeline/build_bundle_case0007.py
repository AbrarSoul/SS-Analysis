"""
Section 9 ground-truth test bundle: CASE-0007
(llamastack/llama-stack, CVE-2026-25211, CWE-532 -- sensitive info in logs).

Core vulnerable mechanism: initialize() logs the entire self.config object
(f"...: {self.config}"), which includes the plaintext database password
(self.config.password is used two lines later to open the psycopg2
connection) -- so the credential ends up in application logs.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0007"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_LINE = '        log.info(f"Initializing PGVector memory adapter with config: {self.config}")\n'
assert VULNERABLE_LINE in original
assert original.count(VULNERABLE_LINE) == 1

# --- Variant 1: renamed vulnerable variant ---
# The logged value is captured under a new name before logging, so a rule
# keyed on the literal token `self.config` inside the f-string would miss
# this. Same exact vulnerability: the full config, password included, is
# still what gets logged.
renamed_source = original.replace(
    VULNERABLE_LINE,
    '        config_snapshot = self.config\n'
    '        log.info(f"Initializing PGVector memory adapter with config: {config_snapshot}")\n',
)
assert renamed_source != original
assert "config_snapshot = self.config" in renamed_source
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: equivalent API-call formatting -- %-style lazy logging
# instead of an eager f-string. Textually very different from the
# original line, same exact vulnerability (full config incl. password
# still passed to the logger).
structural_source = original.replace(
    VULNERABLE_LINE,
    '        log.info("Initializing PGVector memory adapter with config: %s", self.config)\n',
)
assert structural_source != original
assert 'log.info("Initializing PGVector memory adapter with config: %s", self.config)' in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (password never reaches the log)
# but implemented via model_dump() + pop()/reassignment instead of the
# real patch's model_dump(exclude={"password"}) + dict merge, and a
# different redaction placeholder -- not byte-identical to the known fix.
safe_source = original.replace(
    VULNERABLE_LINE,
    '        config_dict = self.config.model_dump()\n'
    '        config_dict["password"] = "<redacted>"\n'
    '        log.info(f"Initializing PGVector memory adapter with config: {config_dict}")\n',
)
assert safe_source != original
assert 'config_dict["password"] = "<redacted>"' in safe_source
assert "{self.config}" not in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Adds a new method that also logs an f-string built from instance state,
# the same superficial shape as the vulnerable line, but the logged value
# is a small dict of booleans -- never self.config, never a credential.
BENIGN_ADDITION = '''
    def log_connection_status(self) -> None:
        """Logs only connection status flags.

        Never includes the full config object or any credential
        material, unlike the vulnerable startup log line this class
        also used to emit.
        """
        status = {
            "connected": self.conn is not None,
            "vector_store_ready": self.vector_store_table is not None,
        }
        log.info(f"PGVector connection status: {status}")
'''
anchor = "    async def initialize(self) -> None:\n        config_dict = self.config.model_dump()"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "log_connection_status" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)

print("Wrote 4 new samples for CASE-0007.")

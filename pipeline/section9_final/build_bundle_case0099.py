"""
Section 9 ground-truth test bundle: CASE-0099
(apache/airflow, CVE-2022-40604, CWE-134 uncontrolled format string).

Core vulnerable mechanism: `FileTaskHandler._read()` builds the worker
log-server URL with
`os.path.join("http://{ti.hostname}:{worker_log_server_port}/log",
log_relative_path).format(ti=ti, ...)`. `log_relative_path` (rendered from
dag_id / task_id / run_id, which users control) is joined INTO the template
BEFORE `.format()` runs, so any `{...}` in it is interpreted as a format
field: `{ti.<attr>}` / `{ti.__class__.__init__.__globals__[...]}` leak
attributes and secrets from the task-instance object into the fetched URL
(and error text). The upstream fix builds the URL with an f-string and
`urljoin`, so the path is never part of a format template.

Every variant is the FULL real file with `_read` replaced. `_read` has one
in-file call site (`read()`), which the renamed variant also renames.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0099"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.py").read_text().splitlines()) + "\n"

START = "    def _read(self, ti, try_number, metadata=None):\n"
END = "    def read(self, task_instance, try_number=None, metadata=None):\n"
s, e = original.index(START), original.index(END)
BLOCK = original[s:e]
CALL = "self._read(task_instance, try_number_element, metadata)"
URL_STMT = '''            url = os.path.join("http://{ti.hostname}:{worker_log_server_port}/log", log_relative_path).format(
                ti=ti, worker_log_server_port=conf.get('logging', 'WORKER_LOG_SERVER_PORT')
            )
'''
assert original.count(START) == 1 and original.count(END) == 1 and BLOCK.count(URL_STMT) == 1
assert original.count(CALL) == 1 and original.count("._read(") == 1


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
        if not line.lstrip().startswith("#"):
            for old, new in pairs:
                line = re.sub(r"\b%s\b" % old, new, line)
        out.append(line)
    return "\n".join(out)


b = BLOCK.replace("def _read(", "def _fetch_task_log(")
b = rename_outside_comments(b, (("log_relative_path", "relative_log_path"), ("location", "local_log_path"), ("url", "worker_log_url")))
assert "relative_log_path).format(" in b and "def _fetch_task_log(" in b and "def _read(" not in b
(CASE_DIR / "variant_vulnerable_01.py").write_text(build(b, "self._fetch_task_log(task_instance, try_number_element, metadata)"))

# --- Variant 2: structurally changed vulnerable variant ---
# Two-step build: the tainted template is materialised first, then formatted.
b = BLOCK.replace(
    URL_STMT,
    '''            url_template = os.path.join("http://{ti.hostname}:{worker_log_server_port}/log", log_relative_path)
            url = url_template.format(
                ti=ti, worker_log_server_port=conf.get('logging', 'WORKER_LOG_SERVER_PORT')
            )
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# `.format()` is applied ONLY to the constant host/port template; the
# user-influenced path is percent-encoded and appended afterwards, so it is
# never interpreted as a format string (upstream uses an f-string + urljoin).
b = BLOCK.replace(
    URL_STMT,
    '''            from urllib.parse import quote

            base_url = "http://{ti.hostname}:{worker_log_server_port}/log".format(
                ti=ti, worker_log_server_port=conf.get('logging', 'WORKER_LOG_SERVER_PORT')
            )
            url = base_url + "/" + quote(log_relative_path)
''')
safe_source = build(b)
assert 'os.path.join("http://{ti.hostname}' not in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import os

HEALTH_PAGE = "health.txt"


def build_worker_health_url(hostname, port):
    """Same os.path.join(template, x).format(...) shape, but the joined-in
    segment is a fixed developer-written constant, so nothing user-controlled
    ever becomes part of the format template; user data (hostname, port) is
    only ever passed as a format ARGUMENT."""
    return os.path.join("http://{hostname}:{port}/log", HEALTH_PAGE).format(
        hostname=hostname, port=port
    )
'''
assert "log_relative_path" not in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0099.")

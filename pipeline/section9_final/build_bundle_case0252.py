"""
Section 9 ground-truth test bundle: CASE-0252
(pallets/werkzeug, src/werkzeug/debug/__init__.py get_machine_id /
_generate, CVE-2019-14806, CWE-331 insufficient entropy in a derived secret).

Core vulnerable mechanism: the interactive debugger is unlocked with a PIN derived
from "public bits" (user name, module, app name, module path) and "private bits"
(the MAC address and `get_machine_id()`). On Linux `_generate` returns the first
non-empty line of `/etc/machine-id` or `/proc/sys/kernel/random/boot_id`. Every
container started from the same image shares the same baked-in `/etc/machine-id` (and a
containerised MAC address is a predictable docker address), so the "secret" half of the
PIN is identical across all deployments of that image and can be computed by anyone who
has the image; an attacker who reaches an exposed debugger can derive the PIN offline. The
upstream fix first reads the first line of `/proc/self/cgroup` and, when it contains
`/docker/`, uses the container id after it.

Measured caveat, kept in the manifest notes: the upstream fix only recognises a first
cgroup line that contains `/docker/` (cgroup v1 Docker). A cgroup v2 host
(`0::/`), Kubernetes (`/kubepods/.../<id>`) or containerd (`cri-containerd-<id>.scope`)
line falls through to the shared machine-id again, and the first line alone may name a
different controller than the docker one. The safe variant looks for a 64-hex-digit
container id anywhere in the cgroup file.

Sibling sites: `get_machine_id` is the only source of the machine-derived secret;
`get_pin_and_cookie_name` calls it once.

Verification: `get_machine_id` (which contains `_generate`) is extracted verbatim from
each full file into a namespace whose `open` is replaced by a stand-in serving a fake
`/etc/machine-id`, `/proc/sys/kernel/random/boot_id` and `/proc/self/cgroup`, with
the module cache reset per scenario. Scenarios: two Docker containers built from the same
image (same machine-id, different cgroup ids), a cgroup v2 container, a Kubernetes-style
container, and a plain host.

Every variant is the FULL real file. `get_machine_id` is called by name from
`get_pin_and_cookie_name`, so its name and signature are kept; the renamed variant
renames locals inside `_generate`.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0252"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


LINUX = '''        # Potential sources of secret information on linux.  The machine-id
        # is stable across boots, the boot id is not
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id":
            try:
                with open(filename, "rb") as f:
                    return f.readline().strip()
            except IOError:
                continue
'''
assert original.count(LINUX) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("    def _generate():")
e = original.index("    _machine_id = rv = _generate()")
seg = original[s:e]
for a, b in (("filename", "source_path"), ("dump", "ioreg_out"), ("match", "serial"), ("machineGuid", "guid"), ("rk", "reg_key")):
    seg = re.sub(r"\b%s\b" % a, b, seg)
seg = seg.replace("with open(source_path, \"rb\") as f:\n                    return f.readline().strip()", "with open(source_path, \"rb\") as handle:\n                    return handle.readline().strip()")
assert "handle.readline" in seg and "source_path" in seg
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + seg + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, LINUX, '''        linux_id = _read_linux_id()
        if linux_id is not None:
            return linux_id
''')
v2 = swap(v2, "def get_machine_id():", '''def _read_linux_id():
    # Potential sources of secret information on linux.  The machine-id
    # is stable across boots, the boot id is not
    for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id":
        try:
            with open(filename, "rb") as f:
                return f.readline().strip()
        except IOError:
            continue
    return None


def get_machine_id():''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, LINUX, '''        # A container id (64 hex digits, from any cgroup line: Docker, Kubernetes, containerd)
        # tells containers apart even when they share the machine-id baked into the image.
        try:
            with open("/proc/self/cgroup") as f:
                cgroup_text = f.read()
        except IOError:
            pass
        else:
            container_id = re.search(r"[0-9a-f]{64}", cgroup_text)
            if container_id is not None:
                return container_id.group(0).encode("utf-8")

        # Potential sources of secret information on linux.  The machine-id
        # is stable across boots, the boot id is not
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id":
            try:
                with open(filename, "rb") as f:
                    return f.readline().strip()
            except IOError:
                continue
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: derive a per-host cache key from a
host-id file, for a cache directory name only (no authentication depends on it)."""


def cache_key(host_id_path="/etc/machine-id"):
    try:
        with open(host_id_path, "rb") as handle:
            return handle.readline().strip()
    except IOError:
        return b"unknown-host"
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)

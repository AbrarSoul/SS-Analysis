"""
Section 9 ground-truth test bundle: CASE-0246
(openstack/cinder, cinder/volume/drivers/dell_emc/scaleio/driver.py
ScaleIODriver.__init__, CVE-2020-10755, CWE-522 insufficiently protected
credentials; OSSN-0086).

Core vulnerable mechanism: `__init__` builds `self.connection_properties` with
the ScaleIO REST gateway's `serverPassword` and `serverToken`.
`initialize_connection` copies that dict and returns it as the `data` of the
connection info, which Cinder stores and hands back to the API caller and to
the compute host that attaches the volume, so the storage array's administrative
credentials become readable by every project user who can request a volume
attachment's connection info (and sit in the Nova database). The upstream fix
removes `serverPassword` and `serverToken` from the dict and adds
`config_group`, so the os-brick connector on the volume host looks the
credentials up in its own configuration.

Measured caveat, kept in the manifest notes: the upstream change depends on
os-brick (outside this file) accepting `config_group`; the local
`_sio_attach_volume` / `_sio_detach_volume` (which call os-brick on the cinder-volume
host with a copy of the same dict) no longer carry credentials in the patched file.
The safe variant keeps the returned connection info free of secrets and adds the
credentials back only to the two local calls, so it does not depend on the
os-brick version.

Sibling sites: `initialize_connection` is where the dict leaves the driver; the two
local uses stay inside the volume service. The `VERSION` / docstring bump in the
upstream diff is documentation and is not reproduced.

Verification: each full file is imported as a module with the `cinder.*`,
`os_brick.*`, `oslo_*`, `distutils`, `six` and `requests` imports stubbed
(`interface.volumedriver` is an identity decorator, `driver.VolumeDriver` a small
base class). A `ScaleIODriver` is constructed with a configuration holding an
administrative password, and `initialize_connection` is called (its QoS helpers are
stubbed); the returned `data` dict is inspected for the password.

Every variant is the FULL real file. `__init__` and `initialize_connection` are the
Cinder driver interface, so their names and signatures are kept; the renamed variant
renames the instance attribute that holds the dict.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0246"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


PROPS = '''        self.connection_properties = {
            'scaleIO_volname': None,
            'hostIP': None,
            'serverIP': self.server_ip,
            'serverPort': self.server_port,
            'serverUsername': self.server_username,
            'serverPassword': self.server_password,
            'serverToken': self.server_token,
            'iopsLimit': None,
            'bandwidthLimit': None,
        }
'''
assert original.count(PROPS) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = re.sub(r"\bself\.connection_properties\b", "self.attach_defaults", original)
assert v1.count("self.attach_defaults") == original.count("self.connection_properties") == 4
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, PROPS, "        self.connection_properties = self._base_connection_properties()\n")
v2 = swap(v2, "    def check_for_setup_error(self):", '''    def _base_connection_properties(self):
        return {
            'scaleIO_volname': None,
            'hostIP': None,
            'serverIP': self.server_ip,
            'serverPort': self.server_port,
            'serverUsername': self.server_username,
            'serverPassword': self.server_password,
            'serverToken': self.server_token,
            'iopsLimit': None,
            'bandwidthLimit': None,
        }

    def check_for_setup_error(self):''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, PROPS, '''        # No credentials in the properties that leave the driver as connection info.
        self.connection_properties = {
            'scaleIO_volname': None,
            'hostIP': None,
            'serverIP': self.server_ip,
            'serverPort': self.server_port,
            'serverUsername': self.server_username,
            'config_group': self.configuration.config_group,
            'iopsLimit': None,
            'bandwidthLimit': None,
        }
''')
v3 = swap(v3, '''        LOG.debug("Calling os-brick to attach ScaleIO volume.")
        connection_properties = dict(self.connection_properties)
''', '''        LOG.debug("Calling os-brick to attach ScaleIO volume.")
        connection_properties = self._local_connection_properties()
''')
v3 = swap(v3, '''        LOG.info("Calling os-brick to detach ScaleIO volume.")
        connection_properties = dict(self.connection_properties)
''', '''        LOG.info("Calling os-brick to detach ScaleIO volume.")
        connection_properties = self._local_connection_properties()
''')
v3 = swap(v3, "    def _sio_attach_volume(self, volume):", '''    def _local_connection_properties(self):
        """Properties for os-brick calls made on this volume host only (never returned to callers)."""
        properties = dict(self.connection_properties)
        properties['serverPassword'] = self.server_password
        properties['serverToken'] = self.server_token
        return properties

    def _sio_attach_volume(self, volume):''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: a dict of connection settings returned
to callers that only holds public, non-secret values (host, port, group name), with
the password kept in the service's own configuration."""


def public_connection_info(host, port, group):
    return {"host": host, "port": port, "config_group": group}
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)

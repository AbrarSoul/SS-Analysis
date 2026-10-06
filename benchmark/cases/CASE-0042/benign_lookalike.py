import subprocess


class SandboxMaintenance:
    """Periodic sandbox cleanup, run on a fixed schedule with no
    per-request or user-controlled input anywhere in the command."""

    def __init__(self, user: str):
        self.user = user

    def clear_temp_files(self):
        # Entirely hardcoded -- nothing here is derived from a request,
        # session id, or any other attacker-reachable value.
        fixed_command = "/usr/bin/find /opt/maxkb/app/sandbox -name '*.tmp' -delete"
        return subprocess.run(
            ["su", "-c", fixed_command, self.user],
            text=True,
            capture_output=True,
        )

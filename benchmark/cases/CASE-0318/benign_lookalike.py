"""Public health endpoint: reports a fixed, server-chosen status file; no request-controlled path and no shell."""
import json

STATUS_FILE = '/var/run/app/upgrade.status'


def upgrade_status_view(read_file=open):
    """Return the progress text of the fixed status file as JSON.

    The path is a module constant, the read is a plain file read (no
    subprocess, no root), so publishing it without a login is intentional.
    """
    try:
        with read_file(STATUS_FILE) as handle:
            text = handle.read()
    except OSError:
        text = ''
    return json.dumps({'abort': 1 if '[200]' in text else 0, 'requestStatus': text})

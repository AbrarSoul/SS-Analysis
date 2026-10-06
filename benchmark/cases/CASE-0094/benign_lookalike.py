import os
import subprocess


def current_user_name():
    """Same '/bin/sh -c "<cmd> %s" % value' shape, but the interpolated value
    is an integer returned by the operating system (os.getuid(), formatted
    with %d), never text supplied by a remote user, so no shell
    metacharacters can be injected."""
    command = '/usr/bin/id -nu %d' % os.getuid()
    return subprocess.check_output(['/bin/sh', '-c', command]).decode().strip()

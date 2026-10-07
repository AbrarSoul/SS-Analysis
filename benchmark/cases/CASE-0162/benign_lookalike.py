import subprocess


def list_installed_policies():
    """Same "run a helper and return its text" shape as run_fix, but the
    command is a fixed argument list with no caller-supplied value in it, and
    no shell is involved."""
    proc = subprocess.Popen(["semodule", "-l"], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, universal_newlines=True)
    return proc.communicate()[0]

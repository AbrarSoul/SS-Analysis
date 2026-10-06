from subprocess import PIPE, Popen


def git_version():
    """Same Popen(['git', ...]) call shape as the status segment, but the
    command is a fixed argument list that does not touch any repository, so no
    repository-supplied configuration (such as core.fsmonitor) is ever read."""
    proc = Popen(['git', '--version'], stdout=PIPE, stderr=PIPE)
    return proc.communicate()[0].decode('utf-8').strip()

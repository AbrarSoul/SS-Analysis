import os


def notify_finished(timeout):
    """Same "build a notify-send shell string and hand it to os.system"
    shape, but every part is constant except the timeout, which is forced
    through int() and formatted with %d, so it can hold only digits (or a
    sign); no text from the backup, the profile or the user reaches the shell."""
    cmd = "notify-send -t %d 'Back In Time' 'Backup finished'" % (1000 * int(timeout))
    return os.system(cmd)

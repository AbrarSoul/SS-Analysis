import logging
import subprocess


class SoundAlertHandler(logging.Handler):
    """Plays a fixed alert sound for ERROR records; the log text never reaches a command."""

    def emit(self, record):
        if record.levelno >= logging.ERROR:
            subprocess.run(["aplay", "/usr/share/sounds/alert.wav"], check=False, timeout=2)

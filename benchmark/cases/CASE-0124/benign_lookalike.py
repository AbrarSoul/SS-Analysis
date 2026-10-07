import os


def run_build(jobs: int) -> int:
    """Same "f-string command handed to os.system" shape, but the only
    interpolated value goes through int(), so it can contain nothing except
    an optional sign and digits (anything else raises ValueError before a
    shell is ever involved), and everything else in the command is a
    constant. No caller-controlled text can reach the shell."""
    command = f"make -j {int(jobs)}"
    return os.system(command)

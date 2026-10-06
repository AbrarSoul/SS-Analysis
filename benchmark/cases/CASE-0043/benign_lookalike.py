import os


def absreal(path: str) -> str:
    return os.path.realpath(os.path.abspath(path))


class HistoryPathResolver:
    """Resolves the server-side history-database path for a volume.

    Unlike VFS.canonical(), this never takes attacker-influenced input --
    `histpath` is set once from server config at startup, never from a
    request path -- so there is no share-restriction to bypass here.
    """

    def __init__(self, histpath: str) -> None:
        self.histpath = histpath

    def canonical_history_path(self, resolve: bool = True) -> str:
        ap = self.histpath
        return absreal(ap) if resolve else ap

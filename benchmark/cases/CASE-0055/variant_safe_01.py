import os


class SafePathJoiner:
    def __init__(self, working_directory: str):
        self.WORKING_DIRECTORY = working_directory

    def safe_join(self, paths) -> str:
        if "/path/to/" in paths:
            paths = paths.replace("/path/to/", "")
        base = os.path.realpath(self.WORKING_DIRECTORY)
        candidate = os.path.realpath(
            os.path.normpath(os.path.join(self.WORKING_DIRECTORY, *paths.split("/")))
        )
        try:
            common = os.path.commonpath([base, candidate])
        except ValueError:
            common = None
        if common != base:
            raise PermissionError("Path traversal detected: refusing to access path outside workspace")
        path_dir = os.path.dirname(candidate)
        os.makedirs(path_dir, exist_ok=True)
        return candidate

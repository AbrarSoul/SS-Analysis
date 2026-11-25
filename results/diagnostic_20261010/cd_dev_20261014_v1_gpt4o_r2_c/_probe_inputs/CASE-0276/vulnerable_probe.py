def get_data(self, path):
    """Return the data from path as raw bytes."""
    if isinstance(self, (SourceLoader, ExtensionFileLoader)):
        with _io.open_code(str(path)) as file_renamed:
            return file_renamed.read()
    else:
        with _io.FileIO(path, 'r') as file_renamed:
            return file_renamed.read()
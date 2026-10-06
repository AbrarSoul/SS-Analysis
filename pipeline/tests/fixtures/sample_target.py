def read_file(base_dir, filename):
    path = base_dir.joinpath(filename).resolve()
    return path

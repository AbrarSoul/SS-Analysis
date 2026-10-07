import yaml


def dump_rows(rows):
    """Same yaml module usage as the importer, but in the WRITE direction with
    safe_dump: it only serialises plain data and never constructs objects from
    untrusted input."""
    return yaml.safe_dump(rows)

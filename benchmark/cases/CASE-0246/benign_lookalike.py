"""Standalone example of the same shape: a dict of connection settings returned
to callers that only holds public, non-secret values (host, port, group name), with
the password kept in the service's own configuration."""


def public_connection_info(host, port, group):
    return {"host": host, "port": port, "config_group": group}

import os

HEALTH_PAGE = "health.txt"


def build_worker_health_url(hostname, port):
    """Same os.path.join(template, x).format(...) shape, but the joined-in
    segment is a fixed developer-written constant, so nothing user-controlled
    ever becomes part of the format template; user data (hostname, port) is
    only ever passed as a format ARGUMENT."""
    return os.path.join("http://{hostname}:{port}/log", HEALTH_PAGE).format(
        hostname=hostname, port=port
    )

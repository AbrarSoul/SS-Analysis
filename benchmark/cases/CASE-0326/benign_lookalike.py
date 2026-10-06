PUBLIC_SETTINGS = ('web2py_version', 'applications_parent')


class RequestEnvironment(object):
    """Builds a request environment that carries only an explicit, non-secret subset of the server settings."""

    def __init__(self, environ, server_settings):
        self.env = dict(environ)
        for key in PUBLIC_SETTINGS:
            if key in server_settings:
                self.env[key] = server_settings[key]

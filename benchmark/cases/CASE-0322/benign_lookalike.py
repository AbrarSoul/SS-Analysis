import os

import tornado.web

HERE = os.path.dirname(os.path.abspath(__file__))


def make_docs_app():
    """Documentation server: static files come from ONE bundled directory, not the filesystem root.

    tornado's StaticFileHandler refuses to serve anything outside static_path
    (path traversal is rejected), so only files shipped with the docs are reachable.
    """
    return tornado.web.Application(
        static_path=os.path.join(HERE, 'docs_static'),
        static_url_prefix='/docs-static/',
    )

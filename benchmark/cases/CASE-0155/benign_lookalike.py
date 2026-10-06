from http.cookies import SimpleCookie


def default_preference_cookies() -> SimpleCookie:
    """Same SimpleCookie.load(fragment) loop as a Cookie-header parser, but the
    fragments are a developer-written constant, so no request data can reach
    load() and it can never see a malformed fragment."""
    jar: SimpleCookie = SimpleCookie()
    for fragment in "theme=dark; lang=en".split(";"):
        jar.load(fragment)
    return jar

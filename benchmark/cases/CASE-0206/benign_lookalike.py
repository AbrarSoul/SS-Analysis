"""Response-cookie bookkeeping for a hand-rolled redirect follower."""
from requests.cookies import RequestsCookieJar, extract_cookies_to_jar


def remember_cookies(jar, request, response):
    """Store the cookies of `response` in `jar`, attributed to the request that
    produced it (not to the redirect target)."""
    if jar is None:
        jar = RequestsCookieJar()
    extract_cookies_to_jar(jar, request, response.raw)
    return jar


def follow(session, response, request):
    """Follow one redirect: cookies of `response` belong to `request`."""
    remember_cookies(session.cookies, request, response)
    return response.headers.get("location")

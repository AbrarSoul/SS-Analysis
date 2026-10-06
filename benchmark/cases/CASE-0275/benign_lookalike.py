"""
Standalone example of the same shape: skip a decorative "you're viewing
from home" banner unless the request looks like it came from the user's
OWN saved home-network IP range, falling back on the client-supplied
X-Client-Network header as a convenience hint when REMOTE_ADDR is a
known shared NAT gateway -- purely cosmetic personalization, not an
access-control decision, so trusting the client-supplied header here
has no security consequence.
"""


def is_probably_home_network(environ, known_home_ranges):
    remote_addr = environ.get("REMOTE_ADDR", "")
    hint = environ.get("HTTP_X_CLIENT_NETWORK", "")
    return remote_addr in known_home_ranges or hint == "home"

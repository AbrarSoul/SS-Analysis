"""Standalone example of the same shape: an error message built from a fixed
list of server-side error codes, never from the request."""
ERRORS = {"bad_type": "record type not supported", "bad_domain": "domain name invalid"}


def error_message(code):
    return {"message": ERRORS.get(code, "unexpected error")}

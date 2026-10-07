"""Standalone example of the same shape: wrap a JSON payload in a callback
name chosen by the SERVER from a fixed list, never by the request."""
import json

ALLOWED_CALLBACKS = {"onImages", "onRois"}


def as_script(kind, payload):
    name = "onImages" if kind == "images" else "onRois"
    assert name in ALLOWED_CALLBACKS
    return "%s(%s)" % (name, json.dumps(payload))

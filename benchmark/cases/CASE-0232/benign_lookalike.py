"""Standalone example of the same shape: a ZeroMQ-style receiver that decodes each
frame with json.loads, so a frame can only ever produce plain data."""
import json


class EventReceiver:
    def __init__(self, socket_factory, endpoint):
        self._socket = socket_factory(zmq_endpoint=endpoint, deserialize=json.loads)

import socket
import time


def send_datagram(wire, destination, timeout=2.0):
    """Same sendto-with-retry loop as the DNS client, but fire-and-forget: it
    never reads a reply, so there is no response to validate, spoof or race."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    deadline = time.time() + timeout
    try:
        while True:
            try:
                s.sendto(wire, destination)
                return
            except socket.timeout:
                if deadline - time.time() <= 0.0:
                    raise
                time.sleep(0.01)
    finally:
        s.close()

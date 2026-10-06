"""Standalone example of the same shape: an HTTPS GET with the default
certificate verification, used to read a public, unauthenticated status page."""
import requests


def read_status(base_url):
    response = requests.get(base_url + "/status.json", timeout=10)
    return response.json()

"""Standalone example of the same shape: download an image from a fixed,
server-configured CDN host only (the host comes from settings, never from user content)."""
import requests

CDN_BASE = "https://cdn.example.com/static/"


def download_static(name: str) -> bytes:
    r = requests.get(CDN_BASE + name.lstrip("/"), timeout=10)
    r.raise_for_status()
    return r.content

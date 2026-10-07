"""
Standalone example of the same shape: register an after_request hook that
adds a Server-Timing header for local performance debugging -- purely
diagnostic, never a security boundary, unlike a framing-restriction
header.
"""
import time


def configure_timing_header(app):
    @app.after_request
    def add_server_timing(response):
        response.headers["Server-Timing"] = f"total;dur={time.process_time() * 1000:.1f}"
        return response

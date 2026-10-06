class MockGenerativeClient:
    """Client for the local mock server used by the test suite."""

    def __init__(self):
        # Same "literal assigned to api_key" shape, but this is the documented
        # dummy token of the local mock server (127.0.0.1 only); it is valid
        # nowhere else and grants nothing, so nothing sensitive is committed.
        self.api_key = "test-token-not-a-real-key"
        self.base_url = "http://127.0.0.1:8080"

    def headers(self):
        return {"Authorization": "Bearer " + self.api_key}

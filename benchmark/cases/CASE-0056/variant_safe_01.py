import time


class HtpasswdAuth:
    MIN_RESPONSE_SECONDS = 1.0

    def __init__(self, filename, verify):
        self.filename = filename
        self.verify = verify

    def is_authenticated(self, user, password):
        started_at = time.perf_counter()
        authenticated = False
        with open(self.filename) as fd:
            for line in fd:
                line = line.strip()
                if not line:
                    continue
                login, hash_value = line.split(":")
                if login == user and self.verify(hash_value, password):
                    authenticated = True
        elapsed = time.perf_counter() - started_at
        remaining = self.MIN_RESPONSE_SECONDS - elapsed
        if remaining > 0:
            time.sleep(remaining)
        return authenticated

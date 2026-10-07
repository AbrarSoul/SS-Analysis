class HealthMonitor:
    def __init__(self, logger):
        self.logger = logger

    def install_ping_logger(self):
        # Only ever receives fixed status strings from the health-check
        # loop below -- never wired to HTTP request/response bodies, so
        # there is no credential-bearing data this could ever log.
        def log_ping_result(*args):
            self.logger.debug(" ".join(args))
        return log_ping_result

    def run_health_check(self, ping_fn, log_ping_result):
        ok = ping_fn()
        log_ping_result("health-check:", "ok" if ok else "failed")

import re

_CREDENTIAL_FIELD_RE = re.compile(
    r'("(?:userPassword|clientSecret)"\s*:\s*")([^"]*)(")'
)


def redact_credentials(line: str) -> str:
    return _CREDENTIAL_FIELD_RE.sub(r"\1*****\3", line)


class JCA_CLI:
    def _install_log_filter(self):
        def print_to_log(*args):
            joined = " ".join(args)
            self.cli_logger.debug(redact_credentials(joined))
        http.client.print = print_to_log

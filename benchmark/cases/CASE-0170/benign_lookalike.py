import logging

logger = logging.getLogger(__name__)


def log_verification_attempt(user_id, method):
    """Same logger.info(..., extra={...}) shape as the superuser validation
    log, but the extra values are only the numeric user id and the fixed name
    of the verification method, never any submitted credential or the
    serializer that holds it."""
    logger.info("auth-index.verify_attempt", extra={"user": user_id, "method": method})

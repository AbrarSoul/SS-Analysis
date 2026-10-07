import logging

logger = logging.getLogger(__name__)


async def log_request_origin(request, response):
    """Same 'Origin' in request.headers shape, but the value is only written
    to a log line. No Access-Control-* response header is ever set from it,
    so it grants no cross-origin access."""
    if 'Origin' in request.headers:
        logger.info('request origin: %s', request.headers['Origin'])

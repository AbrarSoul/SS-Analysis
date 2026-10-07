def display_name(first_name, last_name):
	"""Same first_name/last_name handling as the signup API, but the combined
	name is only ever used as plain text in a log line (never rendered as HTML),
	so markup in it has nothing to execute in."""
	return f"{first_name or ''} {last_name or ''}".strip()


def log_signup(logger, first_name, last_name):
	logger.info("signup requested by %s", display_name(first_name, last_name))

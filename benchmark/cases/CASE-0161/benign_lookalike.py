import logging

logSys = logging.getLogger("fail2ban.benign")


def formatBanLogLine(template, aInfo):
	"""Same <tag> substitution loop as Action.replaceTag, but the result is only
	written to the log (never handed to a shell), so shell metacharacters in the
	matched log lines are inert text."""
	line = template
	for tag in aInfo:
		line = line.replace('<' + tag + '>', str(aInfo[tag]))
	logSys.info(line)
	return line

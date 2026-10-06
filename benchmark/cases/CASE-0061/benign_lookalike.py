def whois_lookup(bot, trigger):
    """Looks up and echoes back public WHOIS info for a nick -- read-only,
    no channel-moderation command is ever issued, so there is no
    multi-target or cross-channel scope for an unvalidated nick to abuse."""
    text = trigger.group().split()
    if len(text) < 2:
        return
    nick = Identifier(text[1])
    bot.write(['WHOIS', nick])

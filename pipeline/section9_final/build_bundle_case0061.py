"""
Section 9 ground-truth test bundle: CASE-0061
(MirahezeBots/sopel-channelmgnt, CVE-2021-21431, CWE-20/CWE-284 improper
input validation enabling access-control bypass).

Core vulnerable mechanism: `kick()` builds an IRC `KICK` command using the
`nick` argument taken directly from the triggering user's message, with no
validation of its content. IRC's KICK command syntax accepts a
COMMA-SEPARATED LIST of target nicknames in a single command -- so a
channel operator authorized to kick users is only meant to target ONE
user per invocation, but an unvalidated `nick` containing a comma (e.g.
`"alice,bob,carol"`) lets a single `.kick` command remove multiple users
at once, exceeding the intended single-target scope of the command. The
fix explicitly rejects any `nick` containing `,` or `#` before it ever
reaches the IRC write.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0061"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''        nick = Identifier(text[1])
        reason = ' '.join(text[2:])
        if nick != bot.config.core.nick and trigger.account in chanops:
            bot.write(['KICK', trigger.sender, nick, ':' + reason])
            if dodeop:
                deopbot(trigger.sender, bot)
        else:
            bot.reply('Access Denied. If in error, please contact the channel founder.')'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename kick -> kick_user, nick -> target. Same exact missing validation
# before the IRC KICK write.
renamed_source = original.replace("def kick(bot, trigger):", "def kick_user(bot, trigger):")
renamed_source = renamed_source.replace(
    VULNERABLE_BLOCK,
    '''        target = Identifier(text[1])
        reason = ' '.join(text[2:])
        if target != bot.config.core.nick and trigger.account in chanops:
            bot.write(['KICK', trigger.sender, target, ':' + reason])
            if dodeop:
                deopbot(trigger.sender, bot)
        else:
            bot.reply('Access Denied. If in error, please contact the channel founder.')''',
)
assert "def kick_user(bot, trigger):" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting
# (inverted guard with early reply/return). Same exact missing
# validation, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''        nick = Identifier(text[1])
        reason = ' '.join(text[2:])
        is_authorized = (nick != bot.config.core.nick and trigger.account in chanops)
        if not is_authorized:
            bot.reply('Access Denied. If in error, please contact the channel founder.')
            return
        bot.write(['KICK', trigger.sender, nick, ':' + reason])
        if dodeop:
            deopbot(trigger.sender, bot)''',
)
assert structural_source != original
assert "is_authorized = (nick != bot.config.core.nick and trigger.account in chanops)" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (reject a nick that could target more than
# one user or reference a channel) but a materially different technique:
# a regex ALLOWLIST of valid IRC nickname characters, rejecting anything
# that doesn't match, instead of the real patch's two separate denylist
# checks for ',' and '#' -- genuinely blocks comma-separated multi-target
# payloads (and any other IRC-significant character), different
# implementation shape.
SAFE_SOURCE = '''import re

_VALID_NICK_RE = re.compile(r"^[A-Za-z0-9_^{}`|-]+$")


def kick(bot, trigger):
    """Kick a user from the channel."""
    chanops = get_chanops(str(trigger.sender), bot.memory['channelmgnt']['jdcache'])
    dodeop = False
    if chanops:
        if bot.channels[trigger.sender].privileges[bot.nick] < OP and trigger.account in chanops:
            bot.say('Please wait...')
            bot.say('op ' + trigger.sender, 'ChanServ')
            time.sleep(1)
            dodeop = True
        text = trigger.group().split()
        argc = len(text)
        if argc < 2:
            return
        nick = Identifier(text[1])
        reason = ' '.join(text[2:])
        if not _VALID_NICK_RE.match(str(nick)):
            return bot.reply('Unable to kick. Invalid nickname.')
        if nick != bot.config.core.nick and trigger.account in chanops:
            bot.write(['KICK', trigger.sender, nick, ':' + reason])
            if dodeop:
                deopbot(trigger.sender, bot)
        else:
            bot.reply('Access Denied. If in error, please contact the channel founder.')
    else:
        bot.reply(f'No ChanOps Found. Please ask for assistance in {bot.settings.channelmgnt.support_channel}')
'''
(CASE_DIR / "variant_safe_01.py").write_text(SAFE_SOURCE)
assert "_VALID_NICK_RE" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (parse a nick argument from the triggering message,
# use it in a bot.write()/reply()) but this sibling only performs a
# read-only WHOIS lookup and echoes the result back -- it never issues a
# privileged channel-moderation command, so a comma-separated or
# '#'-containing value has no way to exceed any intended scope, unlike
# kick()'s IRC KICK write.
BENIGN_SOURCE = '''def whois_lookup(bot, trigger):
    """Looks up and echoes back public WHOIS info for a nick -- read-only,
    no channel-moderation command is ever issued, so there is no
    multi-target or cross-channel scope for an unvalidated nick to abuse."""
    text = trigger.group().split()
    if len(text) < 2:
        return
    nick = Identifier(text[1])
    bot.write(['WHOIS', nick])
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "KICK" not in BENIGN_SOURCE
assert "chanops" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0061.")

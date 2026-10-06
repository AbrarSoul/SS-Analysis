"""
Section 9 ground-truth test bundle: CASE-0048
(Dav-Git/Dav-Cogs, CVE-2021-29501, CWE-74/CWE-77 format-string injection).

Core vulnerable mechanism: `message()` takes a Discord-user-supplied
format-string template (the `message` command argument) and calls
`message.format(user=ctx.author)` directly. Python's `str.format()`
resolves `{user.attr}`-style placeholders via real attribute access on
whatever object is passed -- so a user can put ANY attribute name of the
real `discord.Member` object into their template and have it rendered
back, leaking whatever that attribute exposes (far beyond the intended
name/mention). The fix wraps `ctx.author` in `SafeMember`, a proxy that
only forwards `.name`/`.mention` and returns an empty string for every
other attribute via `__getattr__`.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0048"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''    async def message(self, ctx, *, message: str):
        """Set the message that is shown at the start of each ticket channel.\\n\\nUse ``{user.mention}`` to mention the person who created the ticket."""
        try:
            message.format(user=ctx.author)
            await self.config.guild(ctx.guild).message.set(message)
            await ctx.send(f"The message has been set to `{message}`.")
        except KeyError:
            await ctx.send(
                "Setting the message failed. Please make sure to only use supported variables in  `\\{\\}`"
            )'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename message() -> set_ticket_message, message param -> template. Same
# exact unrestricted str.format(user=ctx.author) attribute exposure.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''    async def set_ticket_message(self, ctx, *, template: str):
        """Set the message that is shown at the start of each ticket channel.\\n\\nUse ``{user.mention}`` to mention the person who created the ticket."""
        try:
            template.format(user=ctx.author)
            await self.config.guild(ctx.guild).message.set(template)
            await ctx.send(f"The message has been set to `{template}`.")
        except KeyError:
            await ctx.send(
                "Setting the message failed. Please make sure to only use supported variables in  `\\{\\}`"
            )''',
)
assert "async def set_ticket_message(self, ctx, *, template: str):" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the validation-formatted
# string before it's discarded. Same exact vulnerability, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    async def message(self, ctx, *, message: str):
        """Set the message that is shown at the start of each ticket channel.\\n\\nUse ``{user.mention}`` to mention the person who created the ticket."""
        try:
            rendered_preview = message.format(user=ctx.author)
            if rendered_preview is not None:
                await self.config.guild(ctx.guild).message.set(message)
                await ctx.send(f"The message has been set to `{message}`.")
        except KeyError:
            await ctx.send(
                "Setting the message failed. Please make sure to only use supported variables in  `\\{\\}`"
            )''',
)
assert structural_source != original
assert "rendered_preview = message.format(user=ctx.author)" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (restrict what a user-controlled format
# string can pull from the author object) but a materially different
# technique: instead of a SafeMember proxy class, builds a fixed, small
# plain dict of only the allowed field names and formats against THAT
# instead of the real object -- genuinely prevents arbitrary attribute
# access, different implementation shape from the real patch.
SAFE_SOURCE = '''def build_format_args(member):
    return {
        "user": type("SafeUserFields", (), {
            "name": member.name,
            "mention": member.mention,
            "__str__": lambda self: member.name,
        })(),
    }


async def set_message(self, ctx, *, message: str):
    """Set the message that is shown at the start of each ticket channel.

    Use ``{user.mention}`` to mention the person who created the ticket."""
    try:
        safe_args = build_format_args(ctx.author)
        message.format(**safe_args)
        await self.config.guild(ctx.guild).message.set(message)
        await ctx.send(f"The message has been set to `{message}`.")
    except KeyError:
        await ctx.send(
            "Setting the message failed. Please make sure to only use supported variables."
        )
'''
(CASE_DIR / "variant_safe_01.py").write_text(SAFE_SOURCE)
assert "SafeUserFields" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (call .format(user=...) on a string inside a command
# handler) but this sibling ALWAYS uses a fixed, hardcoded template
# defined in the bot's own source code -- never a Discord-user-supplied
# template -- so even passing the real ctx.author object directly carries
# no risk: there is no attacker-controlled placeholder syntax to exploit,
# unlike message()'s user-submitted template string.
BENIGN_SOURCE = '''FIXED_WELCOME_TEMPLATE = "Welcome, {user.mention}! Please read the rules."


async def send_welcome(self, ctx):
    """Sends a fixed, developer-authored welcome message -- the template
    itself is never user-supplied, only the author object varies, so
    there is no way for a user to inject their own {attr} placeholders."""
    rendered = FIXED_WELCOME_TEMPLATE.format(user=ctx.author)
    await ctx.send(rendered)
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "message: str" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0048.")

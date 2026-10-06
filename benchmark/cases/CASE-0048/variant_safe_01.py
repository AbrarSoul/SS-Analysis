def build_format_args(member):
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

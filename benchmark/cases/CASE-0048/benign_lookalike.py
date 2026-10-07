FIXED_WELCOME_TEMPLATE = "Welcome, {user.mention}! Please read the rules."


async def send_welcome(self, ctx):
    """Sends a fixed, developer-authored welcome message -- the template
    itself is never user-supplied, only the author object varies, so
    there is no way for a user to inject their own {attr} placeholders."""
    rendered = FIXED_WELCOME_TEMPLATE.format(user=ctx.author)
    await ctx.send(rendered)

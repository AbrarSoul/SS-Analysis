"""
Standalone example of the same shape: after updating a user's DISPLAY
preferences (timezone, locale), invalidate a purely cosmetic cached
render of their dashboard so it regenerates with the new settings on
next view -- a UX freshness concern, not a security boundary, unlike
invalidating a session after a privilege change.
"""


def update_display_prefs(cache, user, timezone, locale):
    user.timezone = timezone
    user.locale = locale
    cache.pop(f"dashboard:{user.name}", None)

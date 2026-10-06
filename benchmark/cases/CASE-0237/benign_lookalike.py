"""Standalone example of the same shape: a per-user route that takes an id from
the URL but compares it with the logged-in user before doing anything."""
from flask import abort


def read_own_preferences(user_id, current_user, store):
    if current_user.id != user_id:
        abort(403)
    return store.get(user_id, {})

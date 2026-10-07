"""Maintenance action: the privileged operation runs only after the caller has been authorised."""
import json


def restart_cache(session, acl_loader, restart):
    """Restart the cache, but only for admins; the check happens BEFORE the action."""
    acl = acl_loader(session['userID'])
    if acl['admin'] != 1:
        return json.dumps({'status': 0, 'error_message': 'not allowed'})
    result = restart()
    return json.dumps({'status': result[0], 'error_message': result[1]})

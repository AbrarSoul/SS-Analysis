def is_admin_role(role_name):
    """Same `==` string comparison shape as the credential check, but on a
    non-secret label (a role name that is shown in the UI), so the comparison
    time reveals nothing an attacker could not already read."""
    return role_name == "admin"

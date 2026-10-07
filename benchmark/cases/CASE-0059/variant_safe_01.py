_LDAP_FILTER_ESCAPES = {
    "\\": "\\5c",
    "*": "\\2a",
    "(": "\\28",
    ")": "\\29",
}


def escape_ldap_filter_value(value):
    return "".join(_LDAP_FILTER_ESCAPES.get(ch, ch) for ch in value)


def useruid(s, login):
    """Connect to a LDAP and check the uid matching the given field data"""
    uid = False
    c = Connection(s, config.LDAPACC,
                   password=config.LDAPPASS, auto_bind=True)

    if c.result["description"] != "success":
        app.logger.error("Error connecting to the LDAP with the service account")
        return False

    safe_login = escape_ldap_filter_value(login)
    if not c.search(config.LDAPBASE,
                    "(" + config.LDAPFIELD + "=" + safe_login + ")") :
        app.logger.error("Error: Connection to the LDAP with service account failed")
    else:
        if len(c.entries) >= 1 :
            if len(c.entries) > 1 :
                app.logger.error("Error: multiple entries with this login. Trying first entry...")
            uid = c.entries[0].entry_dn
        else:
            app.logger.error("Error: Login not found")
        c.unbind()

    return uid

def service_account_entry(s):
    """Looks up the service account's OWN directory entry, using only
    config.LDAPACC -- a fixed, server-side configuration value, never
    anything derived from an incoming user request."""
    c = Connection(s, config.LDAPACC, password=config.LDAPPASS, auto_bind=True)
    if c.result["description"] != "success":
        return None
    if not c.search(config.LDAPBASE, "(" + config.LDAPFIELD + "=" + config.LDAPACC + ")"):
        return None
    return c.entries[0].entry_dn if c.entries else None

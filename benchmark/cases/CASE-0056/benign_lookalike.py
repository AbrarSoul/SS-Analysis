class DisplayNameLookup:
    def __init__(self, filename):
        self.filename = filename

    def get_display_name(self, username):
        """Looks up a user's chosen display name from a public,
        non-secret preferences file -- no credential of any kind is
        involved, so timing behavior here carries no security-relevant
        signal."""
        with open(self.filename) as fd:
            for line in fd:
                line = line.strip()
                if line:
                    login, display_name = line.split(":")
                    if login == username:
                        return display_name
        return username

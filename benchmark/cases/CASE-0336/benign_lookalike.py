import os


def refresh_cms_signatures():
    """Update the CMS signature database: the command line is a constant, no user input reaches the shell."""
    command = 'python3 /usr/src/github/CMSeeK/update_signatures.py --quiet'
    os.system(command)
    return True

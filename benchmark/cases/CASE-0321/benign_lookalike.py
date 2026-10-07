import sqlite3

COUNTABLE_STATUSES = ('active', 'blocked', 'expired')


def count_cards_by_status(db, status):
    """Count cards in a status.

    The status is checked against a fixed allow-list before it is formatted
    into the statement, and the only value that ever reaches the SQL text is
    one of the three literals above, so the string formatting cannot carry
    user input.
    """
    if status not in COUNTABLE_STATUSES:
        raise ValueError('unknown status')
    return db.execute("select count(*) from cards where status = '%s'" % status).fetchone()[0]

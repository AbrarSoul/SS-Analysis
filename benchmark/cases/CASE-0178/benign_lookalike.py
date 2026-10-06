def rename_shelf(session, shelf, new_title, is_title_free):
    """Same assign-then-validate ordering as the shelf editor, but the object
    is only ever changed in memory and the change is rolled back when
    validation fails, and the assigned field is a display title, not the
    shelf's visibility, so a rejected edit cannot leave a privilege change
    pending on the session."""
    old_title = shelf.name
    shelf.name = new_title
    if not is_title_free(shelf):
        shelf.name = old_title
        session.rollback()
        return False
    session.commit()
    return True

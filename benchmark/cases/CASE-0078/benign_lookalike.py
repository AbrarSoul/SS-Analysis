def should_log_verbose_comparison(current_value, expected_value):
    """Purely a logging-verbosity decision -- callers only ever use this
    in an `if should_log_verbose_comparison(...):` truthiness check
    (never `== False`), and nothing security-relevant depends on it, so
    returning a non-boolean falsy value here has no access-control
    consequence, unlike a validator used as an access-control gate."""
    return current_value and current_value == expected_value

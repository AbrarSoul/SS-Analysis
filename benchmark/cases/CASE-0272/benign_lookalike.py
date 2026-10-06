"""
Standalone example of the same shape: derive a display setting (whether to
show a "beta" badge in the UI) from a config flag, computed once and
assigned to a Flask app.config key -- purely cosmetic, never a security
boundary, unlike a cookie's Secure attribute.
"""


def configure_ui_badges(app, feature_config):
    show_beta_badge = bool(feature_config.get_config_value("ui", "beta_features"))
    app.config["SHOW_BETA_BADGE"] = show_beta_badge

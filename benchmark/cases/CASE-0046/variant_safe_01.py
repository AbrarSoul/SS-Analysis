ALLOWED_CONFIG_KEYS = frozenset({
    "cookie", "crontab", "push_config", "tasklist",
    "magic_regex", "plugins", "source",
})


def update():
    global config_data
    if not is_login():
        return jsonify({"success": False, "message": "unauthorized"})
    submitted = request.json or {}
    safe_updates = {k: v for k, v in submitted.items() if k in ALLOWED_CONFIG_KEYS}
    config_data.update(safe_updates)
    Config.write_json(CONFIG_PATH, config_data)

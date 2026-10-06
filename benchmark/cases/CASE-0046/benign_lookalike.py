def update_ui_preferences():
    """Per-session cosmetic preferences only -- theme/locale -- never
    touches the shared server config, so accepting every submitted key
    here carries no privilege-escalation risk."""
    if not is_login():
        return jsonify({"success": False, "message": "unauthorized"})
    prefs = session.get("ui_preferences", {})
    for key, value in request.json.items():
        prefs[key] = value
    session["ui_preferences"] = prefs
    return jsonify({"success": True})

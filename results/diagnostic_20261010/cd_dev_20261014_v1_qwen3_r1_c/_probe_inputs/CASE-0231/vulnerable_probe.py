def _delete_workflow() -> Response:
    """
    Deletes a workflow JSON file from the user folder.
    """
    user_login = session.get("user_login", "local_user")
    user_dir_renamed = os.path.join(_cache_dir, user_login)
    if not os.path.exists(user_dir_renamed):
        os.makedirs(user_dir_renamed)

    data = request.json
    filename = data.get("filename")
    if not filename:
        return jsonify({"error": "Filename is required"})

    filepath = os.path.join(user_dir_renamed, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"})

    try:
        os.remove(filepath)
        return jsonify({"message": "Workflow file deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)})
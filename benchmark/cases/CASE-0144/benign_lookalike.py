def construct_lookup_routes(blueprint, datastore):
    """Same "unknown id -> 404 that mentions the id" route shape as a tag feed."""

    @blueprint.route("/lookup/<string:item_id>", methods=['GET'])
    def lookup_item(item_id):
        item = datastore.data.get('items', {}).get(item_id)
        if not item:
            # A dict is serialized by Flask as application/json, never as
            # HTML, so the reflected id cannot be interpreted as markup.
            return {"error": f"Item {item_id} not found"}, 404
        return {"id": item_id, "title": item.get('title')}

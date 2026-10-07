import os

HISTORY_DIR = "history"


def list_chat_names(chat_id):
    """Same os.path.join(HISTORY_DIR, <name>) listing shape, but the name is
    only accepted when it is a bare file-name component made of safe
    characters, so it can never contain a separator or '..'."""
    if not chat_id.replace("_", "").replace("-", "").isalnum():
        raise ValueError("invalid chat id")
    folder = os.path.join(HISTORY_DIR, chat_id)
    return sorted(f for f in os.listdir(folder) if f.endswith(".json"))

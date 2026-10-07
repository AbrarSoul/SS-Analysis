import shutil
import uuid


async def upload_to_quarantine(background_tasks, file, quarantine_dir):
    """Uploads always land at a server-generated UUID path -- the
    client's own filename is stored only as metadata for later display,
    never used to construct a filesystem path."""
    generated_name = f"{uuid.uuid4().hex}.upload"
    file_path = quarantine_dir / generated_name

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    background_tasks.add_task(scan_quarantined_file, file_path, original_name=file.filename)

    return {"status": "queued", "id": generated_name}

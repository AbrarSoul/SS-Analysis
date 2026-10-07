import os
import shutil


def safe_upload_filename(raw_filename: str) -> str:
    """Reduces an uploaded filename to just its final path component,
    discarding any directory traversal an attacker could embed."""
    if not raw_filename or not raw_filename.strip():
        raise HTTPException(status_code=400, detail="Filename cannot be empty")
    basename_only = os.path.basename(raw_filename)
    if not basename_only or basename_only in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename")
    return basename_only


async def upload_to_input_dir(
    background_tasks: BackgroundTasks, file: UploadFile = File(...)
):
    try:
        safe_name = safe_upload_filename(file.filename)
        if not doc_manager.is_supported_file(safe_name):
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type. Supported types: {doc_manager.supported_extensions}",
            )

        file_path = doc_manager.input_dir / safe_name
        if file_path.exists():
            return InsertResponse(
                status="duplicated",
                message=f"File '{safe_name}' already exists in the input directory.",
            )

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        background_tasks.add_task(pipeline_index_file, rag, file_path)

        return InsertResponse(
            status="success",
            message=f"File '{safe_name}' uploaded successfully. Processing will continue in background.",
        )
    except Exception as e:
        logger.error(f"Error /documents/upload: {file.filename}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

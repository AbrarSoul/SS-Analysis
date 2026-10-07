"""
Section 9 ground-truth test bundle: CASE-0052
(HKUDS/LightRAG, CVE-2025-6773, CWE-22 path traversal).

Core vulnerable mechanism: `upload_to_input_dir()` joins the raw, client-
supplied `file.filename` directly onto the server's input directory
(`doc_manager.input_dir / file.filename`) with no sanitization at all. A
filename containing `../` sequences (or an absolute path) lets an attacker
write the uploaded content outside the intended input directory --
overwriting arbitrary files reachable by the server process. The fix adds
`sanitize_filename()`, which strips path separators and `..` sequences,
then verifies the resolved final path is still inside the input directory
before ever using it.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0052"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''        try:
            if not doc_manager.is_supported_file(file.filename):
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported file type. Supported types: {doc_manager.supported_extensions}",
                )

            file_path = doc_manager.input_dir / file.filename
            # Check if file already exists
            if file_path.exists():
                return InsertResponse(
                    status="duplicated",
                    message=f"File '{file.filename}' already exists in the input directory.",
                )

            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            # Add to background tasks
            background_tasks.add_task(pipeline_index_file, rag, file_path)

            return InsertResponse(
                status="success",
                message=f"File '{file.filename}' uploaded successfully. Processing will continue in background.",
            )'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename upload_to_input_dir -> handle_file_upload, file_path -> dest_path.
# Same exact unsanitized filename join.
renamed_source = original.replace(
    "async def upload_to_input_dir(\n        background_tasks: BackgroundTasks, file: UploadFile = File(...)\n    ):",
    "async def handle_file_upload(\n        background_tasks: BackgroundTasks, file: UploadFile = File(...)\n    ):",
)
renamed_source = renamed_source.replace(
    VULNERABLE_BLOCK,
    '''        try:
            if not doc_manager.is_supported_file(file.filename):
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported file type. Supported types: {doc_manager.supported_extensions}",
                )

            dest_path = doc_manager.input_dir / file.filename
            # Check if file already exists
            if dest_path.exists():
                return InsertResponse(
                    status="duplicated",
                    message=f"File '{file.filename}' already exists in the input directory.",
                )

            with open(dest_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            # Add to background tasks
            background_tasks.add_task(pipeline_index_file, rag, dest_path)

            return InsertResponse(
                status="success",
                message=f"File '{file.filename}' uploaded successfully. Processing will continue in background.",
            )''',
)
assert "async def handle_file_upload(" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting.
# Same exact unsanitized filename join, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''        try:
            is_supported = doc_manager.is_supported_file(file.filename)
            if not is_supported:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported file type. Supported types: {doc_manager.supported_extensions}",
                )

            target_name = file.filename
            file_path = doc_manager.input_dir / target_name
            already_exists = file_path.exists()
            if already_exists:
                return InsertResponse(
                    status="duplicated",
                    message=f"File '{target_name}' already exists in the input directory.",
                )

            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            background_tasks.add_task(pipeline_index_file, rag, file_path)

            return InsertResponse(
                status="success",
                message=f"File '{target_name}' uploaded successfully. Processing will continue in background.",
            )''',
)
assert structural_source != original
assert "target_name = file.filename" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (reject a filename that would escape the
# input directory) but a materially different technique: uses
# os.path.basename() to strip any directory component entirely (rather
# than the real patch's character-stripping + resolve()-based containment
# check) -- genuinely prevents traversal, since only the final path
# component is ever used, different implementation shape.
SAFE_SOURCE = '''import os
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
'''
(CASE_DIR / "variant_safe_01.py").write_text(SAFE_SOURCE)
assert "os.path.basename" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (join a client-influenced name onto a base directory,
# open a file there) but this sibling only ever writes to a path keyed by
# a SERVER-GENERATED UUID, never the client's own filename string -- the
# only thing derived from client input is metadata stored separately, so
# there is no way for a client to influence the actual filesystem path at
# all, unlike upload_to_input_dir()'s direct use of file.filename.
BENIGN_SOURCE = '''import shutil
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
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "doc_manager.input_dir / file.filename" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0052.")

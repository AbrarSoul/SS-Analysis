from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def get_health() -> dict:
    """Same route shape as the token endpoints -- no auth dependency -- but
    it is a deliberately public liveness probe returning only a constant, so
    there is nothing to protect and nothing sensitive to read or change."""
    return {"status": "ok"}

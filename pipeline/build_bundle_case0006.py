"""
Section 9 ground-truth test bundle: CASE-0006
(lintsinghua/DeepAudit, CVE-2026-25729, CWE-863 -- incorrect authorization).

Core vulnerable mechanism: read_users() (GET / -- lists ALL users with
email/phone/role) is gated by Depends(deps.get_current_user), which accepts
ANY authenticated user, not Depends(deps.get_current_active_superuser) like
every other admin-sensitive endpoint in this same file (create_user,
update_user, delete_user, toggle_user_status). Any logged-in non-admin
user can therefore enumerate every account's PII.

Note: read_user_me/update_user_me legitimately use get_current_user (they
operate on the caller's own record), and read_user (singular, by id) is
left untouched in every variant below since it was not part of the
confirmed patch/advisory for this CVE -- Section 9.3 requires representing
only the intended, verified vulnerability mechanism.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0006"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''@router.get("/", response_model=UserListResponse)
async def read_users(
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None, description="搜索关键词"),
    role: Optional[str] = Query(None, description="角色筛选"),
    is_active: Optional[bool] = Query(None, description="状态筛选"),
    current_user: User = Depends(deps.get_current_user),
) -> Any:'''
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# Rename the endpoint function read_users -> list_all_users and its unused
# auth-gate parameter current_user -> requesting_user. Same exact
# under-restrictive dependency (deps.get_current_user, not the superuser
# variant every sibling admin endpoint uses).
RENAMED_BLOCK = '''@router.get("/", response_model=UserListResponse)
async def list_all_users(
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None, description="搜索关键词"),
    role: Optional[str] = Query(None, description="角色筛选"),
    is_active: Optional[bool] = Query(None, description="状态筛选"),
    requesting_user: User = Depends(deps.get_current_user),
) -> Any:'''
renamed_source = original.replace(VULNERABLE_BLOCK, RENAMED_BLOCK)
assert "def read_users(" not in renamed_source
assert "def list_all_users(" in renamed_source
assert "requesting_user: User = Depends(deps.get_current_user)" in renamed_source
# the unrelated read_user (singular) and *_me endpoints must be untouched
assert "async def read_user(" in renamed_source
assert "async def read_user_me(" in renamed_source
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: alternate but equivalent data-flow expression -- the
# dependency function is referenced via a module-level alias instead of
# directly. Same exact under-restrictive authorization, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''_LIST_USERS_AUTH_DEPENDENCY = deps.get_current_user


@router.get("/", response_model=UserListResponse)
async def read_users(
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None, description="搜索关键词"),
    role: Optional[str] = Query(None, description="角色筛选"),
    is_active: Optional[bool] = Query(None, description="状态筛选"),
    current_user: User = Depends(_LIST_USERS_AUTH_DEPENDENCY),
) -> Any:''',
)
assert structural_source != original
assert "_LIST_USERS_AUTH_DEPENDENCY = deps.get_current_user" in structural_source
assert "Depends(_LIST_USERS_AUTH_DEPENDENCY)" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real one-line fix (only superusers may
# list all users) but implemented as an explicit in-body permission check
# instead of swapping the FastAPI dependency -- materially different code
# shape from the real patch, which is otherwise a single-token change.
SAFE_BLOCK = VULNERABLE_BLOCK + '''
    """
    获取用户列表（支持分页、搜索、筛选）
    """
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")
'''
# original body starts right after the docstring; splice explicit-check
# safe variant by replacing the header block AND removing the now-duplicated
# original docstring line that immediately follows it.
ORIGINAL_HEADER_PLUS_DOCSTRING = VULNERABLE_BLOCK + '''
    """
    获取用户列表（支持分页、搜索、筛选）
    """
'''
assert ORIGINAL_HEADER_PLUS_DOCSTRING in original
safe_source = original.replace(ORIGINAL_HEADER_PLUS_DOCSTRING, SAFE_BLOCK)
assert safe_source != original
assert "if not current_user.is_superuser:" in safe_source
assert "raise HTTPException(status_code=403" in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a new endpoint, same
# under-restrictive dependency (Depends(deps.get_current_user)) guarding a
# users-related route, but it returns only an aggregate integer count --
# no per-user PII -- so allowing any authenticated user (not just an admin)
# is genuinely safe here, unlike read_users().
BENIGN_ADDITION = '''
@router.get("/count", response_model=int)
async def count_active_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Returns only an aggregate count of active users to any authenticated
    user. Unlike read_users(), this exposes no per-user PII (email,
    phone, role), so allowing any authenticated user, not just an admin,
    is safe here.
    """
    count_query = select(func.count(User.id)).where(User.is_active == True)
    result = await db.execute(count_query)
    return result.scalar()

'''
anchor = '@router.get("/", response_model=UserListResponse)'
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "count_active_users" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)

print("Wrote 4 new samples for CASE-0006.")

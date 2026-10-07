"""
Section 9 ground-truth test bundle: CASE-0138
(danswer-ai/danswer, backend/danswer/server/manage/slack_bot.py put_tokens,
CVE-2024-32881, CWE-285 improper authorization).

Core vulnerable mechanism: `PUT /admin/slack-bot/tokens` (`put_tokens`) and
`GET /admin/slack-bot/tokens` (`get_tokens`) have no authentication or
authorization dependency, unlike every other route in the module
(`_: User | None = Depends(current_admin_user)`). Any unauthenticated
caller can therefore OVERWRITE the Slack bot's bot/app tokens (hijacking the
bot) and READ them back. The upstream fix adds
`_: User | None = Depends(current_admin_user)` to both functions.

Located target: put_tokens. Because the fix also covers the sibling
get_tokens (same defect, same commit), the SAFE variant protects both routes
and the two vulnerable variants leave both unprotected.

Every variant is the FULL real file. The routes are registered by decorator
and are not called by name, so put_tokens can be renamed freely.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0138"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

PUT = '''@router.put("/admin/slack-bot/tokens")
def put_tokens(tokens: SlackBotTokens) -> None:
    save_tokens(tokens=tokens)
'''
GET_HDR = '''@router.get("/admin/slack-bot/tokens")
def get_tokens() -> SlackBotTokens:
'''
assert original.count(PUT) == 1 and original.count(GET_HDR) == 1
assert original.count("put_tokens") == 1 and "from fastapi import Depends" in original
assert "from danswer.auth.users import current_admin_user" in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, PUT, '''@router.put("/admin/slack-bot/tokens")
def update_slack_tokens(new_tokens: SlackBotTokens) -> None:
    save_tokens(tokens=new_tokens)
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, PUT, '''@router.put("/admin/slack-bot/tokens")
def put_tokens(tokens: SlackBotTokens) -> None:
    payload = tokens
    save_tokens(tokens=payload)
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Admin check declared on the ROUTE (`dependencies=[Depends(current_admin_user)]`)
# for both token routes, instead of upstream's extra `_: User | None = Depends(...)`
# function parameter.
v3 = swap(original, PUT, '''@router.put("/admin/slack-bot/tokens", dependencies=[Depends(current_admin_user)])
def put_tokens(tokens: SlackBotTokens) -> None:
    save_tokens(tokens=tokens)
''')
v3 = swap(v3, GET_HDR, '''@router.get("/admin/slack-bot/tokens", dependencies=[Depends(current_admin_user)])
def get_tokens() -> SlackBotTokens:
''')
assert v3.count("dependencies=[Depends(current_admin_user)]") == 2
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def get_health() -> dict:
    """Same route shape as the token endpoints -- no auth dependency -- but
    it is a deliberately public liveness probe returning only a constant, so
    there is nothing to protect and nothing sensitive to read or change."""
    return {"status": "ok"}
'''
assert "deliberately public" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0138.")

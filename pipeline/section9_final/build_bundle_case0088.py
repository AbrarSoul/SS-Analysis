"""
Section 9 ground-truth test bundle: CASE-0088
(aio-libs/aiohttp, CVE-2026-34515, CWE-36/CWE-918 absolute-path /
UNC-path handling in static file serving).

Core vulnerable mechanism: `StaticResource._handle()` joins the
request-supplied `filename` onto the served directory with
`self._directory.joinpath(filename)`. `pathlib` discards the base when the
joined component is ABSOLUTE, so a filename such as `//network/share` or
`D:\\path` yields an absolute (possibly UNC) path. On Windows, merely
resolving such a UNC path makes the server open an SMB connection to an
attacker-chosen host, leaking NTLM credentials; the later
`relative_to(self._directory)` containment check only runs AFTER that
network access. The upstream fix rejects absolute filenames up front with
`Path(filename).is_absolute()`.

Every variant is the FULL real file with StaticResource._handle replaced
(the renamed variant also renames the two self._handle route
registrations in StaticResource.__init__).
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0088"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.py").read_text().splitlines()) + "\n"

BLOCK = '''    async def _handle(self, request: Request) -> StreamResponse:
        filename = request.match_info["filename"]
        unresolved_path = self._directory.joinpath(filename)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._resolve_path_to_response, unresolved_path
        )
'''
GET_REG = '"GET", self._handle, self, expect_handler=expect_handler'
HEAD_REG = '"HEAD", self._handle, self, expect_handler=expect_handler'
assert original.count(BLOCK) == 1 and original.count(GET_REG) == 1 and original.count(HEAD_REG) == 1


def build(new_block, text=None):
    return (text or original).replace(BLOCK, new_block)


# --- Variant 1: renamed vulnerable variant ---
renamed = build('''    async def _serve_static(self, req_obj: Request) -> StreamResponse:
        relative_name = req_obj.match_info["filename"]
        candidate_path = self._directory.joinpath(relative_name)
        event_loop = asyncio.get_running_loop()
        return await event_loop.run_in_executor(
            None, self._resolve_path_to_response, candidate_path
        )
''')
renamed = renamed.replace(GET_REG, GET_REG.replace("self._handle", "self._serve_static"))
renamed = renamed.replace(HEAD_REG, HEAD_REG.replace("self._handle", "self._serve_static"))
assert renamed.count("self._serve_static") == 2 and renamed.count("def _serve_static") == 1
assert len(re.findall(r"self\._handle\b", renamed)) == 1  # the OTHER class's own _handle registration is untouched
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed)

# --- Variant 2: structurally changed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_02.py").write_text(build('''    async def _handle(self, request: Request) -> StreamResponse:
        requested = request.match_info["filename"]
        target = self._directory.joinpath(requested)
        return await asyncio.get_running_loop().run_in_executor(
            None, self._resolve_path_to_response, target
        )
'''))

# --- Variant 3: transformed safe variant ---
# Rejects absolute, UNC and drive-qualified names on BOTH pathlib flavours
# (PureWindowsPath and PurePosixPath) so the check does not depend on the
# host OS, unlike upstream's Path(filename).is_absolute().
safe = build('''    async def _handle(self, request: Request) -> StreamResponse:
        filename = request.match_info["filename"]
        if (
            PureWindowsPath(filename).is_absolute()
            or PureWindowsPath(filename).drive
            or PurePosixPath(filename).is_absolute()
            or filename.startswith(("//", "\\\\\\\\"))
        ):
            # absolute / UNC / drive-qualified names must never reach the file system
            raise HTTPNotFound()
        unresolved_path = self._directory.joinpath(filename)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._resolve_path_to_response, unresolved_path
        )
''')
assert original.count("from pathlib import Path\n") == 1
safe = safe.replace("from pathlib import Path\n", "from pathlib import Path, PurePosixPath, PureWindowsPath\n")
(CASE_DIR / "variant_safe_01.py").write_text(safe)

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.py").write_text('''import re
from pathlib import Path

_TEMPLATE_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\\.html")


def read_template(base_dir: Path, name: str) -> str:
    """Same base_dir.joinpath(name) shape as static file serving, but the
    name is first restricted to a strict allow-list pattern (no separators,
    no drive letters, no leading slash), so it cannot be an absolute path."""
    if not _TEMPLATE_NAME.fullmatch(name):
        raise ValueError("invalid template name")
    return base_dir.joinpath(name).read_text()
''')
print("Wrote 4 new samples for CASE-0088.")

"""
Section 9 ground-truth test bundle: CASE-0033
(JstnMcBrd/dectalk-tts, CVE-2024-31206, CWE-300/CWE-319/CWE-598 --
cleartext transmission of sensitive data via an insecure channel).

Core vulnerable mechanism: dectalk() sends the caller-supplied `text`
(potentially sensitive TTS input) as a GET query-string parameter over
plain HTTP (new URL('http://tts.cyzon.us/tts')). A network eavesdropper or
MITM can read the full request URL, exposing the text content in transit.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0033"
original = (CASE_DIR / "vulnerable_source.ts").read_text()

VULNERABLE_BLOCK = (
    "export default async function dectalk(text: string): Promise<Buffer> {\n"
    "\t// The API does not like empty prompts\n"
    "\ttext = text.trim();\n"
    "\tif (text.length === 0) {\n"
    "\t\tthrow new TypeError('Text cannot be empty or only whitespace');\n"
    "\t}\n"
    "\n"
    "\t// Format request URL\n"
    "\tconst url = new URL('http://tts.cyzon.us/tts');\n"
    "\turl.search = new URLSearchParams({ text }).toString();\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# Rename the function dectalk -> synthesizeSpeech (it's a default export,
# so no in-file named references to update) and the local url ->
# requestUrl (used again later at `fetch(url)`). Same exact vulnerability:
# still plain HTTP.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    VULNERABLE_BLOCK.replace(
        "export default async function dectalk(text: string): Promise<Buffer> {",
        "export default async function synthesizeSpeech(text: string): Promise<Buffer> {",
    ).replace("const url = new URL", "const requestUrl = new URL").replace(
        "url.search = new URLSearchParams", "requestUrl.search = new URLSearchParams"
    ),
)
renamed_source = renamed_source.replace("const response = await fetch(url);", "const response = await fetch(requestUrl);")
assert renamed_source != original
assert "export default async function synthesizeSpeech" in renamed_source
assert "const requestUrl = new URL('http://tts.cyzon.us/tts');" in renamed_source
assert "await fetch(requestUrl);" in renamed_source
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable / equivalent API-call
# formatting -- the URL is built via the base+relative URL constructor
# overload instead of a single full literal. Same exact vulnerability
# (still plain HTTP), no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    VULNERABLE_BLOCK.replace(
        "\tconst url = new URL('http://tts.cyzon.us/tts');\n",
        "\tconst baseUrl = 'http://tts.cyzon.us';\n"
        "\tconst url = new URL('/tts', baseUrl);\n",
    ),
)
assert structural_source != original
assert "const baseUrl = 'http://tts.cyzon.us';" in structural_source
(CASE_DIR / "variant_vulnerable_02.ts").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (the request now travels over
# HTTPS) but the protocol is built via a template literal referencing a
# separate protocol constant, instead of the real patch's direct literal
# string edit -- not byte-identical to the known fix.
safe_source = original.replace(
    VULNERABLE_BLOCK,
    VULNERABLE_BLOCK.replace(
        "\tconst url = new URL('http://tts.cyzon.us/tts');\n",
        "\tconst protocol = 'https';\n"
        "\tconst url = new URL(`${protocol}://tts.cyzon.us/tts`);\n",
    ),
)
assert safe_source != original
assert "const protocol = 'https';" in safe_source
assert "new URL(`${protocol}://tts.cyzon.us/tts`)" in safe_source
assert "http://tts.cyzon.us" not in safe_source
(CASE_DIR / "variant_safe_01.ts").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a function that also
# fetches a plain http:// URL -- the same superficial shape as the
# vulnerable line -- but it targets localhost, so the traffic never
# leaves the machine and there is no network path for an eavesdropper,
# unlike the remote dectalk() request above.
BENIGN_ADDITION = (
    "\n"
    "const LOCAL_MOCK_SERVER_URL = 'http://localhost:8080/mock-tts';\n"
    "\n"
    "export async function pingLocalMockServer(): Promise<boolean> {\n"
    "\t// localhost traffic never leaves the machine, so there is no\n"
    "\t// network path for an eavesdropper to intercept, unlike the remote\n"
    "\t// dectalk() request above.\n"
    "\tconst response = await fetch(LOCAL_MOCK_SERVER_URL);\n"
    "\treturn response.ok;\n"
    "}\n"
)
anchor = "export default async function dectalk(text: string): Promise<Buffer> {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "pingLocalMockServer" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)

print("Wrote 4 new samples for CASE-0033.")

"""
Section 9 ground-truth test bundle: CASE-0153
(electron/packager, src/resedit.ts resedit, CVE-2024-29900,
CWE-402 transmission of private resources into a new sphere / broken ASAR
integrity resource on Windows).

Core vulnerable mechanism: when `asarIntegrity` is supplied, `resedit`
pushes the integrity resource as
`{ type: 'Integrity', id: 'ElectronAsar', bin: Buffer.from(JSON.stringify(options.asarIntegrity)).buffer }`.
Three things are wrong (measured by running the function with a stubbed
resedit library): the resource type/id are not the upper-case names Electron
reads (`INTEGRITY` / `ELECTRONASAR`), the JSON is the raw `{file: {algorithm,
hash}}` object instead of the list `[{file, alg, value}]` Electron parses, and
`Buffer.from(string).buffer` is the Node.js shared 8 KiB allocation pool, not
the string's bytes, so the stored resource is the whole pool (measured:
8192 bytes with the JSON at an offset, next to unrelated process memory).
The packaged app therefore carries a resource Electron does not use, so the
integrity check that was meant to protect app.asar is silently not applied,
and pool memory is written into the executable. The upstream fix pushes
`INTEGRITY` / `ELECTRONASAR` with the list format and an exact
`Buffer.from(json, 'utf-8')`.

Sibling site: the application-manifest branch also uses `readFile(...).buffer`;
measured, readFile returns an exact-size unpooled buffer, so it is NOT the
same defect and every variant leaves it as is.

Every variant is the FULL real file. `resedit` is an exported function, so the
renamed variant renames its parameters and locals only.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0153"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
assert "\r" not in original

HDR = "export async function resedit(exePath: string, options: ExeMetadata) {\n"
s = original.index(HDR)
e = original.index("\n}\n", s) + len("\n}\n")
BLOCK = original[s:e]
INTEG = '''  if (options.asarIntegrity) {
    res.entries.push({
      type: 'Integrity',
      id: 'ElectronAsar',
      bin: Buffer.from(JSON.stringify(options.asarIntegrity)).buffer,
      lang: languageInfo[0].lang,
      codepage: languageInfo[0].codepage,
    });
  }
'''
assert original.count(HDR) == 1 and BLOCK.count(INTEG) == 1


def build(new_block, extra_before=None):
    assert new_block != BLOCK
    return original[:s] + (extra_before or "") + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK
for old, new in (("exePath", "exeFile"), ("exeData", "rawBytes"), ("options", "opts"), ("resedit", "resEditLib"),
                 ("exe", "pe"), ("res", "resources")):
    if old == "resedit":
        b = b.replace("const resedit = await loadResEdit();", "const resEditLib = await loadResEdit();")
        b = re.sub(r"(?<![.\w$'])resedit\.", "resEditLib.", b)
        continue
    b = re.sub(r"(?<![.\w$'-])%s(?![\w$'-])" % old, new, b)
b = b.replace("export async function resEditLib(", "export async function resedit(")
assert "export async function resedit(exeFile: string, opts: ExeMetadata)" in b
assert "const pe = resEditLib.NtExecutable.from(rawBytes);" in b and "resources.outputResource(pe)" in b
assert "fs.readFile(exeFile)" in b and "${opts.win32Metadata?.['requested-execution-level']}" in b
assert "type: 'Integrity'," in b and "Buffer.from(JSON.stringify(opts.asarIntegrity)).buffer" in b
assert "options" not in b.replace("ExeMetadata", "")
(CASE_DIR / "variant_vulnerable_01.ts").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(INTEG, '''  if (options.asarIntegrity) {
    res.entries.push(integrityEntry(options.asarIntegrity, languageInfo[0]));
  }
''')
helper = '''type IntegrityInput = NonNullable<ExeMetadata['asarIntegrity']>;

function integrityEntry(asarIntegrity: IntegrityInput, language: { lang: number; codepage: number }) {
  return {
    type: 'Integrity',
    id: 'ElectronAsar',
    bin: Buffer.from(JSON.stringify(asarIntegrity)).buffer,
    lang: language.lang,
    codepage: language.codepage,
  };
}

'''
(CASE_DIR / "variant_vulnerable_02.ts").write_text(build(b, extra_before=helper))

# --- Variant 3: transformed safe variant ---
# Correct upper-case type/id and list format, and the bytes are copied into an
# EXACT-size ArrayBuffer (slice of the pooled buffer by offset and length);
# upstream passes the Buffer itself.
b = BLOCK.replace(INTEG, '''  if (options.asarIntegrity) {
    const integrityList = Object.entries(options.asarIntegrity).map(([file, info]) => ({
      file,
      alg: info.algorithm,
      value: info.hash,
    }));
    const bytes = Buffer.from(JSON.stringify(integrityList), 'utf-8');
    res.entries.push({
      type: 'INTEGRITY',
      id: 'ELECTRONASAR',
      bin: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
      lang: languageInfo[0].lang,
      codepage: languageInfo[0].codepage,
    });
  }
''')
(CASE_DIR / "variant_safe_01.ts").write_text(build(b))

# --- Variant 4: benign structural look-alike ---
benign_source = '''/**
 * Same "JSON string -> resource bin" step as an integrity resource, but the
 * bytes are copied into an exact-size ArrayBuffer, so nothing from the shared
 * Buffer pool ends up in the resource.
 */
export function jsonResourceBin(value: unknown): ArrayBuffer {
  const bytes = Buffer.from(JSON.stringify(value), 'utf-8');
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
'''
assert "byteOffset" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)
print("Wrote 4 new samples for CASE-0153.")

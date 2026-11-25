"""CASE-0075 harness (contract v1). Compiles one sample, extracts each crafted zip into a fresh
dest/ folder through every extraction method the sample has, and checks for marker files outside dest/."""
import json, os, re, shutil, subprocess, sys, zipfile

sample, role = sys.argv[1], sys.argv[2]
H = os.path.dirname(os.path.abspath(__file__))
W = "/tmp/w"
man = json.load(open(os.path.join(H, "harness.json")))
ATTACKS = {a["id"]: a["input"] for a in man["attacks"]}
CONTROL = man["control"]
PKG_LISTENER = "cz.speedy11.mcrpx.common.extraction"
METHOD_CANDIDATES = ["extractZip", "unpackResourcePack", "extractMinecraft"]


def result(**kw):
    base = {"compiled": False, "attacks": {}, "control_ok": None, "modified": [], "skipped": None, "notes": ""}
    base.update(kw)
    print("RESULT " + json.dumps(base))
    sys.exit(0)


src = open(sample, encoding="utf-8").read()
modified = []
cls = re.search(r"public\s+(?:final\s+)?class\s+(\w+)", src)
pkg = re.search(r"^\s*package\s+([\w.]+)\s*;", src, re.M)
if not cls:
    result(skipped="no public class found")
cls, pkg = cls.group(1), pkg.group(1) if pkg else ""
fq = f"{pkg}.{cls}" if pkg else cls
methods = [m for m in METHOD_CANDIDATES if re.search(r"public\s+static\s+void\s+" + m + r"\s*\(\s*File\s+\w+\s*,\s*File\s+\w+\s*,\s*ExtractTaskListener", src)]
if not methods:
    result(skipped="has no archive-extraction method (no method taking a zip file, a destination and a listener)")

# Declared, minimal repairs so the sample can run; listed in `modified`.
if "ExtractTaskListener" in src and pkg != PKG_LISTENER and f"import {PKG_LISTENER}.ExtractTaskListener" not in src:
    src = (re.sub(r"^(\s*package\s+[\w.]+\s*;)", r"\1\nimport " + PKG_LISTENER + ".ExtractTaskListener;", src, count=1, flags=re.M)
           if pkg else f"import {PKG_LISTENER}.ExtractTaskListener;\n" + src)
    modified.append("added the missing import of ExtractTaskListener")
stub = re.search(r"(private\s+static\s+void\s+extractFile\s*\(\s*InputStream\s+(\w+)\s*,\s*File\s+(\w+)\s*\)\s*throws\s+IOException\s*\{)\s*//[^\n]*omitted[^\n]*\n(\s*)\}", src)
if stub:
    body = f"{stub.group(1)}\n{stub.group(4)}    java.nio.file.Files.copy({stub.group(2)}, {stub.group(3)}.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);\n{stub.group(4)}}}"
    src = src[:stub.start()] + body + src[stub.end():]
    modified.append("filled in the omitted extractFile body with a plain file copy, so writes can be observed (path checks untouched)")

shutil.rmtree(W, ignore_errors=True)
srcdir = os.path.join(W, "src", *pkg.split(".")) if pkg else os.path.join(W, "src")
os.makedirs(srcdir, exist_ok=True)
open(os.path.join(srcdir, cls + ".java"), "w").write(src)
ldir = os.path.join(W, "src", *PKG_LISTENER.split("."))
os.makedirs(ldir, exist_ok=True)
shutil.copy(os.path.join(H, "ExtractTaskListener.java"), ldir)
shutil.copy(os.path.join(H, "Harness.java"), os.path.join(W, "src"))
javas = [os.path.join(d, f) for d, _, fs in os.walk(os.path.join(W, "src")) for f in fs if f.endswith(".java")]
c = subprocess.run(["javac", "-nowarn", "-d", os.path.join(W, "out")] + javas, capture_output=True, text=True)
if c.returncode != 0:
    print(c.stderr[-2000:])
    result(compiled=False, modified=modified, notes="javac failed: " + " | ".join(l for l in c.stderr.splitlines() if "error:" in l)[:400])

os.makedirs(os.path.join(W, "zips"))
cases = dict(ATTACKS, **{CONTROL["id"]: CONTROL["input"]})
for name, entry in cases.items():
    with zipfile.ZipFile(os.path.join(W, "zips", name + ".zip"), "w") as z:
        z.writestr("pack.mcmeta", '{"pack":{"pack_format":1}}')
        z.writestr("assets/minecraft/.keep", "")   # makes the folders exist, so '..' through them resolves on Linux
        z.writestr(entry, "pwned")


def markers():
    found = []
    for d, _, fs in os.walk("/tmp"):
        found += [os.path.join(d, f) for f in fs if f.startswith("ESCAPED_") and not d.startswith(os.path.join(W, "zips"))]
    return found


exploited = {a: False for a in ATTACKS}
control_ok = False
print(f"sample {os.path.basename(sample)} as {fq}; methods tested: {', '.join(methods)}")
for m in methods:
    for name in cases:
        dest = os.path.join(W, "run", m, name, "dest")
        os.makedirs(dest)
        for f in markers():
            os.remove(f)
        p = subprocess.run(["java", "-cp", os.path.join(W, "out"), "Harness", os.path.join(W, "zips", name + ".zip"), dest, fq, m],
                           capture_output=True, text=True, timeout=30)
        out = [f for f in markers() if not f.startswith(dest + os.sep)]
        if name == CONTROL["id"]:
            ok = any(f == "ok.txt" for _, _, fs in os.walk(dest) for f in fs)
            control_ok = control_ok or ok
            print(f"  {m:<20} {name:<18} control file extracted: {ok}")
        else:
            if out:
                exploited[name] = True
            print(f"  {m:<20} {name:<18} {'ESCAPED -> ' + ', '.join(o.replace(W, '') for o in out) if out else 'contained'}")
        for line in (p.stdout + p.stderr).strip().splitlines()[:3]:
            print("      " + line)
        for f in markers():
            os.remove(f)

result(compiled=True, attacks=exploited, control_ok=control_ok, modified=modified,
       notes=f"tested {fq}: {', '.join(methods)}")

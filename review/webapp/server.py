#!/usr/bin/env python3
"""Ground-truth review server: Python standard library only, SQLite on a persistent volume.

Judges log in with a personal link (/login/<token>) that sets a cookie. Each judge reads and
writes only their own records. The admin (ADMIN_TOKEN) creates judges, sees progress, and
downloads every record in review/record_template.md format.

Blindness is enforced on the server: vulnerable_lines and the Stage 1 notes are only returned
for a case after the judge has locked their own bug location for it.

Environment:
  ADMIN_TOKEN      required, at least 24 characters (fly secrets set ADMIN_TOKEN=...)
  DATA_DIR         where review.db lives (default /data, the Fly volume)
  PORT             default 8080
  SECURE_COOKIES   "1" (default) adds the Secure flag; set "0" only for local http testing
"""
import csv, hashlib, hmac, io, json, os, re, secrets, sqlite3, sys, threading, zipfile
from contextlib import closing
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", "/data")
PORT = int(os.environ.get("PORT", "8080"))
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
SECURE_COOKIES = os.environ.get("SECURE_COOKIES", "1") == "1"
if len(ADMIN_TOKEN) < 24:
    sys.exit("Set ADMIN_TOKEN to a random string of at least 24 characters.")

CHECKS = list("ABCDEFGHIJ")
METHOD_CHECKS = {"E", "H", "I", "J"}
METHODS = {"read": "Read / reasoned", "compiled": "Parsed / compiled", "executed": "Executed", "exploit": "Exploit-tested"}
CHECK_TITLES = {
    "A": "Vulnerable file = real pre-fix code", "B": "Patched file + diff = real fix",
    "C": "Commit is the fix for this CVE", "D": "CWE correct",
    "E": "Real fix really fixes it (executed or reasoned?)", "F": "`vulnerable_lines` locate the bug",
    "G": "Representability label correct", "H": "Both reworded variants vulnerable, same way",
    "I": "Alternative fix safe", "J": "Benign look-alike safe and a real look-alike",
}
DECISIONS = {"Keep", "Keep with corrections", "Exclude"}
ROLES = {"vulnerable_source", "patched_source", "patch", "variant_vulnerable_01", "variant_vulnerable_02", "variant_safe_01", "benign_lookalike"}
MAX_BODY = 600_000
MAX_TEXT = 20_000


def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------- case data (read-only, in memory)
def load_data():
    z = zipfile.ZipFile(os.path.join(HERE, "data", "case_bundle.zip"))
    files, meta = {}, {}
    for n in z.namelist():
        m = re.match(r"^cases/(CASE-\d+)/([^/]+)$", n)
        if not m:
            continue
        cid, name = m.groups()
        base = "patch" if name == "patch.diff" else "metadata" if name == "metadata.json" else name.rsplit(".", 1)[0]
        txt = z.read(n).decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
        if base == "metadata":
            meta[cid] = json.loads(txt)
        else:
            files[(cid, base)] = (name, txt)
    stage1 = json.loads(z.read("stage1.json"))
    index = json.load(open(os.path.join(HERE, "data", "case_index.json")))
    example = open(os.path.join(HERE, "data", "example_record.md"), encoding="utf-8").read()
    return files, meta, stage1, index, example


FILES, META, STAGE1, INDEX, EXAMPLE_MD = load_data()
BY_ID = {c["id"]: c for c in INDEX}
STATIC = {name: open(os.path.join(HERE, "static", name), "rb").read() for name in ("index.html", "admin.html", "nolink.html", "base.css")}

# ---------------------------------------------------------------- database
DB_PATH = os.path.join(DATA_DIR, "review.db")
WRITE_LOCK = threading.Lock()


def conn():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    with closing(conn()) as c, c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS reviewers(
          id INTEGER PRIMARY KEY, tag TEXT UNIQUE NOT NULL, name TEXT NOT NULL DEFAULT '',
          token_hash TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS records(
          reviewer_id INTEGER NOT NULL, case_id TEXT NOT NULL, data TEXT NOT NULL,
          status TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(reviewer_id, case_id));
        CREATE TABLE IF NOT EXISTS history(
          id INTEGER PRIMARY KEY, reviewer_id INTEGER NOT NULL, case_id TEXT NOT NULL,
          at TEXT NOT NULL, event TEXT NOT NULL, data TEXT NOT NULL);
        """)


def token_hash(t):
    return hashlib.sha256(t.encode()).hexdigest()


def get_record(rid, cid):
    with closing(conn()) as c:
        row = c.execute("SELECT data FROM records WHERE reviewer_id=? AND case_id=?", (rid, cid)).fetchone()
    return json.loads(row["data"]) if row else None


def put_record(rid, cid, rec, event):
    with WRITE_LOCK, closing(conn()) as c, c:
        data = json.dumps(rec, ensure_ascii=False)
        c.execute("INSERT INTO records(reviewer_id, case_id, data, status, updated_at) VALUES(?,?,?,?,?) "
                  "ON CONFLICT(reviewer_id, case_id) DO UPDATE SET data=excluded.data, status=excluded.status, updated_at=excluded.updated_at",
                  (rid, cid, data, rec["status"], rec["updatedAt"]))
        c.execute("INSERT INTO history(reviewer_id, case_id, at, event, data) VALUES(?,?,?,?,?)", (rid, cid, rec["updatedAt"], event, data))


# ---------------------------------------------------------------- records
def _s(v, n=MAX_TEXT):
    return v[:n] if isinstance(v, str) else ""


def clean_record(cid, body, ex, tag):
    ex = ex or {}
    locked = bool(ex.get("locationLockedAt"))
    t = now()
    answers = body.get("answers") if isinstance(body.get("answers"), dict) else {}
    evidence = body.get("evidence") if isinstance(body.get("evidence"), dict) else {}
    methods = body.get("methods") if isinstance(body.get("methods"), dict) else {}
    r = {
        "case_id": cid, "reviewer": tag, "checklist_version": "v1",
        "answers": {k: answers[k] for k in CHECKS if answers.get(k) in ("Yes", "No", "Unsure")},
        "evidence": {k: _s(evidence.get(k)) for k in CHECKS if _s(evidence.get(k))},
        "methods": {k: [m for m in METHODS if isinstance(methods.get(k), list) and m in methods[k]] for k in METHOD_CHECKS},
        "decision": body.get("decision") if body.get("decision") in DECISIONS else "",
        "corrections": _s(body.get("corrections")), "exclusionReason": _s(body.get("exclusionReason")),
        "testMaterials": _s(body.get("testMaterials")), "blind": bool(body.get("blind")),
        "status": "final" if body.get("status") == "final" else "draft",
        # fields the client can't overwrite once set
        "ownLocation": ex.get("ownLocation", "") if locked else _s(body.get("ownLocation"), 4000),
        "locationLockedAt": ex.get("locationLockedAt"),
        "createdAt": ex.get("createdAt") or t, "finalizedAt": ex.get("finalizedAt"), "reopenedAt": ex.get("reopenedAt"),
        "updatedAt": t,
    }
    r["methods"] = {k: v for k, v in r["methods"].items() if v}
    if not locked:  # F can't be answered before the reveal
        r["answers"].pop("F", None)
        r["evidence"].pop("F", None)
    if r["status"] == "final" and ex.get("status") != "final":
        r["finalizedAt"] = t
    if r["status"] == "draft" and ex.get("status") == "final":
        r["reopenedAt"] = t
    return r


def missing(r):
    m = []
    if not r.get("locationLockedAt"):
        m.append("Lock your own bug location.")
    for k in CHECKS:
        if not r["answers"].get(k):
            m.append(f"{k}: choose Yes, No or Unsure.")
        if not r["evidence"].get(k, "").strip():
            m.append(f"{k}: write the evidence.")
        if k in METHOD_CHECKS and not r["methods"].get(k):
            m.append(f"{k}: tick how you verified it.")
    if not r["decision"]:
        m.append("Choose a decision.")
    if r["decision"] == "Keep with corrections" and not r["corrections"].strip():
        m.append("List the corrections.")
    if r["decision"] == "Exclude" and not r["exclusionReason"].strip():
        m.append("Write the exclusion reason.")
    if not r["blind"]:
        m.append("Confirm you did not look at model results.")
    return m


# ---------------------------------------------------------------- export (record_template.md)
def _cell(s):
    return re.sub(r"\r?\n", "<br>", str(s or "").replace("|", "\\|")).strip()


def to_markdown(r, tag):
    c = BY_ID.get(r["case_id"], {})
    a, ev, ms = r.get("answers", {}), r.get("evidence", {}), r.get("methods", {})
    lines = ["---", f"case_id: {r['case_id']}", f"reviewer: {tag}", f"date: {(r.get('updatedAt') or '')[:10]}",
             "checklist_version: v1", f"blind_to_model_results: {'yes' if r.get('blind') else 'no'}",
             *[f"{k}: {a.get(k, '')}" for k in CHECKS], f"decision: {r.get('decision', '')}", f"status: {r.get('status', 'draft')}", "---",
             "<!--", "Allowed answers for A-J: Yes / No / Unsure", "Allowed decisions: Keep / Keep with corrections / Exclude",
             "The block above is read by agreement.py - keep its keys and spelling exactly.", "-->", "",
             f"# Review — {r['case_id']}", "", "| Field | Value |", "|---|---|",
             f"| CVE / CWE | {_cell(c.get('cve'))} / {_cell(', '.join(c.get('cwe', [])))} |",
             f"| Repo / changed file | {_cell(c.get('repo'))} / {_cell(c.get('file'))} |",
             f"| Language | {_cell(c.get('lang'))} |",
             f"| My own bug location (written BEFORE opening metadata.json) | {_cell(r.get('ownLocation'))}"
             + (f" (locked {r['locationLockedAt']} on the review server, before vulnerable_lines was shown)" if r.get("locationLockedAt") else "") + " |",
             "", "## Evidence per check", "", "| # | Check | Result | Evidence (what you did, what you saw) |", "|---|---|---|---|"]
    for k in CHECKS:
        how = ("Verified by: " + ", ".join(METHODS[m] for m in ms.get(k, [])) + ". ") if ms.get(k) else ""
        lines.append(f"| {k} | {CHECK_TITLES[k]} | {a.get(k, '')} | {_cell(how + ev.get(k, ''))} |")
    corr = [s.strip() for s in (r.get("corrections") or "").splitlines() if s.strip()]
    lines += ["", "## Corrections proposed", '<!-- One line each: file, what to change, why. Write "None" if none. -->',
              *([s if s.startswith("- ") else "- " + s for s in corr] or ["None"]), "",
              "## Exclusion reason", "<!-- Only if decision = Exclude. -->",
              (r.get("exclusionReason") or "").strip() if r.get("decision") == "Exclude" else "", "",
              "## Test materials", "<!-- Attack inputs used, harness location (review/harness/CASE-XXXX/), what counted as success. -->",
              (r.get("testMaterials") or "").strip(), ""]
    return "\n".join(lines)


def progress_csv(recs):
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(["case_id", "date", "decision", "status", "corrections"])
    for r in recs:
        corr = "; ".join(s.strip() for s in (r.get("corrections") or "").splitlines() if s.strip())[:300]
        w.writerow([r["case_id"], (r.get("updatedAt") or "")[:10], r.get("decision", ""), r.get("status", "draft"), corr])
    return out.getvalue()


def add_reviewer_folder(z, tag, recs):
    recs = sorted(recs, key=lambda r: r["case_id"])
    d = f"cases_reviewed_{tag.lower()}/"
    for r in recs:
        z.writestr(d + f"{r['case_id']}.md", to_markdown(r, tag))
    z.writestr(d + "progress.csv", progress_csv(recs))
    z.writestr(d + "records.json", json.dumps(recs, indent=1, ensure_ascii=False))


def records_of(rid):
    with closing(conn()) as c:
        return [json.loads(x["data"]) for x in c.execute("SELECT data FROM records WHERE reviewer_id=? ORDER BY case_id", (rid,))]


# ---------------------------------------------------------------- HTTP
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
       "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class Handler(BaseHTTPRequestHandler):
    server_version = "gt-review"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # never log login tokens
        p = urlsplit(self.path).path
        if p.startswith("/login/"):
            p = "/login/***"
        sys.stderr.write(f"{now()} {self.command} {p} {args[1] if len(args) > 1 else ''}\n")

    # ---- helpers
    def send(self, status, body=b"", ctype="application/json; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def json(self, obj, status=200):
        self.send(status, json.dumps(obj, ensure_ascii=False))

    def err(self, status, msg):
        self.json({"error": msg}, status)

    def cookies(self):
        c = SimpleCookie()
        try:
            c.load(self.headers.get("Cookie", ""))
        except Exception:
            pass
        return {k: v.value for k, v in c.items()}

    def reviewer(self):
        t = self.cookies().get("gt_t")
        if not t:
            return None
        with closing(conn()) as c:
            row = c.execute("SELECT id, tag, name FROM reviewers WHERE token_hash=? AND disabled=0", (token_hash(t),)).fetchone()
        return dict(row) if row else None

    def switched(self, rv):
        """A tab loaded as one reviewer sends X-Reviewer; the browser's cookie may since belong to another
        reviewer (their link was opened in the same browser). Refuse instead of filing work under the wrong tag."""
        want = self.headers.get("X-Reviewer")
        return bool(want) and want != rv["tag"]

    def switched_err(self, rv):
        return self.json({"error": f"This browser is now signed in as {rv['tag']}, not {self.headers.get('X-Reviewer')}.",
                          "switched": True, "current": rv["tag"]}, 409)

    def is_admin(self):
        t = self.cookies().get("gt_a", "")
        return bool(t) and hmac.compare_digest(t, ADMIN_TOKEN)

    def cookie_header(self, name, value, max_age=60 * 60 * 24 * 180):
        flags = "; HttpOnly; SameSite=Lax; Path=/" + ("; Secure" if SECURE_COOKIES else "")
        return ("Set-Cookie", f"{name}={value}; Max-Age={max_age}{flags}")

    def base_url(self):
        proto = self.headers.get("X-Forwarded-Proto") or ("https" if SECURE_COOKIES else "http")
        return f"{proto}://{self.headers.get('Host', 'localhost')}"

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("too large")
        if not (self.headers.get("Content-Type", "").startswith("application/json")):
            raise ValueError("expected JSON")
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc != self.headers.get("Host"):
            raise PermissionError("cross-site request")
        data = json.loads(self.rfile.read(n) or b"{}")
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        return data

    # ---- routing
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        p = urlsplit(self.path).path
        try:
            if p == "/healthz":
                return self.send(200, "ok", "text/plain")
            if p == "/base.css":
                return self.send(200, STATIC["base.css"], "text/css; charset=utf-8")
            if p.startswith("/login/"):
                return self.login(p[len("/login/"):])
            if p == "/logout":
                return self.send(303, "", "text/plain", [("Location", "/"), self.cookie_header("gt_t", "", 0), self.cookie_header("gt_a", "", 0)])
            if p == "/":
                if self.reviewer():
                    return self.send(200, STATIC["index.html"], "text/html; charset=utf-8")
                if self.is_admin():
                    return self.send(303, "", "text/plain", [("Location", "/admin")])
                return self.send(200, STATIC["nolink.html"], "text/html; charset=utf-8")
            if p == "/admin":
                if not self.is_admin():
                    return self.send(404, STATIC["nolink.html"], "text/html; charset=utf-8")
                return self.send(200, STATIC["admin.html"], "text/html; charset=utf-8")
            if p.startswith("/api/admin/"):
                if not self.is_admin():
                    return self.err(403, "Admin only.")
                return self.admin_get(p)
            if p.startswith("/api/"):
                rv = self.reviewer()
                if not rv:
                    return self.err(401, "Your session has ended. Open your personal link again.")
                if p != "/api/me" and self.switched(rv):
                    return self.switched_err(rv)
                return self.api_get(p, rv)
            return self.send(404, "Not found", "text/plain")
        except BrokenPipeError:
            pass

    def do_PUT(self):
        self.write_request()

    def do_POST(self):
        self.write_request()

    def write_request(self):
        p = urlsplit(self.path).path
        try:
            data = self.body()
        except PermissionError as e:
            return self.err(403, str(e))
        except (ValueError, json.JSONDecodeError) as e:
            return self.err(400, f"Bad request: {e}")
        if p.startswith("/api/admin/"):
            if not self.is_admin():
                return self.err(403, "Admin only.")
            return self.admin_post(p, data)
        rv = self.reviewer()
        if not rv:
            return self.err(401, "Your session has ended. Open your personal link again.")
        if self.switched(rv):
            return self.switched_err(rv)
        m = re.match(r"^/api/records/(CASE-\d{4})$", p)
        if m and self.command == "PUT":
            return self.save_record(rv, m.group(1), data)
        m = re.match(r"^/api/records/(CASE-\d{4})/lock$", p)
        if m and self.command == "POST":
            return self.lock(rv, m.group(1), data)
        return self.err(404, "Not found.")

    # ---- login
    def login(self, token):
        if token and hmac.compare_digest(token, ADMIN_TOKEN):
            return self.send(303, "", "text/plain", [("Location", "/admin"), self.cookie_header("gt_a", token)])
        if re.fullmatch(r"[A-Za-z0-9_-]{20,64}", token or ""):
            with closing(conn()) as c:
                row = c.execute("SELECT id FROM reviewers WHERE token_hash=? AND disabled=0", (token_hash(token),)).fetchone()
            if row:
                return self.send(303, "", "text/plain", [("Location", "/"), self.cookie_header("gt_t", token)])
        return self.send(404, STATIC["nolink.html"], "text/html; charset=utf-8")

    # ---- reviewer API
    def api_get(self, p, rv):
        if p == "/api/me":
            return self.json({"tag": rv["tag"], "name": rv["name"]})
        if p == "/api/index":
            return self.json(INDEX)
        if p == "/api/example":
            return self.json({"markdown": EXAMPLE_MD})
        if p == "/api/records":
            return self.json({r["case_id"]: r for r in records_of(rv["id"])})
        m = re.match(r"^/api/case/(CASE-\d{4})/file/([a-z0-9_]+)$", p)
        if m:
            cid, role = m.groups()
            if cid not in BY_ID or role not in ROLES or (cid, role) not in FILES:
                return self.err(404, "No such file.")
            name, txt = FILES[(cid, role)]
            return self.send(200, txt, "text/plain; charset=utf-8", [("X-File-Name", name)])
        m = re.match(r"^/api/case/(CASE-\d{4})/reveal$", p)
        if m:
            cid = m.group(1)
            rec = get_record(rv["id"], cid) if cid in BY_ID else None
            if not rec or not rec.get("locationLockedAt"):
                return self.err(403, "Lock your own bug location first.")
            md = META.get(cid, {})
            return self.json({"vulnerable_lines": md.get("vulnerable_lines"), "auto_locate_confidence": md.get("auto_locate_confidence"),
                              "changed_function": md.get("changed_function"), "stage1_notes": STAGE1.get(cid, {}).get("notes", "")})
        if p == "/api/export/mine.zip":
            recs = records_of(rv["id"])
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                add_reviewer_folder(z, rv["tag"], recs)
            fn = f"review_records_{rv['tag']}_{now()[:10]}.zip"
            return self.send(200, buf.getvalue(), "application/zip", [("Content-Disposition", f'attachment; filename="{fn}"')])
        return self.err(404, "Not found.")

    def save_record(self, rv, cid, data):
        if cid not in BY_ID:
            return self.err(404, "Unknown case.")
        ex = get_record(rv["id"], cid)
        rec = clean_record(cid, data, ex, rv["tag"])
        if rec["status"] == "final":
            miss = missing(rec)
            if miss:
                return self.json({"error": "Not ready to mark final.", "missing": miss}, 400)
        event = "final" if rec["status"] == "final" and (ex or {}).get("status") != "final" else \
                "reopen" if rec["status"] == "draft" and (ex or {}).get("status") == "final" else "save"
        put_record(rv["id"], cid, rec, event)
        return self.json(rec)

    def lock(self, rv, cid, data):
        if cid not in BY_ID:
            return self.err(404, "Unknown case.")
        ex = get_record(rv["id"], cid)
        if ex and ex.get("locationLockedAt"):
            return self.json(ex)
        loc = _s(data.get("ownLocation"), 4000).strip()
        if len(loc) < 4:
            return self.err(400, "Write your own bug location first.")
        rec = clean_record(cid, ex or {}, ex, rv["tag"])
        rec["ownLocation"], rec["locationLockedAt"] = loc, now()
        put_record(rv["id"], cid, rec, "lock")
        return self.json(rec)

    # ---- admin API
    def admin_get(self, p):
        if p == "/api/admin/reviewers":
            with closing(conn()) as c:
                rows = c.execute("""SELECT r.id, r.tag, r.name, r.created_at, r.disabled,
                    SUM(CASE WHEN x.status='final' THEN 1 ELSE 0 END) AS final,
                    SUM(CASE WHEN x.status='draft' THEN 1 ELSE 0 END) AS draft, MAX(x.updated_at) AS last
                    FROM reviewers r LEFT JOIN records x ON x.reviewer_id=r.id GROUP BY r.id ORDER BY r.tag""").fetchall()
            return self.json({"reviewers": [dict(r) for r in rows], "total_cases": len(INDEX)})
        if p == "/api/admin/export.zip":
            buf = io.BytesIO()
            with closing(conn()) as c:
                revs = c.execute("SELECT id, tag FROM reviewers ORDER BY tag").fetchall()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for r in revs:
                    recs = records_of(r["id"])
                    if recs:
                        add_reviewer_folder(z, r["tag"], recs)
            fn = f"review_records_all_{now()[:10]}.zip"
            return self.send(200, buf.getvalue(), "application/zip", [("Content-Disposition", f'attachment; filename="{fn}"')])
        if p == "/api/admin/backup.db":
            with closing(conn()) as c:
                data = c.serialize()
            fn = f"review_backup_{now()[:10]}.db"
            return self.send(200, data, "application/octet-stream", [("Content-Disposition", f'attachment; filename="{fn}"')])
        return self.err(404, "Not found.")

    def admin_post(self, p, data):
        if p == "/api/admin/reviewers":
            tag = str(data.get("tag", "")).strip().upper()
            name = _s(data.get("name"), 80).strip()
            if not re.fullmatch(r"R\d{1,2}", tag):
                return self.err(400, "Tag must be R followed by a number, for example R2.")
            token = secrets.token_urlsafe(24)
            try:
                with WRITE_LOCK, closing(conn()) as c, c:
                    c.execute("INSERT INTO reviewers(tag, name, token_hash, created_at) VALUES(?,?,?,?)", (tag, name, token_hash(token), now()))
            except sqlite3.IntegrityError:
                return self.err(409, f"{tag} already exists. Use 'New link' on that row instead.")
            return self.json({"tag": tag, "link": f"{self.base_url()}/login/{token}"})
        m = re.match(r"^/api/admin/reviewers/(\d+)/(newlink|disable|enable)$", p)
        if m:
            rid, action = int(m.group(1)), m.group(2)
            with WRITE_LOCK, closing(conn()) as c, c:
                row = c.execute("SELECT tag FROM reviewers WHERE id=?", (rid,)).fetchone()
                if not row:
                    return self.err(404, "No such reviewer.")
                if action == "newlink":
                    token = secrets.token_urlsafe(24)
                    c.execute("UPDATE reviewers SET token_hash=? WHERE id=?", (token_hash(token), rid))
                    return self.json({"tag": row["tag"], "link": f"{self.base_url()}/login/{token}"})
                c.execute("UPDATE reviewers SET disabled=? WHERE id=?", (1 if action == "disable" else 0, rid))
            return self.json({"ok": True})
        return self.err(404, "Not found.")


def main():
    init_db()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.daemon_threads = True
    print(f"review server on :{PORT}, {len(INDEX)} cases, db {DB_PATH}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()

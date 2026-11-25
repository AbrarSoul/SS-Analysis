#!/usr/bin/env python3
"""Move every record (and its edit history) from one reviewer to another, inside the review database.

Used once on 2026-11-25: the coordinator's R1 work was saved under R2 because R2's link had been opened in
the same browser (the cookie is per browser). Where both reviewers have a record for the same case, the
moved (source) record wins and the target's old version stays in history as a 'superseded' event.

Prints counts only, never record contents, so it can be run without seeing another reviewer's answers.

  python3 move_records.py <db path> <from tag> <to tag> [--dry-run]
"""
import json, sqlite3, sys
from datetime import datetime, timezone


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dry = "--dry-run" in sys.argv
    db, src_tag, dst_tag = args
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    c = sqlite3.connect(db)
    ids = dict(c.execute("SELECT tag, id FROM reviewers"))
    src, dst = ids[src_tag], ids[dst_tag]
    rows = c.execute("SELECT case_id, data, status, updated_at FROM records WHERE reviewer_id=?", (src,)).fetchall()
    clash = {r[0] for r in c.execute("SELECT case_id FROM records WHERE reviewer_id=?", (dst,))} & {r[0] for r in rows}
    print(f"{src_tag} -> {dst_tag}: {len(rows)} records to move; {len(clash)} case(s) also under {dst_tag}: {sorted(clash)}")
    with c:
        for cid in clash:
            old = c.execute("SELECT data FROM records WHERE reviewer_id=? AND case_id=?", (dst, cid)).fetchone()[0]
            c.execute("INSERT INTO history(reviewer_id, case_id, at, event, data) VALUES(?,?,?,?,?)",
                      (dst, cid, now, f"superseded_by_{src_tag}_move", old))
            c.execute("DELETE FROM records WHERE reviewer_id=? AND case_id=?", (dst, cid))
        hist = c.execute("UPDATE history SET reviewer_id=? WHERE reviewer_id=?", (dst, src)).rowcount
        for cid, data, status, upd in rows:
            rec = json.loads(data)
            rec["reviewer"] = dst_tag
            new = json.dumps(rec, ensure_ascii=False)
            c.execute("INSERT INTO records(reviewer_id, case_id, data, status, updated_at) VALUES(?,?,?,?,?)", (dst, cid, new, status, upd))
            c.execute("INSERT INTO history(reviewer_id, case_id, at, event, data) VALUES(?,?,?,?,?)",
                      (dst, cid, now, f"moved_from_{src_tag}", new))
        c.execute("DELETE FROM records WHERE reviewer_id=?", (src,))
        print(f"moved {len(rows)} records and {hist} history rows")
        for tag in (src_tag, dst_tag):
            n = dict(c.execute("SELECT status, COUNT(*) FROM records WHERE reviewer_id=? GROUP BY status", (ids[tag],)))
            print(f"  {tag}: final {n.get('final', 0)}, draft {n.get('draft', 0)}")
        if dry:
            c.rollback()
            print("dry run: rolled back")
            return
    print("committed")


if __name__ == "__main__":
    main()

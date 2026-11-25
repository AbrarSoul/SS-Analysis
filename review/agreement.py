#!/usr/bin/env python3
"""
Compare R1 and R2 review records and report agreement per check (A-J) and on
the final decision, with Cohen's kappa. Also lists every case where the two
reviewers disagree, which is the adjudication to-do list.

Usage:
  python3 agreement.py --r1 review/records/R1 --r2 review/records/R2 --out review/agreement
"""
import argparse, csv, re
from collections import Counter
from pathlib import Path

KEYS = list("ABCDEFGHIJ") + ["decision"]


def read_record(p):
    txt = p.read_text(errors="replace")
    m = re.match(r"---\n(.*?)\n---", txt, re.S)
    if not m:
        return None
    rec = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            rec[k.strip()] = v.strip()
    return rec


def kappa(pairs):
    n = len(pairs)
    if n == 0:
        return None, None
    po = sum(a == b for a, b in pairs) / n
    c1, c2 = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum(c1[k] * c2[k] for k in set(c1) | set(c2)) / (n * n)
    k = 1.0 if pe == 1 else (po - pe) / (1 - pe)
    return po, k


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--r1", required=True); ap.add_argument("--r2", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    r1 = {p.stem: read_record(p) for p in Path(a.r1).glob("CASE-*.md")}
    r2 = {p.stem: read_record(p) for p in Path(a.r2).glob("CASE-*.md")}
    both = sorted(c for c in r1 if c in r2 and r1[c] and r2[c])
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)

    lines = [f"cases reviewed by both: {len(both)}", "",
             f"{'check':<10}{'n':>5}{'agree %':>10}{'kappa':>8}"]
    disagreements = []
    for k in KEYS:
        pairs = [(r1[c].get(k, "").lower(), r2[c].get(k, "").lower()) for c in both
                 if r1[c].get(k) and r2[c].get(k)]
        po, kp = kappa(pairs)
        lines.append(f"{k:<10}{len(pairs):>5}{'' if po is None else f'{100*po:.1f}':>10}"
                     f"{'' if kp is None else f'{kp:.2f}':>8}")
        for c in both:
            if r1[c].get(k) and r2[c].get(k) and r1[c][k].lower() != r2[c][k].lower():
                disagreements.append({"case_id": c, "check": k, "R1": r1[c][k], "R2": r2[c][k]})
    lines += ["", "kappa reads: <0.40 poor, 0.41-0.60 moderate, 0.61-0.80 substantial, >0.80 almost perfect",
              "A check with low kappa usually means its wording is unclear - discuss it, don't just adjudicate."]
    (out / "agreement.txt").write_text("\n".join(lines) + "\n")
    with open(out / "disagreements.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["case_id", "check", "R1", "R2"])
        w.writeheader(); w.writerows(disagreements)
    print("\n".join(lines)); print(f"\n{len(disagreements)} disagreement(s) -> {out/'disagreements.csv'}")


if __name__ == "__main__":
    main()

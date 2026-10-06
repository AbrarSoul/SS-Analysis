"""
Joins our 15,673 target-language patch candidates (from
data/morefixes_v4/target_language_candidates.txt, derived purely from
filenames + diff content) against the restored MoreFixes Postgres database
to recover each patch's CVE id(s), CWE id(s)/name(s), and match confidence
score -- the metadata the flat patch-file zip alone cannot provide, but
which design doc Section 7.1 (CVE/GHSA identifier) and Section 6.2 (CWE
distribution reporting) require.

Candidates whose (repo, commit hash) has no corresponding row in the
`fixes` table are flagged separately -- they exist as real exported patch
files but we can't establish their CVE identity from this database, which
matters directly for the Section 7.1 inclusion criterion.
"""
import csv
import subprocess
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "morefixes_v4"
CANDIDATES_FILE = DATA_DIR / "target_language_candidates.txt"
OUTPUT_FILE = DATA_DIR / "candidates_with_cve_cwe.csv"
UNMATCHED_FILE = DATA_DIR / "candidates_without_cve_match.csv"

DOCKER_CMD = ["docker", "exec", "-i", "morefixes-db", "psql", "-U", "postgres", "-d", "morefixes"]


def parse_candidate_filename(filename: str):
    # github.com_{owner}_{name}_{commit}.patch -- owner/name never contain
    # underscores that collide with this split in practice for our data
    # (verified: same regex logic as autogrep/patch_processor.py), but to be
    # safe we mirror its exact regex rather than a naive split.
    import re
    m = re.match(r"github\.com_(.+?)_(.+?)_([a-f0-9]+)\.patch", filename)
    if not m:
        return None
    owner, name, commit = m.groups()
    owner = owner.replace("_", "/")
    return owner, name, commit


def run_psql(sql: str) -> str:
    result = subprocess.run(DOCKER_CMD + ["-t", "-A", "-F", "\t", "-c", sql],
                             capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr}")
    return result.stdout


def main():
    candidates = []
    with open(CANDIDATES_FILE) as f:
        for line in f:
            filename, langs = line.rstrip("\n").split("\t")
            parsed = parse_candidate_filename(filename)
            if not parsed:
                print(f"WARNING: could not parse {filename}")
                continue
            owner, name, commit = parsed
            candidates.append({
                "filename": filename, "owner": owner, "name": name,
                "commit": commit, "languages": langs,
            })
    print(f"Loaded {len(candidates)} candidates")

    # Build a temp table of (repo_url, hash) pairs, then join.
    create_tmp = "CREATE TEMP TABLE candidate_commits (repo_url TEXT, hash TEXT, filename TEXT);"
    values = ",\n".join(
        f"('https://github.com/{c['owner']}/{c['name']}', '{c['commit']}', '{c['filename']}')"
        for c in candidates
    )
    insert_tmp = f"INSERT INTO candidate_commits (repo_url, hash, filename) VALUES\n{values};"

    setup_sql = create_tmp + "\n" + insert_tmp
    result = subprocess.run(DOCKER_CMD, input=setup_sql, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to create/populate temp table: {result.stderr}")
    print("Temp table populated.")

    # NOTE: temp tables are session-scoped, so setup + query must run in the
    # SAME psql invocation/session -- do it all in one script.
    # NOTE: psql's \copy meta-command must be a single line when read from a
    # script/stdin -- it cannot span multiple lines like a real SQL statement
    # can. Using the SQL-level COPY command instead avoids that restriction,
    # at the cost of the output being interleaved with the setup statements'
    # own status lines (CREATE TABLE / INSERT 0 N) in the same stdout stream,
    # so we strip those specific known status-line prefixes before parsing.
    full_sql = setup_sql + """
COPY (
  SELECT cc.filename, cc.repo_url, cc.hash,
         f.cve_id, f.score, f.rel_type,
         string_agg(DISTINCT cwc.cwe_id, ';') AS cwe_ids,
         string_agg(DISTINCT cwe.cwe_name, ';') AS cwe_names
  FROM candidate_commits cc
  JOIN fixes f ON f.repo_url = cc.repo_url AND f.hash = cc.hash
  LEFT JOIN cwe_classification cwc ON cwc.cve_id = f.cve_id
  LEFT JOIN cwe ON cwe.cwe_id = cwc.cwe_id
  GROUP BY cc.filename, cc.repo_url, cc.hash, f.cve_id, f.score, f.rel_type
) TO STDOUT WITH CSV HEADER;
"""
    result = subprocess.run(DOCKER_CMD, input=full_sql, capture_output=True, text=True, timeout=180)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to run join query: {result.stderr}")

    lines = result.stdout.splitlines()
    csv_lines = [ln for ln in lines if not (ln == "CREATE TABLE" or ln.startswith("INSERT 0 "))]

    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(csv_lines) + "\n")

    matched_filenames = set()
    with open(OUTPUT_FILE) as f:
        reader = csv.DictReader(f)
        for row in reader:
            matched_filenames.add(row["filename"])

    print(f"Matched {len(matched_filenames)} / {len(candidates)} candidates to at least one fixes row.")

    unmatched = [c for c in candidates if c["filename"] not in matched_filenames]
    with open(UNMATCHED_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["filename", "owner", "name", "commit", "languages"])
        writer.writeheader()
        writer.writerows(unmatched)
    print(f"Unmatched (no CVE identity found): {len(unmatched)} -> {UNMATCHED_FILE}")
    print(f"Matched output -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

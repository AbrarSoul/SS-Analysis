"""
Section 9 ground-truth test bundle: CASE-0158
(ether/etherpad-lite, src/node/utils/ExportEtherpad.js getPadRaw,
CVE-2015-2298, CWE-200 exposure of sensitive information).

Located target: the `async.waterfall([...` block inside `getPadRaw`.

Core vulnerable mechanism: the pad export looks up the pad's records with
`db.findKeys("pad:" + padId + "*", ...)`: a PREFIX wildcard. Exporting the pad
`test` therefore also returns the records of every other pad whose id
merely starts with `test` (`test2`, `testing`, ...), including private ones,
and includes their content and revisions in the export. The upstream fix
queries the exact pad key (`"pad:" + padId`) and the sub-records
(`"pad:" + padId + ":*"`) separately.

Sibling sites: none in this file (getPadRaw is the only exporter).

Every variant is the FULL real file. getPadRaw is exported and called from
other modules, so the renamed variant keeps its name and renames parameters
and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0158"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

FIND = '''    db.findKeys("pad:"+padId+"*", null, function(err,records){
      if(!err){
        cb(err, records);
      }
    })
'''
assert original.count(FIND) == 1
s = original.index("exports.getPadRaw = function(padId, callback){\n")
BLOCK = original[s:]


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


def rename(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename(BLOCK, (("padId", "padName"), ("callback", "finish"), ("cb", "next"), ("records", "found"),
                   ("data", "dump"), ("entry", "record"), ("authors", "authorAttribs"), ("authorId", "aid"),
                   ("authorEntry", "authorRecord"), ("err", "error")))
v1 = original[:s] + b
assert 'db.findKeys("pad:"+padName+"*", null, function(error,found){' in v1
assert "exports.getPadRaw = function(padName, finish){" in v1 and 'dump["globalAuthor:"+aid] = authorRecord' in v1
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, FIND, '''    var pattern = "pad:" + padId + "*";
    db.findKeys(pattern, null, function(err,records){
      if(!err){
        cb(err, records);
      }
    })
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Keeps the single wildcard query but filters its result to the pad's own
# key and its ':'-separated sub-records; upstream issues two exact queries.
v3 = swap(original, FIND, '''    db.findKeys("pad:"+padId+"*", null, function(err,records){
      if(!err){
        var own = "pad:"+padId;
        cb(err, records.filter(function(key){
          return key === own || key.indexOf(own + ":") === 0;
        }));
      }
    })
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''var db = require("../db/DB").db;

/**
 * Same db.findKeys("pad:...*") prefix query as the pad export, but the prefix
 * is a fixed string with no pad id in it: this is the admin-only listing of
 * every pad, so returning all of them is the intended behaviour.
 */
exports.listAllPadKeys = function(callback){
  db.findKeys("pad:*", null, function(err, keys){
    callback(err, keys);
  });
};
'''
assert 'findKeys("pad:*"' in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0158.")

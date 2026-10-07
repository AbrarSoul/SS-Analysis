"""
Offline, read-only analysis of the MoreFixes v4 patch-file zip: for each
patch, determine which language(s) it touches (reusing Autogrep's own
patch_processor.py extension map for consistency with what the real
pipeline will recognize) and whether it parses as a well-formed, non-empty,
non-binary unified diff -- without extracting anything to disk yet.

This is preparation for design doc Section 8 Step 1 ("filter by language...
patch availability, and source-file type"), scoped to what's mechanically
checkable from the zip alone (no repo/network access, no CVE/CWE metadata --
that requires the SQL dump, handled separately).
"""
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "autogrep"))
from patch_processor import PatchProcessor  # noqa: E402
from config import Config  # noqa: E402

ZIP_PATH = Path(__file__).resolve().parent.parent / "data" / "morefixes_v4" / "patch-files2026-06-20.zip"

TARGET_LANGUAGES = {"python", "java", "javascript", "typescript"}


def main():
    pp = PatchProcessor(Config())

    lang_counts = Counter()
    multi_lang_target_count = 0
    empty_count = 0
    unparseable_filename_count = 0
    no_recognized_language_count = 0
    per_case_languages = {}

    with zipfile.ZipFile(ZIP_PATH) as zf:
        patch_names = [n for n in zf.namelist() if n.endswith(".patch")]
        print(f"Total .patch entries in zip: {len(patch_names)}")

        for i, name in enumerate(patch_names, 1):
            filename = Path(name).name
            try:
                owner, repo, commit = pp.parse_patch_filename(filename)
            except ValueError:
                unparseable_filename_count += 1
                continue

            content = zf.read(name)
            if not content.strip():
                empty_count += 1
                continue

            try:
                text = content.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                text = content.decode("utf-8", errors="replace")

            languages_in_patch = set()
            for line in text.split("\n"):
                if line.startswith("diff --git"):
                    parts = line.split()
                    if len(parts) >= 4:
                        touched_file = parts[-1][2:]  # strip b/ prefix
                        lang = pp.get_language_from_file(touched_file)
                        if lang:
                            languages_in_patch.add(lang)

            if not languages_in_patch:
                no_recognized_language_count += 1
                continue

            for lang in languages_in_patch:
                lang_counts[lang] += 1

            target_hit = languages_in_patch & TARGET_LANGUAGES
            if target_hit:
                per_case_languages[filename] = sorted(languages_in_patch)
                if len(target_hit) > 1:
                    multi_lang_target_count += 1

            if i % 10000 == 0:
                print(f"  ...processed {i}/{len(patch_names)}")

    print()
    print("=== Language counts across ALL recognized-language patches ===")
    for lang, count in lang_counts.most_common(20):
        print(f"  {lang:20s} {count}")

    print()
    print("=== Target-language (Python/Java/JS/TS) candidate summary ===")
    for lang in sorted(TARGET_LANGUAGES):
        count = sum(1 for langs in per_case_languages.values() if lang in langs)
        print(f"  {lang:15s} {count}")
    print(f"  TOTAL unique target-language patches: {len(per_case_languages)}")
    print(f"  (of which touch >1 target language): {multi_lang_target_count}")

    print()
    print("=== Data-quality notes ===")
    print(f"  Empty patch files: {empty_count}")
    print(f"  Unparseable filenames (didn't match github.com_owner_name_hash.patch): {unparseable_filename_count}")
    print(f"  No recognized-language file in diff at all: {no_recognized_language_count}")

    out_path = Path(__file__).resolve().parent.parent / "data" / "morefixes_v4" / "target_language_candidates.txt"
    with open(out_path, "w") as f:
        for filename, langs in sorted(per_case_languages.items()):
            f.write(f"{filename}\t{','.join(langs)}\n")
    print()
    print(f"Wrote {len(per_case_languages)} candidate filenames to {out_path}")


if __name__ == "__main__":
    main()

#!/bin/bash
# Syntax-only sanity check for extracted single-file Java snippets that
# cannot fully compile (missing classpath deps from the larger project).
# Renames a temp copy to match the public class name (javac requires this),
# compiles it, and fails only on syntax-error diagnostics -- "cannot find
# symbol" / "package does not exist" errors from unresolved imports are
# expected and ignored.
set -uo pipefail
SRC="$1"
CLASS_NAME=$(grep -oE '(public )?(final )?(abstract )?class [A-Za-z0-9_]+' "$SRC" | head -1 | awk '{print $NF}')
if [ -z "$CLASS_NAME" ]; then
  CLASS_NAME=$(grep -oE '(public )?interface [A-Za-z0-9_]+' "$SRC" | head -1 | awk '{print $NF}')
fi
TMPDIR=$(mktemp -d)
cp "$SRC" "$TMPDIR/${CLASS_NAME}.java"
OUT=$(javac -d "$TMPDIR/out" "$TMPDIR/${CLASS_NAME}.java" 2>&1)
mkdir -p "$TMPDIR/out"
SYNTAX_ERRORS=$(echo "$OUT" | grep -E "illegal start of|';' expected|'\)' expected|'\}' expected|reached end of file while parsing|not a statement|<identifier> expected|class, interface, (enum, or record)? expected" || true)
rm -rf "$TMPDIR"
if [ -n "$SYNTAX_ERRORS" ]; then
  echo "SYNTAX ERRORS in $SRC:"
  echo "$SYNTAX_ERRORS"
  exit 1
else
  echo "$SRC: no syntax errors (semantic 'cannot find symbol' errors from missing classpath deps are expected and ignored)"
  exit 0
fi

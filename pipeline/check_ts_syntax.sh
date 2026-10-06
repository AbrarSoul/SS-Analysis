#!/bin/bash
# Syntax-only check for extracted single-file TypeScript snippets that
# cannot fully type-check (missing project deps/imports). Uses tsc
# --noEmit with relaxed settings and greps out only genuine syntax
# errors, ignoring "cannot find module/name" semantic errors expected
# from an incomplete classpath.
set -uo pipefail
TSC=/private/tmp/claude-504/-Users-nkabmo-Desktop-Tools-SS/6ee5c369-bfd5-4593-a467-4e411c8a56b6/scratchpad/ts-check/node_modules/.bin/tsc
SRC="$1"
OUT=$("$TSC" --noEmit --allowJs --checkJs false --target esnext --module esnext --moduleResolution node \
  --jsx react --skipLibCheck --noResolve --strict false "$SRC" 2>&1)
# TS1xxx codes are syntax errors; TS2xxx/TS7xxx are semantic (missing
# module/name/type) errors, expected here and ignored.
SYNTAX_ERRORS=$(echo "$OUT" | grep -E "error TS1[0-9]{3}:" || true)
if [ -n "$SYNTAX_ERRORS" ]; then
  echo "SYNTAX ERRORS in $SRC:"
  echo "$SYNTAX_ERRORS"
  exit 1
else
  echo "$SRC: no syntax errors (semantic TS2xxx/TS7xxx errors from missing imports/types are expected and ignored)"
  exit 0
fi

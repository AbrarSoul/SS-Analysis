#!/usr/bin/env bash
# Deploy (or update) the review server on Fly.io. Safe to run again: each step is skipped if already done.
set -euo pipefail
cd "$(dirname "$0")"
APP=$(awk -F'"' '/^app =/{print $2}' fly.toml)
TOKFILE="$HOME/.config/gt-review/admin_token"   # admin password: kept outside the repo, never committed

python3 build_data.py                                            # cases, index, worked example -> data/

if ! fly status -a "$APP" >/dev/null 2>&1; then
  fly apps create "$APP" --org personal
fi
if ! fly volumes list -a "$APP" 2>/dev/null | grep -q review_data; then
  fly volumes create review_data --region arn --size 1 -a "$APP" -y   # 1 GB disk for review.db
fi
if [ ! -s "$TOKFILE" ]; then
  mkdir -p "$(dirname "$TOKFILE")"; (umask 077; python3 -c "import secrets; print(secrets.token_urlsafe(32))" > "$TOKFILE")
fi
if ! fly secrets list -a "$APP" 2>/dev/null | grep -q ADMIN_TOKEN; then
  printf 'ADMIN_TOKEN=%s\n' "$(cat "$TOKFILE")" | fly secrets import -a "$APP" --stage
fi

fly deploy --ha=false -a "$APP"
echo
echo "Deployed: https://$APP.fly.dev"
echo "Open the admin page with:  open \"https://$APP.fly.dev/login/\$(cat $TOKFILE)\""

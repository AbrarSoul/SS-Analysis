# Review server on Fly.io

A small web app where judges carry out the ground-truth review (checks A–J). Judges need only a personal link. They don't need a Claude account and don't download any files.

| File | What it is |
|---|---|
| `server.py` | The server. Python standard library only; records are stored in SQLite on a Fly volume. |
| `static/index.html` | The judge page: case list, code viewer and diff, A–J checklist, step-by-step guide. |
| `static/admin.html` | Your page: add judges, see progress, download records and backups. |
| `build_data.py` | Packs the 154 cases, a case index that keeps judges blind, and the worked example into `data/`. Contains no model results. |
| `deploy.sh` | Deploys or updates the app in one command. |

## Deploy (first time and every update)

```
review/webapp/deploy.sh
```

On the first run, the script:
1. creates the Fly app (named in `fly.toml`);
2. creates a 1 GB volume for the database;
3. generates an admin password and saves it to `~/.config/gt-review/admin_token`. It is never stored in the repo, so keep that file safe;
4. deploys the app.

Later runs only rebuild the data and redeploy. Judges' records are on the volume and are kept.

## Use it

1. **Open the admin page:**
   `open "https://<app>.fly.dev/login/$(cat ~/.config/gt-review/admin_token)"`
2. **Add each judge** (tag `R2`, `R3`, …) and send them the personal link privately. Anyone holding the link can review as that judge. If a link is lost or leaked, click **New link** and the old one stops working.
3. **To review cases yourself**, add yourself as `R1` and open that link in a private window.
4. **Collecting results:** click **Download all records** to get `cases_reviewed_r2/CASE-XXXX.md` and so on, then run:
   `python3 review/agreement.py --r1 <...>/cases_reviewed_r1 --r2 <...>/cases_reviewed_r2 --out review/agreement`
5. **Backups:** **Download database backup** saves the whole database, including the full edit history. Fly also snapshots the volume daily.

## Rules the server enforces
- Each judge sees and edits only their own records.
- `vulnerable_lines` and the Stage 1 notes for a case are sent only after that judge has locked their own bug location. The lock time comes from the server and can't be changed afterwards.
- A record can be marked final only when it is complete.
- Every save is kept in a history table.

## Cost and shutdown
- The app uses one small machine (shared CPU, 256 MB) that stops when idle and starts again on the next visit (first load takes a few seconds), plus a 1 GB volume. Expect a few dollars a month at most; check your Fly billing page for exact figures.
- When the review is over: download all records and a backup, then run `fly apps destroy <app>`. This deletes the app, its data and the judges' links.

## Try it locally
```
ADMIN_TOKEN=local-admin-token-0123456789abcdef DATA_DIR=/tmp/gtdata SECURE_COOKIES=0 python3 review/webapp/server.py
open http://localhost:8080/login/local-admin-token-0123456789abcdef
```

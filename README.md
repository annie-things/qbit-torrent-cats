# torrent-cats

Organize completed qBittorrent torrents by tracker code and date, while keeping category save paths compatible with Auto Torrent Management (AutoTMM). Works as an on-completion script in qBittorrent, can also be used manually on a per-torrent basis.

## Behavior

Input is a torrent hash (usually qBittorrent completion hook `%I`).

Processing flow:
1. Load config.
2. Fetch torrent info.
3. Skip if current root category is in `ignore_categories`.
4. Skip if torrent tags contain any `ignore_tags`.
5. Skip if `require_downloaded_session` is enabled and downloaded session bytes are below threshold.
6. Resolve tracker host to a code via `tracker_map`; fallback to `unmapped_category`.
7. Build target category.
8. Ensure category exists (create if missing) with save path `<sorted_root>/<target_category>`.
9. Set torrent category and optionally force AutoTMM on.

Notes:
- Existing category save paths are intentionally never modified.
- In `dry_run`, no changes are made; computed values are printed.
- Requests include `Origin`/`Referer` headers derived from `qbt_url` for WebUI CSRF compatibility.

## Category Format

Target category format:
`<TrackerCode>/<PreservedSubcategorySegments>/<Month-Year>`

How category is built:
1. Start from current category segments.
2. If first segment exactly equals computed tracker code, remove it.
3. If last segment matches configured month-year token format, remove it.
4. Apply preserve rules.
5. Prepend tracker code and append current month-year segment.

Preserve rules:
- `preserve_subcategories: "*"` preserves all remaining segments.
- `preserve_subcategories` as list/comma string preserves only when rules match.
- With `preserve_subcategory_match_anywhere: false`:
  the first remaining segment must match preserve list; if it matches, all remaining segments are kept.
- With `preserve_subcategory_match_anywhere: true`:
  first matching segment anywhere is kept as a single preserved segment.

## Month/Year Tokens

Final date segment is always `<month_token>-<year_token>`.

Month token definitions:
- `M`: `1` to `12` (no leading zero)
- `MM`: `01` to `12`
- `MMM`: `Jan`, `Feb`, `Mar`, `Apr`, `May`, `Jun`, `Jul`, `Aug`, `Sep`, `Oct`, `Nov`, `Dec`
- `MMMM`: `January` to `December`

Year token definitions:
- `YY`: last 2 digits of year (for 2026 -> `26`)
- `YYYY`: 4-digit year (for 2026 -> `2026`)

Examples for February 2026:
- `M` + `YY` -> `2-26`
- `MM` + `YY` -> `02-26`
- `MMM` + `YY` -> `Feb-26`
- `MMMM` + `YYYY` -> `February-2026`

## Tracker Mapping Rules

`tracker_map` accepts:
- JSON object: `{ "host": "CODE" }`
- JSON list: `[{"pattern":"host-or-wildcard","code":"CODE"}]`

Matching behavior:
1. Exact host match first.
2. Wildcard/suffix matches next (`*.example.org` or `.example.org`).
3. Longest suffix wins when multiple suffixes match.
4. If no match, use `unmapped_category`.

Tracker host normalization:
- Lowercased.
- Trailing dots removed.

## Configuration Reference

Defaults shown are code defaults.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `qbt_url` | string | `http://127.0.0.1:8080` | Absolute qBittorrent WebUI URL (`http`/`https`). |
| `qbt_username` | string | `""` | WebUI username. Must be set together with password, or both unset. |
| `qbt_password` | string | `""` | WebUI password. |
| `sorted_root` | string | `~/Downloads-Sorted` | Root directory used to build category save paths. |
| `ignore_categories` | array or comma string | `""` | Skip torrent when current root category matches (case-insensitive). |
| `ignore_tags` | array or comma string | `""` | Skip torrent when any tag matches (case-insensitive). |
| `preserve_subcategories` | array, comma string, or `"*"` string | `"FL"` | Controls preserved category segments. Use literal string `"*"` to preserve all. |
| `preserve_subcategory_match_anywhere` | boolean | `false` | If true, preserve matching can come from any segment and keeps only first match. |
| `month_format` | string | `MMM` | Month token format. Allowed: `M`, `MM`, `MMM`, `MMMM`. |
| `year_format` | string | `YY` | Year token format. Allowed: `YY`, `YYYY`. |
| `unmapped_category` | string | `UNMAPPED` | Tracker code used when no mapping matches. |
| `require_downloaded_session` | boolean | `true` | Only process when session downloaded bytes threshold is met. |
| `downloaded_session_min_bytes` | integer >= 0 | `1` | Minimum downloaded session bytes required. |
| `force_auto_tmm` | boolean | `true` | Re-enable AutoTMM after setting category. |
| `dry_run` | boolean | `false` | Print computed result only; perform no writes. |
| `timeout_seconds` | integer | `15` | HTTP timeout for qBittorrent API calls; must be `> 0`. |
| `tracker_map` | object or list | `{}` | Tracker host/pattern to category code mapping. |

Type parsing details:
- Boolean strings accepted: `1,true,yes,on` and `0,false,no,off`.
- Integer settings accept numeric strings.
- String-list settings accept either array form or comma-separated string form.

## Config File Resolution

Resolution order:
1. CLI argument: `torrent_cats.py <hash> [config_file]`
2. Fallback: `config.json` beside the script.

Path behavior:
- If config path is relative, it is resolved relative to the script directory (not current shell directory).
- If no config file exists at fallback location, script runs with defaults.
- If explicit config path is provided but missing, script exits with error.

## Install

```bash
sudo mkdir -p /opt/torrent-cats
sudo cp torrent_cats.py run_torrent_cats.sh example.config.json /opt/torrent-cats/
cd /opt/torrent-cats
sudo cp example.config.json config.json
sudo chmod +x run_torrent_cats.sh torrent_cats.py
```

Set qBittorrent completion command:

```bash
/opt/torrent-cats/run_torrent_cats.sh "%I"
```

## Containerized Deployment

- `qbt_url` must be reachable from where the script runs.
- `sorted_root` must be valid from qBittorrent's filesystem perspective.
- If qBittorrent runs in a container, use container-visible paths.

## Testing

Use dry-run first:
1. Set `"dry_run": true` in config.
2. Run with a known hash:

```bash
/opt/torrent-cats/run_torrent_cats.sh "<INFO_HASH>"
```

Optional logging from completion hook:

```bash
/opt/torrent-cats/run_torrent_cats.sh "%I" >> /opt/torrent-cats/torrent_cats.log 2>&1
```

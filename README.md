Organise your torrents in qBittorrent by tracker and per month, with appropriate categories and save paths set to work correctly with Auto Torrent Management.

## Behavior

- Input: torrent hash from qBittorrent completion hook (`%I`)
- Tracker host resolves to a tracker code from `tracker_map`
- Output category format: `<TrackerCode>/<OptionalSubcategory>/<Month-Year>` (All configurable)
- Save path format: `<sorted_root>/<category>`
- Missing categories are created automatically
- Existing category save paths are not modified
- Tracker fallback when unmapped: `unmapped_category` (default `UNMAPPED`, configurable)

## Install

1. Copy files:

```bash
sudo mkdir -p /opt/torrent-cats
sudo cp torrent_cats.py run_torrent_cats.sh example.config.json /opt/torrent-cats/
cd /opt/torrent-cats
sudo cp example.config.json config.json
sudo chmod +x run_torrent_cats.sh torrent_cats.py
```

2. Edit config:

```bash
sudo nano /opt/torrent-cats/config.json
```

3. Configure qBittorrent completion command:

```bash
/opt/torrent-cats/run_torrent_cats.sh "%I"
```

## Configuration

Primary config file: `config.json`.

Options:
- `qbt_url`: WebUI API URL, such as `http://127.0.0.1:8080`
- `qbt_username`: WebUI username, optional if localhost auth bypass is enabled
- `qbt_password`: WebUI password
- `sorted_root` (string): absolute destination root path for category save paths.
- `ignore_categories` (array or comma string): root categories to skip.
- `ignore_tags` (array or comma string): torrent tags to skip (case-insensitive).
- `preserve_subcategories` (array, comma string, or `"*"`): Preserves the torrent's previous category. Default behavior preserves `FL`.
- `preserve_subcategory_match_anywhere` (boolean): when `true`, preserve matching works on any category segment and keeps only the first matching segment.
    - Example with `preserve_subcategories: ["Cat1"]` and category `Cat3/Cat1/Cat2`: result includes `.../Cat1/<Month-Year>`
- `month_format`: `M`, `MM`, `MMM`, or `MMMM` (e.g. February -> 2; 02; Feb; February)
- `year_format`: `YY` or `YYYY` (Last 2 digits or full year)
- `unmapped_category`: category code used when no tracker mapping matches (Default: UNMAPPED)
- `require_downloaded_session` (boolean): when true, only process torrents that downloaded data in the current session.
- `downloaded_session_min_bytes` (integer): minimum downloaded-session bytes required to process.
- `force_auto_tmm` (boolean): re-enable AutoTMM after category set?
- `dry_run` (boolean): Log intended output category and path without making any changes.
- `timeout_seconds`: HTTP timeout for API calls.
- `tracker_map` (object or list): tracker mapping rules.

`tracker_map` examples:

```json
{
  "bibliotik.me": "BIB",
  "*.t-ru.org": "RUTor"
}
```

```json
[
  { "pattern": "bibliotik.me", "code": "BIB" },
  { "pattern": "*.t-ru.org", "code": "RUTor" }
]
```

Config file selection order:

1. CLI argument: `torrent_cats.py <hash> [config_file]`
2. `./config.json` (same directory as script)

Recheck behavior:
- qBittorrent completion hooks can run after a recheck when a torrent transitions to complete.
- With `require_downloaded_session: true`, recheck-only completions with no new downloaded bytes are skipped.

## Containerized Deployment

- `qbt_url` must be reachable from the environment where the script runs.
- `sorted_root` must be valid from qBittorrent's filesystem view.
- If qBittorrent is containerized, use the path as mounted inside the qBittorrent container.

## Testing

1. Set `"dry_run": true` in config.
2. Complete a test torrent, or run manually:

```bash
/opt/torrent-cats/run_torrent_cats.sh "<INFO_HASH>"
```

3. Optional log capture in completion command:

```bash
/opt/torrent-cats/run_torrent_cats.sh "%I" >> /opt/torrent-cats/torrent_cats.log 2>&1
```

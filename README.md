# torrent-cats

Categorizes completed qBittorrent torrents into AutoTMM-safe categories:

`<TrackerCode>/<optional preserved subcategory>/<Month-Year>`

## What It Does

Input is a torrent hash (typically qBittorrent completion hook `%I`).
Accepted hash formats: 40-char (v1) or 64-char (v2) hexadecimal.

Flow:
1. Load config.
2. Fetch torrent + trackers.
3. Skip by `ignore_categories`, `ignore_tags`, or downloaded-session threshold.
4. Resolve tracker host with `tracker_map` (exact first, then longest suffix wildcard).
5. Build target category and save path.
6. Create missing category (without modifying existing category save paths).
7. Set torrent category and optionally re-enable AutoTMM.

`dry_run = true` prints computed output and performs no writes.

## Category Rules

Build target category from current category:
1. Split current category by `/`.
2. Remove leading segment if it already equals computed tracker code.
3. Remove trailing segment if it matches current month/year token format.
4. Apply subcategory preservation rules.
5. Prepend tracker code and append current month/year segment.

Preservation behavior:
- `preserve_subcategories = "*"` keeps all remaining segments.
- `preserve_subcategory_match_anywhere = false` keeps remaining segments only when first segment matches a preserved root.
- `preserve_subcategory_match_anywhere = true` keeps only the first matching segment anywhere.

Example (`month_format = "MMM"`, `year_format = "YY"`, current month = March 2026):
- Current category: `ATH/FL/Movies/Feb-26`
- Resolved tracker: `ATH`
- Settings: `preserve_subcategories = ["FL"]`, `preserve_subcategory_match_anywhere = false`
- Result category: `ATH/FL/Movies/Mar-26`

## Config

Preferred format is TOML so notes can live inline with the config file.

- Use `config.toml` (copy from `example.config.toml`)
- CLI override: `torrent_cats.py <hash> [config_file]`

Default lookup when no CLI config is provided:
1. `config.toml` beside script
2. If missing, run with defaults

## Key Settings

| Key | Default | Purpose |
|---|---|---|
| `qbt_url` | `http://127.0.0.1:8080` | qBittorrent WebUI base URL (`http`/`https`) |
| `qbt_username` / `qbt_password` | `""` / `""` | Set both or neither |
| `sorted_root` | `~/Downloads-Sorted` | Root path used for category save paths |
| `ignore_categories` | `""` | Skip when current root category matches |
| `ignore_tags` | `""` | Skip when torrent has matching tag |
| `preserve_subcategories` | `"FL"` | Preserved roots list, comma string, or `"*"` |
| `preserve_subcategory_match_anywhere` | `false` | Preserve first match anywhere (instead of first segment only) |
| `month_format` | `MMM` | `M`, `MM`, `MMM`, or `MMMM` |
| `year_format` | `YY` | `YY` or `YYYY` |
| `unmapped_category` | `UNMAPPED` | Fallback tracker code when no mapping matches |
| `require_downloaded_session` | `true` | Gate processing on session-downloaded bytes |
| `downloaded_session_min_bytes` | `1` | Minimum bytes when gate is enabled |
| `force_auto_tmm` | `true` | Re-enable AutoTMM after category update |
| `dry_run` | `false` | Compute/log only |
| `timeout_seconds` | `15` | qBittorrent API timeout (`> 0`) |
| `tracker_map` | `{}` | TOML table mapping host/wildcard (`*.example.org`) to tracker code |

Type parsing:
- Booleans also accept strings: `1,true,yes,on` and `0,false,no,off`.
- Integer settings also accept numeric strings.
- List settings accept arrays or comma-separated strings.

## Install

```bash
sudo mkdir -p /opt/torrent-cats
sudo cp torrent_cats.py run_torrent_cats.sh example.config.toml /opt/torrent-cats/
cd /opt/torrent-cats
sudo cp example.config.toml config.toml
sudo chmod +x run_torrent_cats.sh torrent_cats.py
```

Set qBittorrent completion command:

```bash
/opt/torrent-cats/run_torrent_cats.sh "%I"
```

## Quick Validation

1. Set `dry_run = true` in config.
2. Run with a known hash:

```bash
/opt/torrent-cats/run_torrent_cats.sh "<INFO_HASH>"
```

Optional completion-hook logging:

```bash
/opt/torrent-cats/run_torrent_cats.sh "%I" >> /opt/torrent-cats/torrent_cats.log 2>&1
```

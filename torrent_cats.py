#!/usr/bin/env python3
"""Categorize completed qBittorrent torrents by tracker and month."""

from __future__ import annotations

import datetime as dt
import http.cookiejar
import json
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

DEFAULT_CONFIG_FILE = "config.toml"
DEFAULT_SORTED_ROOT_DIRNAME = "Downloads-Sorted"
DEFAULT_IGNORE_CATEGORIES = ""
DEFAULT_IGNORE_TAGS = ""
DEFAULT_PRESERVE_SUBCATEGORIES = "FL"
DEFAULT_UNMAPPED_CATEGORY = "UNMAPPED"
DEFAULT_MONTH_FORMAT = "MMM"
DEFAULT_YEAR_FORMAT = "YY"
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_REQUIRE_DOWNLOADED_SESSION = True
DEFAULT_DOWNLOADED_SESSION_MIN_BYTES = 1
MONTH_NAMES_SHORT = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
MONTH_NAMES_LONG = (
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)
ALLOWED_MONTH_FORMATS = {"MM", "M", "MMM", "MMMM"}
ALLOWED_YEAR_FORMATS = {"YY", "YYYY"}
INFO_HASH_PATTERN = re.compile(r"^(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")


def load_config_file(path: Path) -> dict[str, Any]:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise RuntimeError(f"Unable to parse TOML config file {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Config file must contain an object at top-level: {path}")
    return payload


def parse_month_format(value: object, setting_name: str) -> str:
    if not isinstance(value, str):
        raise RuntimeError(f"Setting '{setting_name}' must be a string.")
    normalized = value.strip()
    if normalized not in ALLOWED_MONTH_FORMATS:
        allowed = ", ".join(sorted(ALLOWED_MONTH_FORMATS))
        raise RuntimeError(f"Setting '{setting_name}' must be one of: {allowed}.")
    return normalized


def parse_year_format(value: object, setting_name: str) -> str:
    if not isinstance(value, str):
        raise RuntimeError(f"Setting '{setting_name}' must be a string.")
    normalized = value.strip()
    if normalized not in ALLOWED_YEAR_FORMATS:
        allowed = ", ".join(sorted(ALLOWED_YEAR_FORMATS))
        raise RuntimeError(f"Setting '{setting_name}' must be one of: {allowed}.")
    return normalized


def format_month_year_segment(month_format: str, year_format: str, now: dt.datetime | None = None) -> str:
    current = now or dt.datetime.now()
    if month_format == "MM":
        month_part = f"{current.month:02d}"
    elif month_format == "M":
        month_part = str(current.month)
    elif month_format == "MMM":
        month_part = MONTH_NAMES_SHORT[current.month - 1]
    elif month_format == "MMMM":
        month_part = MONTH_NAMES_LONG[current.month - 1]
    else:
        raise RuntimeError(f"Unsupported month format: {month_format}")

    if year_format == "YY":
        year_part = f"{current.year % 100:02d}"
    elif year_format == "YYYY":
        year_part = f"{current.year:04d}"
    else:
        raise RuntimeError(f"Unsupported year format: {year_format}")

    return f"{month_part}-{year_part}"


def month_year_segment_pattern(month_format: str, year_format: str) -> re.Pattern[str]:
    if month_format == "MM":
        month_pattern = r"(0[1-9]|1[0-2])"
    elif month_format == "M":
        month_pattern = r"([1-9]|1[0-2])"
    elif month_format == "MMM":
        month_pattern = "(" + "|".join(MONTH_NAMES_SHORT) + ")"
    elif month_format == "MMMM":
        month_pattern = "(" + "|".join(MONTH_NAMES_LONG) + ")"
    else:
        raise RuntimeError(f"Unsupported month format: {month_format}")

    if year_format == "YY":
        year_pattern = r"\d{2}"
    elif year_format == "YYYY":
        year_pattern = r"\d{4}"
    else:
        raise RuntimeError(f"Unsupported year format: {year_format}")

    return re.compile(rf"^{month_pattern}-{year_pattern}$")


def parse_string_list(value: object, setting_name: str) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        parsed: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise RuntimeError(f"Setting '{setting_name}' list entries must be strings.")
            entry = item.strip()
            if entry:
                parsed.append(entry)
        return parsed
    raise RuntimeError(f"Setting '{setting_name}' must be a string or a list of strings.")


def parse_ignore_roots(value: object) -> set[str]:
    return {item.lower() for item in parse_string_list(value, "ignore_categories")}


def parse_ignore_tags(value: object) -> set[str]:
    return {item.lower() for item in parse_string_list(value, "ignore_tags")}


def parse_preserve_roots(value: object) -> tuple[bool, set[str]]:
    if isinstance(value, str):
        candidate = value.strip()
        if candidate == "*":
            return True, set()
        return False, {item.lower() for item in parse_string_list(candidate, "preserve_subcategories")}
    return False, {item.lower() for item in parse_string_list(value, "preserve_subcategories")}


def parse_bool(value: object, setting_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise RuntimeError(f"Setting '{setting_name}' must be a boolean.")


def parse_int(value: object, setting_name: str) -> int:
    if isinstance(value, bool):
        raise RuntimeError(f"Setting '{setting_name}' must be an integer.")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        normalized = value.strip()
        if normalized:
            try:
                return int(normalized)
            except ValueError as exc:
                raise RuntimeError(f"Setting '{setting_name}' must be an integer.") from exc
    raise RuntimeError(f"Setting '{setting_name}' must be an integer.")


def parse_non_negative_int(value: object, setting_name: str) -> int:
    parsed = parse_int(value, setting_name)
    if parsed < 0:
        raise RuntimeError(f"Setting '{setting_name}' must be >= 0.")
    return parsed


def read_string_setting(
    config: dict[str, Any],
    config_key: str,
    default: str,
) -> str:
    raw = config.get(config_key, default)
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise RuntimeError(f"Setting '{config_key}' must be a string.")
    return raw.strip()


def split_category(category: str) -> list[str]:
    return [segment for segment in category.split("/") if segment]


def should_ignore(category: str, ignore_roots: set[str]) -> bool:
    segments = split_category(category)
    return bool(segments) and segments[0].lower() in ignore_roots


def parse_torrent_tags(value: object) -> set[str]:
    if isinstance(value, str):
        return {tag.strip().lower() for tag in value.split(",") if tag.strip()}
    if isinstance(value, list):
        tags: set[str] = set()
        for item in value:
            if isinstance(item, str):
                normalized = item.strip().lower()
                if normalized:
                    tags.add(normalized)
        return tags
    return set()


def should_ignore_for_tags(torrent: dict[str, object], ignore_tags: set[str]) -> tuple[bool, set[str]]:
    if not ignore_tags:
        return False, set()
    torrent_tags = parse_torrent_tags(torrent.get("tags", ""))
    matched = torrent_tags.intersection(ignore_tags)
    return bool(matched), matched


def build_target_category(
    tracker_code: str,
    current_category: str,
    month_year: str,
    month_year_pattern: re.Pattern[str],
    preserve_all: bool,
    preserve_roots: set[str],
    preserve_match_anywhere: bool,
) -> str:
    preserved = split_category(current_category)
    if preserved and preserved[0] == tracker_code:
        preserved = preserved[1:]
    if preserved and month_year_pattern.fullmatch(preserved[-1]):
        preserved = preserved[:-1]
    if preserved and not preserve_all:
        if preserve_match_anywhere:
            matched_segment = next((segment for segment in preserved if segment.lower() in preserve_roots), "")
            preserved = [matched_segment] if matched_segment else []
        elif preserved[0].lower() not in preserve_roots:
            preserved = []
    parts = [tracker_code, *preserved, month_year]
    return "/".join(part for part in parts if part)


def build_save_path(root: Path, category: str) -> str:
    return str(root.joinpath(*split_category(category)))


def extract_tracker_host(url: str) -> str:
    candidate = url.strip()
    if not candidate or "://" not in candidate:
        return ""
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.hostname:
        return parsed.hostname.lower().rstrip(".")
    match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#]+)", candidate)
    if match:
        return match.group(1).lower().rstrip(".")
    return ""


def parse_tracker_map_payload(payload: object, source_name: str) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []

    if isinstance(payload, dict):
        iterator = payload.items()
    else:
        raise RuntimeError(f"{source_name} must be a TOML table/object.")

    for pattern, code in iterator:
        if not isinstance(pattern, str):
            raise RuntimeError(f"Invalid mapping key in {source_name}: keys must be strings.")
        if not isinstance(code, str):
            raise RuntimeError(f"Invalid mapping value for '{pattern}' in {source_name}: code must be a string.")

        norm_pattern = pattern.strip().lower().rstrip(".")
        norm_code = code.strip()
        if not norm_pattern or not norm_code:
            raise RuntimeError(
                f"Invalid mapping in {source_name}: pattern='{pattern}' code='{code}' must be non-empty."
            )
        entries.append((norm_pattern, norm_code))
    return entries


def build_tracker_rule_maps(entries: Iterable[tuple[str, str]]) -> tuple[dict[str, str], dict[str, str]]:
    exact_map: dict[str, str] = {}
    suffix_map: dict[str, str] = {}
    for pattern, code in entries:
        if pattern.startswith("*."):
            suffix_map[f".{pattern[2:].lstrip('.')}"] = code
        elif pattern.startswith("."):
            suffix_map[pattern] = code
        else:
            exact_map[pattern] = code
    return exact_map, suffix_map


def load_tracker_rule_maps(config: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    entries: list[tuple[str, str]] = []

    if "tracker_map" in config:
        entries.extend(parse_tracker_map_payload(config["tracker_map"], "tracker_map"))

    return build_tracker_rule_maps(entries)


def pick_tracker_code(
    trackers: Iterable[dict[str, object]],
    exact_map: dict[str, str],
    suffix_map: dict[str, str],
    unmapped_category: str,
) -> tuple[str, str]:
    ordered_suffixes = sorted(suffix_map.items(), key=lambda item: len(item[0]), reverse=True)
    for tracker in trackers:
        host = extract_tracker_host(str(tracker.get("url", "")))
        if not host:
            continue
        if host in exact_map:
            return exact_map[host], host
        for suffix, code in ordered_suffixes:
            if host == suffix.lstrip(".") or host.endswith(suffix):
                return code, host
    return unmapped_category, ""


class QBittorrentClient:
    def __init__(self, base_url: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        parsed = urllib.parse.urlsplit(self.base_url)
        self._origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def _request(self, method: str, endpoint: str, params: dict[str, str] | None = None) -> str:
        url = f"{self.base_url}{endpoint}"
        payload = None
        headers: dict[str, str] = {}
        if self._origin:
            # qBittorrent WebUI expects Referer or Origin matching the request host.
            headers["Origin"] = self._origin
            headers["Referer"] = self._origin
        if method == "GET":
            if params:
                url = f"{url}?{urllib.parse.urlencode(params)}"
        else:
            payload = urllib.parse.urlencode(params or {}).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        request = urllib.request.Request(url=url, data=payload, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                return response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {endpoint} failed ({exc.code}): {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Unable to connect to {self.base_url}: {exc.reason}") from exc

    def login(self, username: str, password: str) -> None:
        response = self._request(
            "POST",
            "/api/v2/auth/login",
            {"username": username, "password": password},
        ).strip()
        if response != "Ok.":
            raise RuntimeError(f"qBittorrent login failed: {response}")

    def get_torrent(self, torrent_hash: str) -> dict[str, object]:
        payload = self._request("GET", "/api/v2/torrents/info", {"hashes": torrent_hash})
        torrents = json.loads(payload)
        if not torrents:
            raise RuntimeError(f"Torrent not found for hash: {torrent_hash}")
        return torrents[0]

    def get_trackers(self, torrent_hash: str) -> list[dict[str, object]]:
        payload = self._request("GET", "/api/v2/torrents/trackers", {"hash": torrent_hash})
        return json.loads(payload)

    def get_properties(self, torrent_hash: str) -> dict[str, object]:
        payload = self._request("GET", "/api/v2/torrents/properties", {"hash": torrent_hash})
        return json.loads(payload)

    def get_categories(self) -> dict[str, dict[str, object]]:
        payload = self._request("GET", "/api/v2/torrents/categories")
        return json.loads(payload)

    def create_category(self, category: str, save_path: str) -> None:
        self._request(
            "POST",
            "/api/v2/torrents/createCategory",
            {"category": category, "savePath": save_path},
        )

    def set_category(self, torrent_hash: str, category: str) -> None:
        self._request(
            "POST",
            "/api/v2/torrents/setCategory",
            {"hashes": torrent_hash, "category": category},
        )

    def set_auto_management(self, torrent_hash: str, enabled: bool = True) -> None:
        self._request(
            "POST",
            "/api/v2/torrents/setAutoManagement",
            {"hashes": torrent_hash, "enable": "true" if enabled else "false"},
        )


def ensure_category_save_path(client: QBittorrentClient, category: str, save_path: str) -> None:
    categories = client.get_categories()
    existing = categories.get(category)
    if existing is None:
        client.create_category(category, save_path)
    # Existing category save paths are intentionally not modified.


def read_int_like(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        candidate = value.strip()
        if candidate:
            try:
                return int(candidate)
            except ValueError:
                return None
    return None


def resolve_downloaded_session_bytes(
    client: QBittorrentClient,
    torrent_hash: str,
    torrent_info: dict[str, object],
) -> int:
    properties = client.get_properties(torrent_hash)
    props_value = read_int_like(properties.get("total_downloaded_session"))
    if props_value is not None:
        return max(0, props_value)

    info_value = read_int_like(torrent_info.get("downloaded_session"))
    if info_value is not None:
        return max(0, info_value)

    return 0


def resolve_config_path(script_dir: Path, argv: list[str]) -> tuple[Path, bool]:
    arg_config = argv[2].strip() if len(argv) >= 3 else ""

    if arg_config:
        config_path = Path(arg_config)
        is_explicit = True
    else:
        config_path = script_dir / DEFAULT_CONFIG_FILE
        is_explicit = False

    if not config_path.is_absolute():
        config_path = script_dir / config_path
    return config_path, is_explicit


def validate_qbt_url(base_url: str) -> None:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("Setting 'qbt_url' must be an absolute URL such as http://127.0.0.1:8080.")


def validate_torrent_hash(torrent_hash: str) -> str:
    normalized = torrent_hash.strip().lower()
    if not INFO_HASH_PATTERN.fullmatch(normalized):
        raise RuntimeError("Torrent hash must be 40-char (v1) or 64-char (v2) hexadecimal.")
    return normalized


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("Usage: torrent_cats.py <torrent_hash> [config_file(.toml)]", file=sys.stderr)
        return 2

    script_dir = Path(__file__).resolve().parent
    config_path, explicit_config = resolve_config_path(script_dir, argv)
    if config_path.exists():
        config = load_config_file(config_path)
    elif explicit_config:
        raise RuntimeError(f"Config file not found: {config_path}")
    else:
        config = {}

    torrent_hash = validate_torrent_hash(argv[1])
    base_url = read_string_setting(config, "qbt_url", "http://127.0.0.1:8080").rstrip("/")
    username = read_string_setting(config, "qbt_username", "")
    password = read_string_setting(config, "qbt_password", "")
    sorted_root = Path(
        read_string_setting(
            config,
            "sorted_root",
            str(Path.home() / DEFAULT_SORTED_ROOT_DIRNAME),
        )
    )

    ignore_roots = parse_ignore_roots(config.get("ignore_categories", DEFAULT_IGNORE_CATEGORIES))
    ignore_tags = parse_ignore_tags(config.get("ignore_tags", DEFAULT_IGNORE_TAGS))
    preserve_all, preserve_roots = parse_preserve_roots(
        config.get("preserve_subcategories", DEFAULT_PRESERVE_SUBCATEGORIES)
    )
    preserve_match_anywhere = parse_bool(
        config.get("preserve_subcategory_match_anywhere", False),
        "preserve_subcategory_match_anywhere",
    )
    force_auto_tmm = parse_bool(config.get("force_auto_tmm", True), "force_auto_tmm")
    dry_run = parse_bool(config.get("dry_run", False), "dry_run")
    timeout_seconds = parse_int(config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS), "timeout_seconds")
    if timeout_seconds <= 0:
        raise RuntimeError("Setting 'timeout_seconds' must be > 0.")
    month_format = parse_month_format(config.get("month_format", DEFAULT_MONTH_FORMAT), "month_format")
    year_format = parse_year_format(config.get("year_format", DEFAULT_YEAR_FORMAT), "year_format")
    require_downloaded_session = parse_bool(
        config.get("require_downloaded_session", DEFAULT_REQUIRE_DOWNLOADED_SESSION),
        "require_downloaded_session",
    )
    downloaded_session_min_bytes = parse_non_negative_int(
        config.get("downloaded_session_min_bytes", DEFAULT_DOWNLOADED_SESSION_MIN_BYTES),
        "downloaded_session_min_bytes",
    )

    unmapped_category = read_string_setting(
        config,
        "unmapped_category",
        DEFAULT_UNMAPPED_CATEGORY,
    )
    if not unmapped_category:
        raise RuntimeError("unmapped_category must be a non-empty string.")

    month_year = format_month_year_segment(month_format, year_format)
    month_year_pattern = month_year_segment_pattern(month_format, year_format)

    exact_map, suffix_map = load_tracker_rule_maps(config)

    if not base_url:
        raise RuntimeError("qBittorrent URL is empty. Set qbt_url in config.")
    validate_qbt_url(base_url)
    if bool(username) ^ bool(password):
        raise RuntimeError("Set both username/password, or leave both unset.")

    client = QBittorrentClient(base_url=base_url, timeout_seconds=timeout_seconds)

    if username and password:
        client.login(username, password)

    torrent = client.get_torrent(torrent_hash)
    current_category = str(torrent.get("category", "") or "").strip()
    if should_ignore(current_category, ignore_roots):
        print(f"Skipped {torrent_hash}: category '{current_category}' is ignored.")
        return 0
    ignore_for_tags, matched_tags = should_ignore_for_tags(torrent, ignore_tags)
    if ignore_for_tags:
        matched_list = ", ".join(sorted(matched_tags))
        print(f"Skipped {torrent_hash}: matched ignore_tags [{matched_list}].")
        return 0

    downloaded_session_bytes = resolve_downloaded_session_bytes(client, torrent_hash, torrent)
    if require_downloaded_session and downloaded_session_bytes < downloaded_session_min_bytes:
        print(
            f"Skipped {torrent_hash}: downloaded_session={downloaded_session_bytes} bytes "
            f"(minimum {downloaded_session_min_bytes})."
        )
        return 0

    tracker_code, matched_host = pick_tracker_code(
        client.get_trackers(torrent_hash),
        exact_map,
        suffix_map,
        unmapped_category,
    )
    target_category = build_target_category(
        tracker_code,
        current_category,
        month_year,
        month_year_pattern,
        preserve_all,
        preserve_roots,
        preserve_match_anywhere,
    )
    target_path = build_save_path(sorted_root, target_category)

    if dry_run:
        print(
            "DRY RUN:",
            f"hash={torrent_hash}",
            f"tracker={matched_host or 'unknown'}",
            f"current_category={current_category or '(none)'}",
            f"downloaded_session={downloaded_session_bytes}",
            f"target_category={target_category}",
            f"target_path={target_path}",
            f"config={config_path}",
        )
        return 0

    ensure_category_save_path(client, target_category, target_path)
    client.set_category(torrent_hash, target_category)
    if force_auto_tmm:
        client.set_auto_management(torrent_hash, True)

    print(
        f"Updated {torrent_hash}: tracker={matched_host or 'unknown'} "
        f"category='{target_category}' savePath='{target_path}'"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except Exception as exc:
        print(f"torrent_cats.py error: {exc}", file=sys.stderr)
        raise SystemExit(1)

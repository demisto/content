import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

import json
import re
import time
from typing import Any
from urllib.parse import urlparse

import requests

# ============================================================
# SOCFWPackManager (bootloader)
# - list: shows SOC Framework pack catalog (paging/filtering)
# - apply: resolves pack_id via secops-framework pack_catalog.json
# - marketplace install: resolves the transitive mandatory-dependency set and
#   installs it via core-api-* against the platform marketplace endpoints
# - custom ZIP install: socfw-install-pack (SOCFWPackManager integration instance)
#   credentials stored masked in integration params
# - configure: integrations/jobs/lookups from xsoar_config.json (via core-api-*)
#
# FIXES INCLUDED:
# - Lookups: reliably CREATE dataset if missing (direct /public_api/v1/xql/add_dataset),
#           then POPULATE if empty (even when overwrite_lookup=false).
# - Lookups: add_data uses same request shape as LookupDatasetCreator.
# - Avoid /xsoar routes that 303 redirect in some tenants (prefer /public_api).
# - http_get_json supports JSON-stream / concatenated JSON objects
#           (prevents "Extra data: line 2 column 1 ...")
# - Dependencies: install custom pack dependencies from xsoar_config.json "custom_packs"
# - Polling: timeout fallback checks for REAL pack id (not zip filename)
# - Stream normalize: handles stream-returned list containing list-of-dicts
#
# FIX NOW (minimal change):
# - Jobs: DO NOT configure/create/update if job already exists (prevents duplicates on rerun)
# ============================================================

SCRIPT_NAME = "SOCFWPackManager"

# ---------------------------
# Basic helpers
# ---------------------------


def _norm(s: Any) -> str:
    return (str(s) if s is not None else "").strip()


def _to_lower(s: Any) -> str:
    return _norm(s).lower()


def _safe_sort_key(row: dict[str, Any], key: str) -> str:
    return _norm(row.get(key, "")).lower()


def _guess_pack_id_from_label(label: str) -> str:
    """Pack ID for a release asset filename or label.

    Convert:
      - soc-common-playbooks-unified.zip               -> soc-common-playbooks-unified
      - soc-common-playbooks-unified-v2.7.53.zip       -> soc-common-playbooks-unified
      - soc-common-playbooks-unified-v2.7.53           -> soc-common-playbooks-unified
      - soc-optimization-unified-v3.11.1-pr1008.zip    -> soc-optimization-unified
      - soc-common-playbooks-unified                   -> soc-common-playbooks-unified

    Must agree with pack_dir_name() in the integration: that decides the pack
    ID written to the tenant, and this decides the ID polled for afterwards.
    Only a trailing "-v<version>" is stripped, so a pack whose own name
    contains "-v" is left intact.
    """
    s = _norm(label)
    if not s:
        return s
    if s.lower().endswith(".zip"):
        s = s[:-4]
    return re.sub(r"-v\d+(?:\.\d+)*(?:-[A-Za-z0-9]+)?$", "", s).strip()


def _extract_custom_packs_from_xsoar_cfg(xsoar_cfg: dict[str, Any]) -> list[dict[str, str]]:
    """
    Returns a normalized list of custom packs to install from xsoar_config.json.
    Expected input key: custom_packs
    Each item: { "id": "...", "url": "...", "system": "yes" }
    Output: [{ "name": "<id>", "url": "<url>" }, ...]
    """
    packs = xsoar_cfg.get("custom_packs") or []
    out: list[dict[str, str]] = []

    if isinstance(packs, list):
        for p in packs:
            if not isinstance(p, dict):
                continue
            url = _norm(p.get("url"))
            pid = _norm(p.get("id") or p.get("name") or url)
            system = _norm(p.get("system") or "true")
            if url:
                out.append({"name": pid or url, "url": url, "system": system})
    return out


# ---------------------------
# Demisto helpers
# ---------------------------


def socfw_get_error(res):
    # Renamed from get_error to avoid shadowing CommonServerPython.get_error
    try:
        return res[0].get("Contents") or res[0].get("HumanReadable") or str(res[0])
    except Exception:
        return str(res)


def socfw_is_error(res0):
    # Renamed from is_error to avoid shadowing CommonServerPython.is_error
    try:
        return bool(res0.get("Type") == 4)  # entryTypes["error"] == 4
    except Exception:
        return False


def get_contents(res):
    if not res or not isinstance(res, list) or not res[0]:
        return {}
    return res[0].get("Contents") or {}


def arg_to_bool(val, default=False) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s == "":
        return default
    return s in ("true", "1", "yes", "y", "on")


def to_int(val, default: int) -> int:
    try:
        return int(val)
    except Exception:
        return default


def bool_str_tf(val: bool) -> str:
    return "true" if bool(val) else "false"


def is_timeout_error(err_text: str) -> bool:
    if not err_text:
        return False
    t = err_text.lower()
    return (
        "timeout" in t
        or "timed out" in t
        or "read timed out" in t
        or "request timed out" in t
        or "context deadline exceeded" in t
        or "client.timeout exceeded" in t
        or "awaiting headers" in t
        or "context deadline exceeded (client.timeout exceeded while awaiting headers)" in t
    )


def emit_progress(message: str, stage: str | None = None):
    title = f"{SCRIPT_NAME} — {stage}" if stage else SCRIPT_NAME
    return_results(
        {
            "Type": 1,
            "ContentsFormat": "markdown",
            "Contents": message,
            "HumanReadable": f"### {title}\n{message}",
        }
    )


def log(message: str, stage: str | None, debug: bool, always: bool = False):
    if always or debug:
        emit_progress(message, stage=stage)


def exec_cmd(command: str, args: dict[str, Any], fail_on_error: bool = True):
    res = demisto.executeCommand(command, args)
    if not res:
        if fail_on_error:
            raise Exception(f"{command} returned empty response")
        return res
    if socfw_is_error(res[0]):
        if fail_on_error:
            raise Exception(socfw_get_error(res))
        return res
    return res


def exec_with_retry(
    command: str,
    args: dict[str, Any],
    retry_count: int,
    retry_sleep_seconds: int,
    context_for_error: str,
    fail_on_error: bool = True,
):
    last_err = None
    for attempt in range(1, max(1, retry_count) + 1):
        try:
            return exec_cmd(command, args, fail_on_error=fail_on_error)
        except Exception as e:
            last_err = str(e)
            if attempt >= retry_count:
                break
            # Backoff via platform Sleep script — no time.sleep in pack code.
            demisto.executeCommand("Sleep", {"seconds": str(max(1, retry_sleep_seconds))})
            continue
    if fail_on_error:
        raise Exception(f"{context_for_error}\nError: {last_err}")
    return None


def is_instance_already_exists_error(err_text: str) -> bool:
    if not err_text:
        return False
    return "already exists (33)" in err_text.lower()


# ---------------------------
# Pre/Post docs helpers (LOUD + optional content)
# ---------------------------


def _md_link(name: str, url: str) -> str:
    n = (name or "").strip() or url
    u = (url or "").strip()
    if not u:
        return f"- {n}"
    return f"- [{n}]({u})"


def _github_blob_to_raw(url: str) -> str:
    """
    Convert a github.com /blob/ URL to its raw.githubusercontent.com equivalent.
    Pass-through for already-raw URLs and anything we don't recognize.

    Hostname comparison is exact (not substring) to prevent URLs like
    https://attacker.com/?x=raw.githubusercontent.com from masquerading as
    trusted GitHub URLs.
    """
    u = (url or "").strip()
    if not u:
        return u
    try:
        parsed = urlparse(u)
    except ValueError:
        return u
    if parsed.scheme not in ("http", "https"):
        return u
    host = (parsed.hostname or "").lower()
    # Already a raw GitHub URL — pass through unchanged
    if host == "raw.githubusercontent.com":
        return u
    # Convert https://github.com/<org>/<repo>/blob/<branch>/<path...> to raw URL
    if host == "github.com":
        parts = (parsed.path or "").lstrip("/").split("/")
        if len(parts) >= 5 and parts[2] == "blob":
            org = parts[0]
            repo = parts[1]
            branch = parts[3]
            path = "/".join(parts[4:])
            return f"https://raw.githubusercontent.com/{org}/{repo}/{branch}/{path}"
    return u


def _fetch_text(url: str, timeout: int = 20) -> str:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text or ""


def _truncate_text(s: str, max_chars: int, max_lines: int) -> str:
    if not s:
        return ""
    lines = s.splitlines()
    if max_lines and len(lines) > max_lines:
        lines = lines[:max_lines]
        s = "\n".join(lines) + "\n\n... (truncated by max_lines) ..."
    if max_chars and len(s) > max_chars:
        s = s[:max_chars] + "\n\n... (truncated by max_chars) ..."
    return s


def has_config_docs(xsoar_cfg: dict[str, Any], when: str) -> bool:
    key = "pre_config_docs" if when == "pre" else "post_config_docs"
    docs = xsoar_cfg.get(key) or []
    if not isinstance(docs, list):
        return False
    for d in docs:
        if isinstance(d, dict) and _norm(d.get("url") or d.get("name")):
            return True
        if isinstance(d, str) and _norm(d):
            return True
    return False


def print_config_docs(
    xsoar_cfg: dict[str, Any],
    when: str,
    debug: bool,
    include_doc_content: bool = False,
    doc_content_max_chars: int = 6000,
    doc_content_max_lines: int = 200,
):
    key = "pre_config_docs" if when == "pre" else "post_config_docs"
    docs = xsoar_cfg.get(key) or []
    if not isinstance(docs, list) or not docs:
        log(f"No {key} found in xsoar_config.json.", stage=f"docs.{when}", debug=debug)
        return

    banner_title = (
        " 🚧 PRE-INSTALL / PRE-CONFIG REQUIRED STEPS" if when == "pre" else "✅ POST-INSTALL / POST-CONFIG MANUAL STEPS"
    )
    banner_sub = (
        "_These docs usually contain prerequisites / manual steps you must complete BEFORE install._"
        if when == "pre"
        else "_These docs usually contain manual follow-ups and validation steps AFTER completion._"
    )

    banner = "\n".join(["---", f"## {banner_title}", banner_sub, "---"])

    link_lines: list[str] = []
    normalized_docs: list[dict[str, str]] = []
    for d in docs:
        if isinstance(d, dict):
            name = _norm(d.get("name") or "")
            url = _norm(d.get("url") or "")
            if url or name:
                link_lines.append(_md_link(name, url))
                normalized_docs.append({"name": name or url, "url": url})
        elif isinstance(d, str):
            s = _norm(d)
            if s:
                link_lines.append(f"- {s}")
                normalized_docs.append({"name": s, "url": s})

    if not link_lines:
        log(f"No valid entries in {key}.", stage=f"docs.{when}", debug=debug)
        return

    want_content = bool(include_doc_content or debug)
    body: list[str] = [banner, "### Links", *link_lines]

    if want_content and normalized_docs:
        body += ["", "### Doc contents (preview)", " _Showing a truncated preview._", ""]

        for d in normalized_docs:
            name = d.get("name") or ""
            url = d.get("url") or ""
            raw_url = _github_blob_to_raw(url)
            try:
                text = _fetch_text(raw_url, timeout=20)
                text = _truncate_text(text, max_chars=doc_content_max_chars, max_lines=doc_content_max_lines)

                body.append(
                    "\n".join(
                        [
                            "<details>",
                            f"<summary><b>{name}</b> (click to expand)</summary>",
                            "",
                            "```markdown",
                            text,
                            "```",
                            "",
                            f"_Source: {raw_url}_",
                            "</details>",
                            "",
                        ]
                    )
                )
            except Exception as e:
                body.append(f"- **{name}**: could not fetch preview ({e})")

    emit_progress("\n".join(body), stage=f"docs.{when}")


# ---------------------------
# Core API wrappers
# ---------------------------


def core_api_get(path: str, using: str = "", execution_timeout: int = 600) -> dict[str, Any]:
    args = {"uri": path, "execution-timeout": str(execution_timeout)}
    if using:
        args["using"] = using
    res = exec_cmd("core-api-get", args)
    return get_contents(res) or {}


def core_api_post(path: str, body: Any, using: str = "", execution_timeout: int = 600) -> dict[str, Any]:
    args = {"uri": path, "body": json.dumps(body if body is not None else {}), "execution-timeout": str(execution_timeout)}
    if using:
        args["using"] = using
    res = exec_cmd("core-api-post", args)
    return get_contents(res) or {}


def core_api_put(path: str, body: Any, using: str = "", execution_timeout: int = 600) -> dict[str, Any]:
    args = {"uri": path, "body": json.dumps(body if body is not None else {}), "execution-timeout": str(execution_timeout)}
    if using:
        args["using"] = using
    res = exec_cmd("core-api-put", args)
    return get_contents(res) or {}


# ---------------------------
# HTTP JSON helpers
# ---------------------------


def _parse_json_stream(raw: str) -> Any:
    """
    Parse a string that may contain:
      - one JSON document (object/array)
      - NDJSON/JSONL (one JSON value per line)
      - concatenated JSON values (e.g. {}{} or {}\n{} with extra whitespace)
    Returns:
      - single parsed value if exactly one JSON value
      - list of parsed values if multiple JSON values are present
    """
    raw = (raw or "").strip()
    if not raw:
        return []

    dec = json.JSONDecoder()
    idx = 0
    n = len(raw)
    values: list[Any] = []

    while idx < n:
        while idx < n and raw[idx].isspace():
            idx += 1
        if idx >= n:
            break
        val, end = dec.raw_decode(raw, idx)
        values.append(val)
        idx = end

    if len(values) == 1:
        return values[0]
    return values


def http_get_text(url: str, timeout: int = 30) -> str:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text or ""


def http_get_json(url: str, timeout: int = 30) -> Any:
    """
    Supports:
      - standard JSON (object/array)
      - NDJSON / JSONL
      - concatenated JSON stream (prevents 'Extra data' errors)
    """
    raw = http_get_text(url, timeout=timeout).strip()
    if not raw:
        return []
    try:
        return json.loads(raw)
    except Exception:
        return _parse_json_stream(raw)


# ---------------------------
# Catalog + Manifest resolver
# ---------------------------

DEFAULT_CATALOG_URL = "https://raw.githubusercontent.com/Palo-Cortex/secops-framework/refs/heads/main/pack_catalog.json"


def fetch_pack_catalog(catalog_url: str = DEFAULT_CATALOG_URL) -> dict[str, Any]:
    data = http_get_json(catalog_url)
    if not isinstance(data, dict):
        raise Exception(f"pack_catalog.json unexpected format at {catalog_url}")
    return data


def find_pack_in_catalog(catalog: dict[str, Any], pack_id: str) -> dict[str, Any] | None:
    packs = catalog.get("packs") or catalog.get("Packs") or catalog.get("items") or []
    if not isinstance(packs, list):
        return None
    for p in packs:
        if isinstance(p, dict) and (p.get("id") == pack_id):
            return p
    return None


def resolve_manifest(pack_id: str, include_hidden: bool, catalog_url: str) -> dict[str, Any]:
    if pack_id.startswith(("http://", "https://")):
        return http_get_json(pack_id)

    catalog = fetch_pack_catalog(catalog_url)
    pack = find_pack_in_catalog(catalog, pack_id)
    if not pack:
        raise Exception(f"Pack '{pack_id}' not found in pack_catalog.json")

    visible = bool(pack.get("visible", True))
    if (not include_hidden) and (not visible):
        raise Exception(
            f"Pack '{pack_id}' is marked visible=false in the catalog. " f"Re-run with include_hidden=true to install it anyway."
        )

    version = (pack.get("version") or "").strip()
    if not version:
        raise Exception(f"Pack '{pack_id}' missing version in pack_catalog.json")

    xsoar_config_url = (
        f"https://raw.githubusercontent.com/Palo-Cortex/secops-framework/refs/heads/main/Packs/{pack_id}/xsoar_config.json"
    )
    release_tag = f"{pack_id}-v{version}"
    zip_url = f"https://github.com/Palo-Cortex/secops-framework/releases/download/{release_tag}/{release_tag}.zip"

    marketplace_packs = [
        {"id": "Base", "version": "latest"},
        {"id": "CommonScripts", "version": "latest"},
        {"id": "CommonPlaybooks", "version": "latest"},
        {"id": "DemistoRESTAPI", "version": "latest"},
        {"id": "Whois", "version": "latest"},
    ]

    return {
        "marketplace_packs": marketplace_packs,
        "custom_zip_urls": [{"url": zip_url, "name": release_tag}],
        "xsoar_config_url": xsoar_config_url,
        "pack_catalog_entry": pack,
        "pack_version": version,
    }


# ---------------------------
# list action (filter + paging)
# ---------------------------


DEFAULT_DOCS_BASE_URL = "https://palo-cortex.github.io/secops-framework"


def _pack_docs_url(pack: dict[str, Any], docs_base_url: str) -> str:
    """Absolute URL to a pack's documentation.

    Prefers an explicit `docs` URL from the catalog entry; otherwise derives one
    from `docs_path` against the docs site. Must be absolute -- a relative href
    is resolved against the tenant host and lands the analyst back in XSIAM.
    """
    explicit = _norm(pack.get("docs"))
    if explicit.startswith(("http://", "https://")):
        return explicit

    base = (docs_base_url or "").rstrip("/")
    if not base:
        return ""
    docs_path = explicit or _norm(pack.get("docs_path")) or ""
    slug = docs_path.rstrip("/").split("/")[-1] if docs_path else _norm(pack.get("id"))
    if not slug:
        return ""
    return f"{base}/{slug}/overview/"


def do_list(args: dict[str, Any]):
    using = _norm(args.get("using") or "")
    include_hidden = arg_to_bool(args.get("include_hidden"), False)

    text_filter = _to_lower(args.get("filter") or args.get("q") or "")
    visible_only_raw = arg_to_bool(args.get("visible_only"), True)
    visible_only = bool(visible_only_raw) and (not include_hidden)

    limit = max(1, to_int(args.get("limit"), 50))
    offset = max(0, to_int(args.get("offset"), 0))
    sort_by = (_norm(args.get("sort_by")) or "id").strip()
    sort_dir = (_norm(args.get("sort_dir")) or "asc").strip().lower()
    fields = argToList(args.get("fields")) or ["id", "version", "installed", "status", "docs"]
    show_total = arg_to_bool(args.get("show_total"), True)
    group_by_category = arg_to_bool(args.get("group_by_category"), True)
    output_format = (_norm(args.get("output_format")) or "list").strip().lower()
    debug = arg_to_bool(args.get("debug"), False)

    catalog_url = _norm(args.get("catalog_url") or DEFAULT_CATALOG_URL)
    # An explicitly empty docs_base_url disables linking, so distinguish it
    # from the argument being absent.
    docs_base_arg = args.get("docs_base_url")
    docs_base_url = _norm(DEFAULT_DOCS_BASE_URL if docs_base_arg is None else docs_base_arg)

    emit_progress("Fetching catalog…", stage="list")

    catalog = fetch_pack_catalog(catalog_url)
    packs = catalog.get("packs") or catalog.get("Packs") or catalog.get("items") or []
    if not isinstance(packs, list):
        raise Exception("pack_catalog.json is missing 'packs' list")

    # An empty map means the lookup failed rather than a tenant with no packs,
    # so report unknown instead of claiming everything is missing.
    installed = fetch_installed_packs(using)
    installed_known = bool(installed)

    rows: list[dict[str, Any]] = []
    for p in packs:
        if not isinstance(p, dict):
            continue

        visible = bool(p.get("visible", True))

        if (not include_hidden) and (not visible):
            continue
        if visible_only and (not visible):
            continue

        pack_id = p.get("id", "")
        catalog_version = p.get("version", "")
        installed_version = (installed.get(pack_id) or {}).get("version") or ""

        if not installed_known:
            status = "unknown"
        elif not installed_version:
            status = "not installed"
        elif _ver_key(catalog_version) > _ver_key(installed_version):
            status = "update available"
        elif _ver_key(catalog_version) < _ver_key(installed_version):
            status = "ahead of catalog"
        else:
            status = "up to date"

        row = {
            "id": pack_id,
            "display_name": p.get("display_name") or p.get("name") or "",
            "category": p.get("category") or "Uncategorized",
            "version": catalog_version,
            "installed": installed_version or "-",
            "status": status,
            "docs": _pack_docs_url(p, docs_base_url),
            "visible": str(visible).lower(),
            "path": p.get("path") or f"Packs/{pack_id}",
        }

        if text_filter:
            hay = " ".join([_to_lower(row.get("id")), _to_lower(row.get("display_name")), _to_lower(row.get("path"))])
            if text_filter not in hay:
                continue

        rows.append(row)

    total = len(rows)

    allowed_sort = {"id", "display_name", "category", "version", "installed", "status", "visible", "path"}
    if sort_by not in allowed_sort:
        sort_by = "id"
    reverse = sort_dir == "desc"
    rows.sort(key=lambda r: _safe_sort_key(r, sort_by), reverse=reverse)
    if group_by_category:
        rows.sort(key=lambda r: _to_lower(r.get("category")))

    page = rows[offset : offset + limit]
    start = offset + 1 if page else 0
    end = offset + len(page)

    allowed_fields = ["id", "display_name", "category", "version", "installed", "status", "docs", "visible", "path"]
    fields = [f for f in fields if f in allowed_fields] or ["id", "version", "installed", "status", "docs"]

    def cell(row: dict[str, Any], col: str) -> str:
        value = _norm(row.get(col, ""))
        # The docs link is its own column rather than wrapping the id, which
        # has to stay plain text so it can be copied into pack_id=.
        if col == "docs":
            return f"[docs]({value})" if value else ""
        if col == "display_name" and len(value) > 46:
            value = value[:45].rstrip() + "…"
        return value

    def render_lines(subset: list[dict[str, Any]]) -> str:
        """One line per pack.

        Deliberately not a markdown list: a bold category heading placed
        directly after a list item is absorbed into that list as a lazy
        continuation, which indents every heading after the first. Separating
        them with blank lines instead would push the entry past the war room's
        line cap. Tables are avoided for the same reason, plus a single-row
        table gets transposed into a vertical key/value block.
        """
        out = []
        for r in subset:
            status = r["status"]
            if status == "not installed":
                detail = f"not installed · {r['version']} available"
            elif status == "update available":
                detail = f"{r['installed']} → {r['version']} · update available"
            elif status == "ahead of catalog":
                detail = f"{r['installed']} · ahead of catalog ({r['version']})"
            elif status == "unknown":
                detail = f"{r['version']} · install state unknown"
            else:
                detail = f"{r['version']} · up to date"
            # Pack id stays unlinked so it can be copied into pack_id=.
            line = f"{r['id']} — {detail}"
            if r.get("docs"):
                line += f" · [docs]({r['docs']})"
            out.append(line)
        return "\n".join(out)

    def render_table(subset: list[dict[str, Any]], cols: list[str]) -> str:
        out = "| " + " | ".join(cols) + " |\n"
        out += "| " + " | ".join(["---"] * len(cols)) + " |\n"
        for r in subset:
            out += "| " + " | ".join([cell(r, c) for c in cols]) + " |\n"
        return out

    # The war room truncates an entry past roughly 25-30 rendered lines, so the
    # header is one line and the diagnostics only appear when asked for.
    headline = f"{total} pack(s)"
    if installed_known:
        counts: dict[str, int] = {}
        for r in rows:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        if counts:
            headline += " · " + " · ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    else:
        headline += " · install state unknown"
    if show_total and (offset or end < total):
        headline += f" · showing {start}-{end}"

    summary_lines = [headline]
    if debug:
        summary_lines += [
            f"using: {(using or '(default)')}",
            f"catalog_url: {catalog_url}",
            f"docs_base_url: {docs_base_url or '(disabled)'}",
            f"include_hidden: {include_hidden}, visible_only: {visible_only}",
            f"sort: {sort_by} {sort_dir}, limit: {limit}, offset: {offset}",
        ]
    if text_filter:
        summary_lines.append(f"filter: `{text_filter}`")

    if output_format == "table":
        if group_by_category:
            cols = [f for f in fields if f != "category"]
            sections = []
            for category in sorted({r["category"] for r in page}, key=lambda c: c.lower()):
                subset = [r for r in page if r["category"] == category]
                sections.append(f"**{category}**\n\n" + render_table(subset, cols))
            body = "\n".join(sections)
        else:
            body = render_table(page, fields)
    elif group_by_category:
        sections = []
        for category in sorted({r["category"] for r in page}, key=lambda c: c.lower()):
            subset = [r for r in page if r["category"] == category]
            sections.append(f"**{category}**\n" + render_lines(subset))
        body = "\n".join(sections)
    else:
        body = render_lines(page)

    emit_progress("\n".join(summary_lines) + "\n\n" + body, stage="list")


# ---------------------------
# Marketplace install
# ---------------------------


MARKETPLACE_API_ROOT = "/contentpacks"
MAX_DEPENDENCY_ROUNDS = 8


CORE_REST_API_BRANDS = ("Core REST API", "DemistoRESTAPI", "Demisto REST API")


def find_core_rest_api_instances() -> list[dict[str, str]]:
    """Enabled Core REST API instances, read from the module list.

    Uses demisto.getModules() rather than an API call, so it still answers when
    the Core REST API instance is the thing that is missing.
    """
    try:
        modules = demisto.getModules() or {}
    except Exception as e:
        demisto.debug(f"getModules unavailable: {e}")
        return []
    found = []
    for name, meta in modules.items():
        if not isinstance(meta, dict):
            continue
        if (meta.get("brand") or "") in CORE_REST_API_BRANDS:
            found.append({"name": name, "brand": meta.get("brand", ""), "state": meta.get("state", "")})
    return found


def _core_rest_api_hint() -> str:
    """Points at the missing instance when one is the likely cause."""
    if find_core_rest_api_instances():
        return "A Core REST API instance is configured, so this is a route or payload problem."
    return (
        "No Core REST API instance is configured on this tenant — that is almost certainly "
        "the cause. It is this pack's only external dependency."
    )


class DependencyLookupError(Exception):
    """Raised when the marketplace dependency endpoint is unusable.

    Distinct from a generic failure because the install endpoint requires a
    complete dependency closure -- without this lookup any install request is
    guaranteed to be rejected, and the rejection names the install endpoint
    rather than the real cause.
    """


def _ver_key(value: Any) -> tuple:
    """Comparable key for an X.Y.Z pack version; non-numeric parts sort as 0."""
    parts = []
    for chunk in str(value or "").split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def fetch_installed_packs(using: str) -> dict[str, dict[str, Any]]:
    """Installed pack id -> {version, update_available}."""
    out: dict[str, dict[str, Any]] = {}
    try:
        res = core_api_get(f"{MARKETPLACE_API_ROOT}/metadata/installed", using=using)
    except Exception as e:
        # Degrading quietly here makes every pack look uninstalled, so say so.
        emit_progress(
            "\n".join(
                [
                    "⚠️ Could not read installed packs.",
                    f"- endpoint: `GET {MARKETPLACE_API_ROOT}/metadata/installed`",
                    f"- error: {e}",
                    "Install state and version comparisons below are unreliable.",
                ]
            ),
            stage="packs.marketplace.warning",
        )
        return out
    packs = (res.get("response") or []) if isinstance(res, dict) else []
    for pack in packs:
        pid = pack.get("id")
        if pid:
            out[pid] = {
                "version": pack.get("currentVersion") or "",
                "update_available": bool(pack.get("updateAvailable")),
            }
    return out


def fetch_installed_marketplace_pack_ids(using: str) -> list[str]:
    return sorted(fetch_installed_packs(using).keys())


def resolve_latest_version(pack_id: str, using: str) -> str:
    """Latest published version of a pack.

    The marketplace metadata response embeds the pack's entire content listing
    and can run to tens of megabytes, so callers should fall back to the
    installed version wherever that is acceptable.
    """
    res = core_api_get(f"{MARKETPLACE_API_ROOT}/marketplace/{pack_id}", using=using)
    body = (res.get("response") or {}) if isinstance(res, dict) else {}
    version = body.get("currentVersion")
    if not version:
        raise Exception(
            f"Could not resolve the latest version of '{pack_id}' from the marketplace. "
            f"Check that the Core REST API instance is configured and the pack exists."
        )
    return version


def fetch_mandatory_dependencies(packs: list[dict[str, str]], using: str) -> dict[str, dict[str, str]]:
    """Direct mandatory dependencies per pack, as {pack_id: {dep_id: min_version}}.

    The body must be a bare JSON array; this endpoint rejects an object wrapper,
    unlike the install endpoint which requires one.
    """
    out: dict[str, dict[str, str]] = {}
    try:
        res = core_api_post(f"{MARKETPLACE_API_ROOT}/marketplace/search/dependencies", body=packs, using=using)
    except Exception as e:
        # A quiet failure here collapses the closure to just the requested
        # packs, and the install endpoint then rejects it for missing
        # dependencies -- which points at the wrong endpoint entirely.
        emit_progress(
            "\n".join(
                [
                    "⚠️ Dependency lookup failed — the install set will be incomplete.",
                    f"- endpoint: `POST {MARKETPLACE_API_ROOT}/marketplace/search/dependencies`",
                    f"- requested: {', '.join(p.get('id', '?') for p in packs)}",
                    f"- error: {e}",
                    "If the install below reports missing dependencies, this is the cause,",
                    "not the install endpoint.",
                    _core_rest_api_hint(),
                ]
            ),
            stage="packs.marketplace.warning",
        )
        raise DependencyLookupError(str(e)) from e
    body = (res.get("response") or {}) if isinstance(res, dict) else {}
    for entry in body.get("packs") or []:
        deps = ((entry.get("extras") or {}).get("pack") or {}).get("dependencies") or {}
        out[entry.get("id")] = {
            dep_id: (meta.get("minVersion") or "1.0.0") for dep_id, meta in deps.items() if meta.get("mandatory")
        }
    return out


def resolve_install_closure(
    seed_packs: list[dict[str, str]],
    using: str,
    installed: dict[str, dict[str, Any]],
    upgrade: bool = False,
) -> dict[str, str]:
    """Expand the requested packs into their full transitive mandatory set.

    The install endpoint validates the request as a self-contained graph: every
    pack listed must also list its mandatory dependencies, whether or not those
    are already on the tenant. A partial set is rejected outright, so the whole
    closure has to be resolved before installing anything.

    A requested version of "latest" means "ensure present" by default, so an
    installed pack keeps the version it has. With upgrade=True it instead means
    "bring to the newest published version", which is what actually moves a
    pack forward. Dependencies are never force-upgraded either way -- they only
    move when a mandatory minVersion demands it.
    """
    wanted: dict[str, str] = {}
    frontier: list[dict[str, str]] = []

    for pack in seed_packs:
        pid = pack.get("id")
        if not pid:
            continue
        version = _norm(pack.get("version"))
        if version in ("", "latest", "*"):
            current = installed.get(pid, {}).get("version") or ""
            # The marketplace lookup returns the pack's whole content listing
            # and can be tens of megabytes, so only pay for it when the answer
            # can actually differ from what is already on the tenant.
            needs_lookup = not current or (upgrade and installed.get(pid, {}).get("update_available"))
            version = resolve_latest_version(pid, using) if needs_lookup else current
        wanted[pid] = version
        frontier.append({"id": pid, "version": version})

    # Highest minVersion demanded for each dependency so far. Several packs
    # commonly require the same dependency at different minimums -- Base and
    # CommonScripts may want Core >= 3.5.75 while CommonPlaybooks only wants
    # 3.5.73 -- and the install is rejected unless the highest one is used.
    # Taking the first value seen silently loses the stricter requirement.
    required_min: dict[str, str] = {}
    for _ in range(MAX_DEPENDENCY_ROUNDS):
        if not frontier:
            break
        deps_by_pack = fetch_mandatory_dependencies(frontier, using)
        frontier = []
        for mandatory in deps_by_pack.values():
            for dep_id, min_version in mandatory.items():
                prior = required_min.get(dep_id)
                if prior is not None and _ver_key(prior) >= _ver_key(min_version):
                    continue
                required_min[dep_id] = min_version
                current = installed.get(dep_id, {}).get("version") or ""
                version = current if _ver_key(current) >= _ver_key(min_version) else min_version
                if wanted.get(dep_id) == version:
                    continue
                wanted[dep_id] = version
                # Re-queued because raising a version can change what that
                # version itself depends on.
                frontier.append({"id": dep_id, "version": version})

    return wanted


def _marketplace_context_rows(
    requested_ids: set,
    installed_now: dict[str, str],
    already_present: dict[str, str],
    failed: dict[str, str],
) -> list[dict[str, str]]:
    """Rows for the ConfigurationSetup.MarketplacePacks context key.

    Field names and status strings intentionally match what
    XSIAMContentPackInstaller produced, so existing consumers of this key --
    notably the PoV Companion -- keep working unchanged.
    """
    rows = []
    for pack_id, version in sorted(installed_now.items()):
        rows.append(
            {
                "packid": pack_id,
                "packversion": str(version),
                "installationstatus": "Success." if pack_id in requested_ids else "Installed as requirement.",
            }
        )
    for pack_id in sorted(requested_ids):
        if pack_id in already_present:
            rows.append(
                {
                    "packid": pack_id,
                    "packversion": str(already_present[pack_id]),
                    "installationstatus": "Already Installed on the machine.",
                }
            )
        if pack_id in failed:
            rows.append(
                {
                    "packid": pack_id,
                    "packversion": str(failed[pack_id]),
                    "installationstatus": "Failed to install.",
                }
            )
    return rows


def _emit_marketplace_context(rows: list[dict[str, str]]) -> None:
    return_results(
        CommandResults(
            outputs_prefix="ConfigurationSetup.MarketplacePacks",
            outputs_key_field="packid",
            outputs=rows,
        )
    )


def install_marketplace_packs(
    marketplace_packs: list[dict[str, str]],
    using: str,
    retry_count: int,
    retry_sleep_seconds: int,
    debug: bool,
    upgrade: bool = False,
) -> dict[str, Any]:
    requested_ids = {p.get("id") for p in marketplace_packs if p.get("id")}
    installed = fetch_installed_packs(using)
    try:
        closure = resolve_install_closure(marketplace_packs, using, installed, upgrade=upgrade)
    except DependencyLookupError as e:
        # Sending a knowingly-incomplete set produces a "missing dependencies"
        # rejection that blames the install endpoint. Stop here instead.
        failed = {pid: "" for pid in requested_ids}
        _emit_marketplace_context(_marketplace_context_rows(requested_ids, {}, {}, failed))
        raise Exception(
            "Cannot resolve the marketplace dependency set, so the install was not attempted. "
            "The install endpoint requires every mandatory dependency in one request and would "
            f"reject an incomplete set. Underlying error: {e}"
        ) from e

    pending = {pid: ver for pid, ver in closure.items() if _ver_key(ver) > _ver_key(installed.get(pid, {}).get("version"))}

    if debug:
        emit_progress(
            "\n".join(
                ["Marketplace install plan:"]
                + [f'- {pid} @ {ver}{"" if pid in pending else "  (already satisfied)"}' for pid, ver in sorted(closure.items())]
            ),
            stage="packs.marketplace",
        )

    if not pending:
        emit_progress(
            f"Marketplace packs already satisfied ({len(closure)} in dependency set); nothing to install.",
            stage="packs.marketplace",
        )
        _emit_marketplace_context(_marketplace_context_rows(requested_ids, {}, closure, {}))
        return {"installed": {}, "already_present": closure, "dependency_set": closure}

    emit_progress(
        f"Installing marketplace packs… ({len(pending)} to change, {len(closure)} in dependency set)",
        stage="packs.marketplace",
    )

    payload = [{"id": pid, "version": ver} for pid, ver in sorted(closure.items())]
    try:
        exec_with_retry(
            "core-api-post",
            {
                "uri": f"{MARKETPLACE_API_ROOT}/marketplace/install",
                # ignoreWarnings is required on any tenant that already has
                # content: an upgrade that re-declares an existing incident
                # field is otherwise rejected outright ("Field with name X
                # already exists", possibleResolutions skip/replace). Without
                # it a single pre-existing field fails the whole install.
                "body": json.dumps({"packs": payload, "ignoreWarnings": True}),
                "execution-timeout": "600",
            },
            retry_count=retry_count,
            retry_sleep_seconds=retry_sleep_seconds,
            context_for_error="Failed installing marketplace packs",
            fail_on_error=True,
        )
    except Exception:
        failed = {pid: closure[pid] for pid in requested_ids if pid in closure}
        _emit_marketplace_context(_marketplace_context_rows(requested_ids, {}, {}, failed))
        raise

    already = {k: v for k, v in closure.items() if k not in pending}
    _emit_marketplace_context(_marketplace_context_rows(requested_ids, pending, already, {}))

    emit_progress(
        "Marketplace packs installed: " + ", ".join(f"{k}@{v}" for k, v in sorted(pending.items())),
        stage="packs.marketplace.result",
    )
    return {"installed": pending, "already_present": already, "dependency_set": closure}


# ---------------------------
# xsoar_config
# ---------------------------


def fetch_xsoar_config(xsoar_config_url: str) -> dict[str, Any]:
    data = http_get_json(xsoar_config_url)
    if not isinstance(data, dict):
        raise Exception(f"xsoar_config.json unexpected format at {xsoar_config_url}")
    return data


# ---------------------------
# Custom packs install (with timeout -> polling fallback)
# ---------------------------


def wait_for_pack_installed(
    pack_id: str,
    using: str,
    poll_seconds: int,
    poll_interval_seconds: int,
    debug: bool,
) -> bool:
    deadline = time.time() + max(0, poll_seconds)
    interval = max(5, poll_interval_seconds)

    log(
        f"Polling for pack install completion: **{pack_id}** (up to {poll_seconds}s, every {interval}s)…",
        stage="packs.custom.poll",
        debug=debug,
        always=True,
    )

    while True:
        try:
            installed = fetch_installed_marketplace_pack_ids(using)
            if pack_id in installed:
                log(f"Pack **{pack_id}** is now installed.", stage="packs.custom.poll", debug=debug, always=True)
                return True
        except Exception as e:
            log(f" Poll check error (will retry): {e}", stage="packs.custom.poll.debug", debug=debug)

        if time.time() >= deadline:
            log(
                f"Polling window expired; pack **{pack_id}** not detected as installed yet.",
                stage="packs.custom.poll",
                debug=debug,
                always=True,
            )
            return False

        # Backoff via platform Sleep script — no time.sleep in pack code.
        demisto.executeCommand("Sleep", {"seconds": str(interval)})


def install_custom_pack_zip(
    url: str,
    asset_filename: str,
    using: str,
    retry_count: int,
    retry_sleep_seconds: int,
    debug: bool,
    poll_seconds: int = 0,
    poll_interval_seconds: int = 60,
):
    """
    Install a custom pack ZIP via the SOCFWPackManager integration instance.

    The integration holds XSIAM credentials (masked) and uploads the pack as
    system content via demisto-sdk upload_content_entity.

    Integration instance name defaults to "SOCFWPackManager".
    The using arg overrides this if multiple instances exist.
    """
    if debug:
        emit_progress(
            "\n".join(
                [
                    "install_custom_pack_zip (socfw-install-pack):",
                    f"- url:      {url}",
                    f"- filename: {asset_filename}",
                ]
            ),
            stage="packs.custom.debug",
        )

    # Do not pass 'using' — let XSIAM route to whichever instance supports
    # socfw-install-pack. Hardcoding the instance name breaks when XSIAM
    # appends "_instance_1" or similar to the default instance name.
    args = {
        "url": url,
        "filename": asset_filename,
    }

    try:
        exec_with_retry(
            "socfw-install-pack",
            args,
            retry_count=retry_count,
            retry_sleep_seconds=retry_sleep_seconds,
            context_for_error=f"Failed installing {asset_filename}",
            fail_on_error=True,
        )
    except Exception:
        # The system content-bundle endpoint returns 500 on some tenants even
        # when the bundle was accepted, so an error here is inconclusive.
        # Confirm against the installed-pack list before reporting a failure.
        pack_id = _guess_pack_id_from_label(asset_filename)
        if poll_seconds <= 0 or not pack_id:
            raise
        emit_progress(
            f"Install of **{asset_filename}** reported an error; verifying against installed packs.",
            stage="packs.custom.verify",
        )
        if not wait_for_pack_installed(pack_id, using, poll_seconds, poll_interval_seconds, debug):
            raise

    emit_progress(
        f"Pack **{asset_filename}** installed.",
        stage="packs.custom.result",
    )


def configure_integrations_from_xsoar_config(
    xsoar_cfg: dict[str, Any],
    using: str,
    retry_count: int,
    retry_sleep_seconds: int,
    installed_pack_ids: list[str],
    debug: bool,
) -> dict[str, Any]:
    items = [x for x in (xsoar_cfg.get("integration_instances", []) or []) if isinstance(x, dict)]
    emit_progress(f"Configuring integration instances… ({len(items)} instance(s))", stage="configure.integrations")

    summary = {
        "attempted": 0,
        "ok": 0,
        "already_exists": 0,
        "skipped_missing_pack": 0,
        "skipped_missing_brand": 0,
        "failed": 0,
        "failed_items": [],
    }

    for inst in items:
        instance_name = (inst.get("name") or "").strip()
        if not instance_name:
            continue

        required_pack = (inst.get("required_pack_id") or inst.get("marketplace_pack") or inst.get("pack_id") or "").strip()
        if required_pack and required_pack not in installed_pack_ids:
            summary["skipped_missing_pack"] += 1  # type: ignore[operator]
            log(
                f"Skipping integration instance **{instance_name}** — marketplace pack **{required_pack}** not installed.",
                stage="configure.integrations.debug",
                debug=debug,
            )
            continue

        brand = (inst.get("brand") or "").strip()
        if not brand:
            summary["skipped_missing_brand"] += 1  # type: ignore[operator]
            log(
                f"Skipping integration instance **{instance_name}** — missing required field `brand`.",
                stage="configure.integrations.debug",
                debug=debug,
            )
            continue

        summary["attempted"] += 1  # type: ignore[operator]

        payload = {
            "name": instance_name,
            "brand": brand,
            "enabled": inst.get("enabled", "true"),
            "category": inst.get("category") or "",
            "data": inst.get("data") or [],
        }

        log(
            f"Creating/updating integration instance: **{instance_name}** (brand: **{brand}**)",
            stage="configure.integrations.debug",
            debug=debug,
        )

        def _do_put(_payload=payload):
            return core_api_put(
                "/xsoar/public/v1/settings/integration",
                _payload,
                using=using,
                execution_timeout=600,
            )

        last_err = None
        for attempt in range(1, max(1, retry_count) + 1):
            try:
                resp = _do_put()
                rid = (resp.get("id") if isinstance(resp, dict) else None) or ""
                summary["ok"] += 1  # type: ignore[operator]
                log(
                    f"Integration instance **{instance_name}** created/updated. id={rid or '(unknown)'}",
                    stage="configure.integrations.result",
                    debug=debug,
                )
                break
            except Exception as e:
                last_err = str(e)

                if is_instance_already_exists_error(last_err):
                    summary["already_exists"] += 1  # type: ignore[operator]
                    log(
                        f"Integration instance **{instance_name}** already exists — skipping (idempotent).",
                        stage="configure.integrations.result",
                        debug=debug,
                    )
                    break

                if attempt >= retry_count:
                    summary["failed"] += 1  # type: ignore[operator]
                    summary["failed_items"].append({"name": instance_name, "error": last_err})  # type: ignore[attr-defined]
                    emit_progress(
                        f"Failed configuring integration instance **{instance_name}**.\nError: {last_err}",
                        stage="configure.integrations.error",
                    )
                    break

                # Backoff via platform Sleep script — no time.sleep in pack code.
                demisto.executeCommand("Sleep", {"seconds": str(max(1, retry_sleep_seconds))})

    emit_progress(
        "\n".join(
            [
                "Integration instances summary:",
                f"- attempted: {summary['attempted']}",
                f"- ok: {summary['ok']}",
                f"- already exists: {summary['already_exists']}",
                f"- skipped (missing pack): {summary['skipped_missing_pack']}",
                f"- skipped (missing brand): {summary['skipped_missing_brand']}",
                f"- failed: {summary['failed']}",
                "",
                "_Note: UI/index propagation can take a few minutes after instance create/update._",
            ]
        ),
        stage="configure.integrations.summary",
    )

    return summary


# ---------------------------
# Lookup dataset population (FIXED + aligned to LookupDatasetCreator)
# ---------------------------


def _is_dataset_not_found_error(err_text: str, dataset_name: str) -> bool:
    t = (err_text or "").lower()
    dn = (dataset_name or "").lower()
    return (
        ("dataset" in t and "not found" in t and dn in t)
        or (f"dataset {dn} not found" in t)
        or (f"dataset '{dn}' not found" in t)
        or (f'dataset "{dn}" not found' in t)
    )


def _xql_get_datasets(using: str, debug: bool) -> list[dict[str, Any]]:
    try:
        resp = core_api_post("/public_api/v1/xql/get_datasets", body={}, using=using, execution_timeout=600) or {}
        if isinstance(resp, dict):
            if isinstance(resp.get("reply"), list):
                return [x for x in resp.get("reply") if isinstance(x, dict)]  # type: ignore[union-attr]
            r = resp.get("response") or {}
            if isinstance(r, dict) and isinstance(r.get("reply"), list):
                return [x for x in r.get("reply") if isinstance(x, dict)]  # type: ignore[union-attr]
        return []
    except Exception as e:
        if debug:
            emit_progress(f"get_datasets failed: {e}", stage="configure.lookups.debug")
        return []


def _dataset_exists(dataset_name: str, using: str, debug: bool) -> bool:
    want = _norm(dataset_name).lower()
    for d in _xql_get_datasets(using=using, debug=debug):
        n = _norm(d.get("Dataset Name") or d.get("dataset_name") or d.get("name"))
        if n and n.lower() == want:
            return True
    return False


def _wait_for_dataset(dataset_name: str, using: str, debug: bool, wait_seconds: int = 90, interval_seconds: int = 3) -> bool:
    deadline = time.time() + max(1, wait_seconds)
    while time.time() < deadline:
        if _dataset_exists(dataset_name, using=using, debug=debug):
            return True
        # Backoff via platform Sleep script — no time.sleep in pack code.
        demisto.executeCommand("Sleep", {"seconds": str(max(1, interval_seconds))})
    return False


def _xql_call_first_working(paths: list[str], body: dict[str, Any], using: str, debug: bool) -> dict[str, Any]:
    last_err = None
    for p in paths:
        try:
            return core_api_post(p, body=body, using=using, execution_timeout=600) or {}
        except Exception as e:
            last_err = str(e)
            if debug:
                emit_progress(f"Lookup API probe failed on {p}: {e}", stage="configure.lookups.debug")
    raise Exception(f"Lookup API call failed on all known endpoints. Last error: {last_err}")


def _xql_lookup_get_total_count(dataset_name: str, using: str, debug: bool) -> int | None:
    body = {"request_data": {"dataset_name": dataset_name, "filters": [], "limit": 1}}
    try:
        resp = _xql_call_first_working(
            paths=["/public_api/v1/xql/lookups/get_data"],
            body=body,
            using=using,
            debug=debug,
        )
    except Exception as e:
        if _is_dataset_not_found_error(str(e), dataset_name):
            return None
        raise

    reply = resp.get("reply") if isinstance(resp, dict) else None
    if isinstance(reply, dict):
        tc = reply.get("total_count")
        try:
            return int(tc)  # type: ignore[arg-type]
        except Exception:
            return 0

    tc = resp.get("total_count") if isinstance(resp, dict) else None
    try:
        return int(tc)  # type: ignore[arg-type]
    except Exception:
        return 0


def _normalize_lookup_rows(source_obj: Any) -> list[dict[str, Any]]:
    """
    Accept:
      - [ {row}, {row} ]
      - { "data": [ {row}, ... ] }
      - { "<anything>": [ {row}, ... ] } (first list-of-dict value wins)
      - stream list containing a list-of-dicts somewhere: [ {...meta...}, [ {row}, ... ] ]
    """
    if isinstance(source_obj, list):
        if source_obj and all(isinstance(x, dict) for x in source_obj):
            return [r for r in source_obj if isinstance(r, dict)]
        for v in source_obj:
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                return v
        return [r for r in source_obj if isinstance(r, dict)]

    if isinstance(source_obj, dict):
        if isinstance(source_obj.get("data"), list):
            return [r for r in source_obj.get("data") if isinstance(r, dict)]  # type: ignore[union-attr]
        for _k, v in source_obj.items():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                return v

    return []


def _remove_omitted_fields(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    omitted = ["_collector_name", "_collector_type", "_insert_time", "_update_time"]
    for r in rows:
        for f in omitted:
            r.pop(f, None)
    return rows


def _xql_lookup_add_data_list(dataset_name: str, rows: list[dict[str, Any]], using: str, debug: bool):
    if not rows:
        raise Exception("No rows to upload")
    body = {"request_data": {"dataset_name": dataset_name, "data": rows}}
    _ = _xql_call_first_working(
        paths=["/public_api/v1/xql/lookups/add_data"],
        body=body,
        using=using,
        debug=debug,
    )


def _xql_create_dataset_direct(ds: dict[str, Any], using: str, debug: bool):
    dataset_name = _norm(ds.get("dataset_name") or ds.get("name"))
    if not dataset_name:
        raise Exception("Lookup dataset definition missing 'dataset_name'/'name'")

    dataset_type = ds.get("dataset_type") or "lookup"
    dataset_schema = ds.get("dataset_schema") or {}

    body = {
        "request_data": {
            "dataset_name": dataset_name,
            "dataset_type": dataset_type,
            "dataset_schema": dataset_schema,
        }
    }

    _ = core_api_post("/public_api/v1/xql/add_dataset", body=body, using=using, execution_timeout=600)


def configure_lookups_from_xsoar_config(
    xsoar_cfg: dict[str, Any],
    using: str,
    retry_count: int,
    retry_sleep_seconds: int,
    overwrite_lookup: bool,
    debug: bool,
) -> dict[str, Any]:
    dsets = [x for x in (xsoar_cfg.get("lookup_datasets", []) or []) if isinstance(x, dict)]
    emit_progress(f"Configuring lookup datasets… ({len(dsets)} dataset(s))", stage="configure.lookups")

    summary = {"attempted": 0, "ok": 0, "failed": 0, "failed_items": []}

    for ds in dsets:
        name = (ds.get("name") or ds.get("dataset_name") or "").strip()
        if not name:
            continue

        summary["attempted"] += 1  # type: ignore[operator]
        log(f"Configuring lookup dataset: **{name}**", stage="configure.lookups.debug", debug=debug)

        # Ensure dataset exists
        exists = _wait_for_dataset(name, using=using, debug=debug, wait_seconds=45, interval_seconds=3)
        if not exists:
            emit_progress(
                f"Dataset **{name}** not visible via get_datasets. Creating directly via /public_api/v1/xql/add_dataset…",
                stage="configure.lookups.create",
            )
            try:
                _xql_create_dataset_direct(ds, using=using, debug=debug)
            except Exception as e:
                summary["failed"] += 1  # type: ignore[operator]
                summary["failed_items"].append(  # type: ignore[attr-defined]
                    {"name": name, "error": f"Direct create failed: {e}"}
                )
                emit_progress(f"Failed creating lookup dataset **{name}**.\nError: {e}", stage="configure.lookups.error")
                continue

            exists = _wait_for_dataset(name, using=using, debug=debug, wait_seconds=90, interval_seconds=3)

        if not exists:
            summary["failed"] += 1  # type: ignore[operator]
            summary["failed_items"].append(  # type: ignore[attr-defined]
                {
                    "name": name,
                    "error": f"Dataset '{name}' not found via get_datasets after direct create.",
                }
            )
            emit_progress(
                f"Failed configuring lookup dataset **{name}**.\n"
                f"Error: Dataset '{name}' not found via get_datasets after direct create.",
                stage="configure.lookups.error",
            )
            continue

        # Decide whether to populate
        try:
            before_count = _xql_lookup_get_total_count(name, using=using, debug=debug)
        except Exception as e:
            summary["failed"] += 1  # type: ignore[operator]
            summary["failed_items"].append({"name": name, "error": str(e)})  # type: ignore[attr-defined]
            emit_progress(f"Failed reading lookup count for **{name}**.\nError: {e}", stage="configure.lookups.error")
            continue

        if before_count is not None and before_count > 0 and (not overwrite_lookup):
            summary["ok"] += 1  # type: ignore[operator]
            emit_progress(
                f"Lookup **{name}** already has data (total_count={before_count}). "
                f"Not modifying it unless `overwrite_lookup=true`.",
                stage="configure.lookups.result",
            )
            continue

        should_populate = overwrite_lookup or (before_count is None) or (before_count == 0)
        if not should_populate:
            summary["ok"] += 1  # type: ignore[operator]
            emit_progress(f"Lookup **{name}** is present; no population needed.", stage="configure.lookups.result")
            continue

        # Populate
        try:
            url = _norm(ds.get("url"))
            if not url:
                raise Exception("Dataset needs population but `url` is missing in xsoar_config.json")

            emit_progress(
                "\n".join(
                    [
                        f"Populating lookup **{name}** from URL:",
                        f"- {url}",
                        f"- overwrite_lookup={overwrite_lookup}",
                        f"- total_count(before)={before_count if before_count is not None else '(not readable yet)'}",
                    ]
                ),
                stage="configure.lookups.load",
            )

            source_obj = http_get_json(url)
            rows = _normalize_lookup_rows(source_obj)
            rows = _remove_omitted_fields(rows)

            if not rows:
                raise Exception(f"Downloaded JSON but found 0 usable rows. url={url}")

            _xql_lookup_add_data_list(dataset_name=name, rows=rows, using=using, debug=debug)

            # Brief settle before count check — via platform Sleep script.
            demisto.executeCommand("Sleep", {"seconds": "2"})

            after_count = None
            try:
                after_count = _xql_lookup_get_total_count(name, using=using, debug=debug)
            except Exception:
                after_count = None

            emit_progress(
                f"Lookup **{name}** population complete."
                + (f" total_count(after)={after_count}" if after_count is not None else " (count not yet readable)"),
                stage="configure.lookups.result",
            )

            summary["ok"] += 1  # type: ignore[operator]

        except Exception as e:
            summary["failed"] += 1  # type: ignore[operator]
            summary["failed_items"].append({"name": name, "error": str(e)})  # type: ignore[attr-defined]
            emit_progress(f"Failed populating lookup dataset **{name}**.\nError: {e}", stage="configure.lookups.error")

    emit_progress(
        "\n".join(
            [
                "Lookups summary:",
                f"- attempted: {summary['attempted']}",
                f"- ok: {summary['ok']}",
                f"- failed: {summary['failed']}",
            ]
        ),
        stage="configure.lookups.summary",
    )
    return summary


# ---------------------------
# Jobs verification + upsert
# ---------------------------


def _extract_list(resp: Any) -> list[dict[str, Any]]:
    if isinstance(resp, dict):
        v = resp.get("response")
        if isinstance(v, dict):
            data = v.get("data")
            if isinstance(data, list):
                return [x for x in data if isinstance(x, dict)]
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
        for k in ("data", "jobs", "result"):
            vv = resp.get(k)
            if isinstance(vv, list):
                return [x for x in vv if isinstance(x, dict)]
    if isinstance(resp, list):
        return [x for x in resp if isinstance(x, dict)]
    return []


def _job_name(job_obj: dict[str, Any]) -> str:
    return _norm(job_obj.get("name") or job_obj.get("jobName") or job_obj.get("job_name") or job_obj.get("displayName") or "")


def _job_id(job_obj: dict[str, Any]) -> str:
    return _norm(job_obj.get("id") or job_obj.get("_id") or job_obj.get("jobId") or "")


def jobs_api_endpoints() -> dict[str, str]:
    return {
        "search_xsoar": "/xsoar/public/v1/jobs/search",
        "search_public": "/public/v1/jobs/search",
        "create_xsoar": "/xsoar/public/v1/jobs",
        "create_public": "/public/v1/jobs",
        "update_xsoar": "/xsoar/public/v1/jobs",
        "update_public": "/public/v1/jobs",
    }


def jobs_api_search_probe(using: str) -> str | None:
    eps = jobs_api_endpoints()
    probe_body = {"page": 0, "size": 1, "query": "", "sort": [{"field": "id", "asc": True}]}
    for p in (eps["search_xsoar"], eps["search_public"]):
        try:
            _ = core_api_post(p, body=probe_body, using=using, execution_timeout=600)
            return p
        except Exception:
            continue
    return None


def jobs_api_find_by_name(name: str, using: str, search_path: str | None, debug: bool) -> dict[str, Any] | None:
    n = _norm(name).lower()

    if search_path:
        try:
            body = {"page": 0, "size": 50, "query": f'name:"{name}"', "sort": [{"field": "id", "asc": True}]}
            resp = core_api_post(search_path, body=body, using=using, execution_timeout=600)
            rows = _extract_list(resp)
            for r in rows:
                if _job_name(r).lower() == n:
                    return r
        except Exception as e:
            if debug:
                emit_progress(f"Job search failed on {search_path}: {e}", stage="configure.jobs.debug")

    if search_path:
        try:
            body = {"page": 0, "size": 200, "query": "", "sort": [{"field": "id", "asc": True}]}
            resp = core_api_post(search_path, body=body, using=using, execution_timeout=600)
            rows = _extract_list(resp)
            for r in rows:
                if _job_name(r).lower() == n:
                    return r
        except Exception:
            pass

    return None


def jobs_api_upsert(job: dict[str, Any], using: str, search_path: str, debug: bool) -> dict[str, Any]:
    eps = jobs_api_endpoints()
    name = _job_name(job)
    if not name:
        raise Exception("Job object missing name")

    existing = jobs_api_find_by_name(name, using=using, search_path=search_path, debug=debug)
    existing_id = _job_id(existing) if existing else ""

    create_paths = [eps["create_xsoar"], eps["create_public"]]
    update_paths = [eps["update_xsoar"], eps["update_public"]]

    if existing_id:
        last_err = None
        for base in update_paths:
            try:
                resp = core_api_put(f"{base}/{existing_id}", body=job, using=using, execution_timeout=600)
                return {"action": "updated", "endpoint": f"{base}/{existing_id}", "response": resp, "job_id": existing_id}
            except Exception as e:
                last_err = str(e)
                continue

        for base in create_paths:
            try:
                resp = core_api_post(base, body=job, using=using, execution_timeout=600)
                return {
                    "action": "created_via_post_fallback",
                    "endpoint": base,
                    "response": resp,
                    "job_id": existing_id,
                    "warning": last_err,
                }
            except Exception as e:
                last_err = str(e)
                continue

        raise Exception(f"Failed updating job '{name}'. Last error: {last_err}")

    last_err = None
    for base in create_paths:
        try:
            resp = core_api_post(base, body=job, using=using, execution_timeout=600)
            return {"action": "created", "endpoint": base, "response": resp}
        except Exception as e:
            last_err = str(e)
            continue

    raise Exception(f"Failed creating job '{name}'. Last error: {last_err}")


def configure_jobs_from_xsoar_config(
    xsoar_cfg: dict[str, Any],
    using: str,
    retry_count: int,
    retry_sleep_seconds: int,
    debug: bool,
) -> dict[str, Any]:
    jobs = [x for x in (xsoar_cfg.get("jobs", []) or []) if isinstance(x, dict)]
    emit_progress(f"Configuring jobs… ({len(jobs)} job(s))", stage="configure.jobs")

    summary = {
        "attempted": 0,
        "ok": 0,
        "failed": 0,
        "failed_items": [],
        "notes": [],
    }

    search_path = jobs_api_search_probe(using=using)
    if not search_path:
        emit_progress(
            "\n".join(
                [
                    "❌ Jobs API is not reachable (permissions/endpoint).",
                    "This script will NOT claim jobs were configured if it cannot verify them.",
                    "Fix permissions/role or confirm the correct jobs endpoint, then rerun.",
                ]
            ),
            stage="configure.jobs.error",
        )
        summary["notes"].append("jobs_api_unreachable=true")  # type: ignore[attr-defined]

    for job in jobs:
        name = _norm(job.get("name") or job.get("job_name") or "")
        if not name:
            continue

        summary["attempted"] += 1  # type: ignore[operator]
        log(f"Configuring job: **{name}**", stage="configure.jobs.debug", debug=debug)

        if not search_path:
            summary["failed"] += 1  # type: ignore[operator]
            summary["failed_items"].append(  # type: ignore[attr-defined]
                {"name": name, "error": "Jobs API verification unavailable; cannot confirm job creation/update."}
            )
            continue

        # ✅ FIX: If the job already exists, do nothing (prevents duplicates on rerun).
        existing = None
        for _i in range(1, 6):  # small settle loop for index propagation
            existing = jobs_api_find_by_name(name, using=using, search_path=search_path, debug=debug)
            if existing:
                break
            # Backoff via platform Sleep script — no time.sleep in pack code.
            demisto.executeCommand("Sleep", {"seconds": "1"})

        if existing:
            summary["ok"] += 1  # type: ignore[operator]
            log(f"⏭️ Job **{name}** already exists — skipping.", stage="configure.jobs.result", debug=debug, always=True)
            continue

        try:
            _ = jobs_api_upsert(job, using=using, search_path=search_path, debug=debug)

            verified = None
            for _i in range(1, 8):
                verified = jobs_api_find_by_name(name, using=using, search_path=search_path, debug=debug)
                if verified:
                    break
                # Backoff via platform Sleep script — no time.sleep in pack code.
                demisto.executeCommand("Sleep", {"seconds": "2"})

            if not verified:
                raise Exception("Upsert ran but job still not visible via Jobs API.")

            summary["ok"] += 1  # type: ignore[operator]
            log(f"✅ Job **{name}** created and verified.", stage="configure.jobs.result", debug=debug, always=True)

        except Exception as e:
            summary["failed"] += 1  # type: ignore[operator]
            summary["failed_items"].append({"name": name, "error": str(e)})  # type: ignore[attr-defined]
            emit_progress(f"Failed configuring job **{name}**.\nError: {e}", stage="configure.jobs.error")

    emit_progress(
        "\n".join(
            [
                "Jobs summary:",
                f"- attempted: {summary['attempted']}",
                f"- ok (verified/skip): {summary['ok']}",
                f"- failed: {summary['failed']}",
                f"- notes: {', '.join(summary['notes']) if summary['notes'] else '(none)'}",  # type: ignore[arg-type]
            ]
        ),
        stage="configure.jobs.summary",
    )
    return summary


# ---------------------------
# Main
# ---------------------------


# ─────────────────────────────────────────
# action=configure — config only, no install
# ─────────────────────────────────────────


def do_configure(args):
    pack_id = (args.get("pack_id") or "").strip()
    catalog_url = _norm(args.get("catalog_url") or DEFAULT_CATALOG_URL)
    using = (args.get("using") or "").strip()
    retry_count = to_int(args.get("retry_count"), 5)
    retry_sleep = to_int(args.get("retry_sleep_seconds"), 15)
    overwrite = arg_to_bool(args.get("overwrite_lookup"), False)
    cfg_jobs = arg_to_bool(args.get("configure_jobs"), True)
    cfg_integrations = arg_to_bool(args.get("configure_integrations"), True)
    cfg_lookups = arg_to_bool(args.get("configure_lookups"), True)
    debug = arg_to_bool(args.get("debug"), False)
    include_doc_content = arg_to_bool(args.get("include_doc_content"), False)
    doc_content_max_chars = to_int(args.get("doc_content_max_chars"), 6000)
    doc_content_max_lines = to_int(args.get("doc_content_max_lines"), 200)

    if not pack_id:
        raise Exception("pack_id is required for action=configure")

    catalog = fetch_pack_catalog(catalog_url)
    pack = find_pack_in_catalog(catalog, pack_id)

    xsoar_config_url = (
        (pack.get("xsoar_config") or pack.get("xsoar_config_url") or "")
        if pack
        else f"https://raw.githubusercontent.com/Palo-Cortex/secops-framework/refs/heads/main/Packs/{pack_id}/xsoar_config.json"
    )

    emit_progress(
        "\n".join(
            [
                f"action=configure for **{pack_id}**",
                f"- xsoar_config_url: {xsoar_config_url}",
                f"- jobs={cfg_jobs}, integrations={cfg_integrations}, lookups={cfg_lookups}",
                f"- overwrite_lookup={overwrite}",
            ]
        ),
        stage="configure.start",
    )

    xsoar_cfg = fetch_xsoar_config(xsoar_config_url) or {}

    emit_progress(
        "\n".join(
            [
                "xsoar_config loaded.",
                f"- integration_instances: {len(xsoar_cfg.get('integration_instances', []) or [])}",
                f"- jobs:                  {len(xsoar_cfg.get('jobs', []) or [])}",
                f"- lookup_datasets:       {len(xsoar_cfg.get('lookup_datasets', []) or [])}",
            ]
        ),
        stage="configure.summary",
    )

    installed_pack_ids = fetch_installed_marketplace_pack_ids(using)

    if cfg_integrations:
        configure_integrations_from_xsoar_config(
            xsoar_cfg=xsoar_cfg,
            using=using,
            retry_count=retry_count,
            retry_sleep_seconds=retry_sleep,
            installed_pack_ids=installed_pack_ids,
            debug=debug,
        )
    if cfg_jobs:
        configure_jobs_from_xsoar_config(
            xsoar_cfg=xsoar_cfg,
            using=using,
            retry_count=retry_count,
            retry_sleep_seconds=retry_sleep,
            debug=debug,
        )
    if cfg_lookups:
        configure_lookups_from_xsoar_config(
            xsoar_cfg=xsoar_cfg,
            using=using,
            retry_count=retry_count,
            retry_sleep_seconds=retry_sleep,
            overwrite_lookup=overwrite,
            debug=debug,
        )

    emit_progress("Configuration complete.", stage="configure.done")
    print_config_docs(
        xsoar_cfg,
        when="post",
        debug=debug,
        include_doc_content=include_doc_content,
        doc_content_max_chars=doc_content_max_chars,
        doc_content_max_lines=doc_content_max_lines,
    )


# ─────────────────────────────────────────
# action=sync-tags — update value_tags lookup
# ─────────────────────────────────────────

VALUE_TAGS_URL = (
    "https://raw.githubusercontent.com/Palo-Cortex/secops-framework"
    "/refs/heads/main/Packs/soc-optimization-unified/Lookup/value_tags.json"
)
VALUE_TAGS_DATASET = "value_tags"


def _compute_hash(obj):
    import hashlib

    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hashlib.md5(canonical.encode()).hexdigest()  # guardrails-disable-line # nosec


VALUE_TAGS_LIST_NAME = "SOCFWTagsVersion"


def _get_current_meta(using, debug):
    """
    Read version metadata from the SOCFWTagsVersion XSIAM List.
    Lists are the reliable way to persist small state across script runs —
    lookup dataset schemas don't accommodate arbitrary extra fields.
    Returns None if the list doesn't exist or has never been written.
    """
    try:
        res = exec_cmd("getList", {"listName": VALUE_TAGS_LIST_NAME}, fail_on_error=False)
        if not res or socfw_is_error(res[0]):
            return None
        contents = get_contents(res)
        if not contents:
            return None
        # contents may be the raw string or a dict depending on list format
        raw = contents if isinstance(contents, str) else json.dumps(contents)
        if not raw or raw.strip() == "":
            return None
        return json.loads(raw)
    except Exception:
        return None


def _set_current_meta(meta: dict[str, Any], using: str, debug: bool):
    """
    Write version metadata to the SOCFWTagsVersion XSIAM List.
    Creates the list if it doesn't exist, updates it if it does.
    """
    payload = json.dumps(meta)
    # Try setList first (update); fall back to createList if it doesn't exist
    res = exec_cmd("setList", {"listName": VALUE_TAGS_LIST_NAME, "listData": payload}, fail_on_error=False)
    if res and socfw_is_error(res[0]):
        # List may not exist yet — create it
        exec_cmd(
            "createList",
            {"listName": VALUE_TAGS_LIST_NAME, "listData": payload},
            fail_on_error=True,
        )


def do_sync_tags(args):
    using = (args.get("using") or "").strip()
    force = arg_to_bool(args.get("force"), False)
    tags_url = _norm(args.get("tags_url") or VALUE_TAGS_URL)
    debug = arg_to_bool(args.get("debug"), False)

    emit_progress(
        "\n".join(
            [
                "action=sync-tags",
                f"- dataset: {VALUE_TAGS_DATASET}",
                f"- source:  {tags_url}",
                f"- force:   {force}",
            ]
        ),
        stage="sync-tags.start",
    )

    # Fetch incoming
    source_obj = http_get_json(tags_url)
    rows = _normalize_lookup_rows(source_obj)
    rows = _remove_omitted_fields(rows)

    if not rows:
        raise Exception("Downloaded value_tags.json but found 0 usable rows.")

    incoming_hash = _compute_hash(rows)
    emit_progress(
        f"Downloaded **{len(rows)}** rows. Incoming hash: `{incoming_hash}`",
        stage="sync-tags.fetch",
    )

    # Check current version
    meta = _get_current_meta(using=using, debug=debug)
    current_hash = (meta or {}).get("hash", "")
    current_version = (meta or {}).get("version", "")
    current_updated = (meta or {}).get("updated_at", "")

    if meta:
        emit_progress(
            "\n".join(
                [
                    "Current value_tags version:",
                    f"- version:    `{current_version}` (hash: `{current_hash}`)",
                    f"- updated_at: {current_updated}",
                ]
            ),
            stage="sync-tags.version",
        )
    else:
        emit_progress(
            "No version metadata found — first sync or metadata row missing.",
            stage="sync-tags.version",
        )

    # Up to date?
    if not force and current_hash and current_hash == incoming_hash:
        emit_progress(
            "\n".join(
                [
                    "**value_tags is already up to date.** No update needed.",
                    f"  Version: `{current_version}` (hash: `{current_hash}`)",
                    "",
                    "Run with `force=true` to overwrite anyway.",
                ]
            ),
            stage="sync-tags.result",
        )
        return_results(
            {
                "action": "sync-tags",
                "status": "up_to_date",
                "dataset": VALUE_TAGS_DATASET,
                "version": current_version,
                "hash": current_hash,
                "rows": len(rows),
                "updated": False,
            }
        )
        return

    # Apply update
    import time as _time

    updated_at = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
    short_ver = incoming_hash[:8]
    # Upload only the actual value_tags rows — no meta row in the dataset.
    # Version state is stored in the SOCFWTagsVersion List (reliable persistence).
    _xql_lookup_add_data_list(
        dataset_name=VALUE_TAGS_DATASET,
        rows=rows,
        using=using,
        debug=debug,
    )

    # Persist version metadata to List
    _set_current_meta(
        {
            "hash": incoming_hash,
            "version": short_ver,
            "updated_at": updated_at,
            "row_count": str(len(rows)),
        },
        using=using,
        debug=debug,
    )

    changed = current_hash != incoming_hash if current_hash else True
    emit_progress(
        "\n".join(
            [
                f"{'value_tags **updated**.' if changed else 'value_tags force-refreshed.'}",
                f"- Rows:         {len(rows)}",
                f"- New version:  `{short_ver}` (hash: `{incoming_hash}`)",
                f"- Updated at:   {updated_at}",
                *(
                    ["- Previous:     `" + current_hash[:8] + "` (hash: `" + current_hash + "`)"]
                    if current_hash and changed
                    else []
                ),
            ]
        ),
        stage="sync-tags.result",
    )

    return_results(
        {
            "action": "sync-tags",
            "status": "updated",
            "dataset": VALUE_TAGS_DATASET,
            "version": short_ver,
            "hash": incoming_hash,
            "rows": len(rows),
            "updated": True,
            "previous_hash": current_hash or None,
            "updated_at": updated_at,
        }
    )


def _run_main():
    args = demisto.args()

    action = (args.get("action") or "apply").strip().lower()
    pack_id = (args.get("pack_id") or "").strip()
    include_hidden = arg_to_bool(args.get("include_hidden"), False)
    dry_run = arg_to_bool(args.get("dry_run"), False)

    install_marketplace_flag = arg_to_bool(args.get("install_marketplace"), True)
    apply_configure = arg_to_bool(args.get("apply_configure"), True)
    configure_jobs = arg_to_bool(args.get("configure_jobs"), True)
    configure_integrations = arg_to_bool(args.get("configure_integrations"), True)
    configure_lookups = arg_to_bool(args.get("configure_lookups"), True)
    overwrite_lookup = arg_to_bool(args.get("overwrite_lookup"), False)

    include_doc_content = arg_to_bool(args.get("include_doc_content"), False)
    doc_content_max_chars = to_int(args.get("doc_content_max_chars"), 6000)
    doc_content_max_lines = to_int(args.get("doc_content_max_lines"), 200)

    pre_config_done = arg_to_bool(args.get("pre_config_done"), False)
    pre_config_gate = arg_to_bool(args.get("pre_config_gate"), True)

    retry_count = to_int(args.get("retry_count"), 5)
    retry_sleep_seconds = to_int(args.get("retry_sleep_seconds"), 15)
    using = (args.get("using") or "").strip()
    execution_timeout = to_int(args.get("execution_timeout"), 1200)

    skip_verify = arg_to_bool(args.get("skip_verify"), True)
    skip_validation = arg_to_bool(args.get("skip_validation"), False)

    install_timeout = to_int(args.get("install_timeout"), 3600)

    post_install_poll_seconds = to_int(args.get("post_install_poll_seconds"), 1800)
    post_install_poll_interval_seconds = to_int(args.get("post_install_poll_interval_seconds"), 60)
    continue_on_install_timeout = arg_to_bool(args.get("continue_on_install_timeout"), False)

    fail_on_marketplace_errors = arg_to_bool(args.get("fail_on_marketplace_errors"), False)
    upgrade_marketplace = arg_to_bool(args.get("upgrade_marketplace"), False)

    debug = arg_to_bool(args.get("debug"), False)

    catalog_url = _norm(args.get("catalog_url") or DEFAULT_CATALOG_URL)

    if action not in ("apply", "list", "configure", "sync-tags", "diagnose"):
        raise Exception(f"Unsupported action: {action}")

    if action == "list":
        return do_list(args)

    if action == "diagnose":
        return do_diagnose(args)

    if action == "configure":
        return do_configure(args)

    if action == "sync-tags":
        return do_sync_tags(args)

    if not pack_id:
        raise Exception("pack_id is required for action=apply")

    emit_progress(
        "\n".join(
            [
                f"Starting {action} for **{pack_id}**",
                f"- catalog_url={catalog_url}",
                f"- include_hidden={include_hidden}",
                f"- dry_run={dry_run}",
                f"- install_marketplace={install_marketplace_flag}",
                f"- apply_configure={apply_configure} (jobs={configure_jobs}, "
                f"integrations={configure_integrations}, lookups={configure_lookups})",
                f"- overwrite_lookup={overwrite_lookup}",
                f"- retries={retry_count}, retry_sleep_seconds={retry_sleep_seconds}",
                f"- using={(using or '(default)')}",
                f"- execution_timeout={execution_timeout}",
                f"- install_timeout={install_timeout}",
                f"- skip_verify={skip_verify}",
                f"- skip_validation={skip_validation}",
                f"- post_install_poll_seconds={post_install_poll_seconds}",
                f"- post_install_poll_interval_seconds={post_install_poll_interval_seconds}",
                f"- continue_on_install_timeout={continue_on_install_timeout}",
                f"- fail_on_marketplace_errors={fail_on_marketplace_errors}",
                f"- upgrade_marketplace={upgrade_marketplace}",
                f"- include_doc_content={include_doc_content} "
                f"(max_chars={doc_content_max_chars}, max_lines={doc_content_max_lines})",
                f"- pre_config_gate={pre_config_gate}",
                f"- pre_config_done={pre_config_done}",
                f"- debug={debug}",
            ]
        ),
        stage="start",
    )

    emit_progress("Resolving install manifest…", stage="manifest")
    manifest = resolve_manifest(pack_id, include_hidden=include_hidden, catalog_url=catalog_url)

    marketplace_packs = manifest.get("marketplace_packs") or []
    custom_zip_urls = manifest.get("custom_zip_urls") or []
    xsoar_config_url = manifest.get("xsoar_config_url") or ""

    emit_progress(
        "\n".join(
            [
                "Manifest resolved.",
                f"- marketplace_packs: {len(marketplace_packs)}",
                f"- custom ZIP URLs: {len(custom_zip_urls)}",
                f"- xsoar_config_url: {xsoar_config_url or '(none)'}",
            ]
        ),
        stage="manifest.summary",
    )

    xsoar_cfg: dict[str, Any] = {}
    if xsoar_config_url:
        emit_progress("Fetching xsoar_config.json…", stage="xsoar_config.fetch")
        xsoar_cfg = fetch_xsoar_config(xsoar_config_url) or {}

        cfg_marketplace_packs = xsoar_cfg.get("marketplace_packs") or []
        if isinstance(cfg_marketplace_packs, list) and cfg_marketplace_packs:
            marketplace_packs = cfg_marketplace_packs

        # ✅ Pull custom pack dependencies from xsoar_config.json (authoritative)
        cfg_custom_packs = _extract_custom_packs_from_xsoar_cfg(xsoar_cfg)
        if cfg_custom_packs:
            custom_zip_urls = cfg_custom_packs
            emit_progress(
                "\n".join(
                    [
                        "Using custom_packs from xsoar_config.json:",
                        *[f"- {x.get('name')} -> {x.get('url')}" for x in custom_zip_urls],
                    ]
                ),
                stage="packs.custom.from_config",
            )

        emit_progress(
            "\n".join(
                [
                    "xsoar_config loaded.",
                    f"- integration_instances: {len(xsoar_cfg.get('integration_instances', []) or [])}",
                    f"- jobs: {len(xsoar_cfg.get('jobs', []) or [])}",
                    f"- lookup_datasets: {len(xsoar_cfg.get('lookup_datasets', []) or [])}",
                    f"- has_pre_config_docs: {has_config_docs(xsoar_cfg, 'pre')}",
                    f"- has_post_config_docs: {has_config_docs(xsoar_cfg, 'post')}",
                ]
            ),
            stage="xsoar_config.summary",
        )

        print_config_docs(
            xsoar_cfg,
            when="pre",
            debug=debug,
            include_doc_content=include_doc_content,
            doc_content_max_chars=doc_content_max_chars,
            doc_content_max_lines=doc_content_max_lines,
        )

        if pre_config_gate and has_config_docs(xsoar_cfg, "pre") and not pre_config_done:
            emit_progress(
                "\n".join(
                    [
                        "🛑 **Pre-config required**",
                        "Pre-config docs were printed above.",
                        "",
                        "After completing those steps, rerun with:",
                        "- `pre_config_done=true`",
                        "",
                        f"Example:\n`!SOCFWPackManager action=apply pack_id={pack_id} pre_config_done=true`",
                        "",
                        "To bypass this stop (not recommended), run with:",
                        "- `pre_config_gate=false`",
                    ]
                ),
                stage="docs.pre.gate",
            )
            return_results(
                {
                    "pack_id": pack_id,
                    "xsoar_config_url": xsoar_config_url,
                    "stopped_after_pre_docs": True,
                    "next_command_hint": f"!SOCFWPackManager action=apply pack_id={pack_id} pre_config_done=true",
                }
            )
            return None

    if dry_run:
        emit_progress("dry_run=True — not installing or configuring anything.", stage="done")
        return None

    marketplace_errors: list[str] = []
    if install_marketplace_flag and marketplace_packs:
        mp = []
        for p in marketplace_packs:
            if isinstance(p, dict) and p.get("id"):
                mp.append({"id": p.get("id"), "version": p.get("version", "latest")})

        try:
            _ = install_marketplace_packs(mp, using, retry_count, retry_sleep_seconds, debug=debug, upgrade=upgrade_marketplace)
        except Exception as e:
            marketplace_errors.append(str(e))
            emit_progress(f"Marketplace install failed.\nError: {e}", stage="packs.marketplace.error")
            if fail_on_marketplace_errors:
                raise

    if custom_zip_urls:
        emit_progress(f"Installing custom pack ZIPs… ({len(custom_zip_urls)} ZIP(s))", stage="packs.custom")
        for item in custom_zip_urls:
            if isinstance(item, str):
                url = item
            else:
                url = item.get("url") or item.get("zip_url") or ""
            if not url:
                continue

            # Filename = last URL segment including .zip
            asset_fname = url.rstrip("/").split("/")[-1]
            if not asset_fname.endswith(".zip"):
                asset_fname += ".zip"

            emit_progress(f"Installing: **{asset_fname}**\n- {url}", stage="packs.custom")

            install_custom_pack_zip(
                url=url,
                asset_filename=asset_fname,
                using=using,
                retry_count=retry_count,
                retry_sleep_seconds=retry_sleep_seconds,
                debug=debug,
                poll_seconds=post_install_poll_seconds,
                poll_interval_seconds=post_install_poll_interval_seconds,
            )

    integration_summary = None
    jobs_summary = None
    lookups_summary = None

    if apply_configure and xsoar_cfg:
        emit_progress("Configuring from xsoar_config…", stage="configure")

        emit_progress(
            "\n".join(
                [
                    "Configure plan:",
                    f"- integration_instances: {len(xsoar_cfg.get('integration_instances', []) or [])}",
                    f"- jobs: {len(xsoar_cfg.get('jobs', []) or [])}",
                    f"- lookup_datasets: {len(xsoar_cfg.get('lookup_datasets', []) or [])}",
                ]
            ),
            stage="configure.plan",
        )

        installed_pack_ids = fetch_installed_marketplace_pack_ids(using)

        if configure_integrations:
            integration_summary = configure_integrations_from_xsoar_config(
                xsoar_cfg=xsoar_cfg,
                using=using,
                retry_count=retry_count,
                retry_sleep_seconds=retry_sleep_seconds,
                installed_pack_ids=installed_pack_ids,
                debug=debug,
            )

        if configure_jobs:
            jobs_summary = configure_jobs_from_xsoar_config(
                xsoar_cfg=xsoar_cfg,
                using=using,
                retry_count=retry_count,
                retry_sleep_seconds=retry_sleep_seconds,
                debug=debug,
            )

        if configure_lookups:
            lookups_summary = configure_lookups_from_xsoar_config(
                xsoar_cfg=xsoar_cfg,
                using=using,
                retry_count=retry_count,
                retry_sleep_seconds=retry_sleep_seconds,
                overwrite_lookup=overwrite_lookup,
                debug=debug,
            )

    emit_progress("Done.", stage="done")

    results_obj = {
        "pack_id": pack_id,
        "xsoar_config_url": xsoar_config_url,
        "catalog_url": catalog_url,
        "marketplace_errors": marketplace_errors,
        "debug": debug,
        "install_timeout": install_timeout,
        "skip_verify": skip_verify,
        "skip_validation": skip_validation,
        "post_install_poll_seconds": post_install_poll_seconds,
        "post_install_poll_interval_seconds": post_install_poll_interval_seconds,
        "continue_on_install_timeout": continue_on_install_timeout,
        "configure_summary": {
            "integrations": integration_summary,
            "jobs": jobs_summary,
            "lookups": lookups_summary,
        },
    }

    return_results(results_obj)

    if xsoar_cfg:
        print_config_docs(
            xsoar_cfg,
            when="post",
            debug=debug,
            include_doc_content=include_doc_content,
            doc_content_max_chars=doc_content_max_chars,
            doc_content_max_lines=doc_content_max_lines,
        )
        return None
    return None


# ---------------------------
# diagnose action
# ---------------------------


def do_diagnose(args: dict[str, Any]):
    """Probe every platform endpoint the marketplace install path depends on.

    Read-only. Exists because a failure in any one of these surfaces later as a
    confusing error attributed to a different endpoint -- most often a
    dependency-lookup failure reported as a rejected install.
    """
    using = _norm(args.get("using") or "")
    probe_pack = _norm(args.get("probe_pack")) or "Whois"

    results: list[dict[str, str]] = []

    def record(name: str, endpoint: str, ok: bool, detail: str):
        results.append({"check": name, "endpoint": endpoint, "result": "pass" if ok else "FAIL", "detail": detail})

    # Checked first and without an API call: every endpoint below runs through
    # core-api-*, so a missing instance would otherwise surface as an opaque
    # transport error on each of them.
    instances = find_core_rest_api_instances()
    record(
        "Core REST API instance",
        "demisto.getModules()",
        bool(instances),
        ", ".join(f"{i['name']} ({i['state'] or 'unknown state'})" for i in instances)
        if instances
        else "none configured — core-api-* cannot run. Configure the Core REST API "
        "integration (DemistoRESTAPI pack); it is this pack's only external dependency.",
    )

    installed: dict[str, dict[str, Any]] = {}
    endpoint = f"GET {MARKETPLACE_API_ROOT}/metadata/installed"
    try:
        res = core_api_get(f"{MARKETPLACE_API_ROOT}/metadata/installed", using=using)
        packs = (res.get("response") or []) if isinstance(res, dict) else []
        installed = {p["id"]: p for p in packs if p.get("id")}
        has_version = any(p.get("currentVersion") for p in packs)
        record(
            "installed packs",
            endpoint,
            bool(packs) and has_version,
            f"{len(packs)} pack(s)" + ("" if has_version else " — no currentVersion field present"),
        )
    except Exception as e:
        record("installed packs", endpoint, False, str(e)[:300])

    # Use a version the tenant actually has; the endpoints reject unknown ones.
    probe_version = (installed.get(probe_pack) or {}).get("currentVersion") or ""
    if not probe_version and installed:
        probe_pack = sorted(installed)[0]
        probe_version = (installed.get(probe_pack) or {}).get("currentVersion") or ""

    endpoint = f"GET {MARKETPLACE_API_ROOT}/marketplace/{probe_pack}"
    try:
        res = core_api_get(f"{MARKETPLACE_API_ROOT}/marketplace/{probe_pack}", using=using)
        latest = ((res.get("response") or {}) if isinstance(res, dict) else {}).get("currentVersion")
        record(
            "marketplace metadata (resolves 'latest')",
            endpoint,
            bool(latest),
            f"latest={latest}" if latest else "no currentVersion in response",
        )
    except Exception as e:
        record("marketplace metadata (resolves 'latest')", endpoint, False, str(e)[:300])

    endpoint = f"POST {MARKETPLACE_API_ROOT}/marketplace/search/dependencies"
    if not probe_version:
        record("dependency lookup", endpoint, False, "skipped — no installed version available to probe with")
    else:
        try:
            deps = fetch_mandatory_dependencies([{"id": probe_pack, "version": probe_version}], using)
            found = deps.get(probe_pack) or {}
            record("dependency lookup", endpoint, True, f"{probe_pack}@{probe_version} → {len(found)} mandatory")
        except Exception as e:
            record("dependency lookup", endpoint, False, str(e)[:300])

    header = "| check | result | detail |\n| --- | --- | --- |\n"
    table = header + "".join("| {} | {} | {} |\n".format(r["check"], r["result"], r["detail"].replace("|", "/")) for r in results)
    failed = [r for r in results if r["result"] == "FAIL"]
    verdict = (
        "All checks passed — the marketplace install path is usable on this tenant."
        if not failed
        else "FAILED: " + ", ".join(r["check"] for r in failed)
    )

    emit_progress(
        f"{verdict}\n\nprobe pack: {probe_pack}@{probe_version or 'unknown'}\n\n" + table,
        stage="diagnose",
    )
    return_results(
        CommandResults(
            outputs_prefix="SOCFramework.PackManager.Diagnose",
            outputs_key_field="check",
            outputs=results,
        )
    )


def main():
    """Entry point with standard XSOAR error handling.

    Wraps the orchestrator in try/except so any uncaught exception surfaces
    via return_error() instead of crashing with a raw traceback.
    """
    try:
        _run_main()
    except Exception as exc:
        return_error(f"{SCRIPT_NAME} failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

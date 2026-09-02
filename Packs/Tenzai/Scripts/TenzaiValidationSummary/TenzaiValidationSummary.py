import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re
from datetime import datetime, UTC
from html import escape
from typing import Any

# The Validate tab renders the Tenzai verdict as a self-contained "results panel" styled in
# theme-adaptive native Unity chrome — it inherits the console shell, so it reads on both the light
# and dark XSIAM themes: a compact Tenzai brand header + action links, a classification chip row,
# a monospace stat-card grid matching the Figma design (Result | Status | Findings | Started at |
# Credit usage), a per-severity badge row, and an expandable per-finding list. Each finding is a
# native <details> disclosure: collapsed it shows a severity chip + title; expanded it reveals
# Impact, Description, Reproduction, and Fix guidance subsections, with fenced code (the coding-agent
# prompt / fix config / reproduction) rendered inline as monospace blocks. There is no separate
# findings grid — a layout widget has a size cap and cannot run JavaScript. Exposure validation
# confirms one vulnerability (1-2 findings, not a full-scan flood), so the per-section budgets are
# generous and trim only unusually long sections; the full untruncated detail opens in Tenzai (linked).
#
# HTML-entry constraints: only inline `style=` attributes render reliably in a layout widget.
# `<style>` blocks, `<svg>`, JavaScript, and web fonts are stripped/blocked by the entry
# sanitizer, so the look uses a system sans + monospace pairing and inline CSS only, and it goes
# theme-adaptive by inheritance (transparent surfaces + `color:inherit`) rather than a media query
# (which the sanitizer would strip). <details>/<summary> is the only no-JS disclosure available;
# its native marker is kept as the expand affordance (a custom chevron can't track open/closed
# state without stripped CSS).

# Palette — theme-adaptive native Unity chrome. The widget can't detect the tenant theme (inline
# style only; no media query, no JS), so it goes theme-adaptive by inheritance: transparent
# surfaces + inherited ink read on both the light and dark XSIAM shells. Only the saturated
# semantic/brand accents (verdict red/green, link/running blue, severity hues) carry fixed colors —
# they read on either shell — and DIM/FAINT are mid-greys legible on both.
BG = "transparent"  # panel surface — inherit the console shell (no dark box in light mode)
INK = "inherit"  # primary text — inherit the shell's default ink
LINE = "rgba(127,127,127,.28)"  # dividers / borders — visible on both shells
TILE = "rgba(127,127,127,.10)"  # recessed fill (tiles, code blocks) — subtle on both
DIM = "#7f8791"  # secondary text — mid-grey legible on white and dark
FAINT = "#79828d"  # faint labels / filled Error pill — mid-grey, reads on both
BLOOD = "#f2607b"
BLOOD2 = "#4aa8d8"
RUN_BLUE = "#29b2ff"  # Unity --color-blue-500 / --text-color-link: running-pill accent + agent-log link (Figma 66:1776)
OK = "#3fbf6d"
SANS = "'Helvetica Neue',Helvetica,Arial,system-ui,-apple-system,sans-serif"
MONO = "ui-monospace,'SF Mono','JetBrains Mono','Cascadia Code',Menlo,Consolas,monospace"

# Empty-state (Validate tab, ENG-7075) — native "Unity" look, theme-adaptive by inheritance.
# The widget can't detect the tenant theme (inline style only; no media query, no JS), so the
# empty-state pitch paints NO background and inherits the host ink; hierarchy comes from size and
# weight, and only the brand mark + the Learn link carry a fixed color (picked to read on both the
# light and dark Cortex shells). Matches Figma Cortex Unity 66:1750 (dark) / 95:3709 (light).
FIGTREE = "Figtree,'Helvetica Neue',Helvetica,Arial,system-ui,-apple-system,sans-serif"
LINK_ACCENT = "#1f83d6"  # shared action-link color — mid blue, legible on the light (#fbfcfe) and dark (#172130) shells

# The Tenzai brand mark (the neon "spark" glyph), embedded as a base64 PNG data URI so the
# header renders the logo lockup beside the wordmark. Inline `<svg>` is stripped by the entry
# sanitizer, so a raster `data:` URI is the only in-panel path for the real mark. If the
# sanitizer also blocks `<img>`/`data:` URIs the wordmark still stands on its own and the
# alt text degrades cleanly — so this is additive, never a regression.
LOGO_DATA_URI = "data:image/png;base64,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"  # noqa: E501

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_COLORS = {"Critical": "#ff5865", "High": "#ff9147", "Medium": "#f5c451", "Low": "#5fa2f6"}


def _as_rows(findings: Any) -> list:
    """The findings grid comes back as a list of row dicts (or a lone dict / None)."""
    if isinstance(findings, list):
        return [row for row in findings if isinstance(row, dict)]
    if isinstance(findings, dict):
        return [findings]
    return []


def _severity_level(value: Any) -> str | None:
    """Map a stored severity value to a known level, tolerating case/emoji/markup noise."""
    raw = str(value or "").strip().lower()
    return next((level for level in SEVERITY_ORDER if level.lower() in raw), None)


def _severity_counts(rows: list) -> dict:
    """Tally findings by severity level (unknown severities are ignored)."""
    counts = {level: 0 for level in SEVERITY_ORDER}
    for row in rows:
        level = _severity_level(row.get("severity"))
        if level:
            counts[level] += 1
    return counts


def _is_validated(value: Any) -> bool | None:
    """Interpret ``tenzaiissuevalidated`` (stored as a 'true'/'false' string or a bool)."""
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in ("true", "yes", "1"):
        return True
    if text in ("false", "no", "0"):
        return False
    return None


def _attribution(row: dict) -> str:
    """A finding row's attribution: ``own`` / ``discovered`` / ``unattributed`` (default ``own``).

    ``own`` is the default so rows written before this field existed (or any row without it) still
    render as the exposure's own findings rather than vanishing from the count.
    """
    value = str(row.get("attribution") or "").strip().lower()
    return value if value in ("own", "discovered", "unattributed") else "own"


def _format_credit(value: Any) -> str | None:
    """Render the credit usage as ``NN.NN ACU`` (best effort)."""
    if value in (None, ""):
        return None
    try:
        return f"{float(value):.2f} ACU"
    except (TypeError, ValueError):
        return f"{value} ACU"


def _parse_datetime(value: Any) -> datetime | None:
    """Parse a stored ``date`` field into a tz-aware ``datetime`` (UTC), or None.

    XSIAM ``date`` fields read back either as an ISO-8601 string (with ``Z``, an offset, or
    naive) or as epoch milliseconds; tolerate both. A naive value is assumed UTC. Returns
    None for anything unparseable so the caller can omit the cell.
    """
    if value in (None, ""):
        return None
    # Epoch millis (int, or an all-digit string) — the numeric form XSIAM sometimes stores.
    if isinstance(value, int | float) or (isinstance(value, str) and value.strip().isdigit()):
        try:
            return datetime.fromtimestamp(float(value) / 1000.0, tz=UTC)
        except (TypeError, ValueError, OverflowError, OSError):
            return None
    raw = str(value).strip()
    # fromisoformat (3.11+) accepts the trailing 'Z'; normalise it anyway for older runtimes.
    iso = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _format_started_at(value: Any) -> str | None:
    """Render the assessment start as ``Aug 17th 2026 19:13`` (matching the Figma stat card).

    Rendered in UTC: the panel is server-rendered HTML and cannot convert to the viewer's
    timezone (no JS in a layout widget). Returns None (omit the cell) when unparseable.
    """
    dt = _parse_datetime(value)
    if dt is None:
        return None
    dt = dt.astimezone(UTC)
    day = dt.day
    # Ordinal suffix: 11th/12th/13th are the -th exceptions, otherwise 1st/2nd/3rd.
    suffix = "th" if 11 <= day % 100 <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
    return f"{dt.strftime('%b')} {day}{suffix} {dt.strftime('%Y %H:%M')}"


def _panel(inner: str) -> str:
    """Wrap content in the flat native-chrome results-panel shell.

    Borderless and flush: the Cortex layout section already draws the outer frame, so the
    widget must not add a second border/card (that produced a double frame + dead gutter).
    Inner regions manage their own horizontal padding; the metric strip is full-bleed.
    """
    return f'<div style="font-family:{SANS};color:{INK};background:{BG};line-height:1.5;padding-bottom:6px;">{inner}</div>'


def _header(right: str = "") -> str:
    # Compact brand header (Figma Cortex Unity 66:1776 / 95:3775): the teal Tenzai asterisk mark +
    # a "Tenzai validation" wordline in the inherited shell ink — no filled band, so it reads on the
    # light and dark themes alike. The <img> is a base64 data URI (see LOGO_DATA_URI); if the entry
    # sanitizer drops it, the text alone still reads as the brand.
    brand = (
        f'<span style="display:inline-flex;align-items:center;gap:9px;">'
        f'<img src="{LOGO_DATA_URI}" alt="Tenzai" width="19" height="19" '
        f'style="display:block;width:19px;height:19px;flex:0 0 auto;" />'
        f'<span style="font-family:{SANS};font-weight:600;font-size:15px;letter-spacing:-.005em;'
        f'color:inherit;">Tenzai validation</span></span>'
    )
    return (
        f'<div style="display:flex;justify-content:space-between;align-items:center;gap:12px 16px;'
        f'flex-wrap:wrap;padding:14px 18px;border-bottom:1px solid {LINE};">'
        f"{brand}{right}</div>"
    )


def _status_note(text: str, color: str = DIM) -> str:
    """The mono status line shown at the top-right of the header."""
    return (
        f'<span style="font-family:{MONO};font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;'
        f'color:{color};white-space:nowrap;">{text}</span>'
    )


def _header_link(url: str, label: str) -> str:
    """An action link for the header's right slot (moved out of the metric strip)."""
    return (
        f'<a href="{escape(url, quote=True)}" target="_blank" rel="noopener noreferrer" '
        f'style="color:{LINK_ACCENT};text-decoration:none;font-family:{MONO};font-size:12px;'
        f'letter-spacing:.04em;white-space:nowrap;">{label} &#8599;</a>'
    )


def _header_actions(reference: str, log_url: str | None, note: str) -> str:
    """The header's right slot: the Tenzai / agent-log actions, then the status note."""
    parts = []
    if reference:
        parts.append(_header_link(reference, "View in Tenzai"))
    if log_url:
        parts.append(_header_link(log_url, "View agent log"))
    parts.append(note)
    divider = f'<span style="color:{FAINT};margin:0 10px;">|</span>'
    return f'<span style="display:inline-flex;align-items:center;flex-wrap:wrap;">{divider.join(parts)}</span>'


def _chip(text: str) -> str:
    """A small native-chrome classification pill (e.g. a CWE or OWASP tag)."""
    return (
        f'<span style="display:inline-block;font-family:{MONO};font-size:11.5px;letter-spacing:.04em;'
        f"color:{DIM};background:{TILE};border:1px solid {LINE};border-radius:4px;padding:5px 10px;"
        f'margin:0 8px 8px 0;">{text}</span>'
    )


def _classification(cwe: str, owasp: str) -> str:
    """The exposure classification chips (CWE / OWASP), or "" when neither is set."""
    chips = [_chip(escape(value)) for value in (cwe, owasp) if value]
    if not chips:
        return ""
    return f'<div style="padding:10px 18px 2px;">{"".join(chips)}</div>'


def _agent_log_url(reference: str) -> str | None:
    """Derive the agent-activity-log URL from the terminal reference URL.

    The reference is the Tenzai findings view (``…/tests/<id>/findings``); the agent
    log is the sibling ``…/log`` view. Returns ``None`` when the reference is absent or
    is not the expected findings URL — a wrong link is worse than none.
    """
    ref = (reference or "").strip()
    suffix = "/findings"
    if ref.endswith(suffix):
        return ref[: -len(suffix)] + "/log"
    return None


def _tile(label: str, value_html: str, color: str = INK, small: bool = False) -> str:
    size = "14px" if small else "19px"
    return (
        f'<div style="background:{TILE};padding:16px 18px;display:flex;flex-direction:column;gap:8px;min-width:0;">'
        f'<span style="font-family:{MONO};font-size:10px;letter-spacing:.2em;text-transform:uppercase;'
        f'color:{FAINT};">{label}</span>'
        f'<span style="font-family:{MONO};font-size:{size};color:{color};letter-spacing:-.01em;'
        f'overflow:hidden;text-overflow:ellipsis;">{value_html}</span></div>'
    )


def _telemetry(tiles: list) -> str:
    # Full-bleed metric strip: top+bottom hairlines only (no side border / radius) so it spans
    # the panel edge-to-edge; the 1px grid gaps over a LINE background draw the cell dividers.
    return (
        f'<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:{LINE};'
        f'border-top:1px solid {LINE};border-bottom:1px solid {LINE};margin:18px 0 0;">{"".join(tiles)}</div>'
    )


def _sev_badges(counts: dict) -> str:
    """The Figma "Findings severity" row: one round letter-badge per level + its count.

    All four levels are always shown (including zeros), matching the Figma stat block
    (C 3 · H 1 · M 0 · L 2). Each badge is a filled circle carrying the level's initial.
    """
    if not any(counts[level] for level in SEVERITY_ORDER):
        return ""
    badges = "".join(
        f'<span style="display:inline-flex;align-items:center;gap:8px;white-space:nowrap;">'
        f'<span style="display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;'
        f"border-radius:50%;background:{SEVERITY_COLORS[level]};color:#0e1116;font-family:{SANS};font-size:11px;"
        f'font-weight:700;">{level[0]}</span>'
        f'<span style="font-family:{SANS};font-size:14px;color:{INK};">{counts[level]}</span></span>'
        for level in SEVERITY_ORDER
    )
    return (
        f'<div style="font-family:{MONO};font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:{FAINT};'
        f'margin:22px 0 11px;">Findings severity</div>'
        f'<div style="display:flex;flex-wrap:wrap;gap:12px 22px;align-items:center;">{badges}</div>'
    )


MAX_PANEL_FINDINGS = 12  # keep the panel HTML comfortably under the layout-widget size cap


# Per-section source-char budgets for the expanded finding. Exposure validation confirms a single
# vulnerability (typically 1-2 findings, never a full-scan flood), so the budgets are generous and
# the fenced code (coding-agent prompt / fix config / reproduction) renders inline as monospace
# blocks; only an unusually long section is trimmed, with the full untruncated detail in Tenzai.
_SECTION_BUDGET = {"impact": 900, "description": 2500, "reproduction": 3200, "guidance": 3200}
_SECTIONS = [("impact", "Impact"), ("description", "Description"), ("reproduction", "Reproduction"), ("guidance", "Fix guidance")]


def _truncate_lines(text: str, limit: int) -> str:
    """Trim to ``limit`` on a whole-line boundary so a numbered step is never severed mid-sentence.

    Keeps at least the first line; an overflowing section ends on a clean line plus an ellipsis
    marker, and the full narrative is always one click away via the Tenzai reference link.
    """
    text = text.strip()
    if len(text) <= limit:
        return text
    kept: list[str] = []
    total = 0
    for line in text.split("\n"):
        if kept and total + len(line) + 1 > limit:
            break
        kept.append(line)
        total += len(line) + 1
    return "\n".join(kept).rstrip() + "\n\n…"


def _split_detail(detail: Any) -> dict:
    """Break the combined ``detail`` markdown into impact / description / reproduction / guidance.

    ``detail`` is the assessment, then ``## Reproduction``, then ``## Fix Guidance`` (built by the
    integration's ``_finding_detail_markdown``). The assessment's first paragraph is the impact and
    the rest is the description. Fenced code blocks are kept (rendered inline by ``_detail_body_html``).
    """
    parts = re.split(r"\n#{1,6}\s+(Reproduction|Fix Guidance|Remediation guidance)\s*\n+", str(detail or ""))
    out = {"impact": "", "description": "", "reproduction": "", "guidance": ""}
    assessment = re.sub(r"^\*\*\s*Impact:?\s*\*\*\s*", "", parts[0].strip()).strip()
    paras = [p.strip() for p in re.split(r"\n\s*\n", assessment) if p.strip()]
    if paras:
        out["impact"] = paras[0]
        out["description"] = "\n\n".join(paras[1:])
    for i in range(1, len(parts) - 1, 2):
        out["reproduction" if "reproduction" in parts[i].lower() else "guidance"] = parts[i + 1].strip()
    return out


def _light_markdown(text: str) -> str:
    """Escape text, then apply a minimal, entry-safe markdown pass: line breaks + bold."""
    html = re.sub(r"\n{2,}", "<br><br>", escape(text.strip())).replace("\n", "<br>")
    return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", html)


def _detail_body_html(text: str) -> str:
    """Render a finding-section body: prose via the light markdown pass, and fenced ``` code blocks
    as monospace boxes (the coding-agent prompt / fix config / reproduction the analyst copies)."""
    code_style = (
        f"font-family:{MONO};font-size:12px;color:{INK};background:{TILE};border:1px solid {LINE};"
        f"border-radius:4px;padding:11px 14px;margin:10px 0 0;max-width:{_MEASURE};"
        f"white-space:pre-wrap;word-break:break-word;overflow-x:auto;"
    )
    out: list[str] = []
    # Split on fenced blocks, capturing the code content; even parts are prose, odd parts are code.
    for i, part in enumerate(re.split(r"```[^\n]*\n?(.*?)```", text, flags=re.DOTALL)):
        if i % 2 == 1:
            code = part.strip("\n")
            if code.strip():
                out.append(f'<pre style="{code_style}">{escape(code)}</pre>')
        else:
            prose = _light_markdown(part)
            if prose.strip():
                out.append(f"<div>{prose}</div>")
    return "".join(out)


def _severity_rank(row: dict) -> int:
    """Sort key: known severities in Critical→Low order, unknown levels last."""
    level = _severity_level(row.get("severity"))
    return SEVERITY_ORDER.index(level) if level is not None and level in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _detail_html(detail: Any) -> str:
    """The expanded finding body: Impact, Description, Reproduction, and Fix guidance subsections,
    with fenced code (coding-agent prompt / fix config / reproduction) rendered inline as monospace
    blocks. Sections are trimmed on a whole-line boundary only if unusually long (exposure
    validation yields 1-2 findings, so the generous budgets rarely bite); the full untruncated
    detail always opens in Tenzai.
    """
    sections = _split_detail(detail)
    blocks = []
    for key, label in _SECTIONS:
        raw = sections.get(key)
        if not raw:
            continue
        trimmed = _truncate_lines(raw, _SECTION_BUDGET[key])
        if trimmed.count("```") % 2:  # a trim landed inside a fence — close it so it renders as code
            trimmed += "\n```"
        blocks.append(
            f'<div style="margin-top:15px;"><div style="font-family:{MONO};font-size:10px;letter-spacing:.18em;'
            f'text-transform:uppercase;color:{FAINT};margin-bottom:6px;">{label}</div>'
            f'<div style="font-family:{SANS};font-size:13.7px;color:{DIM};line-height:1.7;max-width:{_MEASURE};">'
            f"{_detail_body_html(trimmed)}</div></div>"
        )
    return "".join(blocks)


def _finding(row: dict, reference: str) -> str:
    """One finding as a native ``<details>`` disclosure.

    Collapsed (the ``<summary>``): a color-coded severity chip + the finding title. Expanded:
    Impact, Description, Reproduction, and Fix guidance subsections (fenced code rendered inline as
    monospace blocks, trimmed only if unusually long) plus a link to the full detail in Tenzai.
    ``<details>`` is the only no-JS disclosure the entry sanitizer allows; its native marker is
    kept as the expand affordance.
    """
    level = _severity_level(row.get("severity"))
    color = SEVERITY_COLORS.get(level or "", DIM)
    label = (level or "Finding").upper()
    title = escape(str(row.get("finding") or "Untitled finding"))
    detail_html = _detail_html(row.get("detail"))

    chip = (
        f'<span style="font-family:{MONO};font-size:9.5px;font-weight:700;letter-spacing:.12em;'
        f'text-transform:uppercase;color:{color};margin-right:10px;white-space:nowrap;">'
        f'<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:{color};'
        f'margin-right:7px;vertical-align:middle;"></span>{label}</span>'
    )
    # A finding that isn't the alert's own exposure is tagged so the analyst never reads it as this
    # alert's verdict: "Discovered" (a different CVE found while testing) or "Unverified" (no lead
    # correlated, so ownership is unknown).
    attribution = _attribution(row)
    tag_label = {"discovered": "Discovered", "unattributed": "Unverified"}.get(attribution, "")
    attribution_tag = (
        f'<span style="font-family:{MONO};font-size:9px;font-weight:700;letter-spacing:.1em;'
        f"text-transform:uppercase;color:{LINK_ACCENT};border:1px solid {LINK_ACCENT};border-radius:3px;"
        f'padding:1px 6px;margin-left:10px;white-space:nowrap;vertical-align:middle;">{tag_label}</span>'
        if tag_label
        else ""
    )
    summary = (
        f'<summary style="cursor:pointer;padding:13px 4px;border-top:1px solid {LINE};">'
        f'{chip}<span style="font-family:{SANS};font-size:15px;color:{INK};letter-spacing:-.005em;">{title}</span>'
        f"{attribution_tag}</summary>"
    )
    link = (
        f'<div style="margin-top:15px;"><a href="{escape(reference, quote=True)}" target="_blank" '
        f'rel="noopener noreferrer" style="font-family:{MONO};font-size:11px;color:{LINK_ACCENT};text-decoration:none;">'
        f"Full reproduction script &amp; fix in Tenzai &#8599;</a></div>"
        if reference
        else ""
    )
    body = f'<div style="padding:2px 4px 16px 19px;">{detail_html}{link}</div>' if (detail_html or link) else ""
    return f"<details>{summary}{body}</details>"


def _findings_section(rows: list, reference: str, label: str) -> str:
    """One labeled, severity-ordered ``<details>`` group.

    Capped at ``MAX_PANEL_FINDINGS`` so a large finding set cannot blow the widget size cap; the
    remainder is called out (the complete set is always available in Tenzai).
    """
    if not rows:
        return ""
    ordered = sorted(rows, key=_severity_rank)
    shown = ordered[:MAX_PANEL_FINDINGS]
    body = "".join(_finding(row, reference) for row in shown)
    extra = len(ordered) - len(shown)
    more = (
        f'<div style="font-family:{MONO};font-size:11px;color:{FAINT};margin-top:14px;">'
        f"+{extra} more findings — see all in Tenzai</div>"
        if extra > 0
        else ""
    )
    return (
        f'<div style="font-family:{MONO};font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:{FAINT};'
        f'margin:26px 0 4px;border-top:1px solid {LINE};padding-top:18px;">{escape(label)}</div>'
        f"{body}{more}"
    )


def _findings_list(rows: list, reference: str = "") -> str:
    """The expandable per-finding list under the meter, grouped by attribution.

    Three groups, each under its own header so a finding is never read as the wrong thing: the
    alert's OWN confirmed findings; findings *discovered during validation* (a different CVE than the
    matched exposure); and *unverified* findings (no lead correlated, so ownership is unknown). The
    attribution is a per-row field set by the integration; a row without it defaults to "own".
    """
    if not rows:
        return ""
    own = [row for row in rows if _attribution(row) == "own"]
    discovered = [row for row in rows if _attribution(row) == "discovered"]
    unattributed = [row for row in rows if _attribution(row) == "unattributed"]
    return (
        _findings_section(own, reference, "Findings confirmed")
        + _findings_section(discovered, reference, "Discovered during validation")
        + _findings_section(unattributed, reference, "Findings — correlation unverified")
    )


_MEASURE = "84ch"  # cap prose line length so long narratives stay scannable, not a wall of text


def _md_inline(text: str) -> str:
    """Inline markdown for a single line: escape, then **bold** and `code` (subtle mono)."""
    html = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escape(text))
    return re.sub(
        r"`([^`]+)`",
        lambda m: f'<code style="font-family:{MONO};font-size:.92em;color:{INK};">{m.group(1)}</code>',
        html,
    )


def _rationale_body_html(body: str) -> str:
    """Render an assessment section body.

    Lines separated by a Markdown hard break (two trailing spaces) belong to one paragraph and are
    joined with ``<br>`` so they render tight, exactly as the Tenzai app shows them; only a blank line
    starts a new paragraph (and earns the inter-paragraph margin). Numbered steps become their own
    rows, and a step whose trailing ``: `payload``` is present lifts that payload into an indented
    monospace block (the part an analyst copies).
    """
    para = f"font-family:{SANS};font-size:13.7px;color:{DIM};line-height:1.72;max-width:{_MEASURE};margin:13px 0 0;"
    step = (
        f"font-family:{SANS};font-size:13.7px;color:{DIM};line-height:1.66;max-width:{_MEASURE};"
        f"margin:11px 0 0;padding-left:26px;text-indent:-26px;"
    )
    block = (
        f"font-family:{MONO};font-size:12.5px;color:{INK};background:{TILE};border:1px solid {LINE};"
        f"border-radius:4px;padding:11px 14px;margin:8px 0 0 26px;max-width:{_MEASURE};"
        f"white-space:pre-wrap;word-break:break-all;"
    )
    out: list[str] = []
    run: list[str] = []  # consecutive soft-broken lines share one paragraph, joined with <br>

    def flush() -> None:
        if run:
            out.append(f'<div style="{para}">{"<br>".join(run)}</div>')
            run.clear()

    for raw in body.split("\n"):
        line = raw.strip()
        if not line:
            flush()  # blank line = real paragraph boundary
            continue
        match = re.match(r"^(\d+)\.\s+(.*)$", line)
        if match:
            flush()  # a numbered step ends the running paragraph
            number, content = match.group(1), match.group(2)
            payload = None
            trailing = re.search(r":\s*`([^`]+)`\s*$", content)
            if trailing:
                payload = trailing.group(1)
                content = content[: trailing.start()].rstrip() + ":"
            out.append(f'<div style="{step}"><span style="color:{FAINT};">{number}.</span> {_md_inline(content)}</div>')
            if payload:
                out.append(f'<div style="{block}">{escape(payload)}</div>')
        else:
            run.append(_md_inline(line))
    flush()
    return "".join(out)


_RATIONALE_SECTION_BUDGET = 4000  # per section — fits a full exposure assessment (steps + preconditions);
# a normal rationale is ~2KB, so this rarely truncates, and the panel stays well under the widget size cap


def _rationale_block(rationale: str) -> str:
    """Render the CVE lead's Description/Conclusion narrative as an "Exposure assessment" section.

    ``rationale`` is the markdown built by the integration (``## Description`` … ``## Conclusion`` …).
    Each ``##`` heading becomes a mono subsection label; the body is rendered with the minimal,
    entry-safe markdown pass and capped so a long narrative can't blow the widget size cap (the full
    text is always available via the Tenzai link).
    """
    parts = re.split(r"\n?#{1,6}\s+(.+?)\s*\n+", rationale.strip())
    items: list[tuple[str | None, str]] = []
    preamble = parts[0].strip()
    if preamble:
        items.append((None, preamble))
    for i in range(1, len(parts) - 1, 2):
        body = parts[i + 1].strip()
        if body:
            items.append((parts[i].strip(), body))
    if not items:
        return ""

    blocks = []
    for label, body in items:
        label_html = (
            f'<div style="font-family:{MONO};font-size:10px;letter-spacing:.18em;text-transform:uppercase;'
            f'color:{FAINT};margin-bottom:7px;">{escape(label)}</div>'
            if label
            else ""
        )
        body_html = _rationale_body_html(_truncate_lines(body, _RATIONALE_SECTION_BUDGET))
        blocks.append(f'<div style="margin-top:14px;">{label_html}{body_html}</div>')
    header = (
        f'<div style="font-family:{MONO};font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:{FAINT};'
        f'margin:26px 0 0;border-top:1px solid {LINE};padding-top:20px;">Exposure assessment</div>'
    )
    return f'<div style="padding:0 18px 4px;">{header}{"".join(blocks)}</div>'


def _status_panel(status: str, reference: str = "") -> str:
    """Compact panel for a non-terminal assessment (Running / Error).

    When a Tenzai reference URL is present it is offered as a link: the live
    Agent Log while running, or a neutral "View in Tenzai" on error.
    """
    if status == "Running":
        return _running_panel(reference)
    return _error_panel(status, reference)


def _running_panel(reference: str = "") -> str:
    """The Running state, restyled to Figma Cortex Unity node 66:1776 (ENG-7115):
    a bordered dot+label chip (transparent fill, mono), a plain-language line, and
    a "View agent log" link to the live Agent Log when a reference URL is present.
    """
    pill = (
        f'<span style="display:inline-flex;align-items:center;gap:6px;padding:2px 10px;'
        f"border:1px solid {RUN_BLUE};border-radius:4px;background:transparent;"
        f'font-family:{MONO};font-size:12px;font-weight:500;color:{RUN_BLUE};white-space:nowrap;">'
        f'<span style="width:6px;height:6px;border-radius:50%;background:{RUN_BLUE};flex:none;"></span>'
        f"Running</span>"
    )
    children = [
        pill,
        f'<span style="color:{DIM};font-size:14px;font-family:{SANS};">' f"Validation in progress - follow the live</span>",
    ]
    if reference:
        children.append(
            f'<a href="{escape(reference, quote=True)}" target="_blank" rel="noopener noreferrer" '
            f'style="color:{RUN_BLUE};text-decoration:none;font-family:{SANS};font-size:14px;'
            f'font-weight:500;white-space:nowrap;">View agent log &#8599;</a>'
        )
    row = (
        f'<div style="display:flex;align-items:center;flex-wrap:wrap;gap:12px;'
        f'border:1px solid {LINE};border-radius:8px;padding:14px 16px;margin:14px 18px 4px;">'
        f'{"".join(children)}</div>'
    )
    return _panel(f"{_header()}{row}")


def _error_panel(status: str, reference: str = "") -> str:
    """A non-terminal Error state: a filled status pill and a neutral
    "View in Tenzai" link when a reference URL is present (unchanged appearance)."""
    message = f"Assessment {escape(status.lower())}."
    if reference:
        link = (
            f'<a href="{escape(reference, quote=True)}" target="_blank" rel="noopener noreferrer" '
            f'style="color:{LINK_ACCENT};text-decoration:none;">View in Tenzai &#8599;</a>'
        )
        message += f" {link}"
    pill = (
        f'<span style="display:inline-block;padding:3px 12px;border-radius:20px;background:{FAINT};color:#FFFFFF;'
        f'font-family:{MONO};font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;">{escape(status)}</span>'
    )
    row = (
        f'<div style="display:flex;align-items:center;gap:12px;'
        f'border:1px solid {LINE};border-radius:8px;padding:14px 16px;margin:14px 18px 4px;">{pill}'
        f'<span style="color:{DIM};font-size:14px;font-family:{SANS};">{message}</span></div>'
    )
    return _panel(f"{_header()}{row}")


# The Status cell shows the exposure lead's LITERAL status (the same word the lead's own status
# plane shows), not a Tenzai-side translation — the Figma stat card reads Materialized / Invalidated
# / Blocked verbatim. This map only nice-cases the raw upper-snake enum; unknown values Title-case.
_EXPOSURE_STATUS_LABEL = {
    "BLOCKED": "Blocked",
    "MATERIALIZED": "Materialized",
    "INVALIDATED": "Invalidated",
    "OPEN": "Open",
    "IN_PROGRESS": "In progress",
}


def _exposure_status_label(exposure_status: str, fallback: str = "") -> str:
    """The literal lead status for the Status cell, nice-cased (Materialized / Invalidated / …)."""
    key = exposure_status.strip().upper()
    return _EXPOSURE_STATUS_LABEL.get(key) or exposure_status.strip().title() or (fallback or "—")


def _empty_state(fields: dict, name: str) -> str:
    """The Validate-tab empty state (ENG-7075): a centred pitch inviting the analyst to run a
    Tenzai validation on *this* exposure, matching Figma Cortex Unity 66:1750 / 95:3709.

    Theme-adaptive by inheritance: no background, inherited ink, hierarchy from size/weight; only
    the brand mark and the Learn link carry a fixed color. The per-exposure sentence names the
    structured CVE + host when present, falls back to the exposure name, then to a generic phrase.
    """
    cve = str(fields.get("xdmvulnerabilitycveid") or "").strip()
    hosts = fields.get("xdmtargethostipv4addresses")
    if isinstance(hosts, list):
        host = str(hosts[0]).strip() if hosts else ""
    else:
        host = str(hosts or "").strip()
    exposure_name = str(name or "").strip()
    port_match = re.search(r":(\d{1,5})(?:\D|$)", exposure_name)
    target = f"{host}:{port_match.group(1)}" if host and port_match else host

    def _b(text: str) -> str:
        return f'<b style="font-weight:600;">{escape(text)}</b>'

    if cve and target:
        subject = f"{_b(cve)} on {_b(target)}"
    elif cve and exposure_name:
        subject = f"{_b(cve)} on {_b(exposure_name)}"
    elif exposure_name:
        subject = _b(exposure_name)
    else:
        subject = "this exposure"
    body = (
        f"Tenzai will attempt to reach and exploit {subject}, then report whether the exposure "
        f"is exploitable &mdash; not just present."
    )

    brand = (
        f'<span style="display:inline-flex;align-items:center;gap:12px;">'
        f'<img src="{LOGO_DATA_URI}" alt="Tenzai" width="34" height="34" '
        f'style="display:block;width:34px;height:34px;flex:0 0 auto;" />'
        f'<span style="font-family:{MONO};font-weight:700;letter-spacing:.32em;font-size:22px;'
        f'color:inherit;">TENZAI</span></span>'
    )
    heading = (
        f'<div style="font-family:{FIGTREE};font-size:28px;line-height:36px;font-weight:500;'
        f'letter-spacing:-.01em;color:inherit;margin:20px 0 0;">Validate exposure using offensive agents</div>'
    )
    body_html = (
        f'<div style="font-family:{FIGTREE};font-size:14px;line-height:20px;color:inherit;' f'margin:14px 0 0;">{body}</div>'
    )
    learn = (
        f'<a href="https://www.tenzai.com/" target="_blank" rel="noopener noreferrer" '
        f'style="display:inline-flex;align-items:center;gap:6px;font-family:{FIGTREE};font-size:14px;'
        f'font-weight:500;color:{LINK_ACCENT};text-decoration:none;margin:22px 0 0;">'
        f'Learn about Tenzai <span aria-hidden="true">&#8599;</span></a>'
    )
    # The guidelines helper text now lives in each Actions-section field's `placeholder` (the section
    # `description` was removed), so the pitch ends after the Learn link. XSIAM already boxes each
    # section, so no inner border is drawn; the pitch stays borderless/transparent and the box is the card.
    return (
        f'<div style="font-family:{FIGTREE};color:inherit;background:transparent;line-height:1.5;'
        f'padding:8px 20px 8px;"><div style="max-width:560px;margin:0 auto;">'
        f"{brand}{heading}{body_html}{learn}</div></div>"
    )


def build_summary_html(fields: dict, name: str = "") -> str:
    """Build the Tenzai validation results panel from the persisted result fields."""
    status = str(fields.get("tenzaiassessmentstatus") or "").strip()
    rows = _as_rows(fields.get("tenzaifindings"))
    # The verdict's own findings (the matched exposure) vs. by-products discovered while testing the
    # host vs. unverified findings (no lead correlated). The Findings count and severity badges cover
    # only the exposure's OWN findings; discovered and unverified findings get their own labeled
    # sections below so they are never counted into this alert's verdict.
    own_rows = [row for row in rows if _attribution(row) == "own"]
    validated = _is_validated(fields.get("tenzaiissuevalidated"))
    credit = _format_credit(fields.get("tenzaicreditusage"))
    started_at = _format_started_at(fields.get("tenzaistartedat"))
    reference = str(fields.get("tenzaireferenceurl") or "").strip()
    rationale = str(fields.get("tenzaiissuerationale") or "").strip()
    cwe = str(fields.get("tenzaicwe") or "").strip()
    owasp = str(fields.get("tenzaiowasp") or "").strip()
    exposure_status = str(fields.get("tenzaiexposurestatus") or "").strip()

    if not status and not rows:
        return _empty_state(fields, name)

    if status and status != "Complete":
        return _status_panel(status, reference)

    # The verdict lives in the "Result" cell (Figma has no hero). A Blocked exposure reached the
    # target but every payload was stopped at the edge — no verdict was determined — so it renders
    # "—", NOT "Not Exploitable" (which would misread as "assessed and found safe"), even though the
    # SUCCESS-and-findings gate makes `validated` False on its zero findings.
    if exposure_status.strip().upper() == "BLOCKED":
        result_word, result_color = "—", DIM
    elif validated is True:
        result_word, result_color = "Exploitable", BLOOD
    elif validated is False:
        result_word, result_color = "Not Exploitable", OK
    else:
        result_word, result_color = "—", DIM

    # The Figma stat card is a FIXED five-cell grid: Result | Status | Findings | Started at |
    # Credit usage. Every cell always renders — an absent value shows "—" so the grid never
    # collapses to fewer columns. Status is the exposure lead's LITERAL status (Materialized /
    # Invalidated / Blocked), with NO fallback to the scan status (which would wrongly print
    # "Complete" when the lead status is missing); the Tenzai / agent-log links live in the header.
    tiles = [
        _tile("Result", result_word, result_color),
        _tile("Status", escape(_exposure_status_label(exposure_status)), INK),
        _tile("Findings", str(len(own_rows))),
        _tile("Started at", escape(started_at) if started_at else "—"),
        _tile("Credit usage", escape(credit) if credit else "—"),
    ]

    log_url = _agent_log_url(reference)
    complete_note = _status_note(f'<span style="color:{OK};">&#10003;</span> Assessment complete')
    # The CVE lead's Description/Conclusion rationale renders on both verdicts (after the findings
    # on the exploitable case; where the empty badge row would be on the not-exploitable case).
    below_strip = _sev_badges(_severity_counts(own_rows)) + _findings_list(rows, reference)
    return _panel(
        _header(_header_actions(reference, log_url, complete_note))
        + _classification(cwe, owasp)
        + _telemetry(tiles)
        + (f'<div style="padding:0 18px;">{below_strip}</div>' if below_strip else "")
        + (_rationale_block(rationale) if rationale else "")
    )


def main():
    try:
        incident = demisto.incident() or {}
        fields = incident.get("CustomFields") or {}
        html = build_summary_html(fields, name=str(incident.get("name") or ""))
        return_results({"ContentsFormat": EntryFormat.HTML, "Type": EntryType.NOTE, "Contents": html})
    except Exception as ex:
        return_error(f"Failed to execute TenzaiValidationSummary. Error: {ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

"""Unit tests for the TenzaiValidationSummary dynamic-section results panel."""

from TenzaiValidationSummary import _severity_counts, build_summary_html

FINDINGS = [{"finding": f"Medium finding {i}", "severity": "Medium", "detail": "x"} for i in range(6)] + [
    {"finding": f"Low finding {i}", "severity": "Low", "detail": "y"} for i in range(3)
]

COMPLETE_FIELDS = {
    "tenzaiassessmentstatus": "Complete",
    "tenzaiissuevalidated": "true",
    "tenzaicreditusage": 48.41,
    "tenzaireferenceurl": "https://app.tenzai.io/checks/abc",
    "tenzaifindings": FINDINGS,
}


def test_severity_counts_tallies_by_level():
    counts = _severity_counts(FINDINGS)
    assert counts["Medium"] == 6
    assert counts["Low"] == 3
    assert counts["High"] == 0
    assert counts["Critical"] == 0


def test_severity_counts_tolerates_emoji_and_case():
    counts = _severity_counts([{"severity": "🟠 High"}, {"severity": "critical"}, {"severity": "  Low  "}])
    assert counts["High"] == 1
    assert counts["Critical"] == 1
    assert counts["Low"] == 1


def test_build_summary_html_complete_validated():
    html = build_summary_html(COMPLETE_FIELDS)
    assert "Tenzai validation" in html
    assert "Assessment complete" in html
    # The verdict lives in the "Result" stat cell (Figma has no hero headline).
    assert ">Result<" in html
    assert "Exposure <span" not in html  # the old hero headline is gone
    assert "Exploitable" in html
    assert ">Exploit<" not in html  # the old Exploit cell is dropped (Figma stat card)
    # Severity renders as the Figma "Findings severity" badge row.
    assert "Findings severity" in html
    assert "48.41 ACU" in html
    assert "https://app.tenzai.io/checks/abc" in html
    assert "View in Tenzai" in html
    # The panel lists each finding (title) under a "Findings confirmed" section.
    assert "Findings confirmed" in html
    assert "Medium finding 0" in html
    assert "Low finding 0" in html
    # Findings render as expandable <details> disclosures (no separate grid).
    assert "<details" in html
    assert "<summary" in html
    # Styling must be inline CSS, never SVG/<style> (the entry sanitizer strips them).
    assert "<svg" not in html.lower()
    assert "<style" not in html.lower()


def test_finding_expands_to_all_sections_with_code():
    """A finding expands to Impact / Description / Reproduction / Fix guidance, and fenced code
    (script/config) renders inline as a monospace block — the full untruncated detail is still
    reachable via the Tenzai link."""
    detail = (
        "**Impact:** A MitM attacker can strip SSH extensions to force weaker signatures.\n\n"
        "The server offers chacha20-poly1305 and does not advertise strict-kex.\n\n"
        "## Reproduction\n\n**Steps:**\n1. Capture the KEXINIT\n2. Force chacha20\n\n"
        "```python\nimport socket  # SCRIPT_MARKER\nprint('exploit')\n```\n\n"
        "## Fix Guidance\n\nUpgrade OpenSSH to 9.6 or later."
    )
    fields = {**COMPLETE_FIELDS, "tenzaifindings": [{"finding": "Terrapin", "severity": "Medium", "detail": detail}]}
    html = build_summary_html(fields)
    assert "Terrapin" in html
    # All four section labels + their prose are present.
    for label in ("Impact", "Description", "Reproduction", "Fix guidance"):
        assert label in html
    assert "A MitM attacker can strip SSH extensions" in html  # impact
    assert "does not advertise strict-kex" in html  # description
    assert "Capture the KEXINIT" in html  # reproduction steps
    assert "Upgrade OpenSSH to 9.6" in html  # fix guidance
    # The fenced code now renders inline, inside a monospace <pre> block.
    assert "SCRIPT_MARKER" in html
    assert "import socket" in html
    assert "<pre" in html
    # The full detail is still reachable via the Tenzai link, and no raw markdown/fence leaks.
    assert "Full reproduction script &amp; fix in Tenzai" in html
    assert "**Impact" not in html
    assert "```" not in html


def test_findings_list_caps_at_max_and_notes_remainder():
    """A finding set larger than the cap shows the cap and calls out the remainder."""
    from TenzaiValidationSummary import MAX_PANEL_FINDINGS

    many = [{"finding": f"Finding {i}", "severity": "Low", "detail": "x"} for i in range(MAX_PANEL_FINDINGS + 3)]
    html = build_summary_html({**COMPLETE_FIELDS, "tenzaifindings": many})
    assert "+3 more findings" in html


def test_not_validated_zero_findings_has_no_findings_list():
    """No findings => no 'Findings confirmed' section (that case is handled elsewhere)."""
    html = build_summary_html({**COMPLETE_FIELDS, "tenzaiissuevalidated": "false", "tenzaifindings": []})
    assert "Findings confirmed" not in html


def test_build_summary_html_not_validated():
    html = build_summary_html({**COMPLETE_FIELDS, "tenzaiissuevalidated": "false"})
    assert "Not Exploitable" in html
    # Must not use the ambiguous "validated" wording in the verdict.
    assert "Not Validated" not in html


def test_build_summary_html_running_shows_status_not_verdict():
    html = build_summary_html({"tenzaiassessmentstatus": "Running", "tenzaifindings": []})
    assert "Running" in html
    assert "Exposure <span" not in html
    assert ">Result<" not in html  # the stat card only renders on the completed panel


def test_running_panel_links_to_live_agent_log():
    """While running, the panel links to the live Agent Log when a reference URL is present (ENG-5200)."""
    url = "https://app.tenzai.io/apps/a/tests/t/log"
    html = build_summary_html({"tenzaiassessmentstatus": "Running", "tenzaireferenceurl": url, "tenzaifindings": []})
    assert "Running" in html
    assert "follow the live" in html
    assert "View agent log" in html
    assert url in html
    assert 'target="_blank"' in html


def test_running_panel_without_reference_has_no_link():
    """No reference URL => the plain 'in progress' message and no link."""
    html = build_summary_html({"tenzaiassessmentstatus": "Running", "tenzaifindings": []})
    assert "Validation in progress" in html
    assert "View agent log" not in html
    assert "<a " not in html


def test_running_pill_is_bordered_not_filled():
    """ENG-7115: the Running chip matches Figma 66:1776 — a bordered dot+label chip,
    transparent fill, mixed-case (no uppercased filled pill), hyphen (not em-dash)."""
    html = build_summary_html({"tenzaiassessmentstatus": "Running", "tenzaifindings": []})
    assert "background:transparent" in html  # not a solid-filled pill
    assert "border:1px solid #29b2ff" in html  # Unity blue-500 outline
    assert "text-transform:uppercase" not in html  # keeps "Running", not "RUNNING"
    assert "&#8212;" not in html  # hyphen, not em-dash
    assert "follow the live" in html


def test_error_panel_links_to_tenzai_when_reference_present():
    """A non-terminal Error state offers a neutral 'View in Tenzai' link when a URL is present."""
    url = "https://app.tenzai.io/apps/a/tests/t/log"
    html = build_summary_html({"tenzaiassessmentstatus": "Error", "tenzaireferenceurl": url, "tenzaifindings": []})
    assert "Error" in html
    assert "View in Tenzai" in html
    assert url in html


def test_error_panel_keeps_filled_pill_appearance():
    """Error keeps its filled, uppercased pill; the 'View in Tenzai' link uses the shared
    cross-theme action-link color (LINK_ACCENT), not the Running blue chip."""
    url = "https://app.tenzai.io/apps/a/tests/t/log"
    html = build_summary_html({"tenzaiassessmentstatus": "Error", "tenzaireferenceurl": url, "tenzaifindings": []})
    assert "text-transform:uppercase" in html  # filled uppercased pill (unchanged)
    assert "background:#79828d" in html  # FAINT-filled pill, not a transparent chip
    assert "color:#1f83d6" in html  # LINK_ACCENT link, legible on light + dark
    assert "#29b2ff" not in html  # no Running restyle bleeds into Error
    assert "View agent log" not in html  # Error never shows the agent-log wording


RATIONALE = (
    "## Description\n\nCVE-2018-15473 affects OpenSSH through 7.7.\n\n"
    "## Conclusion\n\nCONFIRMED FALSE POSITIVE — not exploitable."
)


def test_rationale_block_renders_on_not_exploitable():
    """A CVE rationale shows an Exposure assessment block on the not-exploitable verdict (ENG-4910)."""
    html = build_summary_html(
        {**COMPLETE_FIELDS, "tenzaiissuevalidated": "false", "tenzaifindings": [], "tenzaiissuerationale": RATIONALE}
    )
    assert "Not Exploitable" in html
    assert "Exposure assessment" in html
    assert "Description" in html
    assert "Conclusion" in html
    assert "affects OpenSSH" in html
    assert "CONFIRMED FALSE POSITIVE" in html


def test_rationale_block_renders_on_exploitable_alongside_findings():
    """On the exploitable verdict the rationale block renders in addition to the findings list."""
    html = build_summary_html({**COMPLETE_FIELDS, "tenzaiissuerationale": RATIONALE})
    assert "Findings confirmed" in html  # findings list still present
    assert "Exposure assessment" in html  # and the rationale block
    assert "affects OpenSSH" in html


def test_no_rationale_block_when_field_absent():
    """No tenzaiissuerationale => no Exposure assessment block."""
    html = build_summary_html({**COMPLETE_FIELDS, "tenzaiissuevalidated": "false", "tenzaifindings": []})
    assert "Exposure assessment" not in html


def test_stat_card_cells_match_figma():
    """The completed panel renders the Figma stat card: Result | Status | Findings | Started at |
    Credit usage (a fixed five-cell grid). No hero, no Exploit/Duration/Verdict cells."""
    html = build_summary_html(COMPLETE_FIELDS)
    assert ">Result<" in html
    assert ">Status<" in html
    assert ">Findings<" in html
    assert ">Credit usage<" in html
    # Dropped by the Figma realignment:
    assert ">Verdict<" not in html
    assert ">Exploit<" not in html
    assert ">Duration<" not in html


def test_result_cell_verdicts():
    """The Result cell reads Exploitable / Not Exploitable / — for validated True / False / None."""
    exploitable = build_summary_html(COMPLETE_FIELDS)
    assert "Exploitable" in exploitable
    assert "Not Exploitable" not in exploitable
    not_exploitable = build_summary_html({**COMPLETE_FIELDS, "tenzaiissuevalidated": "false"})
    assert "Not Exploitable" in not_exploitable
    inconclusive = build_summary_html({**COMPLETE_FIELDS, "tenzaiissuevalidated": "", "tenzaifindings": []})
    assert "—" in inconclusive  # em-dash — no verdict


def test_blocked_result_is_dash_not_not_exploitable():
    """A BLOCKED exposure reached no verdict: Result is '—', never 'Not Exploitable' — even though
    the zero-finding SUCCESS gate makes `validated` False (Figma 88-2970). Status stays literal."""
    html = build_summary_html(
        {**COMPLETE_FIELDS, "tenzaiissuevalidated": "false", "tenzaifindings": [], "tenzaiexposurestatus": "BLOCKED"}
    )
    assert ">Result<" in html
    assert "—" in html  # Result shows the em-dash
    assert "Not Exploitable" not in html  # must NOT read as "assessed and found safe"
    assert ">Status<" in html
    assert "Blocked" in html  # literal lead status


def test_status_cell_shows_literal_lead_status():
    """The Status cell shows the lead's LITERAL status (Materialized / Invalidated), not the old
    Tenzai-side translation (Exploited / Not affected)."""
    materialized = build_summary_html({**COMPLETE_FIELDS, "tenzaiexposurestatus": "MATERIALIZED"})
    assert "Materialized" in materialized
    assert "Exploited" not in materialized
    invalidated = build_summary_html({**COMPLETE_FIELDS, "tenzaiissuevalidated": "false", "tenzaiexposurestatus": "INVALIDATED"})
    assert "Invalidated" in invalidated
    assert "Not affected" not in invalidated


def test_started_at_cell_formats_iso():
    """A stored ISO start timestamp renders in the Figma 'Started at' cell as 'Mon Dth YYYY HH:MM' (UTC)."""
    html = build_summary_html({**COMPLETE_FIELDS, "tenzaistartedat": "2026-08-17T19:13:46.192631Z"})
    assert ">Started at<" in html
    assert "Aug 17th 2026 19:13" in html


def test_stat_card_is_a_fixed_five_cell_grid():
    """All five Figma cells always render; absent Started at / Credit usage show '—' so the grid
    never collapses to fewer columns."""
    html = build_summary_html({k: v for k, v in COMPLETE_FIELDS.items() if k != "tenzaicreditusage"})
    for label in (">Result<", ">Status<", ">Findings<", ">Started at<", ">Credit usage<"):
        assert label in html
    # Started at and Credit usage are both absent here → both render the em-dash placeholder.
    assert html.count("—") >= 2


def test_started_at_cell_shows_dash_when_absent_or_unparseable():
    """No start timestamp (or an unparseable one) => the Started at cell renders '—', not omitted."""
    for fields in (COMPLETE_FIELDS, {**COMPLETE_FIELDS, "tenzaistartedat": "not-a-date"}):
        html = build_summary_html(fields)
        assert ">Started at<" in html
        assert "Aug " not in html  # no formatted date leaked


def test_status_cell_has_no_scan_status_fallback():
    """An absent lead status renders '—', never the scan status 'Complete' (literal-status rule)."""
    html = build_summary_html({**COMPLETE_FIELDS, "tenzaiexposurestatus": ""})
    assert ">Status<" in html
    # The Status cell must not print the assessment status word.
    assert "Complete<" not in html.split(">Status<", 1)[1][:200]


def test_severity_badges_show_all_levels():
    """The Figma 'Findings severity' badge row renders (all four levels, including zeros)."""
    html = build_summary_html(COMPLETE_FIELDS)
    assert "Findings severity" in html
    assert "Severity distribution" not in html  # the old proportional-bar label is gone


_MIXED_FINDINGS = [
    {"finding": "SQLi in login", "severity": "High", "detail": "x", "cve": "CVE-2023-44487", "attribution": "own"},
    {
        "finding": "CVE-2024-23897: Arbitrary File Read",
        "severity": "Critical",
        "detail": "y",
        "cve": "CVE-2024-23897",
        "attribution": "discovered",
    },
]

_UNATTRIBUTED_FINDINGS = [
    {
        "finding": "CVE-2024-23897: Arbitrary File Read",
        "severity": "High",
        "detail": "z",
        "cve": "CVE-2024-23897",
        "attribution": "unattributed",
    },
]


def test_discovered_finding_renders_in_its_own_section():
    """A discovered finding lists under 'Discovered during validation' with a Discovered tag,
    separate from the exposure's own 'Findings confirmed' section."""
    html = build_summary_html({**COMPLETE_FIELDS, "tenzaifindings": _MIXED_FINDINGS})
    assert "Findings confirmed" in html
    assert "Discovered during validation" in html
    assert ">Discovered<" in html  # the per-finding tag
    # The own finding is above the discovered section; the discovered CVE is not in the own section.
    own_section = html.split("Findings confirmed", 1)[1].split("Discovered during validation", 1)[0]
    assert "SQLi in login" in own_section
    assert "CVE-2024-23897" not in own_section


def test_unattributed_findings_render_in_unverified_section_and_are_not_counted():
    """With no correlated lead, findings render under 'correlation unverified' with an Unverified tag,
    are NOT counted in the Findings cell (0 own), and are absent from the confirmed section."""
    html = build_summary_html({**COMPLETE_FIELDS, "tenzaiissuevalidated": "", "tenzaifindings": _UNATTRIBUTED_FINDINGS})
    assert "correlation unverified" in html
    assert ">Unverified<" in html
    assert "Findings confirmed" not in html  # nothing is "own"
    findings_cell = html.split(">Findings<", 1)[1][:500]
    assert ">0</span>" in findings_cell  # zero own findings counted


def test_findings_count_and_badges_exclude_non_own():
    """The Findings cell and severity badges count only the exposure's own findings."""
    html = build_summary_html({**COMPLETE_FIELDS, "tenzaifindings": _MIXED_FINDINGS})
    # Findings cell reads 1 (one own finding), not 2. The value span follows the label span after a
    # long inline style, so slice generously past it.
    findings_cell = html.split(">Findings<", 1)[1][:500]
    assert ">1</span>" in findings_cell
    assert ">2</span>" not in findings_cell
    assert "Findings severity" in html


def test_no_extra_sections_when_all_findings_are_own():
    """With only own findings, neither the discovered nor the unverified section renders."""
    html = build_summary_html(COMPLETE_FIELDS)
    assert "Findings confirmed" in html
    assert "Discovered during validation" not in html
    assert "correlation unverified" not in html


def test_reference_and_agent_log_links_render_in_header():
    """Reference + agent log are header actions, not strip cells; the agent log derives /findings -> /log."""
    fields = {**COMPLETE_FIELDS, "tenzaireferenceurl": "https://app.tenzai.io/apps/a/tests/b/findings"}
    html = build_summary_html(fields)
    assert "View in Tenzai" in html
    assert "View agent log" in html
    assert "/apps/a/tests/b/log" in html


def test_verification_step_payload_renders_as_monospace_block():
    """A numbered step ending in ': `payload`' lifts the payload into its own code block."""
    rationale = "## Description\n\n1. Probe the host with a payload: `GET /cgi-bin/.%2e/etc/passwd HTTP/1.1`"
    html = build_summary_html({**COMPLETE_FIELDS, "tenzaiissuerationale": rationale})
    assert "GET /cgi-bin/.%2e/etc/passwd HTTP/1.1" in html


def test_hard_broken_lines_share_one_paragraph():
    """Markdown hard breaks (two trailing spaces) keep related lines in one <br>-joined paragraph,
    not one gapped paragraph per line — so header fields render tight like the Tenzai app."""
    rationale = (
        "## Description\n\n**CVE:** CVE-2024-23897  \n**Reported Severity:** Critical  \n**Affected Asset:** http://192.0.2.10:80"
    )
    html = build_summary_html({**COMPLETE_FIELDS, "tenzaiissuerationale": rationale})
    # The three fields are one paragraph joined by <br>, not three separate margin'd divs.
    assert "CVE-2024-23897<br>" in html
    assert "Reported Severity:</strong> Critical<br>" in html


def test_long_rationale_keeps_all_verification_steps():
    """A full exposure assessment (all 5 verification steps + preconditions) is not truncated, and
    truncation — when it does occur — lands on a whole-line boundary, never mid-step."""
    steps = "\n".join(f"{i}. Verification step number {i} with enough words to add length." for i in range(1, 6))
    rationale = f"## Description\n\n**Vulnerability Description:**  \nA long narrative. {'x ' * 200}\n\n{steps}"
    html = build_summary_html({**COMPLETE_FIELDS, "tenzaiissuerationale": rationale})
    for i in range(1, 6):
        assert f"Verification step number {i}" in html


def test_header_renders_logo_lockup():
    """The compact header renders the Tenzai logo (base64 <img>) beside the 'Tenzai validation'
    wordline; both are present."""
    from TenzaiValidationSummary import LOGO_DATA_URI

    html = build_summary_html(COMPLETE_FIELDS)
    assert "Tenzai validation" in html
    assert "<img" in html
    assert LOGO_DATA_URI in html
    assert 'alt="Tenzai"' in html
    # The mark is a raster data URI — inline <svg> is stripped by the entry sanitizer.
    assert "<svg" not in html.lower()


def test_panel_is_theme_adaptive_no_dark_fill():
    """The panel inherits the console theme (transparent surface + inherited ink) so it reads on
    the light Cortex shell — it must not paint the old hardcoded dark surface (ENG-7142)."""
    html = build_summary_html(COMPLETE_FIELDS)
    assert "#1a1e23" not in html  # no hardcoded dark panel fill
    assert "#15181c" not in html  # no hardcoded dark tile fill
    assert "color:inherit" in html  # text inherits the shell ink
    assert "background:transparent" in html


def test_status_panels_are_theme_adaptive():
    """Running and Error status panels also inherit the shell (no dark box) and render the
    thin-bordered card (ENG-7142)."""
    for status in ("Running", "Error"):
        html = build_summary_html({"tenzaiassessmentstatus": status, "tenzaifindings": []})
        assert "#1a1e23" not in html
        assert "background:transparent" in html
        assert "Tenzai validation" in html


def test_build_summary_html_empty_state():
    html = build_summary_html({}, name="CVE-2021-41773 vulnerability at HTTP Server at 192.0.2.10:80")
    # The empty state is the Figma pitch block, not a bare "not run yet" line.
    assert "Validate exposure using offensive agents" in html
    assert "https://www.tenzai.com/" in html
    # The "Assessment complete" note / verdict hero must not appear before a validation has run.
    assert "Assessment complete" not in html
    assert "Exposure <span" not in html


def test_empty_state_names_cve_and_host():
    html = build_summary_html(
        {"xdmvulnerabilitycveid": "CVE-2021-41773", "xdmtargethostipv4addresses": ["192.0.2.10"]},
        name="CVE-2021-41773 vulnerability at HTTP Server at 192.0.2.10:80",
    )
    assert "CVE-2021-41773" in html
    assert "192.0.2.10:80" in html


def test_empty_state_falls_back_to_name_without_cve():
    html = build_summary_html({}, name="Insecure NGINX Web Server (1.17.7) at 10.0.0.5:80")
    assert "Insecure NGINX Web Server (1.17.7) at 10.0.0.5:80" in html
    assert "reach and exploit" in html

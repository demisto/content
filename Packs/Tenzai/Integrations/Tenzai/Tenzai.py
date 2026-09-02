import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Tenzai Integration for Cortex.

Connects Cortex to the Tenzai agentic penetration-testing platform to validate
ASM-discovered exposures. This integration talks to Tenzai's first-party v1
APIs directly (applications / tests / findings): it maps one Cortex ASM
exposure to a find-or-create Tenzai **Application** (per domain) plus an
EXTERNAL_LEAD **scan** — a short, targeted confirm/refute of the single
externally-reported exposure — polls the scan to a terminal state, and reads
the verdict + evidence back out. A confirmed exposure becomes a Tenzai finding.
"""

from CommonServerUserPython import *  # noqa: F401

import re
from datetime import datetime, UTC
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# test-module probes this endpoint: a cheap, authenticated list. 200 => key ok.
TEST_ENDPOINT = "/v1/applications"

# Per-request HTTP timeout (seconds), overridable via the `timeout` instance
# param. Deliberately low: it MUST stay well under the StartAgenticValidation
# poll automation's execution timeout. That script's re-entry makes three
# sequential API calls (get_test + get_test_findings + get_test_leads), so a
# stalled host has to fail within ~3x this budget for the script's graceful
# "retry next tick" path to run — otherwise the whole automation is killed by a
# Docker timeout and the poll loop dies (this is what left issues stuck on
# "Running"). 3x20=60s stays well under the automation's 3m timeout. See ENG-5184.
DEFAULT_HTTP_TIMEOUT = 20

# Ports that imply an HTTP(S) web surface when no explicit type is supplied.
_WEB_PORTS = frozenset({80, 443, 8080, 8443})
_HTTP_PORTS = frozenset({80, 8080})

# HTTP-server product named in the free-text exposure name / issue description.
# Cortex ASM frequently reports a web server on a non-standard port (e.g. "HTTP
# Server ... on version(s) ['ApacheWebServer 2.4.41']" at :15580), which carries
# no http scheme and no known web port — so the scheme/port/classification checks
# miss it and it would fall through to NETWORK_SERVICE. Matching a concrete web-
# server *product* (not a bare http/https token) keeps such exposures WEB_APP and
# scanned over https://, while an unrelated https:// URL sitting in a description
# (e.g. an NVD reference on a PPTP exposure) does NOT trip it. Scheme/protocol are
# detected separately from the actual target — never from arbitrary description text.
# Only products that *imply* an HTTP surface are listed: web servers (apache/nginx/
# httpd/iis/…) and HTTP app servers (gunicorn/uvicorn/kestrel). General-purpose L4/L7
# proxies (haproxy, envoy) are deliberately excluded — they equally front raw TCP, so
# their presence is not evidence the exposed port speaks HTTP.
_WEB_PRODUCT_RE = re.compile(
    r"\b(?:"
    r"web[\s_-]*server|http[\s_-]*server|"
    r"apache(?:[\s_-]*web[\s_-]*server)?|"
    r"nginx(?:[\s_-]*web[\s_-]*server)?|"
    r"httpd|iis|tomcat|jetty|lighttpd|caddy|openresty|"
    r"gunicorn|uvicorn|kestrel|litespeed|traefik"
    r")\b",
    re.IGNORECASE,
)

# Base62 alphabet + fixed width the UI router uses to encode a UUID.
# Mirrors platform/common/utils.py::uuid_to_base62 and the UI's base62.utils.ts.
_BASE62_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_BASE62_UUID_LENGTH = 22

# Nested scan status (status.type, camelCase) -> coarse status the pack polls on.
# Keep polling while Pending|Running; treat Complete|Error as terminal.
_STATUS_MAP = {
    "PENDING": "Pending",
    "INITIALIZING": "Pending",
    "INPROGRESS": "Running",
    "PAUSED": "Running",
    "CANCELLING": "Running",
    "SUCCESS": "Complete",
    "ERROR": "Error",
    "TERMINATED": "Error",
    "CANCELED": "Error",
}

_APP_DESCRIPTION = "Auto-created from a Cortex ASM exposure validation."

# One leading bullet/number prefix to strip before we re-number a step, so we
# don't emit "1. 1. foo". Mirrors platform's finding_ticket_helpers._strip_step.
_STEP_PREFIX_RE = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)")


# ---------------------------------------------------------------------------
# base62 (ported from platform/common/utils.py)
# ---------------------------------------------------------------------------


def uuid_to_base62(uuid_value: str) -> str:
    """Encode a UUID to the 22-char base62 form the UI router uses.

    Known vector: ``0053254e-423e-4ac4-88f0-f0d22b92281d`` -> ``00bzrAULhh4ZlgSZbYKf3V``.
    Raises ``ValueError`` if the input is not a valid UUID hex string.
    """
    hex_str = str(uuid_value).replace("-", "").lower()
    if len(hex_str) != 32 or not all(c in "0123456789abcdef" for c in hex_str):
        raise ValueError(f"Invalid UUID: {uuid_value}")

    num = int(hex_str, 16)
    if num == 0:
        return "0" * _BASE62_UUID_LENGTH

    chars: list[str] = []
    while num > 0:
        chars.append(_BASE62_CHARS[num % 62])
        num //= 62

    return "".join(reversed(chars)).rjust(_BASE62_UUID_LENGTH, "0")


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class Client(BaseClient):
    """Client to interact with Tenzai's first-party v1 API.

    Implements API calls only; holds no Cortex/Demisto logic. Inherits from
    ``BaseClient`` (CommonServerPython), which handles proxy and SSL
    verification. Authentication is a bearer token sent in the
    ``Authorization`` header, wired in ``main`` and passed via ``headers``.
    """

    def test_connection(self) -> dict[str, Any]:
        """Probe a lightweight authenticated endpoint to validate connectivity + key."""
        return self._http_request(method="GET", url_suffix=TEST_ENDPOINT, params={"size": 1})

    def list_applications_by_name(self, name: str) -> dict[str, Any]:
        """List applications whose name *contains* ``name`` (API filter is contains, not exact)."""
        return self._http_request(method="GET", url_suffix="/v1/applications", params={"name": name, "size": 100})

    def create_application(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create an application. May raise a 422 when the name already exists (race)."""
        return self._http_request(method="POST", url_suffix="/v1/applications", json_data=payload)

    def create_test(self, app_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create a scan (test) under an application. Returns the created TestResponse."""
        return self._http_request(method="POST", url_suffix=f"/v1/applications/{app_id}/tests", json_data=payload)

    def get_test(self, test_id: str) -> dict[str, Any]:
        """Get a test/scan by id (TestResponse; status is nested under ``status.type``)."""
        return self._http_request(method="GET", url_suffix=f"/v1/tests/{test_id}")

    def get_test_findings(self, test_id: str) -> dict[str, Any]:
        """Get a test's findings (a fastapi Page: ``{items: [...], total, ...}``)."""
        return self._http_request(method="GET", url_suffix=f"/v1/tests/{test_id}/findings", params={"size": 100})

    def get_test_leads(self, test_id: str) -> dict[str, Any]:
        """Get a test's leads (a fastapi Page: ``{items: [...], total, ...}``).

        Leads are the agent's investigation hypotheses. For an EXTERNAL_LEAD scan
        there is one planner-seeded lead (``origin == "external"``) that carries the
        assessment narrative (``hypothesis``) and terminal verdict (``closedReason``).
        """
        return self._http_request(method="GET", url_suffix=f"/v1/tests/{test_id}/leads", params={"size": 100})


# ---------------------------------------------------------------------------
# Target parsing / app-type derivation / target-url building
# ---------------------------------------------------------------------------


def _parse_target(target: str) -> tuple[str, int | None, str]:
    """Parse a target into ``(host, port, scheme)``.

    Accepts a URL (``https://host:port/path``), a ``host:port`` pair, or a bare
    host/IP. ``host`` is lowercased (it is the per-domain dedupe key);
    ``port``/``scheme`` are ``None``/``""`` when absent. Raises ValueError when
    no host can be parsed.
    """
    raw = (target or "").strip()
    if not raw:
        raise ValueError("target is required")
    # urlparse needs a netloc; prepend "//" for schemeless host[:port] inputs.
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = (parsed.hostname or "").strip().rstrip(".")
    if not host:
        raise ValueError(f"Could not derive a host from target: {target!r}")
    return host.lower(), parsed.port, (parsed.scheme or "").lower()


def _derive_app_type(
    explicit_type: str | None,
    *,
    scheme: str,
    port: int | None,
    service_classification: str | None,
    protocol: str | None,
    hints: str | None = None,
) -> str:
    """Use the explicit type if given, else infer the app type.

    ``hints`` is free text (the exposure name + issue description) that Cortex ASM
    supplies for the exposure. An HTTP-server product named there (e.g. "HTTP
    Server … ApacheWebServer 2.4.41") classifies the exposure as WEB_APP even on a
    non-standard port that isn't in ``_WEB_PORTS`` — otherwise such a web exposure
    falls through to NETWORK_SERVICE and gets scanned as a raw socket.
    """
    if explicit_type:
        return explicit_type

    classification = (service_classification or "").lower()
    proto = (protocol or "").lower()
    if (
        scheme in {"http", "https"}
        or "web" in classification
        or "http" in classification
        or proto in {"http", "https"}
        or port in _WEB_PORTS
        or bool(_WEB_PRODUCT_RE.search(hints or ""))
    ):
        return "WEB_APP"
    # An explicit tcp/udp scheme or any specific socket (port) => network service.
    if scheme in {"tcp", "udp"} or port is not None:
        return "NETWORK_SERVICE"
    # No port, no service signal => a bare host.
    return "NETWORK_HOST"


def _build_target_url(host: str, app_type: str, port: int | None, protocol: str, scheme: str = "") -> str:
    """Build the single scan target in the form each app type's validator expects.

    WEB_APP -> ``https://host[:port]``; NETWORK_SERVICE -> ``tcp://host:port``
    (or ``udp://``); NETWORK_HOST -> bare ``host``.
    """
    if app_type == "WEB_APP":
        if protocol in {"http", "https"}:
            chosen = protocol
        elif scheme in {"http", "https"}:
            chosen = scheme
        elif port in _HTTP_PORTS:
            chosen = "http"
        else:
            chosen = "https"
        return f"{chosen}://{host}:{port}" if port else f"{chosen}://{host}"
    if app_type == "NETWORK_SERVICE":
        if not port:
            raise ValueError("A NETWORK_SERVICE exposure requires a port to build a tcp://host:port target")
        chosen = "udp" if protocol == "udp" or scheme == "udp" else "tcp"
        return f"{chosen}://{host}:{port}"
    # NETWORK_HOST
    return host


# ---------------------------------------------------------------------------
# Guidelines synthesis (CREATE only)
# ---------------------------------------------------------------------------


def _synthesize_app_guidelines(args: dict[str, Any]) -> dict[str, Any]:
    """Structured app guidelines: focus on the exposure, lock scope to one socket.

    Folds in the Cortex issue ``issue_description`` and any ASM correlation ids.
    Applied at app CREATE only; when reusing an existing app we keep its
    guidelines untouched.
    """
    exposure_name = args.get("exposure_name")
    supporting_data = args.get("supporting_data")
    service_classification = args.get("service_classification")
    issue_description = args.get("issue_description")
    asm_service_id = args.get("asm_service_id")
    alert_internal_id = args.get("alert_internal_id")

    focus_parts = [f"Validate the externally-reported exposure: {exposure_name}."]
    if supporting_data:
        focus_parts.append(f"Supporting data from Cortex ASM:\n{supporting_data}")
    if service_classification:
        focus_parts.append(f"Service classification: {service_classification}.")
    if issue_description:
        focus_parts.append(f"Cortex issue description:\n{issue_description}")

    correlation = [
        f"{label}={value}"
        for label, value in (("asm_service_id", asm_service_id), ("alert_internal_id", alert_internal_id))
        if value
    ]

    guidelines: dict[str, Any] = {
        "focusArea": "\n\n".join(focus_parts),
        "outOfScope": (
            "Scope is locked to the single socket/target from the Cortex ASM exposure. "
            "Do not pivot to other hosts, ports, or services."
        ),
    }
    if correlation:
        guidelines["additional"] = "Cortex correlation: " + ", ".join(correlation) + "."
    return guidelines


def _external_lead_category(args: dict[str, Any], cve_id: str | None) -> str:
    """Classify the exposure as a CVE or a misconfiguration for the EXTERNAL_LEAD profile.

    Prefers an explicit ``category`` arg (a structured Cortex signal); otherwise
    infers from whether a ``cve_id`` is present. A CVE lead is only meaningful with
    an identifier, so ``cve`` is emitted only when a ``cve_id`` accompanies it —
    an explicit ``category=cve`` without one degrades to ``misconfiguration`` (a
    direct probe) rather than an id-less CVE objective. No free-text parsing.
    """
    explicit = (args.get("category") or "").strip().lower()
    if explicit == "misconfiguration":
        return explicit
    if explicit == "cve" or cve_id:
        return "cve" if cve_id else "misconfiguration"
    return "misconfiguration"


def _build_external_lead_profile(args: dict[str, Any], target_url: str, port: int | None) -> dict[str, Any]:
    """Build the EXTERNAL_LEAD ``profileConfig`` from the Cortex exposure reference.

    Maps the exposure onto the first-party profile (camelCase wire keys). The four
    required fields (``alertId``, ``title``, ``category``, ``target``) always
    resolve to a non-empty value; optional fields are included only when present and
    valid (``port`` is dropped unless it is an in-range 0..65535 int, matching the
    server-side constraint).
    """
    exposure_name = args.get("exposure_name") or "ASM Exposure"
    cve_id = args.get("cve_id") or None
    category = _external_lead_category(args, cve_id)

    # alertId is required and should correlate the lead back to its source: prefer
    # the Cortex issue id, then the ASM service id, and only fall back to the
    # exposure name when no real identifier was supplied.
    alert_id = args.get("alert_internal_id") or args.get("asm_service_id") or exposure_name
    in_range_port = port if isinstance(port, int) and not isinstance(port, bool) and 0 <= port <= 65535 else None

    # The API's category enum is upper-case (``CVE`` / ``MISCONFIGURATION``); keep the
    # lower-case token internally for the ``cveId`` gate below, but emit upper-case on the wire.
    profile: dict[str, Any] = {
        "profile": "EXTERNAL_LEAD",
        "alertId": alert_id,
        "title": exposure_name,
        "category": category.upper(),
        "target": target_url,
    }
    optional = {
        "cveId": cve_id if category == "cve" else None,
        "ruleId": args.get("rule_id"),
        "port": in_range_port,
        "severity": args.get("severity"),
        "cwe": args.get("cwe"),
        "description": args.get("issue_description"),
        "supportingEvidence": args.get("supporting_data"),
    }
    profile.update({k: v for k, v in optional.items() if v not in (None, "")})
    return profile


def _synthesize_scan_guidelines(args: dict[str, Any]) -> str:
    """Free-text scan guidelines mirroring the focus + single-socket scope lock.

    Analyst-supplied ``guidelines`` are appended as their own section rather than
    replacing the synthesized text: the exposure focus and the scope lock must
    survive whatever the analyst types.
    """
    parts = [f"Validate the externally-reported exposure: {args.get('exposure_name')}."]
    if args.get("supporting_data"):
        parts.append(f"Supporting data: {args.get('supporting_data')}")
    if args.get("issue_description"):
        parts.append(f"Cortex issue description: {args.get('issue_description')}")
    analyst_guidelines = (args.get("guidelines") or "").strip()
    if analyst_guidelines:
        parts.append(f"Analyst guidelines:\n{analyst_guidelines}")
    parts.append("Scope is locked to the single target above; do not pivot to other hosts, ports, or services.")
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Find-or-create (per-domain idempotency)
# ---------------------------------------------------------------------------


def _find_app_by_exact_name(client: Client, domain: str) -> dict[str, Any] | None:
    """Case-insensitive EXACT-name lookup.

    The API's ``name`` filter is *contains*, so we fetch candidates then filter
    for an exact (case-insensitive) match on ``name``.
    """
    page = client.list_applications_by_name(domain)
    for app in page.get("items") or []:
        if (app.get("name") or "").lower() == domain.lower():
            return app
    return None


def _find_or_create_app(client: Client, domain: str, app_type: str, target_url: str, args: dict[str, Any]) -> dict[str, Any]:
    """Reuse the app for this domain, or create it. Resilient to the create race."""
    existing = _find_app_by_exact_name(client, domain)
    if existing is not None:
        return existing

    payload = {
        "applicationType": app_type,
        "name": domain,
        "description": _APP_DESCRIPTION,
        "targets": [{"url": target_url}],
        "guidelines": _synthesize_app_guidelines(args),
    }
    try:
        return client.create_application(payload)
    except DemistoException as e:
        # A concurrent trigger (or a prior partial run) created the same-domain
        # app between our lookup and this insert — the unique lower(name) index
        # rejects it with a 422. Re-GET and reuse the winner.
        message = str(e)
        if "422" in message or "already exists" in message:
            found = _find_app_by_exact_name(client, domain)
            if found is not None:
                return found
        # An older Tenzai backend (pre-ENG-3501) doesn't know the NETWORK_HOST /
        # NETWORK_SERVICE application types and rejects them with a raw pydantic
        # 422. Surface an actionable message instead of the cryptic API error —
        # do NOT silently retry as WEB_APP (that would mis-scan a real non-HTTP
        # service over http://).
        if "not a valid ApplicationType" in message or "valid ApplicationType" in message:
            raise DemistoException(
                f"The Tenzai API rejected application type '{app_type}'. This exposure needs "
                f"the '{app_type}' type, which the connected Tenzai instance does not support "
                "(it predates the Host / Network-Service types). Upgrade the Tenzai API instance "
                "this integration points at, or validate this exposure as a WEB_APP if it is an "
                "HTTP service."
            ) from e
        raise


# ---------------------------------------------------------------------------
# Status mapping
# ---------------------------------------------------------------------------


def _map_status(scan: dict[str, Any]) -> str:
    """Map a test's nested ``status.type`` to the coarse status (default Error)."""
    status_type = ((scan.get("status") or {}).get("type") or "").upper()
    return _STATUS_MAP.get(status_type, "Error")


# ---------------------------------------------------------------------------
# Markdown rendering helpers (ported from validation_service.py)
# ---------------------------------------------------------------------------


def _strip_step(step: str) -> str:
    """Strip one leading bullet/number prefix so re-numbering doesn't produce ``1. 1. foo``."""
    return _STEP_PREFIX_RE.sub("", step).strip()


def _fenced_code(body: str, language: str) -> list[str]:
    """Wrap ``body`` in a backtick fence long enough to survive any backtick run inside it."""
    longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}{language}", body, fence]


def _ordered_item(number: int, text: str) -> list[str]:
    """Render ``text`` as a single markdown ordered-list item ``number. text``.

    Continuation lines are indented to the marker width so multi-line content
    and double-digit positions stay inside the list under CommonMark.
    """
    marker = f"{number}. "
    indent = " " * len(marker)
    body = text.split("\n")
    return [f"{marker}{body[0]}", *(f"{indent}{line}" if line else "" for line in body[1:])]


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Per-finding attribution relative to the matched exposure lead.
ATTR_OWN = "own"  # this alert's own exposure (finding CVE matches the matched lead, or lead has no CVE)
ATTR_DISCOVERED = "discovered"  # a different CVE found while testing the host — a validation by-product
ATTR_UNATTRIBUTED = "unattributed"  # no lead correlated to the alert, so ownership cannot be established


def _finding_cve(finding: dict[str, Any]) -> str | None:
    """Best-effort CVE id parsed from a finding's structured field or its name.

    DISPLAY ONLY — used to attribute a finding relative to the matched exposure's CVE. It is
    deliberately NOT used for lead correlation: the findings API exposes no structured
    ``cve``/``leadId``, so name parsing is the only signal available, and a fragile signal must
    never drive which verdict an alert shows.
    """
    structured = (finding.get("cve") or finding.get("cveId") or "").strip()
    if structured:
        return structured.upper()
    match = _CVE_RE.search(str(finding.get("name") or ""))
    return match.group(0).upper() if match else None


def _finding_attribution(correlation_known: bool, lead_cve: str | None, finding_cve: str | None) -> str:
    """Classify a finding relative to the matched exposure lead (own / discovered / unattributed).

    - No lead correlated to the alert => ``unattributed``: we cannot claim the finding is this
      alert's own exposure, so it is neither counted into the verdict nor treated as a discovery.
    - A CVE that differs from the matched lead's CVE => ``discovered`` (a by-product of testing).
    - Otherwise (matching CVE, or a misconfiguration lead that carries no CVE) => ``own``.
    """
    if not correlation_known:
        return ATTR_UNATTRIBUTED
    if lead_cve and finding_cve and finding_cve != lead_cve:
        return ATTR_DISCOVERED
    return ATTR_OWN


def _finding_name(finding: dict[str, Any]) -> str:
    return finding.get("name") or "Finding"


def _finding_severity(finding: dict[str, Any]) -> str:
    """The finding's severity, uppercased (grid label)."""
    severity = finding.get("severity")
    return str(severity).strip().upper() if severity else ""


def _finding_details(finding: dict[str, Any]) -> str | None:
    """Impact-first then description body for one finding (no header/severity)."""
    parts: list[str] = []
    impact = (finding.get("impact") or "").strip()
    description = (finding.get("description") or "").strip()
    if impact:
        parts.append(f"**Impact:** {impact}")
    if description:
        parts.append(description)
    return "\n\n".join(parts) or None


def _finding_reproduction(finding: dict[str, Any]) -> str | None:
    """Reproduction body for one finding: prerequisites + steps + scripts.

    Sensitive parameter defaults already arrive as the literal ``[REDACTED]``
    from the API — the platform never serves the real value.
    """
    parts: list[str] = []
    prerequisites = finding.get("prerequisites") or []
    if prerequisites:
        parts.append("**Prerequisites:**")
        parts.extend(f"- {item}" for item in prerequisites)
        parts.append("")

    steps = [stripped for stripped in (_strip_step(s) for s in (finding.get("steps") or [])) if stripped]
    if steps:
        parts.append("**Steps:**")
        for i, step in enumerate(steps, start=1):
            parts.extend(_ordered_item(i, step))
        parts.append("")

    reproduction = finding.get("reproduction") or {}
    scripts = reproduction.get("scripts") or []
    if scripts:
        parameters = reproduction.get("parameters") or []
        if parameters:
            parts.append("**Parameters:**")
            parts.extend(f"- `{p.get('name')}` = `{p.get('defaultValue')}`" for p in parameters)
            parts.append("")
        for script in scripts:
            language = (script.get("language") or "").lower()
            parts.extend([*_fenced_code((script.get("script") or "").rstrip(), language), ""])

    if not parts:
        return None
    return "\n".join(parts).rstrip()


def _finding_guidance(finding: dict[str, Any]) -> str | None:
    """Remediation body for one finding: items (in order) + coding-agent prompt.

    The finding response's ``remediation.items`` are already ordered (position
    is dropped at the schema level), so we number them sequentially.
    """
    remediation = finding.get("remediation") or {}
    items = remediation.get("items") or []
    prompt = (remediation.get("codingAgentPrompt") or "").strip()
    if not items and not prompt:
        return None

    parts: list[str] = []
    for i, item in enumerate(items, start=1):
        block = f"**{item.get('title') or ''}**"
        description = item.get("description")
        if description:
            block += "\n\n" + description
        parts.extend(_ordered_item(i, block))
    if prompt:
        parts.extend(["", "**Coding-agent prompt:**", "", prompt])
    return "\n".join(parts).rstrip()


def _render_evidence_markdown(scan: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    """Render a markdown summary of the scan's confirmed findings (status-aware when none)."""
    if not findings:
        if ((scan.get("status") or {}).get("type") or "").upper() == "SUCCESS":
            return "No exploitable findings were confirmed for this exposure."
        return "_The validation scan has not produced a confirmed verdict yet._"

    lines = ["## Confirmed findings", ""]
    for finding in findings:
        lines.append(f"### {_finding_name(finding)}")
        lines.append(f"- **Severity:** {_finding_severity(finding)}")
        details = _finding_details(finding)
        if details:
            lines.extend(["", details])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_reproduction_markdown(findings: list[dict[str, Any]]) -> str | None:
    """Per finding: prepend the ``### name`` header, concatenate under ``## Reproduction``."""
    sections: list[str] = []
    for finding in findings:
        body = _finding_reproduction(finding)
        if body:
            sections.extend([f"### {_finding_name(finding)}", "", body, ""])
    if not sections:
        return None
    return ("## Reproduction\n\n" + "\n".join(sections)).rstrip() + "\n"


def _render_guidance_markdown(findings: list[dict[str, Any]]) -> str | None:
    """Per finding: prepend the ``### name`` header, concatenate under ``## Remediation guidance``."""
    sections: list[str] = []
    for finding in findings:
        body = _finding_guidance(finding)
        if body:
            sections.extend([f"### {_finding_name(finding)}", "", body, ""])
    if not sections:
        return None
    return ("## Remediation guidance\n\n" + "\n".join(sections)).rstrip() + "\n"


def _finding_detail_markdown(details: str | None, reproduction: str | None, guidance: str | None) -> str:
    """Combine a finding's details + reproduction + fix guidance into one markdown blob."""
    sections: list[str] = []
    if details:
        sections.append(details.strip())
    if reproduction:
        sections.append(f"## Reproduction\n\n{reproduction.strip()}")
    if guidance:
        sections.append(f"## Fix Guidance\n\n{guidance.strip()}")
    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def test_module(client: Client) -> str:
    """Test API connectivity and authentication.

    Returns ``'ok'`` when the integration can reach Tenzai and the API key is
    accepted. Auth failures are translated into a readable message.
    """
    try:
        client.test_connection()
    except DemistoException as e:
        message = str(e)
        if "Unauthorized" in message or "Forbidden" in message or "401" in message or "403" in message:
            return "Authorization Error: make sure the Tenzai API Key is correctly set."
        raise
    return "ok"


def _derive_app_url(api_url: str) -> str | None:
    """Derive the Tenzai web-app URL from the API URL, or ``None`` when the host
    shape is unrecognised.

    The two hosts mirror each other on every Tenzai environment, so the app URL is
    inferable when the optional ``frontend_url`` param is not configured:

    * ``api.tenzai.io`` / ``api.dev.tenzai.io`` -> ``app.<rest>`` (leading label)
    * ``eu.api.tenzai.io`` -> ``eu.tenzai.io`` (shard label first, ``api`` second -> drop ``api``)

    Anything else returns ``None`` rather than a guess: a wrong link is worse than
    no link, so an unfamiliar host keeps the pre-derivation behaviour.
    """
    parsed = urlparse(api_url if "://" in api_url else f"https://{api_url}")
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    labels = host.split(".")
    if labels[0] == "api" and len(labels) > 1:
        app_host = ".".join(["app"] + labels[1:])
    elif len(labels) > 2 and labels[1] == "api":
        app_host = ".".join([labels[0]] + labels[2:])
    else:
        return None
    netloc = f"{app_host}:{parsed.port}" if parsed.port else app_host
    return f"{parsed.scheme or 'https'}://{netloc}"


def _resolve_frontend_url() -> str:
    """The Tenzai web-app base URL: the explicit ``frontend_url`` param when set,
    otherwise derived from the API URL. Empty string when neither is available."""
    configured = (demisto.params().get("frontend_url") or "").strip().rstrip("/")
    if configured:
        return configured
    return (_derive_app_url((demisto.params().get("url") or "").strip()) or "").rstrip("/")


def _build_reference_url(scan_id: str, application_id: str | None, tab: str) -> str | None:
    """Build the Tenzai UI URL for a scan's ``tab`` view, or ``None`` if not derivable.

    ``tab`` is the test-detail route segment: ``log`` for the live agent-activity
    view (linked while a scan is running) or ``findings`` for the terminal verdict.
    Needs a web-app base URL (the ``frontend_url`` param, else derived from the API
    URL) and a known application id; a missing base or an unparseable id degrades to
    ``None`` (no link) rather than raising.
    """
    frontend_url = _resolve_frontend_url()
    if not frontend_url or not application_id:
        return None
    try:
        return f"{frontend_url}/apps/{uuid_to_base62(application_id)}/tests/{uuid_to_base62(scan_id)}/{tab}"
    except ValueError:
        return None


def create_scan_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Map a Cortex exposure -> find-or-create app + EXTERNAL_LEAD scan.

    Triggers a short, targeted confirm/refute of the single externally-reported
    exposure. Outputs the scan id, application id, and initial status under
    ``Tenzai.Scan``.
    """
    host, target_port, target_scheme = _parse_target(str(args.get("target") or ""))
    port = arg_to_number(args.get("port"))
    if port is None:
        port = target_port
    app_type = _derive_app_type(
        args.get("application_type"),
        scheme=target_scheme,
        port=port,
        service_classification=args.get("service_classification"),
        protocol=args.get("protocol"),
        hints=f"{args.get('exposure_name') or ''}\n{args.get('issue_description') or ''}",
    )
    target_url = _build_target_url(host, app_type, port, (args.get("protocol") or "").lower(), target_scheme)

    app = _find_or_create_app(client, host, app_type, target_url, args)
    app_id = str(app.get("id"))

    # NOTE: do not send ``targets`` here — targets are owned by the application
    # (set at create above) and the API rejects a test that tries to override them
    # (422 "Test targets are managed by the application and cannot be overridden").
    # The test inherits the app's target.
    lead_profile = _build_external_lead_profile(args, target_url, port)
    scan_payload = {
        "name": args.get("exposure_name"),
        "guidelines": _synthesize_scan_guidelines(args),
        "profileConfig": lead_profile,
        "trigger": "MANUAL",
    }
    scan = client.create_test(app_id, scan_payload)

    outputs = {
        "id": scan.get("id"),
        "applicationId": scan.get("applicationId") or app_id,
        "status": _map_status(scan),
    }
    # Echo the correlation keys the lead was seeded with so the caller can re-supply them to
    # ``tenzai-get-scan-result`` (which later runs with only the scan id). Without this the result
    # command cannot scope the verdict to this alert's lead on a multi-lead host scan.
    for out_key, seed_key in (("alertId", "alertId"), ("cve", "cveId"), ("ruleId", "ruleId")):
        seeded = lead_profile.get(seed_key)
        if seeded not in (None, ""):
            outputs[out_key] = seeded
    # Live agent-activity ("Agent log") URL so the Running panel can link straight
    # into the scan in flight; omitted when frontend_url is not configured.
    reference_url = _build_reference_url(str(outputs["id"]), outputs["applicationId"], "log")
    if reference_url:
        outputs["referenceUrl"] = reference_url
    readable = tableToMarkdown(
        "Tenzai Scan Created",
        {
            "Scan ID": outputs["id"],
            "Application ID": outputs["applicationId"],
            "Status": outputs["status"],
            "Target": target_url,
            "Reference URL": reference_url,
        },
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="Tenzai.Scan",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable,
        raw_response=scan,
    )


@polling_function(
    name="tenzai-get-scan",
    interval=arg_to_number(demisto.args().get("interval_in_seconds", 60)),
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", 3600)),
    requires_polling_arg=False,  # always polls by default (polling=true)
)
def get_scan_command(args: dict[str, Any], client: Client) -> PollResult:
    """Poll a Tenzai scan until it reaches a terminal state.

    Reschedules while Pending/Running; resolves on Complete/Error.
    """
    scan_id = str(args.get("id"))
    scan = client.get_test(scan_id)
    status = _map_status(scan)
    outputs = {"id": scan_id, "status": status}

    if status in ("Pending", "Running"):
        return PollResult(
            response=None,
            partial_result=CommandResults(
                outputs_prefix="Tenzai.Scan",
                outputs_key_field="id",
                readable_output=f"Waiting for Tenzai scan {scan_id} to finish (status: {status})...",
            ),
            continue_to_poll=True,
            args_for_next_run={"id": scan_id, **args},
        )

    command_results = CommandResults(
        outputs_prefix="Tenzai.Scan",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=tableToMarkdown("Tenzai Scan Status", outputs, removeNull=True, headerTransform=string_to_table_header),
        raw_response=scan,
    )
    return PollResult(response=command_results, continue_to_poll=False)


def _norm(value: Any) -> str:
    """Trim + casefold a candidate identifier for equality matching (empty -> '')."""
    return str(value or "").strip().casefold()


def _unique_match(leads: list[dict[str, Any]], key: str, wanted: str) -> dict[str, Any] | None:
    """Return the sole lead whose ``key`` equals ``wanted`` — or ``None`` if 0 or >1 match.

    Uniqueness is the whole point: a host scan can carry sibling leads that share a value
    (e.g. two leads for the same CVE), so a key that selects more than one lead is NOT a
    safe correlation and must be rejected rather than resolved to an arbitrary ``[0]``.
    """
    if not wanted:
        return None
    hits = [lead for lead in leads if _norm(lead.get(key)) == wanted]
    return hits[0] if len(hits) == 1 else None


def _match_lead_to_alert(
    leads: list[dict[str, Any]],
    alert_id: str | None,
    cve: str | None,
    rule_id: str | None,
) -> dict[str, Any] | None:
    """Correlate the exposure lead to *this* Cortex alert, or ``None`` when unresolved.

    Match precedence, each accepted only when it selects EXACTLY ONE lead:
      1. ``alertId`` — the strongest key (the lead was seeded with the originating alert id).
      2. ``cve`` + ``ruleId`` together — a composite that disambiguates same-CVE siblings.
      3. ``cve`` alone — last structured resort (skipped when the CVE is not unique).
    A sole lead on the scan is a safe fallback only when NO correlation keys were supplied
    (nothing to disambiguate against); if keys were supplied and none matched, that is a
    real miss and must return ``None`` — never borrow a sibling lead's verdict. Selection is
    on STRUCTURED lead fields only; finding-name CVE parsing is display-only, never here.
    """
    alert_id_n, cve_n, rule_id_n = _norm(alert_id), _norm(cve), _norm(rule_id)

    match = _unique_match(leads, "alertId", alert_id_n)
    if match is not None:
        return match

    if cve_n and rule_id_n:
        composite = [lead for lead in leads if _norm(lead.get("cve")) == cve_n and _norm(lead.get("ruleId")) == rule_id_n]
        if len(composite) == 1:
            return composite[0]

    match = _unique_match(leads, "cve", cve_n)
    if match is not None:
        return match

    # No correlation keys at all -> a sole lead is unambiguous and safe to use. Any supplied
    # key that failed to resolve is a miss (ambiguous or absent), so we return None.
    if not (alert_id_n or cve_n or rule_id_n):
        return leads[0] if len(leads) == 1 else None
    return None


def _validated_from_status(exposure_status: str | None) -> bool | None:
    """Map the matched lead's terminal status to the tri-state ``validated`` verdict.

    MATERIALIZED -> True (exploit confirmed), INVALIDATED -> False (assessed, not exploitable),
    everything else (BLOCKED / OPEN / IN_PROGRESS / unknown / unmatched) -> ``None`` (no verdict).
    BLOCKED explicitly must NOT read as False: the target was reached but payloads stopped at the
    edge, so no exploitability verdict was determined. Lead-scoped, replacing the old test-scoped
    ``SUCCESS and len(findings) > 0`` gate that answered "did the host scan find anything".
    """
    key = _norm(exposure_status).upper()
    if key == "MATERIALIZED":
        return True
    if key == "INVALIDATED":
        return False
    return None


def _render_lead_rationale_markdown(lead: dict[str, Any] | None) -> str | None:
    """Render a CVE lead's assessment narrative + verdict as markdown, or ``None``.

    Only CVE (vulnerability) leads get a rationale block — a CVE lead is the one with a
    structured ``cve`` set (misconfiguration leads have none). ``hypothesis`` is the
    DESCRIPTION narrative; ``closedReason`` is the terminal CONCLUSION (absent until the
    lead is closed). Returns ``None`` when the lead is not a CVE lead or carries no text.
    """
    if not lead or not (lead.get("cve") or "").strip():
        return None
    description = (lead.get("hypothesis") or "").strip()
    conclusion = (lead.get("closedReason") or "").strip()
    sections: list[str] = []
    if description:
        sections.append(f"## Description\n\n{description}")
    if conclusion:
        sections.append(f"## Conclusion\n\n{conclusion}")
    return "\n\n".join(sections) or None


def _format_timeline_ts(value: Any) -> str:
    """ISO-8601 timestamp -> compact ``MM-DD HH:MM:SS`` via slicing; raw fallback if unexpected."""
    raw = str(value or "").strip()
    if len(raw) >= 19 and raw[10:11] == "T":
        return f"{raw[5:10]} {raw[11:19]}"
    return raw


def _timeline_rows(lead: dict[str, Any]) -> list[dict[str, str]]:
    """Rows for the Tenzai Timeline grid from the lead's ``statusHistory`` (chronological)."""
    rows: list[dict[str, str]] = []
    for entry in lead.get("statusHistory") or []:
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status") or "").strip()
        if status:
            rows.append({"status": status, "time": _format_timeline_ts(entry.get("timestamp"))})
    return rows


def _parse_iso_utc(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp into a tz-aware UTC ``datetime``, or ``None``.

    Tolerates a trailing ``Z`` and fractional seconds; a naive value is assumed UTC.
    """
    raw = value.strip()
    if not raw:
        return None
    iso = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC)


def _lead_started_at(lead: dict[str, Any]) -> str | None:
    """The assessment's start timestamp, as the FULL ISO-8601 string (no truncation).

    The assessment start is the exposure lead's ``OPEN`` transition — the earliest one, chosen by
    PARSED timestamp rather than trusting API/list order. A non-OPEN status is never treated as the
    start (a lead can be created directly IN_PROGRESS/BLOCKED with no meaningful start). Unlike
    ``_format_timeline_ts`` (which drops the year for the compact grid), this keeps the raw ISO so
    the panel can render a real "Started at" date. Returns ``None`` when no timestamped OPEN entry
    exists (the panel then renders the cell as "—").
    """
    opens: list[tuple[datetime, str]] = []
    for entry in lead.get("statusHistory") or []:
        if not isinstance(entry, dict) or str(entry.get("status") or "").strip().upper() != "OPEN":
            continue
        ts = str(entry.get("timestamp") or "").strip()
        parsed = _parse_iso_utc(ts)
        if parsed is not None:
            opens.append((parsed, ts))
    if not opens:
        return None
    return min(opens, key=lambda pair: pair[0])[1]


def get_scan_result_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """Fetch the verdict + evidence of a completed Tenzai scan, scoped to the alert's own lead.

    The verdict fields (``validated``, ``exposureStatus``, ``cwe``, ``owaspCategory``, ``timeline``,
    ``startedAt``) all derive from the ONE exposure lead correlated to this alert (by ``alertId``,
    then ``cve`` + ``ruleId``); ``validated`` is that lead's terminal status mapped to a tri-state
    (MATERIALIZED->true / INVALIDATED->false / else None) — NOT the old test-wide "SUCCESS and any
    finding" gate. The scan-level narrative (``evidence`` / ``reproduction`` / ``guidance``) is
    rendered from the matched exposure's OWN findings only, so a sibling CVE found while testing the
    host never describes this alert's verdict.

    Returns two ``CommandResults``: the verdict under ``Tenzai.Scan`` and, when there are findings,
    one row per finding under ``Tenzai.Finding`` — each tagged with an ``attribution``
    (own / discovered / unattributed) so the consumer can present by-products and uncorrelated
    findings distinctly from the alert's own exposure.
    """
    scan_id = str(args.get("id"))
    scan = client.get_test(scan_id)
    findings_page = client.get_test_findings(scan_id)
    findings = findings_page.get("items") or []

    # Correlation keys threaded from the caller (the button self-poll re-supplies these on every
    # scheduled tick; the playbook maps them from the alert). They scope the verdict to THIS alert's
    # lead rather than an arbitrary sibling on the same host. Absent -> unresolved (safe dashes).
    alert_id = args.get("alert_id")
    cve_arg = args.get("cve")
    rule_id = args.get("rule_id")

    # Best-effort: the exposure lead carries the assessment rationale + structured classification.
    # A stalled/failed leads fetch must never break the verdict — degrade to no lead (dashes).
    leads_fetch_ok = True
    try:
        leads = client.get_test_leads(scan_id).get("items") or []
    except DemistoException as exc:
        demisto.debug(f"Tenzai leads fetch failed for {scan_id}; omitting rationale: {exc}")
        leads, leads_fetch_ok = [], False
    matched_lead = _match_lead_to_alert(leads, alert_id, cve_arg, rule_id)
    correlation_known = matched_lead is not None
    # Tri-state correlation for the write-back readiness gate — a definitive no-match must NOT
    # be conflated with a transient failed/empty fetch (which would write a partial verdict):
    #   resolved  -> a lead matched this alert.
    #   unmatched -> leads were fetched and none correlate (final; nothing to wait for).
    #   pending   -> the fetch failed OR returned no leads yet (transient; keep polling).
    if correlation_known:
        correlation_state = "resolved"
    elif not leads_fetch_ok or not leads:
        correlation_state = "pending"
    else:
        correlation_state = "unmatched"
    lead_rationale = _render_lead_rationale_markdown(matched_lead)
    lead = matched_lead or {}
    # The exposure lead also carries the assessment's structured classification; surface it
    # so the panel can render CWE / OWASP chips. Empty strings collapse to None (omitted).
    cwe = (lead.get("cwe") or "").strip() or None
    owasp_category = (lead.get("owaspCategory") or "").strip() or None
    # The lead's terminal status (BLOCKED / MATERIALIZED / INVALIDATED / …) is the exposure
    # outcome the panel shows in its Status metric — distinct from the coarse scan status.
    exposure_status = (lead.get("status") or "").strip() or None
    lead_cve = (lead.get("cve") or "").strip().upper() or None

    # Structured extra for the panel's sidebar: the exposure Timeline (the lead's status history).
    timeline = _timeline_rows(lead)
    # The assessment start (full ISO) for the panel's "Started at" cell — the lead's OPEN entry.
    started_at = _lead_started_at(lead)

    # Verdict is now LEAD-scoped (the matched exposure's terminal status), not test-scoped: a host
    # scan finding *something* no longer marks THIS alert exploitable. Unmatched/BLOCKED -> None.
    validated = _validated_from_status(exposure_status)

    application_id = scan.get("applicationId")
    reference_url = _build_reference_url(scan_id, application_id, "findings")

    # One structured row per finding for the Tenzai Findings grid. Every finding produced while
    # testing the host is kept, each tagged with an ``attribution``: ``own`` (this alert's exposure),
    # ``discovered`` (a different CVE found while testing — a by-product), or ``unattributed`` (no
    # lead correlated, so ownership is unknown). The CVE is parsed from the finding name for DISPLAY
    # only — never for the lead correlation above. ``own_findings`` (below) scopes the scan-level
    # narrative so a by-product never describes this alert's verdict.
    finding_rows: list[dict[str, Any]] = []
    own_findings: list[dict[str, Any]] = []
    for finding in findings:
        details = _finding_details(finding)
        reproduction = _finding_reproduction(finding)
        guidance = _finding_guidance(finding)
        finding_cve = _finding_cve(finding)
        attribution = _finding_attribution(correlation_known, lead_cve, finding_cve)
        if attribution == ATTR_OWN:
            own_findings.append(finding)
        row = {
            "title": _finding_name(finding),
            "severity": _finding_severity(finding),
            "details": details,
            "reproduction": reproduction,
            "guidance": guidance,
            "detail": _finding_detail_markdown(details, reproduction, guidance),
            "cve": finding_cve,
            "attribution": attribution,
        }
        finding_rows.append(row)

    outputs = {
        "id": scan_id,
        "applicationId": application_id,
        "status": _map_status(scan),
        "validated": validated,
        # Tri-state lead correlation (resolved / unmatched / pending) the write-back readiness
        # gate keys off: only ``resolved`` carries enrichment worth waiting for; ``unmatched`` is
        # written at once; ``pending`` (failed/empty fetch) keeps the poll loop waiting.
        "correlationState": correlation_state,
        # Scan-level narrative is scoped to the exposure's OWN findings — a sibling/uncorrelated
        # finding must never populate this alert's evidence/reproduction/guidance. By-products and
        # unattributed findings remain visible per-row under Tenzai.Finding (with their attribution).
        "evidence": _render_evidence_markdown(scan, own_findings),
        "reproduction": _render_reproduction_markdown(own_findings),
        "guidance": _render_guidance_markdown(own_findings),
        "leadRationale": lead_rationale,
        "creditUsage": scan.get("acuCount"),
        "duration": scan.get("duration"),
        "referenceUrl": reference_url,
        "cwe": cwe,
        "owaspCategory": owasp_category,
        "exposureStatus": exposure_status,
        "startedAt": started_at,
        "timeline": timeline,
    }
    # `validated` is a real boolean verdict — keep it even when False (remove_empty_elements
    # would strip a False). Strip only the optional Nones from the scan outputs.
    scan_outputs = {k: v for k, v in outputs.items() if v is not None or k == "validated"}

    readable = tableToMarkdown(
        "Tenzai Scan Result",
        {
            "Scan ID": scan_id,
            "Application ID": application_id,
            "Status": outputs["status"],
            "Validated": validated,
            "Findings": len(findings),
            "Credit Usage": outputs["creditUsage"],
            "Duration (s)": outputs["duration"],
            "Reference URL": reference_url,
            "CWE": cwe,
            "OWASP": owasp_category,
            "Exposure Status": exposure_status,
            "Started At": started_at,
        },
        removeNull=True,
    )
    # Two root context paths (per the frozen contract, and how the consumer
    # script reads them): the verdict under Tenzai.Scan and one row per finding
    # under the sibling Tenzai.Finding — findings are NOT nested inside the scan.
    results = [
        CommandResults(
            outputs_prefix="Tenzai.Scan",
            outputs_key_field="id",
            outputs=scan_outputs,
            readable_output=readable,
            raw_response={"scan": scan, "findings": findings},
        )
    ]
    if finding_rows:
        # Each finding row keeps its keys even when a section is None (so the grid
        # cells are addressable); drop only the intra-row Nones for cleanliness.
        finding_outputs = [{k: v for k, v in row.items() if v is not None} for row in finding_rows]
        results.append(
            CommandResults(
                outputs_prefix="Tenzai.Finding",
                outputs_key_field="title",
                outputs=finding_outputs,
                readable_output=tableToMarkdown(
                    "Tenzai Findings",
                    [
                        {
                            "Title": r["title"],
                            "Severity": r["severity"],
                            "CVE": r.get("cve"),
                            # Only surface a non-own attribution in the table (own is the default).
                            "Attribution": r["attribution"] if r.get("attribution") != ATTR_OWN else None,
                        }
                        for r in finding_rows
                    ],
                    headers=["Title", "Severity", "CVE", "Attribution"],
                    removeNull=True,
                ),
            )
        )
    return results


def _client_from_params(params: dict[str, Any]) -> Client:
    """Build the API client from instance params, with a bounded HTTP timeout.

    The per-request timeout defaults to ``DEFAULT_HTTP_TIMEOUT`` and is
    overridable via the ``timeout`` param. Keeping it low is what lets the
    StartAgenticValidation poll loop reschedule on a stalled host instead of the
    whole automation being killed by its execution timeout (see
    ``DEFAULT_HTTP_TIMEOUT``).
    """
    api_key = (params.get("credentials") or {}).get("password")
    timeout = arg_to_number(params.get("timeout")) or DEFAULT_HTTP_TIMEOUT
    return Client(
        base_url=(params.get("url") or "").rstrip("/"),
        verify=not params.get("insecure", False),
        headers={"Authorization": f"Bearer {api_key}"},
        proxy=params.get("proxy", False),
        timeout=timeout,
    )


def main() -> None:  # pragma: no cover
    """Parse params and dispatch the command."""
    params = demisto.params()
    command = demisto.command()

    api_key = (params.get("credentials") or {}).get("password")
    if not api_key:
        return_error("A Tenzai API Key is required. Configure it in the integration instance.")

    demisto.debug(f"Command being called is {command}")
    try:
        client = _client_from_params(params)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "tenzai-create-scan":
            return_results(create_scan_command(client, demisto.args()))
        elif command == "tenzai-get-scan":
            return_results(get_scan_command(demisto.args(), client))
        elif command == "tenzai-get-scan-result":
            return_results(get_scan_result_command(client, demisto.args()))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

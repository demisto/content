"""tLab Anti-APT Verdicts integration for Cortex XSOAR.

Pulls finished sandbox analyses out of tLab Anti-APT and turns them into
incidents.

This is the PULL half of a two-sided integration. The Go connector shipped
alongside this pack is the PUSH half, and the two are mutually exclusive by
design: enabling both produces two incidents for every analysis. The incident
they build is defined by docs/verdict-incident-schema.json and must stay
identical on both paths, down to the incident name, because an analyst
comparing a pushed and a pulled incident for the same report should not be
able to tell which half made it.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

from TLabAntiAPTApiModule import *  # noqa: F401,E402

# XSOAR severities. 0.5 is Informational, which is a real value here rather
# than a rounding accident: a WHITELIST verdict is a finding worth recording
# and worth never alerting on.
SEVERITY_UNKNOWN = 0.0
SEVERITY_INFO = 0.5
SEVERITY_LOW = 1.0
SEVERITY_MEDIUM = 2.0
SEVERITY_HIGH = 3.0
SEVERITY_CRITICAL = 4.0

# Mirrors SEVERITY_MAP in the Go connector's config.go. Both halves must agree,
# so changing one without the other is a defect.
DEFAULT_SEVERITY_MAP = {
    VERDICT_MALWARE: SEVERITY_HIGH,
    VERDICT_SUSPICIOUS: SEVERITY_MEDIUM,
    VERDICT_OK: SEVERITY_LOW,
    VERDICT_CLEAN: SEVERITY_LOW,
    VERDICT_WHITELIST: SEVERITY_INFO,
    VERDICT_UNKNOWN: SEVERITY_LOW,
}

DEFAULT_NAME_TEMPLATE = "tLab Anti-APT {verdict}: {filename}"
DEFAULT_VERDICTS = [VERDICT_MALWARE, VERDICT_SUSPICIOUS]
INCIDENT_TYPE = "tLab Anti-APT Verdict"
DELIVERY_PULL = "PULL"

OUTPUT_VERDICT = "TLabAntiAPT.Verdict"
RE_ATTACK = re.compile(r"^T\d{4}(\.\d{3})?$")

# The seen set only has to cover the maturation window: a report that left it
# can never be re-read. Pruning at twice the window is slack for clock skew.
SEEN_PRUNE_FACTOR = 2


# --------------------------------------------------------------------------
# Incident shape
# --------------------------------------------------------------------------
def dedupe_key(installation_id: str, report_id: int) -> str:
    """tlab-apt:<installation>:<report id>.

    Deliberately not derived from the file hash: the same file legitimately
    produces new detections, and collapsing those would hide re-infections.
    """
    return f"tlab-apt:{installation_id or ''}:{report_id}"


def render_incident_name(template: str | None, report: dict, verdict: str) -> str:
    """Mirrors RenderIncidentName in the Go connector, fallbacks included."""
    score, present = score_value(report)
    file_dto = report.get("file") or {}
    sha256 = file_dto.get("hashSha256") or ""
    report_id = arg_to_number(report.get("sampleReportId")) or 0

    filename = report.get("uploadedFilename") or ""
    if not filename:
        filename = sha256[:12] if len(sha256) >= 12 else f"sample {report_id}"

    source = report.get("source") or {}
    replacements = {
        "{verdict}": verdict,
        "{filename}": filename,
        "{sha256}": sha256,
        "{score}": f"{score:.2f}" if present else "n/a",
        "{report_id}": str(report_id),
        "{source_type}": source.get("sourceType") or "",
    }
    out = template or DEFAULT_NAME_TEMPLATE
    for key, value in replacements.items():
        out = out.replace(key, value)
    return out.strip()


def severity_for(verdict: str, score: float, present: bool, severity_map: dict, critical_score: int) -> float:
    """Mirrors SeverityForVerdict in the Go connector."""
    severity = severity_map.get(verdict, SEVERITY_LOW)
    if critical_score > 0 and verdict == VERDICT_MALWARE and present and score >= critical_score:
        return SEVERITY_CRITICAL
    return severity


def parse_severity_map(raw) -> dict:
    """Parses "MALWARE:3,SUSPICIOUS:2" the way the Go connector's env var does."""
    items = argToList(raw)
    if not items:
        return dict(DEFAULT_SEVERITY_MAP)
    parsed = dict(DEFAULT_SEVERITY_MAP)
    for item in items:
        name, _, value = str(item).partition(":")
        name = name.strip().upper()
        if name not in DEFAULT_SEVERITY_MAP:
            raise DemistoException(f"Severity map: unknown verdict '{name}'.")
        try:
            severity = float(value)
        except ValueError:
            raise DemistoException(f"Severity map: '{item}' is not VERDICT:severity.") from None
        if severity not in (0, 0.5, 1, 2, 3, 4):
            raise DemistoException(f"Severity map: {severity} is not an XSOAR severity (0, 0.5, 1, 2, 3, 4).")
        parsed[name] = severity
    return parsed


def as_float(value) -> float | None:
    """arg_to_number rejects non-integers, and sandbox scores are fractional."""
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def report_url(base_url: str | None, report_id: int) -> str:
    base = (base_url or "").rstrip("/")
    return f"{base}/reports/{report_id}" if base else ""


def contract_payload(report: dict, params: dict, enrichment: dict | None = None) -> dict:
    """Builds docs/verdict-incident-schema.json.

    The Go connector builds the same object in RawJSON(). Keys are omitted
    rather than set to null when a value is absent, which is what the schema's
    nullable types allow and what keeps the two halves byte-comparable.
    """
    report_id = arg_to_number(report.get("sampleReportId")) or 0
    suspicious_from = float(params.get("score_threshold_suspicious") or DEFAULT_SUSPICIOUS_FROM)
    malicious_from = float(params.get("score_threshold_malicious") or DEFAULT_MALICIOUS_FROM)
    verdict = canonical_verdict(report, suspicious_from=suspicious_from, malicious_from=malicious_from)
    score, present = score_value(report)
    file_dto = report.get("file") or {}
    source = report.get("source") or {}
    classifier = report.get("malwareClassifierResult") or {}
    enrichment = enrichment or {}

    payload = {
        "tlab_dedupe_key": dedupe_key(params.get("installation_id") or "", report_id),
        "tlab_sample_report_id": report_id,
        "tlab_verdict": verdict,
        "tlab_delivery_mode": DELIVERY_PULL,
        "tlab_whitelisted": bool(report.get("whitelisted")),
        "tlab_av_detected": bool(enrichment.get("av_detected")),
        "tlab_multistage": bool(classifier.get("multiStage")),
        "tlab_attack_techniques": enrichment.get("attack_techniques") or [],
        "tlab_threat_indicators": enrichment.get("threat_indicators") or [],
        "tlab_tags": argToList(report.get("tags")) or [],
    }

    optional = {
        "tlab_analysis_request_id": arg_to_number(report.get("analysisRequestId")),
        "tlab_access_code": report.get("accessCode"),
        "tlab_report_type": report.get("sampleReportType"),
        "tlab_completeness": report.get("sampleReportCompleteness"),
        # Both raw enums are kept: an analyst must be able to see what the
        # server actually said, not only our canonicalisation of it.
        "tlab_score_level": report.get("verdict"),
        "tlab_file_verdict": file_dto.get("fileVerdict"),
        "tlab_file_sha256": file_dto.get("hashSha256"),
        "tlab_file_sha1": file_dto.get("hashSha1"),
        "tlab_file_md5": file_dto.get("hashMd5"),
        "tlab_file_name": report.get("uploadedFilename"),
        "tlab_file_size": arg_to_number(file_dto.get("size")),
        "tlab_file_type": file_dto.get("fileType"),
        "tlab_mime_type": file_dto.get("mimeType"),
        "tlab_source_type": source.get("sourceType"),
        "tlab_source_uid": source.get("sourceUid"),
        "tlab_malware_family": classifier.get("primaryType"),
        "tlab_malware_confidence": as_float(classifier.get("confidence")),
        "tlab_dyn_report_id": arg_to_number(report.get("dynReportId")),
        "tlab_stat_report_id": arg_to_number(report.get("statReportId")),
        "tlab_report_url": report_url(params.get("url"), report_id),
        "tlab_create_time": epoch_to_iso(report.get("createTime")),
        "tlab_update_time": epoch_to_iso(report.get("updateTime")),
    }
    for key, value in optional.items():
        if value not in (None, ""):
            payload[key] = value

    # -1.0 is the API's "no score" default and the schema forbids it, so an
    # absent score is an absent key rather than a misleading number.
    if present:
        payload["tlab_score"] = score
    max_score = as_float(report.get("maxSampleReportScore"))
    if max_score is not None and max_score >= 0:
        payload["tlab_max_score"] = max_score
    return payload


# Machine names from x-xsoar-custom-field-names. The mapper shipped with this
# pack does the same translation on the supported path; this table exists for
# the fallback below.
CUSTOM_FIELD_NAMES = {
    "tlab_dedupe_key": "tlabdedupekey",
    "tlab_sample_report_id": "tlabsamplereportid",
    "tlab_access_code": "tlabaccesscode",
    "tlab_verdict": "tlabverdict",
    "tlab_score_level": "tlabscorelevel",
    "tlab_file_verdict": "tlabfileverdict",
    "tlab_score": "tlabscore",
    "tlab_completeness": "tlabcompleteness",
    "tlab_report_type": "tlabreporttype",
    "tlab_file_sha256": "tlabfilesha256",
    "tlab_file_name": "tlabfilename",
    "tlab_file_type": "tlabfiletype",
    "tlab_av_detected": "tlabavdetected",
    "tlab_malware_family": "tlabmalwarefamily",
    "tlab_attack_techniques": "tlabattacktechniques",
    "tlab_source_type": "tlabsourcetype",
    "tlab_report_url": "tlabreporturl",
    "tlab_delivery_mode": "tlabdeliverymode",
}


def custom_fields(payload: dict) -> dict:
    return {machine: payload[key] for key, machine in CUSTOM_FIELD_NAMES.items() if key in payload}


def build_incident(report: dict, params: dict, severity_map: dict, enrichment: dict | None = None) -> dict:
    payload = contract_payload(report, params, enrichment)
    score, present = score_value(report)
    return {
        "name": render_incident_name(params.get("incident_name_template"), report, payload["tlab_verdict"]),
        "occurred": payload.get("tlab_create_time") or epoch_to_iso(report.get("updateTime")),
        "type": params.get("incidentType") or INCIDENT_TYPE,
        "severity": severity_for(
            payload["tlab_verdict"],
            score,
            present,
            severity_map,
            arg_to_number(params.get("severity_critical_score")) or 0,
        ),
        "dbotMirrorId": payload["tlab_dedupe_key"],
        # The mapper shipped with this pack is the supported way to populate
        # the fields. CustomFields is a belt-and-braces fallback for instances
        # configured without one; where the server ignores it, the values are
        # still in rawJSON and in the labels.
        "CustomFields": custom_fields(payload),
        "rawJSON": json.dumps(payload),
    }


# --------------------------------------------------------------------------
# Enrichment
# --------------------------------------------------------------------------
def enrich(client: TLabClient, report_id: int) -> dict:
    """Threat indicators, ATT&CK techniques and the AV flag, in one call.

    The sample report list carries no AV result, so detectedByAv has to be
    derived. A MALICIOUS indicator from the AV source is exactly that signal.
    """
    out: dict = {"attack_techniques": [], "threat_indicators": [], "av_detected": False}
    payload = client.get_threat_indicators(report_id)
    techniques: set = set()
    for indicator in payload.get("indicators") or []:
        level = str(indicator.get("level") or "").upper()
        source = str(indicator.get("source") or "").upper()
        if source == "AV" and level == "MALICIOUS":
            out["av_detected"] = True
        if level in ("MALICIOUS", "SUSPICIOUS"):
            out["threat_indicators"].append(
                remove_empty_elements(
                    {
                        "source": indicator.get("source"),
                        "level": level,
                        "title": indicator.get("title") or indicator.get("key") or "",
                        "count": arg_to_number(indicator.get("count")),
                    }
                )
            )
        techniques.update(str(t) for t in (indicator.get("attack") or []) if RE_ATTACK.match(str(t)))
    out["attack_techniques"] = sorted(techniques)
    return out


# --------------------------------------------------------------------------
# Cursor
# --------------------------------------------------------------------------
# Same dual cursor as the feed and the Go connector, for the same reason: the
# server has no updatedSince filter, and analyses complete out of id order, so
# a single cursor is provably lossy in one direction or unfilterable in the
# other. Unlike the feed, duplicates here are not free -- they are duplicate
# incidents -- so the seen set below is load-bearing rather than an
# optimisation.
def discovery_page(client: TLabClient, cursor: int, size: int, params: dict) -> dict:
    return client.list_sample_reports(
        page=0,
        size=size,
        sort="sampleReportId,asc",
        min_report_id=cursor,
        completeness=completeness_filter(params),
        root_only=root_only(params),
    )


def maturation_page(client: TLabClient, lookback_hours: int, size: int, params: dict) -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=max(1, lookback_hours))
    return client.list_sample_reports(
        page=0,
        size=size,
        sort="updateTime,desc",
        date_from=since.strftime(TLAB_DATE_FORMAT),
        completeness=completeness_filter(params),
        root_only=root_only(params),
    )


def completeness_filter(params: dict) -> list:
    """A PARTIALLY_COMPLETE verdict can still change, and an incident whose
    severity drops after the analyst triaged it is worse than a late one."""
    return ["COMPLETE", "PARTIALLY_COMPLETE"] if param_bool(params, "include_partial") else ["COMPLETE"]


def root_only(params: dict) -> bool:
    """Dropped and embedded files get their own reports. Without this every
    archive turns into a dozen incidents for one delivery."""
    return param_bool(params, "root_reports_only", True)


def param_bool(params: dict, key: str, default: bool = False) -> bool:
    value = params.get(key)
    if value is None or value == "":
        return default
    try:
        return argToBoolean(value)
    except ValueError:
        return default


def next_cursor(reports: list, current: int) -> int:
    highest = current
    for report in reports:
        report_id = arg_to_number(report.get("sampleReportId")) or 0
        highest = max(highest, report_id + 1)
    return highest


def prune_seen(seen: dict, lookback_hours: int) -> dict:
    """Drop keys for reports that can no longer reappear in the maturation
    window, so last run does not grow without bound."""
    if not seen:
        return {}
    horizon = datetime.now(timezone.utc) - timedelta(hours=max(1, lookback_hours) * SEEN_PRUNE_FACTOR)
    kept = {}
    for key, stamp in seen.items():
        moment = epoch_to_datetime(stamp)
        if moment is None or moment >= horizon:
            kept[key] = stamp
    return kept


# --------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------
def collect_reports(client: TLabClient, params: dict, last_run: dict, preview: bool = False) -> tuple[list, int]:
    # first_report_id is a floor, not just the starting point of the first
    # fetch: XSOAR keeps the cursor across instance edits, so a value set after
    # fetching had started would otherwise be ignored and the backfill from 0
    # would go on. Raising the floor only moves the cursor forward, so it
    # cannot re-create incidents. Going below it takes clearing the parameter.
    floor = arg_to_number(params.get("first_report_id")) or 0
    cursor = arg_to_number(last_run.get("report_cursor"))
    cursor = floor if cursor is None else max(cursor, floor)
    page_size = arg_to_number(params.get("max_fetch")) or 50
    lookback = arg_to_number(params.get("maturation_lookback_hours")) or 0

    reports: dict[int, dict] = {}
    for report in discovery_page(client, cursor, page_size, params).get("content") or []:
        report_id = arg_to_number(report.get("sampleReportId"))
        if report_id is not None:
            reports[report_id] = report
    advanced = next_cursor(list(reports.values()), cursor)

    if lookback and not preview:
        for report in maturation_page(client, lookback, page_size, params).get("content") or []:
            report_id = arg_to_number(report.get("sampleReportId"))
            # At or above the cursor is discovery's job; taking it here would
            # double the enrichment cost for nothing. Below the floor is what
            # the operator asked not to fetch.
            if report_id is not None and report_id not in reports and floor <= report_id < cursor:
                reports[report_id] = report

    ordered = sorted(reports.values(), key=lambda r: arg_to_number(r.get("sampleReportId")) or 0)
    return ordered, advanced


def build_incidents(client: TLabClient, params: dict, reports: list, seen: dict) -> list:
    verdicts = {v.upper() for v in (argToList(params.get("verdicts")) or DEFAULT_VERDICTS)}
    severity_map = parse_severity_map(params.get("severity_map"))
    enrichment_on = param_bool(params, "enrich_incidents", True)
    installation = params.get("installation_id") or ""
    now = datetime.now(timezone.utc).strftime(TLAB_DATE_FORMAT)

    incidents = []
    for report in reports:
        report_id = arg_to_number(report.get("sampleReportId")) or 0
        key = dedupe_key(installation, report_id)
        if key in seen:
            continue
        payload_verdict = canonical_verdict(
            report,
            suspicious_from=float(params.get("score_threshold_suspicious") or DEFAULT_SUSPICIOUS_FROM),
            malicious_from=float(params.get("score_threshold_malicious") or DEFAULT_MALICIOUS_FROM),
        )
        if payload_verdict not in verdicts:
            continue

        enrichment = None
        if enrichment_on:
            try:
                enrichment = enrich(client, report_id)
            except Exception as exc:  # noqa: BLE001 - one bad report must not sink the fetch
                demisto.debug(f"enrichment failed for report {report_id}: {exc}")

        incidents.append(build_incident(report, params, severity_map, enrichment))
        seen[key] = now
    return incidents


# Where tlab-verdicts-reset-cursor leaves its request. XSOAR 6 does not
# reliably keep demisto.setLastRun() called outside fetch-incidents, so the
# command writes to the integration context and the next fetch applies it.
CURSOR_OVERRIDE_KEY = "cursor_override"


def fetch_incidents_command(client: TLabClient, params: dict) -> None:
    last_run = demisto.getLastRun() or {}
    override = (demisto.getIntegrationContext() or {}).get(CURSOR_OVERRIDE_KEY)
    if isinstance(override, dict):
        last_run = {key: value for key, value in last_run.items() if key != "report_cursor"}
        if override.get("report_cursor") is not None:
            last_run["report_cursor"] = override["report_cursor"]
    seen = dict(last_run.get("seen") or {})
    lookback = arg_to_number(params.get("maturation_lookback_hours")) or 0

    reports, cursor = collect_reports(client, params, last_run)
    incidents = build_incidents(client, params, reports, seen)

    demisto.incidents(incidents)
    # Only after the incidents are handed over, so a failure re-fetches the
    # window instead of silently skipping it.
    demisto.setLastRun(
        {
            "report_cursor": cursor,
            "seen": prune_seen(seen, lookback or 24),
            "last_fetch": datetime.now(timezone.utc).strftime(TLAB_DATE_FORMAT),
        }
    )
    if override is not None:
        merge_integration_context(**{CURSOR_OVERRIDE_KEY: None})
    demisto.debug(f"tLab verdicts: {len(incidents)} incidents from {len(reports)} reports, cursor now {cursor}")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def get_verdicts_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    """Preview. Creates no incidents and does not move the cursor."""
    limit = arg_to_number(args.get("limit")) or 10
    last_run = {"report_cursor": arg_to_number(args.get("from_report_id"))} if args.get("from_report_id") else {}
    reports, _ = collect_reports(client, params, last_run, preview=True)
    incidents = build_incidents(client, params, reports[:limit], {})

    rows = [
        {
            "Name": incident["name"],
            "Report ID": incident["CustomFields"].get("tlabsamplereportid"),
            "Verdict": incident["CustomFields"].get("tlabverdict"),
            "Score": incident["CustomFields"].get("tlabscore"),
            "Severity": incident["severity"],
            "File": incident["CustomFields"].get("tlabfilename"),
            "Occurred": incident.get("occurred"),
        }
        for incident in incidents
    ]
    outputs = [json.loads(incident["rawJSON"]) for incident in incidents]
    return CommandResults(
        outputs_prefix=OUTPUT_VERDICT,
        outputs_key_field="tlab_dedupe_key",
        outputs=outputs or None,
        raw_response=outputs,
        readable_output=tableToMarkdown(
            f"tLab Anti-APT verdicts ({len(rows)})",
            rows,
            headers=["Name", "Report ID", "Verdict", "Score", "Severity", "File", "Occurred"],
            removeNull=True,
        )
        if rows
        else "No verdicts matched the configured filters.",
    )


def reset_cursor_command(args: dict) -> CommandResults:
    report_id = arg_to_number(args.get("from_report_id"))
    merge_integration_context(**{CURSOR_OVERRIDE_KEY: {"report_cursor": report_id}})
    if report_id is None:
        return CommandResults(
            readable_output="Fetch cursor reset. The next fetch starts from the configured first sample report id."
        )
    return CommandResults(
        readable_output=f"Fetch cursor set to sample report {report_id}; the next fetch starts there. "
        "A First sample report id above it still takes precedence."
    )


def test_module_command(client: TLabClient, params: dict) -> str:
    parse_severity_map(params.get("severity_map"))
    for verdict in argToList(params.get("verdicts")) or []:
        if verdict.upper() not in DEFAULT_SEVERITY_MAP:
            raise DemistoException(f"Verdicts: '{verdict}' is not a tLab verdict.")
    if not (params.get("installation_id") or "").strip():
        raise DemistoException(
            "Installation ID is required. It is part of every deduplication key, so leaving it empty "
            "makes incidents from two tLab installations collide."
        )
    client.list_sample_reports(page=0, size=1, sort="sampleReportId,asc")
    return "ok"


def build_client(params: dict) -> TLabClient:
    return TLabClient(
        base_url=params.get("url") or "",
        auth_mode=params.get("auth_mode") or AUTH_TLAB_ACCOUNT,
        credentials=params.get("credentials") or {},
        client_name=params.get("client_name") or "xsoar",
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
        auth_url=params.get("auth_url") or "",
    )


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    try:
        client = build_client(params)

        if command == "test-module":
            return_results(test_module_command(client, params))
        elif command == "fetch-incidents":
            fetch_incidents_command(client, params)
        elif command == "tlab-get-verdicts":
            return_results(get_verdicts_command(client, args, params))
        elif command == "tlab-verdicts-reset-cursor":
            return_results(reset_cursor_command(args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as exc:  # noqa: BLE001 - XSOAR requires a single catch-all in main
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command}. Error: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re
import traceback
from typing import Any

# The ad-hoc button drives the full validation loop itself (create -> poll ->
# write-back) via ScheduledCommand, so a single click behaves like the playbook.
# The playbook passes poll=false and owns its own poll + write-back, so the loop
# is not run twice.
POLL_INTERVAL_SECONDS = 60
POLL_TIMEOUT_SECONDS = 3600
MAX_POLLS = POLL_TIMEOUT_SECONDS // POLL_INTERVAL_SECONDS
_TERMINAL_STATUSES = ("Complete", "Error")
# A scan's test-level status can go terminal before the platform has closed the lead
# (terminal ``exposureStatus`` + CVE ``leadRationale``). After the scan is terminal we
# poll this many extra times, one interval apart, for that enrichment to land before the
# atomic write-back — otherwise the Validate panel shows a verdict beside empty cells.
TERMINAL_MAX_RETRIES = 5

# ASM exposure names embed the socket, e.g. "PPTP Server at 1.2.3.4:1723"
# or "Insecure NGINX Web Server (1.17.7) at 10.0.0.5:80". These let us
# recover a target when the issue carries no (resolvable) asmserviceid.
_AT_SOCKET_RE = re.compile(r"\bat\s+([A-Za-z0-9.\-]+)(?::(\d{1,5}))?\s*$", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b")


def target_from_exposure_name(name: str | None) -> str | None:
    """Best-effort ``host``/``host:port`` extraction from an ASM exposure name.

    Tenzai's target parser accepts a URL, a ``host:port`` pair, or a bare host,
    so returning the embedded socket is enough for it to map the app type and
    build the scan target. Returns ``None`` when nothing host-like is found (the
    caller then raises a clear error).
    """
    if not name:
        return None
    match = _AT_SOCKET_RE.search(name.strip())
    if match and ("." in match.group(1) or match.group(2)):
        host, port = match.group(1), match.group(2)
        return f"{host}:{port}" if port else host
    # Fall back to the first IPv4[:port] found anywhere in the name.
    ip_match = _IPV4_RE.search(name)
    if ip_match:
        host, port = ip_match.group(1), ip_match.group(2)
        return f"{host}:{port}" if port else host
    return None


def run_command(command: str, args: dict[str, Any]) -> list:
    """Run a command and raise on an error entry."""
    entries = demisto.executeCommand(command, args)
    if is_error(entries):
        raise DemistoException(f"Failed to execute '{command}': {get_error(entries)}")
    return entries


def extract_context(entries: list, prefix: str) -> dict[str, Any]:
    """Return the first EntryContext value whose key matches `prefix` (ignoring DT selectors)."""
    for entry in entries or []:
        context = entry.get("EntryContext") or {}
        for key, value in context.items():
            if key.split("(")[0].strip() == prefix:
                if isinstance(value, list):
                    return value[0] if value else {}
                return value or {}
    return {}


def extract_context_list(entries: list, prefix: str) -> list[dict[str, Any]]:
    """Return the EntryContext value for `prefix` as a list (ignoring DT selectors).

    ``tenzai-get-scan-result`` returns the findings under their own top-level
    ``Tenzai.Finding`` context (a sibling of ``Tenzai.Scan``), so they are read
    as a list rather than from inside the scan object.
    """
    for entry in entries or []:
        context = entry.get("EntryContext") or {}
        for key, value in context.items():
            if key.split("(")[0].strip() == prefix:
                if isinstance(value, list):
                    return value
                return [value] if value else []
    return []


def _resolve_target_and_create_scan(args: dict[str, Any]) -> tuple[str, str | None, dict[str, Any]]:
    """Resolve a scan target from the args and create a Tenzai validation scan.

    Prefers an explicit ``target``; otherwise enriches a ``service_id`` via
    ``asm-get-external-service``; otherwise parses the socket out of the exposure
    name. The Cortex issue Description (``issue_description``) is folded into the
    scan so it enriches the Tenzai application guidelines. Returns the created
    scan ``id``, the live Agent-log reference URL (or ``None`` when the integration
    cannot build one), and the correlation keys (``alert_id``/``cve``/``rule_id``)
    the lead was seeded with — the poll loop re-supplies these to
    ``tenzai-get-scan-result`` so the verdict scopes to this alert's lead. Raises if
    no target can be derived or the create call returns no id.
    """
    service_id = args.get("service_id") or args.get("asm_service_id")
    alert_internal_id = args.get("alert_internal_id")
    exposure_name = args.get("exposure_name") or "ASM Exposure"
    issue_description = args.get("issue_description")
    target = args.get("target")
    supporting_data = args.get("supporting_data")
    port = args.get("port")
    protocol = args.get("protocol")
    service_classification = args.get("service_classification")
    application_type = args.get("application_type")
    # EXTERNAL_LEAD exposure-reference fields (pass-through; category is inferred
    # from cve_id downstream when not given explicitly).
    category = args.get("category")
    cve_id = args.get("cve_id")
    rule_id = args.get("rule_id")
    severity = args.get("severity")
    cwe = args.get("cwe")

    # Enrich from ASM when we have a service id but no explicit target.
    if service_id and not target:
        service = extract_context(run_command("asm-get-external-service", {"service_id": service_id}), "ASM.ExternalService")
        ips = service.get("ips") or []
        target = service.get("domain") or service.get("ip_address") or (ips[0] if ips else None)
        port = port or service.get("port")
        protocol = protocol or service.get("protocol")
        if not service_classification:
            classifications = service.get("active_classifications") or service.get("service_type")
            service_classification = (
                ", ".join(str(c) for c in classifications) if isinstance(classifications, list) else classifications
            )
        # The service's inferred CVEs are a property of the IP/service, not of this
        # specific Cortex issue — so they are context/evidence only, never the
        # EXTERNAL_LEAD cve_id/category. Deriving category=cve from them would
        # mislabel a misconfiguration issue and pin Tenzai to an unrelated CVE. A
        # genuine issue-level CVE arrives via the explicit cve_id arg (mapped from
        # the Cortex issue's own CVE field).
        if not supporting_data:
            cves = service.get("externally_inferred_cves")
            if cves:
                cve_list = cves if isinstance(cves, list) else [cves]
                supporting_data = "Inferred CVEs (service-wide): " + ", ".join(str(c) for c in cve_list)

    # Fall back to the socket embedded in the exposure name (ASM issues on some
    # tenants carry no asmserviceid, but the name has the host:port).
    if not target:
        target = target_from_exposure_name(exposure_name)

    if not target:
        raise DemistoException(
            "Could not determine a target. Provide 'target', a 'service_id' that resolves to one, "
            "or an 'exposure_name' containing a host/IP (e.g. 'PPTP Server at 1.2.3.4:1723')."
        )

    create_args = assign_params(
        target=target,
        exposure_name=exposure_name,
        issue_description=issue_description,
        supporting_data=supporting_data,
        application_type=application_type,
        port=str(port) if port not in (None, "") else None,
        protocol=protocol,
        service_classification=service_classification,
        asm_service_id=service_id,
        alert_internal_id=alert_internal_id,
        category=category,
        cve_id=cve_id,
        rule_id=rule_id,
        severity=severity,
        cwe=cwe,
        guidelines=args.get("guidelines"),
    )
    scan = extract_context(run_command("tenzai-create-scan", create_args), "Tenzai.Scan")
    scan_id = scan.get("id")
    if not scan_id:
        raise DemistoException("tenzai-create-scan did not return a scan id.")
    # Correlation keys as the lead was actually seeded (echoed by tenzai-create-scan), falling
    # back to the raw args. Carried through the poll loop so the verdict binds to this alert's lead.
    correlation = assign_params(
        alert_id=scan.get("alertId") or alert_internal_id or service_id,
        cve=scan.get("cve") or cve_id,
        rule_id=scan.get("ruleId") or rule_id,
    )
    return scan_id, scan.get("referenceUrl"), correlation


def _current_assessment_status() -> str | None:
    """The issue's current Tenzai Assessment Status, used to avoid starting a duplicate run."""
    incident = demisto.incident() or {}
    return (incident.get("CustomFields") or {}).get("tenzaiassessmentstatus")


def _poll_scheduled_command(
    scan_id: str,
    poll_count: int,
    correlation: dict[str, Any] | None = None,
    *,
    terminal_retry_count: int = 0,
    write_only: bool = False,
) -> ScheduledCommand:
    """Reschedule this script to poll the scan again, carrying the iteration state.

    The correlation keys (``alert_id``/``cve``/``rule_id``) ride along on every tick so the
    terminal ``tenzai-get-scan-result`` can scope the verdict to this alert's lead — a scheduled
    re-entry has only these args, not the original alert context. ``terminal_retry_count`` bounds
    the post-terminal enrichment wait, and ``write_only`` is preserved so the playbook path keeps
    retrying enrichment (it polls scan status, not readiness) instead of writing a partial verdict.
    """
    scheduled_args: dict[str, Any] = {"scan_id_internal": scan_id, "poll_count": poll_count}
    scheduled_args.update(correlation or {})
    if terminal_retry_count:
        scheduled_args["terminal_retry_count"] = terminal_retry_count
    if write_only:
        scheduled_args["write_only"] = "true"
    return ScheduledCommand(
        command="StartAgenticValidation",
        next_run_in_seconds=POLL_INTERVAL_SECONDS,
        args=scheduled_args,
        timeout_in_seconds=POLL_TIMEOUT_SECONDS,
    )


# A matched lead is only "enriched" once it reaches one of these terminal statuses. A
# non-empty but still-open status (OPEN / IN_PROGRESS) means the lead has not closed yet,
# so the verdict is not ready to write.
_TERMINAL_LEAD_STATUSES = ("MATERIALIZED", "INVALIDATED", "BLOCKED")
# Terminal statuses that close the lead with a written conclusion — a CVE lead in one of
# these must carry its rationale before we write. BLOCKED (target reached but stopped at
# the safety boundary) has no verdict/conclusion, so rationale is not required for it.
_CONCLUDED_LEAD_STATUSES = ("MATERIALIZED", "INVALIDATED")


def _verdict_is_enriched(result: dict[str, Any], cve_supplied: bool) -> bool:
    """Whether a RESOLVED (lead-matched) terminal result carries the enrichment the panel needs.

    The matched lead must have reached a terminal status (MATERIALIZED / INVALIDATED /
    BLOCKED) — a non-empty but still-open status (OPEN / IN_PROGRESS) is not ready. For a CVE
    validation, a concluded lead (MATERIALIZED / INVALIDATED) must also carry its
    ``leadRationale`` narrative. ``startedAt``, ``creditUsage`` and the findings count are
    best-effort and never gate the write: INVALIDATED legitimately reports zero findings.
    """
    status = str(result.get("exposureStatus") or "").strip().upper()
    if status not in _TERMINAL_LEAD_STATUSES:
        return False
    return not (cve_supplied and status in _CONCLUDED_LEAD_STATUSES and not str(result.get("leadRationale") or "").strip())


def _terminal_ready_to_write(result: dict[str, Any], correlation: dict[str, Any], terminal_retry_count: int) -> bool:
    """True when a TERMINAL scan result should be written now.

    ``correlationState`` (from ``tenzai-get-scan-result``) is tri-state, so a definitive
    no-match is never conflated with a failed/empty leads fetch:
      * ``unmatched`` — leads fetched and none correlate: a final result with no enrichment
        coming, so write the inconclusive verdict at once.
      * ``resolved`` — a lead matched: write once its terminal status (+ CVE rationale) lands.
      * ``pending`` — the leads fetch failed or returned empty (not yet populated): keep waiting.
    The retry cap is the backstop: once exhausted, write whatever we have rather than poll forever.
    """
    if terminal_retry_count >= TERMINAL_MAX_RETRIES:
        demisto.debug(
            f"Tenzai {result.get('id')}: correlation/enrichment not ready after "
            f"{TERMINAL_MAX_RETRIES} retries; writing partial verdict."
        )
        return True
    state = str(result.get("correlationState") or "").strip().lower()
    if state == "unmatched":
        return True
    if state == "resolved":
        return _verdict_is_enriched(result, cve_supplied=bool((correlation or {}).get("cve")))
    return False  # pending — fetch failure or leads not yet populated


def _findings_grid_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map the fetched findings to ``tenzaifindings`` grid rows.

    The grid shows severity + finding title + a Details cell (the combined
    ``detail`` markdown built by the integration). Row dict keys must match the
    grid column keys exactly. Empty cells are dropped so a sparse finding still
    renders its title.
    """
    rows = []
    for finding in findings or []:
        row = assign_params(
            finding=finding.get("title"),
            severity=finding.get("severity"),
            detail=finding.get("detail"),
            cve=finding.get("cve"),
            # "own" is the default/expected case; only carry a non-own attribution into the grid.
            attribution=finding.get("attribution") if finding.get("attribution") not in (None, "", "own") else None,
        )
        if row:
            rows.append(row)
    return rows


def _write_verdict_to_incident(result: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    """Write the terminal Tenzai verdict onto the issue (mirrors the playbook's setIncident).

    The verdict is written as one atomic result block: every field that describes
    *this* scan's outcome is set on every terminal write, cleared to an empty value
    when this scan has no data for it. A conditional "write only when non-empty"
    leaves a prior run's data behind — a fresh 0-finding "Not Exploitable" verdict
    would keep the previous scan's findings grid (and reproduction/guidance), so the
    panel renders "Not Exploitable" next to N stale findings (ENG-5198). The scan
    pipeline is the sole writer of these fields.
    """
    status = result.get("status")
    if status != "Complete":
        demisto.executeCommand("setIncident", {"tenzaiassessmentstatus": status or "Error"})
        return

    # Text result fields: written every time. ``or ""`` clears any value a prior run
    # left behind when this scan has none (e.g. no reproduction on a not-exploitable
    # verdict), so the field can never drift out of sync with the verdict.
    fields: dict[str, Any] = {
        "tenzaiassessmentstatus": "Complete",
        "tenzaiassessmentevidence": result.get("evidence") or "",
        "tenzaireproduction": result.get("reproduction") or "",
        "tenzaiguidance": result.get("guidance") or "",
        "tenzaiissuerationale": result.get("leadRationale") or "",
        "tenzaireferenceurl": result.get("referenceUrl") or "",
        "tenzaicwe": result.get("cwe") or "",
        "tenzaiowasp": result.get("owaspCategory") or "",
        "tenzaiexposurestatus": result.get("exposureStatus") or "",
        "tenzaistartedat": result.get("startedAt") or "",
    }
    # Credit is a numeric field and every completed scan reports one; write it when
    # present rather than coercing an empty string onto a number field.
    credit = result.get("creditUsage")
    if credit is not None:
        fields["tenzaicreditusage"] = credit
    # Duration is a numeric field (whole seconds) and every completed scan reports one; write
    # it when present rather than coercing an empty string onto a number field (mirrors credit).
    duration = result.get("duration")
    if duration is not None:
        fields["tenzaiassessmentduration"] = duration
    # Record the verdict only — Tenzai does not change the issue severity (that stays with the
    # analyst / Cortex). The tri-state verdict is written on EVERY terminal run: "true"
    # (MATERIALIZED), "false" (INVALIDATED), or cleared to "" when inconclusive (BLOCKED /
    # unresolved / no matched lead). Clearing is essential — leaving None untouched lets a prior
    # run's "true" survive a later BLOCKED/unmatched result, so the panel would show a stale
    # Exploitable verdict for an exposure that no longer has one.
    validated = result.get("validated")
    if validated is True:
        fields["tenzaiissuevalidated"] = "true"
    elif validated is False:
        fields["tenzaiissuevalidated"] = "false"
    else:
        fields["tenzaiissuevalidated"] = ""
    demisto.executeCommand("setIncident", fields)

    # Populate the Tenzai Findings grid — the layout's results table. Grid fields
    # are set as a list of row dicts under the ``customFields`` wrapper (a plain
    # top-level arg does not populate a grid). Always overwrite it, even with an
    # empty list: that clears rows a prior scan left behind so the grid always
    # matches the current verdict (ENG-5198).
    demisto.executeCommand(
        "setIncident",
        {
            "customFields": {
                "tenzaifindings": _findings_grid_rows(findings),
                "tenzaitimeline": result.get("timeline") or [],
            }
        },
    )


def start_agentic_validation(args: dict[str, Any]) -> CommandResults:
    """Button/playbook entry point.

    First call with ``poll`` true (the ad-hoc button): create a scan, mark the
    issue Running, and start a self-poll loop that writes the verdict once the
    scan is terminal. With ``poll`` false (the playbook): create only — the
    playbook owns polling and calls back with ``write_only`` to persist the verdict.
    Scheduled re-entries (``scan_id_internal`` set) poll the result until terminal
    or the polling window is exhausted; a ``write_only`` re-entry fetches once and
    writes the verdict without rescheduling (the playbook already polled to terminal),
    so BOTH paths persist through the single ``_write_verdict_to_incident`` writer —
    scalars, findings grid, timeline, and the cleared boolean verdict alike.
    """
    scan_id = args.get("scan_id_internal")

    if not scan_id:
        poll = argToBoolean(args.get("poll", "true"))
        if poll:
            ScheduledCommand.raise_error_if_not_supported()
            # Don't start a second scan if one is already in flight on this issue.
            if _current_assessment_status() == "Running":
                return CommandResults(
                    readable_output="A Tenzai validation is already running for this issue; not starting another."
                )
        scan_id, reference_url, correlation = _resolve_target_and_create_scan(args)
        # Mark Running and, when available, surface the live Agent-log link so the
        # panel can link into the scan in flight. The terminal write-back later
        # overwrites tenzaireferenceurl with the findings URL.
        running_fields: dict[str, Any] = {"tenzaiassessmentstatus": "Running"}
        if reference_url:
            running_fields["tenzaireferenceurl"] = reference_url
        demisto.executeCommand("setIncident", running_fields)
        # Surface the correlation keys alongside the scan id so the playbook path can pass them
        # to tenzai-get-scan-result (the button path threads them via the scheduled command below).
        outputs = {"id": scan_id, "status": "Running", **correlation}
        if not poll:
            # Playbook path: create only; the playbook owns poll + write-back.
            return CommandResults(
                outputs_prefix="Tenzai.Scan",
                outputs_key_field="id",
                outputs=outputs,
                readable_output=f"Started Tenzai validation scan **{scan_id}**.",
            )
        # Button path: create and drive the poll loop ourselves.
        return CommandResults(
            outputs_prefix="Tenzai.Scan",
            outputs_key_field="id",
            outputs=outputs,
            readable_output=f"Started Tenzai validation scan **{scan_id}**; polling for the verdict...",
            scheduled_command=_poll_scheduled_command(scan_id, 1, correlation),
        )

    # Scheduled re-entry: fetch the verdict, tolerating transient failures. Two bounded
    # windows govern the loop: ``poll_count``/``MAX_POLLS`` waits for the scan to go terminal
    # (button path only); ``terminal_retry_count``/``TERMINAL_MAX_RETRIES`` then waits for the
    # lead enrichment (exposureStatus / CVE rationale) to land before the atomic write-back,
    # so the panel never renders a verdict beside empty Status/rationale cells.
    poll_count = arg_to_number(args.get("poll_count")) or 1
    terminal_retry_count = arg_to_number(args.get("terminal_retry_count")) or 0
    # Correlation keys carried from the first tick — re-supplied so the verdict binds to this
    # alert's lead, and forwarded onto the next scheduled tick.
    correlation = assign_params(
        alert_id=args.get("alert_id"),
        cve=args.get("cve"),
        rule_id=args.get("rule_id"),
    )
    write_only = argToBoolean(args.get("write_only", "false"))

    try:
        entries = run_command("tenzai-get-scan-result", {"id": scan_id, **correlation})
        result = extract_context(entries, "Tenzai.Scan")
        findings = extract_context_list(entries, "Tenzai.Finding")
    except Exception as ex:
        # A transient fetch failure must not abort the loop — retry next tick.
        demisto.error(f"Tenzai poll fetch failed for {scan_id} (attempt {poll_count}/{MAX_POLLS}): {ex}")
        result, findings = {}, []

    status = result.get("status")
    terminal = status in _TERMINAL_STATUSES

    # Playbook path (write_only): the playbook already polled the scan to terminal, so this
    # path does NOT poll scan status or reach the MAX_POLLS/Error branch — it only manages the
    # enrichment window, then persists through the shared writer (one writer for both paths).
    if write_only:
        if terminal and _terminal_ready_to_write(result, correlation, terminal_retry_count):
            _write_verdict_to_incident(result, findings)
            return CommandResults(
                outputs_prefix="Tenzai.Scan",
                outputs_key_field="id",
                outputs=result or {"id": scan_id},
                readable_output=(
                    f"Tenzai validation **{scan_id}** verdict written to the issue "
                    f"(status: {result.get('status')}; validated: {result.get('validated')})."
                ),
            )
        if terminal_retry_count >= TERMINAL_MAX_RETRIES:
            # Reached only when the scan never returned a terminal result (repeated transient
            # fetch failures) — a terminal result at the cap is written above. Mark the issue
            # Error rather than leaving it stuck on Running forever, mirroring the button path.
            demisto.error(
                f"Tenzai validation {scan_id}: no terminal result after {TERMINAL_MAX_RETRIES} "
                f"retries (write_only); marking Error."
            )
            demisto.executeCommand("setIncident", {"tenzaiassessmentstatus": "Error"})
            return CommandResults(readable_output=f"Tenzai validation **{scan_id}**: no terminal result to write; marked Error.")
        return CommandResults(
            readable_output=(
                f"Tenzai validation **{scan_id}** awaiting lead enrichment; "
                f"will retry ({terminal_retry_count + 1}/{TERMINAL_MAX_RETRIES})."
            ),
            scheduled_command=_poll_scheduled_command(
                scan_id, poll_count, correlation, terminal_retry_count=terminal_retry_count + 1, write_only=True
            ),
        )

    # Button path: drive the scan-status poll ourselves.
    if terminal:
        if _terminal_ready_to_write(result, correlation, terminal_retry_count):
            _write_verdict_to_incident(result, findings)
            return CommandResults(
                outputs_prefix="Tenzai.Scan",
                outputs_key_field="id",
                outputs=result,
                readable_output=(
                    f"Tenzai validation **{scan_id}** finished (status: {status}; "
                    f"validated: {result.get('validated')}). Results written to the issue."
                ),
            )
        # Terminal, but enrichment has not landed — keep the issue on Running and retry
        # (do NOT increment poll_count: the scan-status window is done, this is the
        # enrichment window). The issue is never half-cleared because the gate precedes
        # the atomic write.
        return CommandResults(
            readable_output=(
                f"Tenzai validation **{scan_id}** complete but awaiting lead enrichment; "
                f"will retry ({terminal_retry_count + 1}/{TERMINAL_MAX_RETRIES})."
            ),
            scheduled_command=_poll_scheduled_command(
                scan_id, poll_count, correlation, terminal_retry_count=terminal_retry_count + 1
            ),
        )

    if poll_count >= MAX_POLLS:
        # Polling window exhausted (or repeated unusable/empty responses) — record a
        # terminal state so the issue isn't left stuck on "Running" with no signal.
        demisto.executeCommand("setIncident", {"tenzaiassessmentstatus": "Error"})
        return CommandResults(
            readable_output=(
                f"Tenzai validation **{scan_id}** did not reach a verdict within the polling window "
                f"({MAX_POLLS} polls); marked Error. The scan may still be running in Tenzai."
            )
        )

    return CommandResults(
        readable_output=(
            f"Tenzai validation **{scan_id}** still running (status: {status or 'unknown'}); "
            f"will poll again ({poll_count}/{MAX_POLLS})."
        ),
        scheduled_command=_poll_scheduled_command(scan_id, poll_count + 1, correlation),
    )


def main():  # pragma: no cover
    try:
        return_results(start_agentic_validation(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute StartAgenticValidation. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

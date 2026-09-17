"""Unit tests for the StartAgenticValidation script."""

import demistomock as demisto
import pytest
from CommonServerPython import DemistoException
from StartAgenticValidation import (
    MAX_POLLS,
    TERMINAL_MAX_RETRIES,
    _findings_grid_rows,
    _verdict_is_enriched,
    extract_context,
    extract_context_list,
    start_agentic_validation,
    target_from_exposure_name,
)

# ScheduledCommand construction requires a platform version that supports it.
SUPPORTED_VERSION = {"version": "6.10.0", "buildNumber": "12345"}

# tenzai-create-scan returns the scan under Tenzai.Scan with an `id`.
CREATE_ENTRY = [{"Type": 1, "EntryContext": {"Tenzai.Scan(val.id == obj.id)": {"id": "scan_1", "status": "Pending"}}}]
ENRICH_ENTRY = [
    {
        "Type": 1,
        "EntryContext": {
            "ASM.ExternalService(val.service_id == obj.service_id)": {
                "service_id": "svc-1",
                "domain": "vpn.acme.com",
                "ip_address": "1.2.3.4",
                "port": 443,
                "protocol": "tcp",
                "active_classifications": ["WebServer"],
                "externally_inferred_cves": ["CVE-2024-1234"],
            }
        },
    }
]


def _result_entry(payload: dict, findings: list | None = None) -> list:
    """A tenzai-get-scan-result response entry.

    ``tenzai-get-scan-result`` returns the scan object under ``Tenzai.Scan`` and,
    when complete, the findings under their own top-level ``Tenzai.Finding`` context.
    """
    context: dict = {"Tenzai.Scan(val.id == obj.id)": payload}
    if findings is not None:
        context["Tenzai.Finding(val.title == obj.title)"] = findings
    return [{"Type": 1, "EntryContext": context}]


@pytest.fixture
def first_run(mocker):
    """Platform supports scheduling and the issue has no in-flight validation."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    mocker.patch.object(demisto, "incident", create=True, return_value={"CustomFields": {}})


def test_findings_grid_rows_maps_and_drops_empty():
    """Findings map to grid rows by column key; empty cells and empty findings are dropped."""
    rows = _findings_grid_rows(
        [
            {"title": "A", "severity": "HIGH", "detail": "combined markdown"},
            {"title": "B", "severity": "LOW"},  # sparse — keeps title/severity only
            {},  # nothing usable — skipped entirely
        ]
    )
    assert rows == [
        {"finding": "A", "severity": "HIGH", "detail": "combined markdown"},
        {"finding": "B", "severity": "LOW"},
    ]
    assert _findings_grid_rows([]) == []
    assert _findings_grid_rows(None) == []  # type: ignore[arg-type]


def test_findings_grid_rows_carries_cve_and_attribution():
    """A non-own finding carries its CVE and attribution into the grid row; 'own' is dropped (default)."""
    rows = _findings_grid_rows(
        [
            {"title": "own", "severity": "HIGH", "cve": "CVE-2023-44487", "attribution": "own"},
            {"title": "byproduct", "severity": "HIGH", "cve": "CVE-2024-23897", "attribution": "discovered"},
            {"title": "uncorrelated", "severity": "LOW", "cve": "CVE-2020-0001", "attribution": "unattributed"},
        ]
    )
    assert rows[0] == {"finding": "own", "severity": "HIGH", "cve": "CVE-2023-44487"}  # own dropped
    assert rows[1] == {
        "finding": "byproduct",
        "severity": "HIGH",
        "cve": "CVE-2024-23897",
        "attribution": "discovered",
    }
    assert rows[2]["attribution"] == "unattributed"


def test_extract_context_strips_dt_selector():
    """The DT selector in the context key is ignored when matching the prefix."""
    assert extract_context(CREATE_ENTRY, "Tenzai.Scan") == {"id": "scan_1", "status": "Pending"}
    assert extract_context([], "Tenzai.Scan") == {}


def test_extract_context_list_returns_findings():
    """Findings are read from their own top-level Tenzai.Finding context as a list."""
    entries = _result_entry(
        {"id": "scan_1", "status": "Complete", "validated": True},
        findings=[{"title": "A", "severity": "HIGH"}, {"title": "B", "severity": "LOW"}],
    )
    findings = extract_context_list(entries, "Tenzai.Finding")
    assert [f["title"] for f in findings] == ["A", "B"]
    # No findings context -> empty list (not an error).
    assert extract_context_list(_result_entry({"id": "s", "status": "Running"}), "Tenzai.Finding") == []


@pytest.mark.parametrize(
    "name,expected",
    [
        ("PPTP Server at 1.2.3.4:1723", "1.2.3.4:1723"),
        ("Unencrypted FTP Server at 10.0.0.5:21", "10.0.0.5:21"),
        ("Insecure NGINX Web Server (1.17.7) at 10.0.0.5:80", "10.0.0.5:80"),
        ("Exposed VPN at vpn.acme.com:443", "vpn.acme.com:443"),
        ("Bare host at 10.0.0.5", "10.0.0.5"),
        ("No socket in this name", None),
        ("", None),
    ],
)
def test_target_from_exposure_name(name, expected):
    """The host[:port] is recovered from the ASM exposure-name pattern."""
    assert target_from_exposure_name(name) == expected


def test_button_creates_and_polls(mocker, first_run):
    """First click (button): creates a scan, marks Running, and starts the self-poll loop."""
    calls = []

    def fake_execute(command, args):
        calls.append((command, args))
        if command == "tenzai-create-scan":
            return CREATE_ENTRY
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    result = start_agentic_validation({"target": "1.2.3.4", "exposure_name": "Exposed RDP", "alert_internal_id": "a-9"})

    commands = [c[0] for c in calls]
    assert "tenzai-create-scan" in commands
    assert ("setIncident", {"tenzaiassessmentstatus": "Running"}) in calls
    # The correlation keys ride on the outputs (here just alert_id, from alert_internal_id) so the
    # verdict fetch can scope to this alert's lead.
    assert result.outputs == {"id": "scan_1", "status": "Running", "alert_id": "a-9"}
    assert result.scheduled_command is not None  # self-poll loop started


def test_button_writes_live_reference_url_on_running(mocker, first_run):
    """When create returns a live Agent-log URL, it is written to the issue at Running time (ENG-5200)."""
    log_url = "https://app.tenzai.io/apps/a/tests/t/log"
    calls = []

    def fake_execute(command, args):
        calls.append((command, args))
        if command == "tenzai-create-scan":
            return [
                {
                    "Type": 1,
                    "EntryContext": {
                        "Tenzai.Scan(val.id == obj.id)": {"id": "scan_1", "status": "Pending", "referenceUrl": log_url}
                    },
                }
            ]
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    result = start_agentic_validation({"target": "1.2.3.4", "exposure_name": "Exposed RDP"})

    # The Running write carries the live Agent-log link (verdict outputs are unchanged).
    assert ("setIncident", {"tenzaiassessmentstatus": "Running", "tenzaireferenceurl": log_url}) in calls
    assert result.outputs == {"id": "scan_1", "status": "Running"}


def test_button_forwards_analyst_guidelines(mocker, first_run):
    """Analyst guidelines from the Actions section ride along to tenzai-create-scan (ENG-6970)."""
    calls = []

    def fake_execute(command, args):
        calls.append((command, args))
        if command == "tenzai-create-scan":
            return CREATE_ENTRY
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    start_agentic_validation({"target": "1.2.3.4", "exposure_name": "Exposed RDP", "guidelines": "Focus on the login form."})

    create_args = next(args for command, args in calls if command == "tenzai-create-scan")
    assert create_args["guidelines"] == "Focus on the login form."


def test_button_omits_guidelines_when_blank(mocker, first_run):
    """No analyst guidelines => the arg is not sent at all (assign_params drops empties)."""
    calls = []

    def fake_execute(command, args):
        calls.append((command, args))
        if command == "tenzai-create-scan":
            return CREATE_ENTRY
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    start_agentic_validation({"target": "1.2.3.4", "exposure_name": "Exposed RDP"})

    create_args = next(args for command, args in calls if command == "tenzai-create-scan")
    assert "guidelines" not in create_args


def test_button_dedupes_when_already_running(mocker):
    """A second click while a validation is already Running does not start another scan."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    mocker.patch.object(demisto, "incident", create=True, return_value={"CustomFields": {"tenzaiassessmentstatus": "Running"}})
    calls = []
    mocker.patch.object(demisto, "executeCommand", side_effect=lambda c, a: calls.append((c, a)) or [{"Type": 1}])

    result = start_agentic_validation({"target": "1.2.3.4", "exposure_name": "Exposed RDP"})

    assert "tenzai-create-scan" not in [c[0] for c in calls]
    assert result.scheduled_command is None
    assert "already running" in result.readable_output.lower()


def test_playbook_path_creates_only(mocker, first_run):
    """With poll=false (the playbook), the script only creates the scan — no self-poll loop."""
    calls = []

    def fake_execute(command, args):
        calls.append((command, args))
        if command == "tenzai-create-scan":
            return CREATE_ENTRY
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    result = start_agentic_validation(
        {"poll": "false", "target": "1.2.3.4", "exposure_name": "Exposed RDP", "alert_internal_id": "a-1"}
    )

    assert "tenzai-create-scan" in [c[0] for c in calls]
    assert ("setIncident", {"tenzaiassessmentstatus": "Running"}) in calls
    # The playbook path surfaces the correlation keys (alert_id here) so task 3 can pass them on.
    assert result.outputs == {"id": "scan_1", "status": "Running", "alert_id": "a-1"}
    assert result.scheduled_command is None  # the playbook owns polling/write-back


def test_enriches_from_asm_service_and_passes_issue_description(mocker, first_run):
    """With only a service_id, the script enriches from ASM and passes raw fields + the issue
    Description to tenzai-create-scan."""
    captured = {}

    def fake_execute(command, args):
        if command == "asm-get-external-service":
            return ENRICH_ENTRY
        if command == "tenzai-create-scan":
            captured["create_args"] = args
            return CREATE_ENTRY
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    start_agentic_validation(
        {
            "service_id": "svc-1",
            "exposure_name": "Insecure OpenSSH",
            "issue_description": "CVE-2018-15473 user enumeration on the SSH server",
            "alert_internal_id": "a-1",
        }
    )

    ca = captured["create_args"]
    assert ca["target"] == "vpn.acme.com"  # domain preferred over ip
    assert ca["port"] == "443"
    assert ca["protocol"] == "tcp"
    assert ca["service_classification"] == "WebServer"
    assert "CVE-2024-1234" in ca["supporting_data"]  # service-wide CVEs ride as evidence
    assert ca["asm_service_id"] == "svc-1"
    assert ca["issue_description"] == "CVE-2018-15473 user enumeration on the SSH server"
    # The service's inferred CVEs are context only — NOT promoted to cve_id/category,
    # since they belong to the IP/service, not this specific issue.
    assert "cve_id" not in ca


def test_falls_back_to_socket_in_exposure_name(mocker, first_run):
    """With no target and no (resolvable) service_id, parse host:port from the name and create."""
    commands = []
    captured = {}

    def fake_execute(command, args):
        commands.append(command)
        if command == "tenzai-create-scan":
            captured["create_args"] = args
            return CREATE_ENTRY
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    start_agentic_validation({"exposure_name": "PPTP Server at 1.2.3.4:1723", "alert_internal_id": "511620"})

    assert "asm-get-external-service" not in commands
    assert captured["create_args"]["target"] == "1.2.3.4:1723"


def test_without_target_or_service_raises(mocker, first_run):
    """No target, no resolvable service id, and no parseable name is an error."""
    mocker.patch.object(demisto, "executeCommand", side_effect=lambda c, a: [{"Type": 1}])
    with pytest.raises(DemistoException):
        start_agentic_validation({"exposure_name": "x"})


def test_poll_still_running_reschedules(mocker):
    """A re-entry that finds the scan still running reschedules and writes nothing."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    set_incident_calls = []
    fetch_args = {}

    def fake_execute(command, args):
        if command == "tenzai-get-scan-result":
            fetch_args.update(args)
            return _result_entry({"id": "scan_1", "status": "Running", "validated": False})
        if command == "setIncident":
            set_incident_calls.append(args)
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    result = start_agentic_validation({"scan_id_internal": "scan_1", "poll_count": "1"})

    assert result.scheduled_command is not None
    assert set_incident_calls == []  # nothing written while running
    assert fetch_args == {"id": "scan_1"}  # the integration expects `id`, not scan_id


def test_poll_complete_writes_verdict(mocker):
    """A terminal re-entry writes the full verdict and stops polling."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    set_incident_calls = []

    def fake_execute(command, args):
        if command == "tenzai-get-scan-result":
            return _result_entry(
                {
                    "id": "scan_1",
                    "status": "Complete",
                    "validated": True,
                    "correlationState": "resolved",
                    "exposureStatus": "MATERIALIZED",
                    "evidence": "## Confirmed exploitable",
                    "reproduction": "1. Connect\n2. Exploit",
                    "guidance": "Upgrade to the patched version.",
                    "creditUsage": 12,
                    "duration": 252,
                    "startedAt": "2026-08-17T19:13:46.192631Z",
                    "referenceUrl": "https://app.tenzai.io/apps/a/tests/t/findings",
                },
                findings=[
                    {
                        "title": "PPTP cleartext auth",
                        "severity": "HIGH",
                        "detail": "## Impact\nCredentials exposed.\n\n## Reproduction\n\n1. Connect",
                    },
                    {"title": "SMB signing not required", "severity": "MEDIUM"},
                ],
            )
        if command == "setIncident":
            set_incident_calls.append(args)
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    result = start_agentic_validation({"scan_id_internal": "scan_1", "poll_count": "2"})

    assert result.scheduled_command is None
    fields = set_incident_calls[0]
    assert fields["tenzaiassessmentstatus"] == "Complete"
    assert fields["tenzaiissuevalidated"] == "true"
    assert fields["tenzaireproduction"] == "1. Connect\n2. Exploit"
    assert fields["tenzaicreditusage"] == 12
    assert fields["tenzaiassessmentduration"] == 252
    assert fields["tenzaistartedat"] == "2026-08-17T19:13:46.192631Z"  # feeds the panel "Started at" cell
    assert fields["tenzaireferenceurl"].endswith("/findings")
    assert "severity" not in fields  # Tenzai records the verdict but does not change severity

    # The findings populate the Tenzai Findings grid via a customFields setIncident call.
    grid_call = next(args for args in set_incident_calls if "customFields" in args)
    rows = grid_call["customFields"]["tenzaifindings"]
    assert len(rows) == 2
    assert rows[0] == {
        "finding": "PPTP cleartext auth",
        "severity": "HIGH",
        "detail": "## Impact\nCredentials exposed.\n\n## Reproduction\n\n1. Connect",
    }
    # A sparse finding still renders its title/severity; empty cells are dropped.
    assert rows[1] == {"finding": "SMB signing not required", "severity": "MEDIUM"}


def test_poll_complete_not_validated(mocker):
    """A completed-but-not-reproducible verdict records false and leaves severity untouched."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    set_incident_calls = []

    def fake_execute(command, args):
        if command == "tenzai-get-scan-result":
            return _result_entry(
                {
                    "id": "s",
                    "status": "Complete",
                    "validated": False,
                    "correlationState": "resolved",
                    "exposureStatus": "INVALIDATED",
                    "evidence": "No confirmed findings.",
                }
            )
        if command == "setIncident":
            set_incident_calls.append(args)
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    start_agentic_validation({"scan_id_internal": "s", "poll_count": "2"})

    fields = set_incident_calls[0]
    assert fields["tenzaiissuevalidated"] == "false"
    assert "severity" not in fields  # Tenzai does not lower severity
    # No duration on this result => the numeric field is simply not written (not coerced to "").
    assert "tenzaiassessmentduration" not in fields
    # The grid is overwritten even with no findings, so a prior run's rows can't
    # linger under a not-exploitable verdict (ENG-5198).
    grid_call = next(args for args in set_incident_calls if "customFields" in args)
    assert grid_call["customFields"]["tenzaifindings"] == []


def test_poll_complete_clears_stale_findings_grid(mocker):
    """A 0-finding terminal verdict overwrites the findings grid with an empty list.

    Regression guard for ENG-5198: the write-back must set the grid on *every*
    terminal write (not only when findings exist), so a fresh not-exploitable
    verdict overwrites — rather than inherits — a prior scan's findings rows.
    """
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    set_incident_calls = []

    def fake_execute(command, args):
        if command == "tenzai-get-scan-result":
            # SUCCESS with no findings -> Not Exploitable. Note: no Tenzai.Finding context.
            return _result_entry(
                {
                    "id": "s",
                    "status": "Complete",
                    "validated": False,
                    "correlationState": "resolved",
                    "exposureStatus": "INVALIDATED",
                    "evidence": "No exploitable findings were confirmed for this exposure.",
                    "creditUsage": 3.04,
                    "referenceUrl": "https://app.tenzai.io/apps/a/tests/t/findings",
                },
                findings=[],
            )
        if command == "setIncident":
            set_incident_calls.append(args)
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    start_agentic_validation({"scan_id_internal": "s", "poll_count": "2"})

    # Exactly one grid write, carrying empty lists (clears any stale rows) for all grid fields.
    grid_calls = [args for args in set_incident_calls if "customFields" in args]
    assert len(grid_calls) == 1
    assert grid_calls[0] == {"customFields": {"tenzaifindings": [], "tenzaitimeline": []}}

    # The scalar result block is written atomically: fresh evidence, no stale
    # reproduction/guidance carried over from a would-be prior run.
    scalar = set_incident_calls[0]
    assert scalar["tenzaiissuevalidated"] == "false"
    assert scalar["tenzaiassessmentevidence"].startswith("No exploitable findings")
    assert scalar["tenzaireproduction"] == ""
    assert scalar["tenzaiguidance"] == ""
    assert scalar["tenzaiissuerationale"] == ""  # cleared when the scan has no CVE rationale


def test_poll_complete_writes_cve_rationale(mocker):
    """A CVE lead rationale on the result is persisted to tenzaiissuerationale (ENG-4910)."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    rationale = "## Description\n\nCVE hypothesis.\n\n## Conclusion\n\nCONFIRMED FALSE POSITIVE."
    set_incident_calls = []

    def fake_execute(command, args):
        if command == "tenzai-get-scan-result":
            return _result_entry(
                {
                    "id": "s",
                    "status": "Complete",
                    "validated": False,
                    "correlationState": "resolved",
                    "exposureStatus": "INVALIDATED",
                    "evidence": "x",
                    "leadRationale": rationale,
                }
            )
        if command == "setIncident":
            set_incident_calls.append(args)
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    start_agentic_validation({"scan_id_internal": "s", "poll_count": "2"})

    assert set_incident_calls[0]["tenzaiissuerationale"] == rationale


def test_poll_non_bool_validated_clears_rather_than_escalates(mocker):
    """A non-boolean 'validated' (only a real True/False is a verdict) clears the field, never escalates.

    Only a Python bool True/False maps to "true"/"false"; anything else (a stray string, None) is
    inconclusive and clears tenzaiissuevalidated to "" so a prior run's "true" cannot survive.
    """
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    set_incident_calls = []

    def fake_execute(command, args):
        if command == "tenzai-get-scan-result":
            return _result_entry(
                {"id": "s", "status": "Complete", "validated": "false", "correlationState": "unmatched", "evidence": "x"}
            )
        if command == "setIncident":
            set_incident_calls.append(args)
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    start_agentic_validation({"scan_id_internal": "s", "poll_count": "2"})

    fields = set_incident_calls[0]
    assert "severity" not in fields  # not escalated on a truthy non-bool
    assert fields["tenzaiissuevalidated"] == ""  # cleared, not left to drift from a prior run


def test_poll_inconclusive_clears_stale_verdict(mocker):
    """A None (BLOCKED/unmatched) verdict clears tenzaiissuevalidated so a prior 'true' cannot survive."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    set_incident_calls = []

    def fake_execute(command, args):
        if command == "tenzai-get-scan-result":
            return _result_entry(
                {
                    "id": "s",
                    "status": "Complete",
                    "validated": None,
                    "correlationState": "resolved",
                    "evidence": "x",
                    "exposureStatus": "BLOCKED",
                }
            )
        if command == "setIncident":
            set_incident_calls.append(args)
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    start_agentic_validation({"scan_id_internal": "s", "poll_count": "2"})

    assert set_incident_calls[0]["tenzaiissuevalidated"] == ""


def test_write_only_playbook_path_writes_grid_and_timeline(mocker):
    """The playbook (write_only) re-entry fetches once and persists the full verdict — scalars, the
    findings grid, and the timeline — through the SAME writer the button uses, with no rescheduling."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    set_incident_calls = []
    fetch_args = {}

    def fake_execute(command, args):
        if command == "tenzai-get-scan-result":
            fetch_args.update(args)
            return _result_entry(
                {
                    "id": "scan_1",
                    "status": "Complete",
                    "validated": False,
                    "correlationState": "resolved",
                    "evidence": "No exploitable findings were confirmed for this exposure.",
                    "exposureStatus": "INVALIDATED",
                    "leadRationale": "## Conclusion\n\nCONFIRMED FALSE POSITIVE.",
                    "timeline": [{"status": "OPEN", "time": "08-20 15:36"}],
                },
                findings=[
                    {
                        "title": "CVE-2024-23897: Arbitrary File Read",
                        "severity": "HIGH",
                        "detail": "x",
                        "cve": "CVE-2024-23897",
                        "attribution": "discovered",
                    },
                ],
            )
        if command == "setIncident":
            set_incident_calls.append(args)
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    result = start_agentic_validation(
        {"scan_id_internal": "scan_1", "write_only": "true", "alert_id": "600052", "cve": "CVE-2023-44487"}
    )

    # Fetched once, scoped by the correlation keys; no reschedule.
    assert fetch_args == {"id": "scan_1", "alert_id": "600052", "cve": "CVE-2023-44487"}
    assert result.scheduled_command is None
    # The grid + timeline are written on the playbook path (the bug this fixes).
    grid_call = next(args for args in set_incident_calls if "customFields" in args)
    rows = grid_call["customFields"]["tenzaifindings"]
    assert rows[0]["attribution"] == "discovered"
    assert grid_call["customFields"]["tenzaitimeline"] == [{"status": "OPEN", "time": "08-20 15:36"}]
    # And the verdict is cleared (INVALIDATED -> validated False here, written explicitly).
    scalar = set_incident_calls[0]
    assert scalar["tenzaiissuevalidated"] == "false"


def test_poll_re_supplies_correlation_keys_to_result_fetch(mocker):
    """The scheduled re-entry re-supplies alert_id/cve/rule_id to tenzai-get-scan-result and forwards them."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    fetch_args = {}

    def fake_execute(command, args):
        if command == "tenzai-get-scan-result":
            fetch_args.update(args)
            return _result_entry({"id": "scan_1", "status": "Running", "validated": None})
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    result = start_agentic_validation(
        {
            "scan_id_internal": "scan_1",
            "poll_count": "1",
            "alert_id": "600052",
            "cve": "CVE-2023-44487",
            "rule_id": "rule-9",
        }
    )

    # The verdict fetch is scoped by the carried correlation keys...
    assert fetch_args == {
        "id": "scan_1",
        "alert_id": "600052",
        "cve": "CVE-2023-44487",
        "rule_id": "rule-9",
    }
    # ...and the keys ride onto the next scheduled tick.
    next_args = result.scheduled_command._args
    assert next_args["alert_id"] == "600052"
    assert next_args["cve"] == "CVE-2023-44487"
    assert next_args["rule_id"] == "rule-9"


def test_poll_timeout_marks_error(mocker):
    """When the polling window is exhausted with no verdict, the status is set to Error (not stuck Running)."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    set_incident_calls = []

    def fake_execute(command, args):
        if command == "tenzai-get-scan-result":
            return _result_entry({"id": "scan_1", "status": "Running"})
        if command == "setIncident":
            set_incident_calls.append(args)
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    result = start_agentic_validation({"scan_id_internal": "scan_1", "poll_count": str(MAX_POLLS)})

    assert result.scheduled_command is None  # stop polling
    assert set_incident_calls == [{"tenzaiassessmentstatus": "Error"}]


def test_poll_transient_fetch_error_reschedules(mocker):
    """A transient fetch error retries on the next tick rather than aborting the loop."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    mocker.patch.object(demisto, "error")  # the retry path logs via demisto.error; keep it off stdout in tests
    set_incident_calls = []

    def fake_execute(command, args):
        if command == "tenzai-get-scan-result":
            return [{"Type": 4, "Contents": "transient 503"}]  # error entry → run_command raises
        if command == "setIncident":
            set_incident_calls.append(args)
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)

    result = start_agentic_validation({"scan_id_internal": "scan_1", "poll_count": "1"})

    assert result.scheduled_command is not None  # retried, not aborted
    assert set_incident_calls == []  # no premature verdict/error write


# ---------------------------------------------------------------------------
# Enrichment-readiness gate (ENG-7505)
# ---------------------------------------------------------------------------


def test_verdict_is_enriched_open_status_not_ready():
    """A non-empty but still-open lead status (OPEN / IN_PROGRESS) is NOT enriched — the lead
    has not closed yet, so requiring merely-non-empty status would write prematurely."""
    assert _verdict_is_enriched({"exposureStatus": "IN_PROGRESS", "leadRationale": "x"}, cve_supplied=True) is False
    assert _verdict_is_enriched({"exposureStatus": "OPEN"}, cve_supplied=False) is False


def test_verdict_is_enriched_terminal_status_ready():
    assert _verdict_is_enriched({"exposureStatus": "INVALIDATED", "leadRationale": "r"}, cve_supplied=True) is True
    assert _verdict_is_enriched({"exposureStatus": "MATERIALIZED"}, cve_supplied=False) is True


def test_verdict_is_enriched_requires_rationale_for_concluded_cve():
    unenriched = {"exposureStatus": "INVALIDATED", "leadRationale": ""}
    assert _verdict_is_enriched(unenriched, cve_supplied=True) is False
    enriched = {"exposureStatus": "INVALIDATED", "leadRationale": "FALSE POSITIVE — refuted."}
    assert _verdict_is_enriched(enriched, cve_supplied=True) is True


def test_verdict_is_enriched_blocked_needs_no_rationale():
    """BLOCKED (reached but stopped at the safety boundary) has no conclusion, so a CVE lead
    is ready without a rationale — otherwise the loop would spin to the retry cap every time."""
    assert _verdict_is_enriched({"exposureStatus": "BLOCKED", "leadRationale": ""}, cve_supplied=True) is True


def test_verdict_is_enriched_zero_findings_not_missing():
    """INVALIDATED legitimately has zero findings — the findings count never gates readiness."""
    result = {"exposureStatus": "INVALIDATED", "leadRationale": "refuted", "creditUsage": None, "startedAt": None}
    assert _verdict_is_enriched(result, cve_supplied=True) is True


def _run_reentry(mocker, payload, args, findings=None):
    """Drive a scheduled re-entry, capturing setIncident calls. When ``payload`` is None the
    tenzai-get-scan-result fetch raises (transient failure)."""
    mocker.patch.object(demisto, "demistoVersion", return_value=SUPPORTED_VERSION)
    mocker.patch.object(demisto, "error")  # retry/exhaustion paths log via demisto.error; keep off stdout
    mocker.patch.object(demisto, "debug")  # the retry-cap path logs via demisto.debug
    calls: list = []

    def fake_execute(command, a):
        if command == "tenzai-get-scan-result":
            if payload is None:
                return [{"Type": 4, "Contents": "transient 503"}]  # error entry -> run_command raises
            return _result_entry(payload, findings=findings)
        if command == "setIncident":
            calls.append(a)
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute)
    return start_agentic_validation(args), calls


def test_poll_resolved_unenriched_reschedules_without_clearing(mocker):
    """Complete + a matched lead whose enrichment hasn't landed → reschedule, write NOTHING
    (no half-cleared card), carrying an incremented terminal_retry_count."""
    payload = {
        "id": "scan_1",
        "status": "Complete",
        "validated": False,
        "correlationState": "resolved",
        "exposureStatus": "",
        "leadRationale": "",
    }
    result, calls = _run_reentry(mocker, payload, {"scan_id_internal": "scan_1", "poll_count": "3", "cve": "CVE-2023-44487"})
    assert result.scheduled_command is not None
    assert calls == []
    assert result.scheduled_command._args.get("terminal_retry_count") == 1


def test_poll_resolved_open_status_reschedules(mocker):
    """Terminal scan but the matched lead is still IN_PROGRESS → wait, don't write."""
    payload = {
        "id": "scan_1",
        "status": "Complete",
        "validated": None,
        "correlationState": "resolved",
        "exposureStatus": "IN_PROGRESS",
    }
    result, calls = _run_reentry(mocker, payload, {"scan_id_internal": "scan_1", "poll_count": "3"})
    assert result.scheduled_command is not None
    assert calls == []


def test_poll_pending_reschedules_no_partial_write(mocker):
    """correlationState=pending (failed/empty leads fetch) must keep waiting, never write a
    partial verdict — this is the original bug the tri-state guards against."""
    payload = {"id": "scan_1", "status": "Complete", "validated": None, "correlationState": "pending"}
    result, calls = _run_reentry(mocker, payload, {"scan_id_internal": "scan_1", "poll_count": "3"})
    assert result.scheduled_command is not None
    assert calls == []


def test_poll_unmatched_writes_immediately(mocker):
    """Leads fetched, none correlate (unmatched) → definitive; write the inconclusive verdict now."""
    payload = {"id": "scan_1", "status": "Complete", "validated": None, "correlationState": "unmatched"}
    result, calls = _run_reentry(mocker, payload, {"scan_id_internal": "scan_1", "poll_count": "3"})
    assert result.scheduled_command is None
    assert calls
    assert calls[0]["tenzaiassessmentstatus"] == "Complete"
    assert calls[0]["tenzaiissuevalidated"] == ""  # inconclusive -> cleared


def test_poll_resolved_enriched_writes_invalidated(mocker):
    """A later enriched tick writes the full verdict: INVALIDATED + start time + ACU + rationale."""
    payload = {
        "id": "scan_1",
        "status": "Complete",
        "validated": False,
        "correlationState": "resolved",
        "exposureStatus": "INVALIDATED",
        "leadRationale": "FALSE POSITIVE — refuted.",
        "creditUsage": 2.18,
        "startedAt": "2026-08-31T12:00:00Z",
    }
    result, calls = _run_reentry(
        mocker,
        payload,
        {"scan_id_internal": "scan_1", "poll_count": "3", "terminal_retry_count": "1", "cve": "CVE-2023-44487"},
    )
    assert result.scheduled_command is None
    fields = calls[0]
    assert fields["tenzaiissuevalidated"] == "false"
    assert fields["tenzaiexposurestatus"] == "INVALIDATED"
    assert fields["tenzaistartedat"] == "2026-08-31T12:00:00Z"
    assert fields["tenzaicreditusage"] == 2.18
    assert fields["tenzaiissuerationale"] == "FALSE POSITIVE — refuted."


def test_poll_retry_cap_writes_partial(mocker):
    """Enrichment window exhausted on a terminal result → write the partial verdict, stop polling."""
    payload = {
        "id": "scan_1",
        "status": "Complete",
        "validated": False,
        "correlationState": "resolved",
        "exposureStatus": "",
        "leadRationale": "",
    }
    result, calls = _run_reentry(
        mocker,
        payload,
        {
            "scan_id_internal": "scan_1",
            "poll_count": "3",
            "terminal_retry_count": str(TERMINAL_MAX_RETRIES),
            "cve": "CVE-2023-44487",
        },
    )
    assert result.scheduled_command is None
    assert calls
    assert "tenzaiassessmentstatus" in calls[0]


def test_write_only_reschedules_when_unenriched(mocker):
    """write_only must ALSO retry: the playbook polls scan status, not enrichment readiness."""
    payload = {
        "id": "scan_1",
        "status": "Complete",
        "validated": False,
        "correlationState": "resolved",
        "exposureStatus": "",
        "leadRationale": "",
    }
    result, calls = _run_reentry(mocker, payload, {"scan_id_internal": "scan_1", "write_only": "true", "cve": "CVE-2023-44487"})
    assert result.scheduled_command is not None
    assert result.scheduled_command._args.get("write_only") == "true"
    assert result.scheduled_command._args.get("terminal_retry_count") == 1
    assert calls == []


def test_write_only_writes_when_enriched(mocker):
    """write_only + a fully-enriched MATERIALIZED result writes Exploitable + attributed findings."""
    payload = {
        "id": "scan_1",
        "status": "Complete",
        "validated": True,
        "correlationState": "resolved",
        "exposureStatus": "MATERIALIZED",
        "leadRationale": "Confirmed exploit.",
        "creditUsage": 5,
    }
    result, calls = _run_reentry(
        mocker,
        payload,
        {"scan_id_internal": "scan_1", "write_only": "true", "cve": "CVE-2024-23897"},
        findings=[{"title": "Arbitrary file read", "severity": "CRITICAL"}],
    )
    assert result.scheduled_command is None
    assert calls[0]["tenzaiissuevalidated"] == "true"
    assert calls[0]["tenzaiexposurestatus"] == "MATERIALIZED"
    grid = next(a for a in calls if "customFields" in a)
    assert len(grid["customFields"]["tenzaifindings"]) == 1


def test_write_only_marks_error_on_fetch_failure_cap(mocker):
    """write_only that never gets a terminal result (repeated fetch failures) must mark the issue
    Error at the cap, not leave it stuck on Running forever."""
    result, calls = _run_reentry(
        mocker,
        None,
        {"scan_id_internal": "scan_1", "write_only": "true", "terminal_retry_count": str(TERMINAL_MAX_RETRIES)},
    )
    assert result.scheduled_command is None
    assert calls
    assert calls[0]["tenzaiassessmentstatus"] == "Error"

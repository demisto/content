"""Tests for the tLab Anti-APT Sandbox integration."""

import json
from pathlib import Path

import pytest

import TLabAntiAPTSandbox as sandbox
from CommonServerPython import DemistoException
from TLabAntiAPTApiModule import AUTH_SOURCE_KEY, TLabClient, TLabRejection

BASE = "https://tlab.example.com"
DATA = Path(__file__).parent / "test_data"


def load(name: str) -> dict:
    return json.loads((DATA / f"{name}.json").read_text())


@pytest.fixture
def client():
    return TLabClient(
        base_url=BASE,
        auth_mode=AUTH_SOURCE_KEY,
        credentials={"password": "key"},
        client_name="xsoar",
        verify=False,
    )


@pytest.fixture
def params():
    return {"url": BASE, "reliability": "B - Usually reliable", "report_url_base": "https://tlab.example.com"}


@pytest.fixture(autouse=True)
def no_incident(mocker):
    mocker.patch.object(sandbox.demisto, "incident", return_value={})
    mocker.patch.object(sandbox.demisto, "getLicenseID", return_value="lic-1")


@pytest.fixture(autouse=True)
def isolate_file_results(tmp_path, monkeypatch):
    """Keep fileResult output out of the repository.

    CommonServerPython.fileResult writes into the current working directory, so
    without this every artifact test would leave a stray file behind. Fixture
    paths are absolute, so changing the directory is safe.
    """
    monkeypatch.chdir(tmp_path)


# --------------------------------------------------------------- test-module


def test_test_module_returns_exactly_ok(client, params, requests_mock):
    # XSOAR shows anything other than an exact "ok" as a failed test, even
    # "ok - connected as …".
    requests_mock.get(f"{BASE}/auth/test", json={"userLogin": "svc", "userRole": "admin"})
    assert sandbox.test_module_command(client, params) == "ok"


def test_test_module_logs_when_the_role_cannot_fetch_artifacts(client, params, requests_mock, mocker):
    # Artifact endpoints are admin-only. A lower role still submits and polls,
    # so the test passes, and the warning goes to the integration log.
    info = mocker.patch.object(sandbox.demisto, "info")
    requests_mock.get(f"{BASE}/auth/test", json={"userLogin": "joe", "userRole": "user"})
    assert sandbox.test_module_command(client, params) == "ok"
    assert "admin or developer" in info.call_args[0][0]


def test_test_module_surfaces_connectivity_failure(client, params, requests_mock):
    requests_mock.get(f"{BASE}/auth/test", status_code=500, text="boom")
    with pytest.raises(Exception, match="Could not reach"):
        sandbox.test_module_command(client, params)


# -------------------------------------------------------------------- submit


def test_submit_file_sends_multipart_with_repeated_keys(client, params, mocker, requests_mock, tmp_path):
    sample = tmp_path / "invoice.exe"
    sample.write_bytes(b"MZ")
    mocker.patch.object(sandbox.demisto, "getFilePath", return_value={"path": str(sample), "name": "invoice.exe"})
    requests_mock.post(f"{BASE}/analyzes/file", json=load("submit_accepted"))

    results = sandbox.submit_file_command(client, {"entry_id": "1@1"}, params)

    body = requests_mock.last_request.text
    assert body.count('name="analysisTypes"') == 2
    assert 'name="source.sourceType"' in body
    assert "CORTEX_XSOAR" in body
    assert results.outputs["AccessCode"] == "acc-123"


def test_submit_file_adds_the_incident_id_as_provenance(client, params, mocker, requests_mock, tmp_path):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"x")
    mocker.patch.object(sandbox.demisto, "getFilePath", return_value={"path": str(sample), "name": "a.bin"})
    mocker.patch.object(sandbox.demisto, "incident", return_value={"id": "42"})
    requests_mock.post(f"{BASE}/analyzes/file", json=load("submit_accepted"))

    sandbox.submit_file_command(client, {"entry_id": "1@1"}, params)
    assert 'name="properties[xsoar_incident_id]"' in requests_mock.last_request.text


def test_submit_file_requires_an_entry_id(client, params):
    with pytest.raises(Exception, match="entry_id is required"):
        sandbox.submit_file_command(client, {}, params)


def test_submit_url_rejection_raises_with_a_readable_message(client, params, requests_mock):
    requests_mock.post(f"{BASE}/analyzes/url", json=load("submit_rejected_url_invalid"))
    with pytest.raises(TLabRejection, match="URL is not valid"):
        sandbox.submit_url_command(client, {"url": "ftp://x"}, params)


def test_whitelisted_submission_is_not_an_error(client, params, requests_mock):
    # "Whitelisted" means there is an answer, so the command returns a result
    # rather than failing the playbook.
    requests_mock.post(f"{BASE}/analyzes/url", json=load("submit_rejected_whitelisted"))
    results = sandbox.submit_url_command(client, {"url": "https://x"}, params)
    assert results.outputs["RejectionCode"] == "common.whitelisted"
    assert results.outputs["Whitelisted"] is True


# ------------------------------------------------------------------- polling


def test_status_is_not_terminal_while_processing(client, params, requests_mock):
    requests_mock.get(f"{BASE}/public/request_status/acc", json=load("request_status_processing"))
    terminal, _ = sandbox.resolve_status(client, "acc", {}, params)
    assert terminal is False


def test_status_is_terminal_on_complete(client, params, requests_mock):
    requests_mock.get(f"{BASE}/public/request_status/acc", json=load("request_status_complete_malware"))
    terminal, results = sandbox.resolve_status(client, "acc", {}, params)
    assert terminal is True
    assert results.outputs["Verdict"] == "MALWARE"
    assert results.outputs["SampleReportId"] == 412839


def test_partial_with_unknown_verdict_keeps_polling(client, params, requests_mock):
    # PARTIALLY_COMPLETE plus UNKNOWN means the analysis is still running.
    requests_mock.get(f"{BASE}/public/request_status/acc", json=load("request_status_partial_unknown"))
    terminal, _ = sandbox.resolve_status(client, "acc", {}, params)
    assert terminal is False


def test_both_raw_verdict_fields_are_preserved(client, params, requests_mock):
    # The server says MALICIOUS on one field and MALWARE on another; an analyst
    # must be able to see both, not only our canonical value.
    requests_mock.get(f"{BASE}/public/request_status/acc", json=load("request_status_complete_malware"))
    _, results = sandbox.resolve_status(client, "acc", {}, params)
    assert results.outputs["ScoreLevel"] == "MALICIOUS"
    assert results.outputs["FileVerdict"] == "MALWARE"
    assert results.outputs["Verdict"] == "MALWARE"
    assert "FileId" not in results.outputs.get("File", {})


def test_unset_file_verdict_is_not_shown(params):
    # The manual file verdict defaults to UNKNOWN; the analysis verdict stays.
    report = {
        "sampleReportId": 1,
        "verdict": "MALICIOUS",
        "sampleReportCompleteness": "COMPLETE",
        "file": {"hashSha256": "a" * 64, "fileVerdict": "UNKNOWN", "fileId": 5},
    }
    outputs = sandbox.analysis_outputs(report, params)
    assert "FileVerdict" not in outputs
    assert "FileVerdict" not in outputs["File"]
    assert "FileId" not in outputs["File"]
    assert outputs["Verdict"] == "MALWARE"


def test_archive_members_do_not_hijack_the_main_report(client, params, requests_mock):
    # A dropped member can score higher than the archive itself; the command
    # must still report the MAIN report as the answer.
    requests_mock.get(f"{BASE}/public/request_status/acc", json=load("request_status_archive_members"))
    _, results = sandbox.resolve_status(client, "acc", {}, params)
    assert results.outputs["SampleReportId"] == 10
    assert [c["SampleReportId"] for c in results.outputs["ChildReports"]] == [11]


def test_extended_fetches_sub_report_ids_from_sample_reports(client, params, requests_mock):
    # The public status endpoint returns SampleReportShortBean, which carries
    # neither dynReportSummary nor statReportSummary.
    requests_mock.get(f"{BASE}/public/request_status/acc", json=load("request_status_complete_malware"))
    requests_mock.get(f"{BASE}/sample_reports/412839", json=load("sample_report_enriched"))
    _, results = sandbox.resolve_status(client, "acc", {"extended": "true"}, params)
    assert results.outputs["DynReportId"] == 777
    assert results.outputs["StatReportId"] == 888


def test_requested_but_not_run_is_surfaced(client, params, requests_mock):
    # The server strips DYN_ANALYSIS on a LITE license, so a "dynamic" request
    # can silently come back static only.
    requests_mock.get(f"{BASE}/public/request_status/acc", json=load("request_status_complete_malware"))
    requests_mock.get(f"{BASE}/sample_reports/412839", json=load("sample_report_enriched"))
    _, results = sandbox.resolve_status(client, "acc", {"extended": "true"}, params)
    assert results.outputs["RequestedButNotRun"] == ["DYN_ANALYSIS"]
    assert "did not run" in results.readable_output


def test_poll_schedules_next_run_when_supported(client, params, requests_mock, mocker):
    requests_mock.get(f"{BASE}/public/request_status/acc", json=load("request_status_processing"))
    mocker.patch.object(sandbox, "supports_scheduled_commands", return_value=True)
    results = sandbox.poll_status_command(client, {"access_code": "acc"}, params)
    assert results.scheduled_command is not None


def test_poll_returns_immediately_when_terminal(client, params, requests_mock, mocker):
    requests_mock.get(f"{BASE}/public/request_status/acc", json=load("request_status_complete_malware"))
    mocker.patch.object(sandbox, "supports_scheduled_commands", return_value=True)
    results = sandbox.poll_status_command(client, {"access_code": "acc"}, params)
    assert results.scheduled_command is None
    assert results.outputs["Verdict"] == "MALWARE"


def test_poll_falls_back_to_blocking_below_6_2(client, params, requests_mock, mocker):
    # Servers below 6.2.0 cannot schedule commands, so the loop runs inline.
    requests_mock.get(
        f"{BASE}/public/request_status/acc",
        [{"json": load("request_status_processing")}, {"json": load("request_status_complete_malware")}],
    )
    mocker.patch.object(sandbox, "supports_scheduled_commands", return_value=False)
    mocker.patch("TLabAntiAPTApiModule.time.sleep")
    results = sandbox.poll_status_command(
        client, {"access_code": "acc", "interval_in_seconds": "1", "timeout_in_seconds": "60"}, params
    )
    assert results.outputs["Verdict"] == "MALWARE"


def test_poll_requires_an_access_code(client, params):
    with pytest.raises(Exception, match="access_code is required"):
        sandbox.poll_status_command(client, {}, params)


def test_detonate_submits_then_polls(client, params, mocker, requests_mock, tmp_path):
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"MZ")
    mocker.patch.object(sandbox.demisto, "getFilePath", return_value={"path": str(sample), "name": "a.exe"})
    mocker.patch.object(sandbox, "supports_scheduled_commands", return_value=True)
    requests_mock.post(f"{BASE}/analyzes/file", json=load("submit_accepted"))
    requests_mock.get(f"{BASE}/public/request_status/acc-123", json=load("request_status_complete_malware"))

    results = sandbox.detonate_command(client, {"entry_id": "1@1"}, params, "file")
    assert results.outputs["Verdict"] == "MALWARE"


def test_detonate_rerun_skips_submission(client, params, requests_mock, mocker):
    # A scheduled re-run arrives with the access code already known and must
    # not submit the sample a second time.
    submit = requests_mock.post(f"{BASE}/analyzes/file", json=load("submit_accepted"))
    requests_mock.get(f"{BASE}/public/request_status/acc-123", json=load("request_status_complete_malware"))
    mocker.patch.object(sandbox, "supports_scheduled_commands", return_value=True)

    sandbox.detonate_command(client, {"access_code": "acc-123"}, params, "file")
    assert submit.call_count == 0


# --------------------------------------------------------------- reputation


def test_dbot_score_and_file_indicator_are_attached(client, params, requests_mock):
    requests_mock.get(f"{BASE}/public/request_status/acc", json=load("request_status_complete_malware"))
    _, results = sandbox.resolve_status(client, "acc", {}, params)
    indicator = results.indicator
    assert indicator is not None
    assert indicator.dbot_score.score == 3
    assert indicator.dbot_score.reliability == "B - Usually reliable"
    assert indicator.sha256.startswith("aaaabbbb")


def test_no_indicator_without_a_hash(params):
    assert sandbox.build_file_indicator({"File": {}}, "B - Usually reliable") is None


# -------------------------------------------------------------------- reports


def test_get_report_returns_the_analysis_shape(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports/412839", json=load("sample_report_enriched"))
    results = sandbox.get_report_command(client, {"sample_report_id": "412839"}, params)
    assert results.outputs["Verdict"] == "MALWARE"
    assert results.outputs["ReportUrl"].endswith("/reports/412839")


def test_threat_indicators_filtering(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports/412839/threat_indicators", json=load("threat_indicators"))
    results = sandbox.get_threat_indicators_command(client, {"sample_report_id": "412839", "level": "MALICIOUS"}, params)
    assert len(results.outputs["Indicators"]) == 1
    assert results.outputs["Indicators"][0]["Objects"][0]["Name"] == "evil.example.com"


def test_threat_indicators_respects_limit(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports/412839/threat_indicators", json=load("threat_indicators"))
    results = sandbox.get_threat_indicators_command(client, {"sample_report_id": "412839", "limit": "1"}, params)
    assert len(results.outputs["Indicators"]) == 1


def test_attack_matrix_outputs_techniques(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports/412839/attack_matrix", json=load("attack_matrix"))
    results = sandbox.get_attack_matrix_command(client, {"sample_report_id": "412839"}, params)
    assert [t["Id"] for t in results.outputs["Techniques"]] == ["T1071", "T1027"]
    assert results.outputs["CatalogVersion"] == "14.1"


# ------------------------------------------------------------------ artifacts


def test_pcap_binary_sends_octet_stream_accept(client, params, requests_mock):
    # Two handlers are mapped to {id}/pcap and differ only by produces, so the
    # Accept header decides which one answers.
    requests_mock.get(f"{BASE}/dyn_reports/5/pcap", content=b"pcap-bytes")
    result = sandbox.get_pcap_command(client, {"dyn_report_id": "5", "format": "pcap"}, params)
    assert requests_mock.last_request.headers["Accept"] == "application/octet-stream"
    assert result["File"] == "tlab_5.pcap"


def test_pcap_json_sends_json_accept(client, params, requests_mock):
    requests_mock.get(f"{BASE}/dyn_reports/5/pcap", json={"flows": []})
    results = sandbox.get_pcap_command(client, {"dyn_report_id": "5", "format": "json"}, params)
    assert requests_mock.last_request.headers["Accept"] == "application/json"
    assert results.outputs["DynReportId"] == 5


def test_pcap_respects_the_size_limit(client, params, requests_mock):
    requests_mock.get(f"{BASE}/dyn_reports/5/pcap", content=b"x" * (3 * 1024 * 1024))
    with pytest.raises(Exception, match="exceeds the configured limit"):
        sandbox.get_pcap_command(client, {"dyn_report_id": "5"}, {**params, "max_artifact_size_mb": 1})


def test_report_pdf_uses_post(client, params, requests_mock):
    # This endpoint is a POST, not a GET — an easy detail to get wrong.
    matcher = requests_mock.post(f"{BASE}/report-pdf/412839", content=b"%PDF-1.4")
    result = sandbox.get_report_pdf_command(client, {"sample_report_id": "412839"}, params)
    assert matcher.call_count == 1
    assert result["File"] == "tlab_report_412839.pdf"


# --------------------------------------------------------------- misc listings


def test_list_env_presets(client, requests_mock):
    requests_mock.get(f"{BASE}/ex_env/presets/global", json=[{"name": "win10"}, {"name": "win7"}])
    results = sandbox.list_env_presets_command(client, {"scope": "global"})
    assert [r["Name"] for r in results.outputs] == ["win10", "win7"]


def test_list_sources(client, requests_mock):
    requests_mock.get(f"{BASE}/sources", json=[{"sourceId": 12, "sourceType": "Cortex XSOAR", "sourceUid": "u"}])
    results = sandbox.list_sources_command(client)
    assert results.outputs[0]["Type"] == "Cortex XSOAR"


# ------------------------------------------------------------ yml drift guard


def _yml_commands() -> set:
    import yaml

    spec = yaml.safe_load((Path(__file__).parent / "TLabAntiAPTSandbox.yml").read_text())
    return {c["name"] for c in spec["script"]["commands"]}


def _implemented_commands() -> set:
    import re

    source = (Path(__file__).parent / "TLabAntiAPTSandbox.py").read_text()
    return set(re.findall(r'command == "([a-z0-9-]+)"', source))


def test_every_declared_command_is_implemented():
    # A command declared in the yml but missing from main() shows up in the
    # XSOAR UI and fails only when an analyst runs it.
    missing = _yml_commands() - _implemented_commands()
    assert not missing, f"declared in the yml but not implemented: {sorted(missing)}"


def test_every_implemented_command_is_declared():
    # The reverse is just as bad: working code nobody can reach.
    extra = _implemented_commands() - _yml_commands() - {"test-module"}
    assert not extra, f"implemented but not declared in the yml: {sorted(extra)}"


def test_polling_commands_declare_the_polling_flag():
    import yaml

    spec = yaml.safe_load((Path(__file__).parent / "TLabAntiAPTSandbox.yml").read_text())
    polling = {c["name"] for c in spec["script"]["commands"] if c.get("polling")}
    # Without polling: true the server never re-runs the command, so a
    # detonation would return "still running" and stop there.
    assert polling == {"tlab-get-submission-status", "tlab-detonate-file", "tlab-detonate-url"}


def test_polling_commands_hide_the_internal_polling_argument():
    import yaml

    spec = yaml.safe_load((Path(__file__).parent / "TLabAntiAPTSandbox.yml").read_text())
    for command in spec["script"]["commands"]:
        if not command.get("polling"):
            continue
        args = {a["name"]: a for a in command.get("arguments", [])}
        assert "polling" in args, f"{command['name']} must accept the internal polling argument"
        assert args["polling"].get("hidden") is True, f"{command['name']} must hide the polling argument"


def test_yml_pins_the_same_docker_image_as_the_api_module():
    import yaml

    integration = yaml.safe_load((Path(__file__).parent / "TLabAntiAPTSandbox.yml").read_text())
    # The ApiModule lives in Packs/ApiModules/Scripts - demisto-sdk hardcodes
    # that path as API_MODULES_SCRIPTS_DIR and looks nowhere else.
    module_path = Path(__file__).parents[3] / "ApiModules" / "Scripts" / "TLabAntiAPTApiModule" / "TLabAntiAPTApiModule.yml"
    module = yaml.safe_load(module_path.read_text())
    # A mismatch means air-gapped servers would need two images, and the one
    # nobody pre-loaded fails at command time rather than at install time.
    assert integration["script"]["dockerimage"] == module["dockerimage"]


# ----------------------------------------------------------------- source uid

LICENSE_ID = "CUIDe91c462e6d94d66f36914a40d81394d6124e9b2e7a56d5c4dbdfbfaafdb2223eCUID"


def test_source_uid_defaults_to_license_id_cut_to_column(mocker):
    # sources.source_uid is VARCHAR(45); the full 72-character license ID made
    # the server drop the source and run the analysis without one.
    mocker.patch.object(sandbox.demisto, "getLicenseID", return_value=LICENSE_ID)
    uid = sandbox.source_uid({})
    assert uid == LICENSE_ID[: sandbox.SOURCE_UID_MAX_LEN]
    assert len(uid) == 45


def test_source_uid_prefers_configured_value():
    assert sandbox.source_uid({"source_uid": " xsoar-lab "}) == "xsoar-lab"


def test_source_uid_rejects_configured_value_over_column():
    with pytest.raises(DemistoException, match="at most 45"):
        sandbox.source_uid({"source_uid": "x" * 46})


def test_test_module_fails_on_too_long_source_uid(client, params):
    with pytest.raises(DemistoException, match="Source UID"):
        sandbox.test_module_command(client, {**params, "source_uid": "x" * 46})


def test_submit_sends_cut_license_id(mocker, params):
    mocker.patch.object(sandbox.demisto, "getLicenseID", return_value=LICENSE_ID)
    settings = sandbox.submit_settings_from_args({}, params)
    assert ("source.sourceUid", LICENSE_ID[:45]) in settings.to_form()

"""Tests for the tLab Anti-APT Sandbox integration."""

import json
from pathlib import Path
import pytest
import TLabAntiAPTSandbox as sandbox
from CommonServerPython import DemistoException
from TLabAntiAPTSandbox import (
    AUTH_SOURCE_KEY,
    TLabClient,
    TLabRejection,
    ACTIONABLE_VERDICTS,
    AUTH_INTERNAL,
    AUTH_SIGN_IN,
    AUTH_TLAB_ACCOUNT,
    jwt_expiry,
    stored_file_verdict,
    default_auth_url,
    COMPLETENESS_COMPLETE,
    COMPLETENESS_EMPTY,
    COMPLETENESS_PARTIAL,
    DEFAULT_SEVERITY_MAP,
    NON_ERROR_REJECTIONS,
    REJECTION_MESSAGES,
    REPORT_TYPE_DROPPED,
    REPORT_TYPE_MAIN,
    SOURCE_TYPE_DISPLAY,
    SOURCE_TYPE_NAME,
    SubmitSettings,
    VERDICT_CLEAN,
    VERDICT_MALWARE,
    VERDICT_OK,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    VERDICT_WHITELIST,
    canonical_verdict,
    describe_rejection,
    epoch_to_datetime,
    epoch_to_iso,
    is_terminal,
    normalize_verdict,
    score_to_verdict,
    score_value,
    select_main_report,
    validate_sort,
    verdict_to_dbot_score,
    verdict_to_severity,
)
import time

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
    mocker.patch("TLabAntiAPTSandbox.time.sleep")
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


# ===========================================================================
# Shared tLab Anti-APT client (the block every integration carries)
# ===========================================================================
def make_client(auth_mode=AUTH_SOURCE_KEY, secret="key", username="", auth_url=""):
    return TLabClient(
        base_url=BASE,
        auth_mode=auth_mode,
        credentials={"identifier": username, "password": secret},
        client_name="xsoar",
        verify=False,
        auth_url=auth_url,
    )


# ---------------------------------------------------------------- verdicts


def test_normalize_verdict_accepts_both_vocabularies():
    # The server returns MALICIOUS on one field and MALWARE on another for the
    # very same sample.
    assert normalize_verdict("MALICIOUS") == normalize_verdict("MALWARE") == VERDICT_MALWARE
    # CLEAN and OK must stay distinct: ScoreLevel separates score == 0 from 0 < score < 50.
    assert normalize_verdict("CLEAN") != normalize_verdict("OK")
    assert normalize_verdict("whitelisted") == VERDICT_WHITELIST
    assert normalize_verdict(" suspicious ") == VERDICT_SUSPICIOUS
    assert normalize_verdict("nonsense") == ""
    assert normalize_verdict(None) == ""


@pytest.mark.parametrize(
    "score,present,expected",
    [
        (0, False, ""),
        (-1.0, True, ""),  # the API's sentinel for "no score"
        (-0.5, True, ""),
        (0, True, VERDICT_CLEAN),
        (0.1, True, VERDICT_OK),
        (49.9, True, VERDICT_OK),
        (50, True, VERDICT_SUSPICIOUS),
        (85, True, VERDICT_SUSPICIOUS),
        (85.1, True, VERDICT_MALWARE),
        (100, True, VERDICT_MALWARE),
    ],
)
def test_score_to_verdict_boundaries(score, present, expected):
    assert score_to_verdict(score, present) == expected


def test_score_value_handles_the_minus_one_sentinel():
    # sampleScore defaults to -1.0 rather than null, and sampleScoreExists is
    # the real presence flag. Reading -1 as a score would call an unfinished
    # analysis clean.
    assert score_value({"sampleScore": -1.0, "sampleScoreExists": True}) == (0.0, False)
    assert score_value({"sampleScore": 50, "sampleScoreExists": False}) == (0.0, False)
    assert score_value({}) == (0.0, False)
    assert score_value({"sampleScore": 0, "sampleScoreExists": True}) == (0.0, True)
    assert score_value({"sampleScore": 72.5}) == (72.5, True)


def test_file_verdict_code_two_is_never_treated_as_ordinal():
    # FileVerdict skips 2 (MALWARE is 3) while ScoreLevel uses 2 for MALICIOUS.
    # Mapping by number would silently swap meanings, so only names are mapped.
    assert normalize_verdict(2) == ""
    assert normalize_verdict("2") == ""


def test_whitelist_beats_everything():
    for report in (
        {"whitelisted": True, "sampleScore": 99, "sampleScoreExists": True, "sampleReportCompleteness": COMPLETENESS_COMPLETE},
        {
            "file": {"fileVerdict": "WHITELIST"},
            "sampleScore": 99,
            "sampleScoreExists": True,
            "sampleReportCompleteness": COMPLETENESS_COMPLETE,
        },
        {"verdict": "WHITELIST", "sampleScore": 99, "sampleScoreExists": True, "sampleReportCompleteness": COMPLETENESS_COMPLETE},
        {"whitelisted": True, "file": {"fileVerdict": "MALWARE"}},
    ):
        assert canonical_verdict(report) == VERDICT_WHITELIST


def test_score_recomputed_only_when_complete():
    report = {
        "file": {"fileVerdict": "OK"},
        "sampleScore": 95,
        "sampleScoreExists": True,
        "sampleReportCompleteness": COMPLETENESS_COMPLETE,
    }
    assert canonical_verdict(report) == VERDICT_MALWARE

    # Before COMPLETE the stored verdict is trusted rather than recomputed.
    report["sampleReportCompleteness"] = COMPLETENESS_PARTIAL
    assert canonical_verdict(report) == VERDICT_OK


def test_early_verdict_requires_stat_and_av():
    report = {
        "file": {"fileVerdict": "UNKNOWN"},
        "verdict": "UNKNOWN",
        "sampleScore": 90,
        "sampleScoreExists": True,
        "sampleReportCompleteness": COMPLETENESS_PARTIAL,
        "completedAnalyzes": ["STAT_ANALYSIS"],
    }
    assert canonical_verdict(report, early_verdict=True) == VERDICT_UNKNOWN

    report["completedAnalyzes"] = ["STAT_ANALYSIS", "AV_ANALYSIS"]
    assert canonical_verdict(report, early_verdict=True) == VERDICT_MALWARE


def test_canonical_verdict_prefers_file_verdict_then_score_level():
    assert canonical_verdict({"file": {"fileVerdict": "MALWARE"}, "verdict": "OK"}) == VERDICT_MALWARE
    assert canonical_verdict({"verdict": "MALICIOUS"}) == VERDICT_MALWARE
    assert canonical_verdict({}) == VERDICT_UNKNOWN


def test_custom_score_thresholds_are_honoured():
    report = {"sampleScore": 40, "sampleScoreExists": True, "sampleReportCompleteness": COMPLETENESS_COMPLETE}
    assert canonical_verdict(report) == VERDICT_OK
    assert canonical_verdict(report, suspicious_from=30, malicious_from=60) == VERDICT_SUSPICIOUS


@pytest.mark.parametrize(
    "completeness,verdict,expected",
    [
        (COMPLETENESS_COMPLETE, VERDICT_UNKNOWN, True),
        (COMPLETENESS_COMPLETE, VERDICT_MALWARE, True),
        (COMPLETENESS_PARTIAL, VERDICT_MALWARE, True),
        (COMPLETENESS_PARTIAL, VERDICT_WHITELIST, True),
        (COMPLETENESS_PARTIAL, VERDICT_UNKNOWN, False),
        (COMPLETENESS_EMPTY, VERDICT_MALWARE, False),
        ("", VERDICT_MALWARE, False),
    ],
)
def test_is_terminal(completeness, verdict, expected):
    assert is_terminal(completeness, verdict) is expected


def test_unknown_is_not_actionable():
    # UNKNOWN means "keep polling"; treating it as actionable would end
    # polling on every fresh submission.
    assert VERDICT_UNKNOWN not in ACTIONABLE_VERDICTS


@pytest.mark.parametrize(
    "verdict,expected",
    [
        (VERDICT_MALWARE, 3),
        (VERDICT_SUSPICIOUS, 2),
        (VERDICT_OK, 1),
        (VERDICT_CLEAN, 1),
        (VERDICT_WHITELIST, 1),
        (VERDICT_UNKNOWN, 0),
    ],
)
def test_verdict_to_dbot_score(verdict, expected):
    assert verdict_to_dbot_score(verdict) == expected


def test_unknown_can_be_reported_as_benign_when_configured():
    assert verdict_to_dbot_score(VERDICT_UNKNOWN) == 0
    assert verdict_to_dbot_score(VERDICT_UNKNOWN, unknown_is_benign=True) == 1


@pytest.mark.parametrize(
    "verdict,score,present,escalate,expected",
    [
        (VERDICT_MALWARE, 90, True, 0, 3),
        (VERDICT_SUSPICIOUS, 60, True, 0, 2),
        (VERDICT_WHITELIST, 0, True, 0, 0.5),
        (VERDICT_MALWARE, 96, True, 95, 4),  # escalated
        (VERDICT_MALWARE, 94, True, 95, 3),  # below the threshold
        (VERDICT_MALWARE, 0, False, 95, 3),  # escalation needs a score
        (VERDICT_SUSPICIOUS, 99, True, 95, 2),  # escalation is malware-only
        ("BOGUS", 0, False, 0, 1),  # unmapped falls back to Low
    ],
)
def test_verdict_to_severity(verdict, score, present, escalate, expected):
    assert verdict_to_severity(verdict, score, present, DEFAULT_SEVERITY_MAP, escalate) == expected


def test_informational_severity_survives_as_float():
    # 0.5 is Informational on the XSOAR scale; an int anywhere in the path
    # would silently drop it to 0.
    assert verdict_to_severity(VERDICT_WHITELIST) == 0.5


# ------------------------------------------------------------------- dates


@pytest.mark.parametrize(
    "value,expected_iso",
    [
        (1774512000000, "2026-03-26T08:00:00Z"),  # milliseconds
        (1774512000, "2026-03-26T08:00:00Z"),  # seconds, promoted
        ("2026-03-26T08:00:00Z", "2026-03-26T08:00:00Z"),
        (None, None),
        (0, None),
        ("", None),
    ],
)
def test_epoch_parsing_accepts_three_formats(value, expected_iso):
    # tlab-server has no spring.jackson config, so java.util.Date serializes as
    # epoch millis by Jackson default. A Spring Boot upgrade would flip that to
    # ISO strings, so all three shapes are accepted.
    assert epoch_to_iso(value) == expected_iso


def test_epoch_to_datetime_returns_utc():
    parsed = epoch_to_datetime(1774512000000)
    assert parsed is not None
    assert parsed.tzinfo is not None
    assert parsed.year == 2026


# -------------------------------------------------------------- rejections


def test_rejection_table_covers_every_documented_code():
    expected = {
        "common.whitelisted",
        "common.already_analyzed",
        "common.limit_reached",
        "common.invalid_file_size",
        "common.invalid_file_name",
        "common.file_type_no_allowed",
        "common.general_io_error",
        "common.unknown",
        "common.no_such_report",
        "common.mainFileContentMissing",
        "common.extraFileContentMissing",
        "url.invalid",
        "url.protocol_not_allowed",
        "url.download_error",
        "url.download_timeout",
        "archive.password_required",
        "archive.decryption_not_supported",
        "archive.unknown_error",
        "activation.invalidLicense",
    }
    assert expected.issubset(set(REJECTION_MESSAGES))


def test_unknown_rejection_code_is_echoed_not_swallowed():
    text = describe_rejection("some.new.code", "extra detail")
    assert "some.new.code" in text
    assert "extra detail" in text


def test_whitelisted_and_already_analyzed_are_outcomes_not_failures():
    # Both mean "there is a result", so commands return it instead of raising.
    assert {"common.whitelisted", "common.already_analyzed"} == NON_ERROR_REJECTIONS


def test_rejection_exception_keeps_the_raw_code():
    exc = TLabRejection("url.invalid", "bad scheme")
    assert exc.code == "url.invalid"
    assert "URL is not valid" in str(exc)


# ------------------------------------------------------------------ sorting


def test_create_time_sort_is_rejected_before_the_request_leaves():
    # The server does not reject it — it silently reorders by update_time DESC.
    with pytest.raises(Exception) as err:
        validate_sort("createTime,asc")
    assert "createTime" in str(err.value)


@pytest.mark.parametrize("sort", ["", "sampleReportId,asc", "updateTime,desc", "reportTime,asc", "sampleScore,desc", "size,asc"])
def test_valid_sort_keys_pass(sort):
    validate_sort(sort)


# ------------------------------------------------------- main report choice


def test_select_main_report_prefers_explicit_main_type():
    reports = [
        {"sampleReportId": 2, "sampleReportType": REPORT_TYPE_DROPPED, "parentReportId": 1},
        {"sampleReportId": 1, "sampleReportType": REPORT_TYPE_MAIN},
    ]
    assert select_main_report(reports)["sampleReportId"] == 1


def test_select_main_report_falls_back_to_root_then_score():
    reports = [
        {"sampleReportId": 5, "parentReportId": 4, "sampleScore": 90},
        {"sampleReportId": 4, "sampleScore": 10},
    ]
    assert select_main_report(reports)["sampleReportId"] == 4

    # No roots at all: highest score wins, ties broken by lowest id.
    reports = [
        {"sampleReportId": 7, "parentReportId": 1, "sampleScore": 10},
        {"sampleReportId": 6, "parentReportId": 1, "sampleScore": 90},
    ]
    assert select_main_report(reports)["sampleReportId"] == 6
    assert select_main_report([]) is None


# ------------------------------------------------------------------ submit


def test_submit_form_repeats_analysis_types_and_brackets_properties():
    settings = SubmitSettings(
        analysis_types=["STAT_ANALYSIS", "DYN_ANALYSIS"],
        properties={"xsoar_incident_id": "42", "xsoar_instance": "inst"},
        tags=["xsoar", "phishing"],
        source_uid="lic-1",
    )
    form = settings.to_form()
    assert [v for k, v in form if k == "analysisTypes"] == ["STAT_ANALYSIS", "DYN_ANALYSIS"]
    assert ("properties[xsoar_incident_id]", "42") in form
    assert ("properties[xsoar_instance]", "inst") in form
    # Tags are indexed form keys, not a repeated flat key.
    assert ("tags[0].name", "xsoar") in form
    assert ("tags[1].name", "phishing") in form
    # The source type travels by enum NAME; the display code is a different string.
    assert ("source.sourceType", SOURCE_TYPE_NAME) in form
    assert SOURCE_TYPE_NAME != SOURCE_TYPE_DISPLAY


def test_submit_settings_validate_client_side():
    with pytest.raises(Exception, match="3600"):
        SubmitSettings(research_time=99999)
    with pytest.raises(Exception, match="positive"):
        SubmitSettings(research_time=0)
    with pytest.raises(Exception, match="50 characters"):
        SubmitSettings(env_preset="x" * 51)
    with pytest.raises(Exception, match="200 characters"):
        SubmitSettings(command_line_args="x" * 201)
    with pytest.raises(Exception, match="at least one|At least one"):
        SubmitSettings(analysis_types=[])
    with pytest.raises(Exception, match="2 and 150"):
        SubmitSettings(tags=["x"])


def test_submit_form_booleans_are_lowercase_strings():
    form = dict(SubmitSettings(enable_network=True, extract_archive=False).to_form())
    assert form["dynAnalysisSettings.enableNetwork"] == "true"
    assert form["extractArchive"] == "false"


# ------------------------------------------------------------------- auth


def test_auth_header_per_mode(requests_mock):
    requests_mock.get(f"{BASE}/auth/test", json={"userLogin": "svc", "userRole": "admin"})

    make_client(AUTH_SOURCE_KEY, secret="abc").whoami()
    assert requests_mock.last_request.headers["Authorization"] == "Bearer abc"

    make_client(AUTH_INTERNAL, secret="abc").whoami()
    assert requests_mock.last_request.headers["Authorization"] == "Internal abc"


def test_sign_in_token_has_no_scheme_prefix(requests_mock, mocker):
    # The legacy branch on the server looks the raw value up in the token table,
    # so prefixing it with Bearer would break authentication.
    mocker.patch("TLabAntiAPTSandbox.demisto.getIntegrationContext", return_value={})
    mocker.patch("TLabAntiAPTSandbox.demisto.setIntegrationContext")
    requests_mock.post(
        f"{BASE}/auth/sign_in",
        json={"successful": True, "token": {"tokenValue": "opaque-token", "expirationTime": 9999999999000}},
    )
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    make_client(AUTH_SIGN_IN, secret="pw", username="user").whoami()
    assert requests_mock.last_request.headers["Authorization"] == "opaque-token"


def test_sign_in_token_is_cached(requests_mock, mocker):
    context = {}
    mocker.patch("TLabAntiAPTSandbox.demisto.getIntegrationContext", side_effect=lambda: context)
    mocker.patch(
        "TLabAntiAPTSandbox.demisto.setIntegrationContext",
        side_effect=lambda value: context.update(value),
    )
    sign_in = requests_mock.post(
        f"{BASE}/auth/sign_in",
        json={"successful": True, "token": {"tokenValue": "tok", "expirationTime": 9999999999000}},
    )
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    client = make_client(AUTH_SIGN_IN, secret="pw", username="user")
    client.whoami()
    client.whoami()
    assert sign_in.call_count == 1


def test_sign_in_failure_is_reported_clearly(requests_mock, mocker):
    mocker.patch("TLabAntiAPTSandbox.demisto.getIntegrationContext", return_value={})
    requests_mock.post(f"{BASE}/auth/sign_in", json={"successful": False})
    with pytest.raises(Exception, match="username and password"):
        make_client(AUTH_SIGN_IN, secret="pw", username="user").whoami()


def test_client_header_uses_type_semicolon_name(requests_mock):
    # ClientExtractor splits on the first ';' and requires the type to be one of
    # web|mail|endpoint, otherwise the whole header is discarded silently.
    requests_mock.get(f"{BASE}/auth/test", json={})
    make_client().whoami()
    assert requests_mock.last_request.headers["X-Client"] == "endpoint;xsoar"


def test_401_message_explains_the_internal_token_restriction(requests_mock):
    requests_mock.get(f"{BASE}/auth/test", status_code=401, text="nope")
    with pytest.raises(Exception, match="127.0.0.1"):
        make_client(AUTH_INTERNAL).whoami()


def test_403_message_explains_the_role_restriction(requests_mock):
    # Internal tokens authenticate but GET /sample_reports has no branch for
    # the external_service role, so a correct token still gets 403.
    requests_mock.get(f"{BASE}/sample_reports", status_code=403, text="Forbidden")
    with pytest.raises(Exception, match="external_service"):
        make_client().list_sample_reports()


# ------------------------------------------------------------------ paging


def test_list_sample_reports_sends_repeated_array_filters(requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json={"content": [], "last": True})
    make_client().list_sample_reports(
        min_report_id=412840,
        completeness=["COMPLETE", "PARTIALLY_COMPLETE"],
        file_verdicts=["MALWARE", "SUSPICIOUS"],
        root_only=True,
    )
    query = requests_mock.last_request.qs
    assert query["minreportid"] == ["412840"]
    assert sorted(query["completeness"]) == ["complete", "partially_complete"]
    assert sorted(query["fileverdict"]) == ["malware", "suspicious"]
    assert query["rootonly"] == ["true"]
    assert query["sort"] == ["samplereportid,asc"]


def test_iter_sample_reports_stops_on_short_page(requests_mock):
    requests_mock.get(
        f"{BASE}/sample_reports",
        [
            {"json": {"content": [{"sampleReportId": i} for i in range(3)], "last": False}},
            {"json": {"content": [{"sampleReportId": 99}], "last": False}},
        ],
    )
    rows = list(make_client().iter_sample_reports(page_size=3, max_pages=10))
    assert [r["sampleReportId"] for r in rows] == [0, 1, 2, 99]


def test_iter_sample_reports_respects_max_pages(requests_mock):
    requests_mock.get(
        f"{BASE}/sample_reports",
        json={"content": [{"sampleReportId": 1}, {"sampleReportId": 2}], "last": False},
    )
    rows = list(make_client().iter_sample_reports(page_size=2, max_pages=3))
    assert len(rows) == 6


# ----------------------------------------------------------- public routes


def test_request_status_sends_no_authorization_header(requests_mock):
    # /public/** is in the server's unauthenticated path list.
    requests_mock.get(f"{BASE}/public/request_status/abc", json={"analysisRequestStatus": "ACCEPTED"})
    make_client().request_status("abc")
    assert "Authorization" not in requests_mock.last_request.headers


def test_request_status_early_verdict_flag(requests_mock):
    requests_mock.get(f"{BASE}/public/request_status/abc", json={})
    make_client().request_status("abc", early_verdict=True)
    assert requests_mock.last_request.qs["earlyverdict"] == ["true"]


def test_request_status_batch_posts_a_bare_array(requests_mock):
    requests_mock.post(f"{BASE}/public/request_status/batch", json=[])
    make_client().request_status_batch(["a", "b"])
    assert requests_mock.last_request.json() == ["a", "b"]


# --------------------------------------------------------------- artifacts


def test_download_sends_an_explicit_accept_header(requests_mock):
    # DynReportsController maps two handlers to {id}/pcap that differ only by
    # produces, so '*/*' resolves in a Spring-version-dependent way.
    requests_mock.get(f"{BASE}/dyn_reports/5/pcap", content=b"pcapdata")
    data = make_client().download("/dyn_reports/5/pcap", "application/octet-stream", max_bytes=1024)
    assert data == b"pcapdata"
    assert requests_mock.last_request.headers["Accept"] == "application/octet-stream"


def test_download_aborts_when_the_artifact_exceeds_the_limit(requests_mock):
    requests_mock.get(f"{BASE}/dyn_reports/5/memory_dump", content=b"x" * 5000)
    with pytest.raises(Exception, match="exceeds the configured limit"):
        make_client().download("/dyn_reports/5/memory_dump", "application/octet-stream", max_bytes=1000)


def test_download_without_a_limit_returns_everything(requests_mock):
    requests_mock.get(f"{BASE}/x", content=b"y" * 5000)
    assert len(make_client().download("/x", "application/json", max_bytes=0)) == 5000


# ------------------------------------------------------- tlab-auth account

AUTH = "https://tlab.example.com:8002/api"  # derived from BASE: the omni-center portal


def jwt(exp: float) -> str:
    """Unsigned JWT with an exp claim — the client never verifies signatures."""
    import base64
    import json as _json

    def b64(obj):
        return base64.urlsafe_b64encode(_json.dumps(obj).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'HS256'})}.{b64({'exp': exp, 'sub': 'svc'})}.sig"


@pytest.fixture
def context(mocker):
    store = {}
    mocker.patch("TLabAntiAPTSandbox.demisto.getIntegrationContext", side_effect=lambda: dict(store))
    mocker.patch("TLabAntiAPTSandbox.demisto.setIntegrationContext", side_effect=lambda value: store.update(value))
    return store


def test_default_auth_url_uses_the_omni_portal_over_tls():
    # Encrypted, and not https://<host>/api, which on a sandbox host is tlab-server.
    assert default_auth_url("https://10.0.0.5/api") == "https://10.0.0.5:8002/api"
    assert default_auth_url("http://tlab.example.com:8080") == "https://tlab.example.com:8002/api"
    assert default_auth_url("") == ""


def test_auth_url_answered_by_tlab_server_is_named(requests_mock, context):
    # Exactly what a sandbox host returns for /api/auth/login: Spring's error
    # shape from tlab-server, not tlab-auth.
    requests_mock.post(
        f"{AUTH}/auth/login",
        status_code=401,
        json={
            "timestamp": 1,
            "status": 401,
            "error": "Unauthorized",
            "message": "Authentication Failed: No authorizationHeader data",
            "path": "//auth/login",
        },
    )
    with pytest.raises(DemistoException, match="answered by tlab-server, not tlab-auth"):
        make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc").whoami()


def test_jwt_expiry_reads_exp_and_tolerates_garbage():
    assert jwt_expiry(jwt(1_900_000_000)) == 1_900_000_000
    assert jwt_expiry("not-a-jwt") is None


def test_tlab_account_logs_in_and_sends_bearer(requests_mock, context):
    access = jwt(time.time() + 3600)
    login = requests_mock.post(f"{AUTH}/auth/login", json={"access": access, "refresh": "r1"})
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc").whoami()

    assert login.last_request.json() == {"login": "svc", "password": "pw"}
    assert requests_mock.last_request.headers["Authorization"] == f"Bearer {access}"


def test_tlab_account_honours_explicit_auth_url(requests_mock, context):
    login = requests_mock.post("http://10.0.0.5:8033/api/auth/login", json={"access": jwt(time.time() + 3600)})
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc", auth_url="http://10.0.0.5:8033/api/").whoami()

    assert login.call_count == 1


def test_tlab_account_session_is_cached(requests_mock, context):
    login = requests_mock.post(f"{AUTH}/auth/login", json={"access": jwt(time.time() + 3600), "refresh": "r1"})
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    client = make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc")
    client.whoami()
    client.whoami()
    # A new client (the next command run) reuses the integration context too.
    make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc").whoami()

    assert login.call_count == 1


def test_tlab_account_refreshes_before_expiry(requests_mock, context):
    login = requests_mock.post(f"{AUTH}/auth/login", json={"access": jwt(time.time() + 30), "refresh": "r1"})
    fresh = jwt(time.time() + 3600)
    refresh = requests_mock.post(f"{AUTH}/auth/refresh", json={"access": fresh, "refresh": "r2"})
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    client = make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc")
    client.whoami()  # logs in; the token is already inside the refresh margin
    client.whoami()  # must refresh, not log in again

    assert login.call_count == 1
    assert refresh.call_count == 1
    assert refresh.last_request.json() == {"refresh_token": "r1"}
    assert requests_mock.last_request.headers["Authorization"] == f"Bearer {fresh}"


def test_tlab_account_falls_back_to_login_when_refresh_fails(requests_mock, context):
    login = requests_mock.post(
        f"{AUTH}/auth/login",
        [{"json": {"access": jwt(time.time() + 30), "refresh": "r1"}}, {"json": {"access": jwt(time.time() + 3600)}}],
    )
    requests_mock.post(f"{AUTH}/auth/refresh", status_code=401, json={"message": "refresh token expired"})
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    client = make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc")
    client.whoami()
    client.whoami()

    assert login.call_count == 2


def test_tlab_account_retries_once_on_sandbox_401(requests_mock, context):
    requests_mock.post(f"{AUTH}/auth/login", json={"access": jwt(time.time() + 3600), "refresh": "r1"})
    refresh = requests_mock.post(f"{AUTH}/auth/refresh", json={"access": jwt(time.time() + 3600), "refresh": "r2"})
    sandbox = requests_mock.get(f"{BASE}/auth/test", [{"status_code": 401, "text": "revoked"}, {"json": {"userRole": "admin"}}])

    assert make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc").whoami() == {"userRole": "admin"}
    assert refresh.call_count == 1
    assert sandbox.call_count == 2


def test_tlab_account_does_not_loop_on_persistent_401(requests_mock, context):
    requests_mock.post(f"{AUTH}/auth/login", json={"access": jwt(time.time() + 3600), "refresh": "r1"})
    requests_mock.post(f"{AUTH}/auth/refresh", json={"access": jwt(time.time() + 3600), "refresh": "r2"})
    sandbox = requests_mock.get(f"{BASE}/auth/test", status_code=401, text="nope")

    with pytest.raises(DemistoException, match="401"):
        make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc").whoami()
    assert sandbox.call_count == 2


def test_tlab_account_wrong_password_is_tried_once(requests_mock, context):
    # A second attempt with the same wrong password would count twice towards
    # the account lockout in tlab-auth.
    login = requests_mock.post(f"{AUTH}/auth/login", status_code=401, json={"message": "invalid login or password"})

    with pytest.raises(Exception, match="invalid login or password"):
        make_client(AUTH_TLAB_ACCOUNT, secret="bad", username="svc").whoami()
    assert login.call_count == 1


def test_tlab_account_relogs_when_the_account_changes(requests_mock, context):
    login = requests_mock.post(f"{AUTH}/auth/login", json={"access": jwt(time.time() + 3600), "refresh": "r1"})
    requests_mock.get(f"{BASE}/auth/test", json={"userRole": "admin"})

    make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="svc").whoami()
    make_client(AUTH_TLAB_ACCOUNT, secret="pw", username="other").whoami()

    assert login.call_count == 2


def test_tlab_account_without_any_host_explains_itself(context):
    client = TLabClient(base_url="", auth_mode=AUTH_TLAB_ACCOUNT, credentials={"identifier": "svc", "password": "pw"})
    with pytest.raises(Exception, match="Auth server URL"):
        client.whoami()


def test_stored_file_verdict_hides_the_unset_default():
    # Written only by the manual /files/{sha256|id}/verdict routes; UNKNOWN
    # means nobody set it.
    assert stored_file_verdict("UNKNOWN") is None
    assert stored_file_verdict(None) is None
    assert stored_file_verdict("") is None
    assert stored_file_verdict("whitelist") == "WHITELIST"
    assert stored_file_verdict("MALWARE") == "MALWARE"

"""Tests for the tLab Anti-APT Verdicts integration.

The weight here is on two things: the incident is byte-identical to what the
Go connector produces for the same report, and no analysis becomes two
incidents. Everything else is mechanical.
"""

import json
from pathlib import Path

import pytest

import demistomock as demisto
import TLabAntiAPTVerdicts as verdicts
from CommonServerPython import DemistoException
from TLabAntiAPTVerdicts import AUTH_SOURCE_KEY, AUTH_TLAB_ACCOUNT, TLabClient

BASE = "https://tlab.example.com"
DATA = Path(__file__).parent / "test_data"
# Resolved from this file, not the working directory: the content repo runs
# each integration's tests from the integration's own directory.
PACK = Path(__file__).resolve().parents[2]
# The connector half of the contract. Absent outside the connector repo.
SCHEMA = PACK.parents[1] / "docs" / "verdict-incident-schema.json"
SHA256 = "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"


def load(name: str):
    return json.loads((DATA / f"{name}.json").read_text())


def report(index: int = 0) -> dict:
    return load("reports_page")["content"][index]


@pytest.fixture
def client():
    return TLabClient(base_url=BASE, auth_mode=AUTH_SOURCE_KEY, credentials={"password": "key"}, verify=False)


@pytest.fixture
def params():
    return {
        "url": BASE,
        "installation_id": "inst-uuid",
        "max_fetch": 50,
        "maturation_lookback_hours": 0,
        "enrich_incidents": False,
        "verdicts": "MALWARE,SUSPICIOUS",
    }


@pytest.fixture(autouse=True)
def clean_last_run(mocker):
    store: dict = {}
    mocker.patch.object(demisto, "getLastRun", side_effect=lambda: dict(store))
    mocker.patch.object(demisto, "setLastRun", side_effect=lambda v: store.clear() or store.update(v))
    return store


@pytest.fixture(autouse=True)
def clean_context(mocker):
    store: dict = {}
    mocker.patch.object(demisto, "getIntegrationContext", side_effect=lambda: dict(store))
    mocker.patch.object(demisto, "setIntegrationContext", side_effect=lambda v: store.clear() or store.update(v))
    return store


# ------------------------------------------------- parity with the Go connector
# These expectations are copied from internal/xsoarpusher/payload_test.go and
# verdict_test.go. If one half changes, this file must fail.


def test_dedupe_key_matches_the_connector():
    assert verdicts.dedupe_key("inst-uuid", 100) == "tlab-apt:inst-uuid:100"


def test_dedupe_key_is_not_derived_from_the_hash():
    """The same file legitimately produces new detections; collapsing those
    would hide a re-infection."""
    first = {"sampleReportId": 1, "file": {"hashSha256": SHA256}}
    second = {"sampleReportId": 2, "file": {"hashSha256": SHA256}}
    assert verdicts.dedupe_key("i", first["sampleReportId"]) != verdicts.dedupe_key("i", second["sampleReportId"])


@pytest.mark.parametrize(
    "template,expected",
    [
        ("tLab Anti-APT {verdict}: {filename}", "tLab Anti-APT MALWARE: invoice.exe"),
        ("{verdict} score={score} id={report_id}", "MALWARE score=91.50 id=412839"),
        ("{source_type} / {sha256}", "Cortex XSOAR / " + SHA256),
        # An unknown placeholder stays visible rather than silently emptying.
        ("{verdict} {unknown_placeholder}", "MALWARE {unknown_placeholder}"),
    ],
)
def test_incident_name_matches_the_connector(template, expected):
    assert verdicts.render_incident_name(template, report(), "MALWARE") == expected


def test_incident_name_falls_back_to_the_hash_prefix():
    r = report()
    r["uploadedFilename"] = ""
    assert verdicts.render_incident_name("{filename}", r, "MALWARE") == SHA256[:12]


def test_incident_name_falls_back_to_the_report_id():
    r = report()
    r["uploadedFilename"] = ""
    r["file"] = {}
    assert verdicts.render_incident_name("{filename}", r, "MALWARE") == "sample 412839"


@pytest.mark.parametrize(
    "verdict,score,present,critical,expected",
    [
        ("MALWARE", 91.5, True, 0, 3.0),
        ("SUSPICIOUS", 61.0, True, 0, 2.0),
        ("OK", 3.0, True, 0, 1.0),
        ("CLEAN", 0.0, True, 0, 1.0),
        ("WHITELIST", 0.0, False, 0, 0.5),
        ("UNKNOWN", 0.0, False, 0, 1.0),
        # Critical escalation applies to MALWARE only, and only with a score.
        ("MALWARE", 95.0, True, 90, 4.0),
        ("MALWARE", 88.0, True, 90, 3.0),
        ("MALWARE", 0.0, False, 90, 3.0),
        ("SUSPICIOUS", 99.0, True, 90, 2.0),
    ],
)
def test_severity_matches_the_connector(verdict, score, present, critical, expected):
    assert verdicts.severity_for(verdict, score, present, verdicts.DEFAULT_SEVERITY_MAP, critical) == expected


def test_unknown_verdict_does_not_break_severity():
    assert verdicts.severity_for("NOT_A_VERDICT", 0, False, verdicts.DEFAULT_SEVERITY_MAP, 0) == 1.0


# ------------------------------------------------------------------ contract


def test_contract_payload_required_keys(params):
    payload = verdicts.contract_payload(report(), params)
    for key in ("tlab_dedupe_key", "tlab_sample_report_id", "tlab_verdict", "tlab_delivery_mode"):
        assert key in payload
    assert payload["tlab_delivery_mode"] == "PULL"


def test_contract_payload_canonicalises_malicious_to_malware(params):
    """The server returns two enums for one concept. ScoreLevel MALICIOUS and
    FileVerdict MALWARE are the same statement."""
    payload = verdicts.contract_payload(report(), params)
    assert payload["tlab_verdict"] == "MALWARE"
    assert payload["tlab_score_level"] == "MALICIOUS"  # raw, as the server said it
    assert payload["tlab_file_verdict"] == "MALWARE"


def test_contract_payload_full_shape(params):
    payload = verdicts.contract_payload(report(), params)
    assert payload["tlab_sample_report_id"] == 412839
    assert payload["tlab_analysis_request_id"] == 900123
    assert payload["tlab_access_code"] == "ac-412839"
    assert payload["tlab_score"] == 91.5
    assert payload["tlab_max_score"] == 91.5
    assert payload["tlab_file_sha256"] == SHA256
    assert payload["tlab_file_size"] == 2048
    assert payload["tlab_mime_type"] == "application/x-dosexec"
    assert payload["tlab_source_type"] == "Cortex XSOAR"
    assert payload["tlab_source_uid"] == "inc-77"
    assert payload["tlab_malware_family"] == "Emotet"
    assert payload["tlab_malware_confidence"] == 0.92
    assert payload["tlab_multistage"] is True
    assert payload["tlab_report_url"] == f"{BASE}/reports/412839"
    assert payload["tlab_create_time"] == "2026-03-26T08:00:00Z"


def test_score_absent_rather_than_minus_one(params):
    """-1.0 is the API's no-score default, and the schema forbids it."""
    payload = verdicts.contract_payload(load("report_no_score")["content"][0], params)
    assert "tlab_score" not in payload
    assert "tlab_max_score" not in payload


def test_empty_values_are_omitted_not_nulled(params):
    payload = verdicts.contract_payload(load("report_no_score")["content"][0], params)
    assert "tlab_file_name" not in payload
    assert "tlab_source_type" not in payload


@pytest.mark.skipif(not SCHEMA.exists(), reason="the connector schema lives in the connector repo")
def test_custom_field_names_cover_the_contract_mapping():
    """The Go connector fills these names directly because the REST path runs
    no mapper. Drifting apart means the two halves write different incidents."""
    schema = json.loads(SCHEMA.read_text())
    assert schema["x-xsoar-custom-field-names"]["mapping"] == verdicts.CUSTOM_FIELD_NAMES


def test_every_custom_field_has_an_incident_field_in_the_pack():
    """A machine name the pack does not declare is silently dropped by XSOAR."""
    declared = {json.loads(p.read_text())["cliName"] for p in (PACK / "IncidentFields").glob("incidentfield-*.json")}
    assert set(verdicts.CUSTOM_FIELD_NAMES.values()) <= declared


def test_mapper_covers_every_custom_field():
    mapper = json.loads((PACK / "Classifiers/classifier-mapper-incoming-tLab_Anti-APT.json").read_text())
    mapped = {
        entry["simple"] for entry in mapper["mapping"]["tLab Anti-APT Verdict"]["internalMapping"].values() if "simple" in entry
    }
    assert set(verdicts.CUSTOM_FIELD_NAMES) <= mapped


# ------------------------------------------------------------------ incident


def test_build_incident(params):
    incident = verdicts.build_incident(report(), params, verdicts.DEFAULT_SEVERITY_MAP)
    assert incident["name"] == "tLab Anti-APT MALWARE: invoice.exe"
    assert incident["severity"] == 3.0
    assert incident["type"] == "tLab Anti-APT Verdict"
    assert incident["dbotMirrorId"] == "tlab-apt:inst-uuid:412839"
    assert incident["occurred"] == "2026-03-26T08:00:00Z"
    assert incident["CustomFields"]["tlabverdict"] == "MALWARE"
    assert json.loads(incident["rawJSON"])["tlab_sample_report_id"] == 412839


def test_incident_type_param_overrides_the_default(params):
    params["incidentType"] = "Custom Type"
    assert verdicts.build_incident(report(), params, verdicts.DEFAULT_SEVERITY_MAP)["type"] == "Custom Type"


# ------------------------------------------------------------------ severity map


def test_parse_severity_map_defaults():
    assert verdicts.parse_severity_map(None) == verdicts.DEFAULT_SEVERITY_MAP


def test_parse_severity_map_partial_override():
    parsed = verdicts.parse_severity_map("MALWARE:4")
    assert parsed["MALWARE"] == 4.0
    assert parsed["SUSPICIOUS"] == 2.0  # untouched entries keep the default


def test_parse_severity_map_rejects_unknown_verdict():
    with pytest.raises(DemistoException, match="unknown verdict"):
        verdicts.parse_severity_map("NOPE:3")


def test_parse_severity_map_rejects_malformed_pair():
    with pytest.raises(DemistoException, match="not VERDICT:severity"):
        verdicts.parse_severity_map("MALWARE:high")


def test_parse_severity_map_rejects_non_xsoar_severity():
    """XSOAR has six severities. 2.5 would be silently rounded somewhere."""
    with pytest.raises(DemistoException, match="not an XSOAR severity"):
        verdicts.parse_severity_map("MALWARE:2.5")


# ------------------------------------------------------------------ enrichment


def test_enrich(client, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports/412839/threat_indicators", json=load("threat_indicators"))
    out = verdicts.enrich(client, 412839)
    assert out["attack_techniques"] == ["T1027.002", "T1071"]  # "bogus" dropped, deduplicated
    assert out["av_detected"] is True
    titles = [i["title"] for i in out["threat_indicators"]]
    assert "Connects to a known bad host" in titles
    assert "Reads the system language" not in titles  # INFO is noise


def test_enrich_av_flag_needs_a_malicious_av_hit(client, requests_mock):
    """The sample report list carries no AV result, so the flag is derived.
    A heuristic SUSPICIOUS hit is not a detection."""
    requests_mock.get(f"{BASE}/sample_reports/412840/threat_indicators", json=load("threat_indicators_no_av"))
    assert verdicts.enrich(client, 412840)["av_detected"] is False


def test_enrichment_failure_does_not_sink_the_fetch(client, params, requests_mock):
    params["enrich_incidents"] = True
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_page"))
    requests_mock.get(f"{BASE}/sample_reports/412839/threat_indicators", status_code=500, json={})
    requests_mock.get(f"{BASE}/sample_reports/412840/threat_indicators", json=load("threat_indicators_no_av"))
    incidents = verdicts.build_incidents(client, params, load("reports_page")["content"], {})
    assert len(incidents) == 2
    assert incidents[0]["CustomFields"]["tlabattacktechniques"] == []


def test_enrichment_off_leaves_the_derived_fields_empty(client, params):
    incidents = verdicts.build_incidents(client, params, [report()], {})
    assert incidents[0]["CustomFields"]["tlabattacktechniques"] == []
    assert incidents[0]["CustomFields"]["tlabavdetected"] is False


# ------------------------------------------------------------------ filtering


def test_verdict_filter_excludes_benign(client, params):
    incidents = verdicts.build_incidents(client, params, load("reports_page")["content"], {})
    names = [i["CustomFields"]["tlabverdict"] for i in incidents]
    assert names == ["MALWARE", "SUSPICIOUS"]  # the OK report is not an incident


def test_verdict_filter_can_be_widened(client, params):
    params["verdicts"] = "MALWARE,SUSPICIOUS,OK"
    incidents = verdicts.build_incidents(client, params, load("reports_page")["content"], {})
    assert len(incidents) == 3


def test_root_only_is_on_by_default(params):
    assert verdicts.root_only(params) is True


def test_root_only_can_be_disabled(params):
    params["root_reports_only"] = False
    assert verdicts.root_only(params) is False


def test_partial_analyses_excluded_by_default(params):
    assert verdicts.completeness_filter(params) == ["COMPLETE"]


def test_partial_analyses_can_be_included(params):
    params["include_partial"] = True
    assert verdicts.completeness_filter(params) == ["COMPLETE", "PARTIALLY_COMPLETE"]


# ------------------------------------------------------------------ cursor


def test_next_cursor_advances_past_the_highest_id():
    assert verdicts.next_cursor([{"sampleReportId": 7}, {"sampleReportId": 3}], 0) == 8


def test_next_cursor_never_moves_backwards():
    assert verdicts.next_cursor([{"sampleReportId": 3}], 100) == 100


def test_discovery_sends_cursor_and_ascending_sort(client, params, requests_mock):
    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    verdicts.discovery_page(client, 500, 50, params)
    query = mock.last_request.qs
    assert query["minreportid"] == ["500"]
    assert query["sort"] == ["samplereportid,asc"]
    assert query["rootonly"] == ["true"]


def test_maturation_sends_descending_update_time(client, params, requests_mock):
    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    verdicts.maturation_page(client, 24, 50, params)
    assert mock.last_request.qs["sort"] == ["updatetime,desc"]
    assert "minreportid" not in mock.last_request.qs


def test_maturation_only_takes_reports_below_the_cursor(client, params, requests_mock):
    params["maturation_lookback_hours"] = 24
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_page"))
    reports, _ = verdicts.collect_reports(client, params, {"report_cursor": 1})
    assert len(reports) == 3  # discovery found all three; maturation added nothing


def test_preview_skips_the_maturation_pass(client, params, requests_mock):
    params["maturation_lookback_hours"] = 24
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    verdicts.collect_reports(client, params, {}, preview=True)
    sorts = [r.qs["sort"][0] for r in requests_mock.request_history]
    assert sorts == ["samplereportid,asc"]


def test_first_report_id_seeds_the_cursor(client, params, requests_mock):
    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    params["first_report_id"] = 400000
    verdicts.collect_reports(client, params, {})
    assert mock.request_history[0].qs["minreportid"] == ["400000"]


def test_cursor_zero_is_honoured_not_treated_as_missing(client, params, requests_mock):
    """A cursor of 0 is a real value meaning "from the beginning"; falling back
    to first_report_id here would restart a completed backfill."""
    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    verdicts.collect_reports(client, params, {"report_cursor": 0})
    assert mock.request_history[0].qs["minreportid"] == ["0"]


def test_first_report_id_raises_a_stored_cursor(client, params, requests_mock):
    """Set after fetching started: XSOAR kept the old cursor, and the value
    used to be ignored, so the backfill from the beginning went on."""
    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    params["first_report_id"] = 400000
    verdicts.collect_reports(client, params, {"report_cursor": 12})
    assert mock.request_history[0].qs["minreportid"] == ["400000"]


def test_first_report_id_never_moves_the_cursor_back(client, params, requests_mock):
    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    params["first_report_id"] = 400000
    verdicts.collect_reports(client, params, {"report_cursor": 400500})
    assert mock.request_history[0].qs["minreportid"] == ["400500"]


def test_maturation_skips_reports_below_first_report_id(client, params, requests_mock):
    params["maturation_lookback_hours"] = 24
    params["first_report_id"] = 412840
    page = load("reports_page")
    requests_mock.get(
        f"{BASE}/sample_reports",
        [{"json": load("reports_empty")}, {"json": page}],
    )
    reports, _ = verdicts.collect_reports(client, params, {"report_cursor": 999999})
    ids = sorted(r["sampleReportId"] for r in reports)
    assert ids
    assert min(ids) >= 412840


# ------------------------------------------------------------------ deduplication


def test_seen_reports_are_not_sent_twice(client, params):
    seen = {"tlab-apt:inst-uuid:412839": "2026-03-26T08:00:00Z"}
    incidents = verdicts.build_incidents(client, params, load("reports_page")["content"], seen)
    assert [i["CustomFields"]["tlabsamplereportid"] for i in incidents] == [412840]


def test_fetch_records_what_it_sent(mocker, client, params, requests_mock, clean_last_run):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_page"))
    mocker.patch.object(demisto, "incidents")
    verdicts.fetch_incidents_command(client, params)
    assert set(clean_last_run["seen"]) == {"tlab-apt:inst-uuid:412839", "tlab-apt:inst-uuid:412840"}
    assert clean_last_run["report_cursor"] == 412842


def test_second_fetch_of_the_same_window_creates_nothing(mocker, client, params, requests_mock, clean_last_run):
    """The maturation pass re-reads reports on purpose. Without the seen set
    that would mean a duplicate incident on every single run."""
    params["maturation_lookback_hours"] = 24
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_page"))
    created = mocker.patch.object(demisto, "incidents")
    verdicts.fetch_incidents_command(client, params)
    assert len(created.call_args_list[0].args[0]) == 2

    clean_last_run["report_cursor"] = 0  # force discovery to re-read the same page
    verdicts.fetch_incidents_command(client, params)
    assert created.call_args_list[1].args[0] == []


def test_prune_seen_drops_entries_past_the_maturation_window():
    seen = {
        "old": "2020-01-01T00:00:00Z",
        "recent": verdicts.datetime.now(verdicts.timezone.utc).strftime(verdicts.TLAB_DATE_FORMAT),
    }
    assert verdicts.prune_seen(seen, 24) == {"recent": seen["recent"]}


def test_prune_seen_keeps_unparseable_stamps():
    """Dropping a key we cannot date would re-create its incident."""
    assert verdicts.prune_seen({"k": "not-a-date"}, 24) == {"k": "not-a-date"}


def test_last_run_not_saved_when_handover_fails(mocker, client, params, requests_mock, clean_last_run):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_page"))
    mocker.patch.object(demisto, "incidents", side_effect=RuntimeError("server down"))
    with pytest.raises(RuntimeError):
        verdicts.fetch_incidents_command(client, params)
    assert clean_last_run == {}


# ------------------------------------------------------------------ commands


def test_get_verdicts_command(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_page"))
    result = verdicts.get_verdicts_command(client, {"limit": "5"}, params)
    assert len(result.outputs) == 2
    assert "tLab Anti-APT verdicts (2)" in result.readable_output


def test_get_verdicts_command_does_not_move_the_cursor(mocker, client, params, requests_mock, clean_last_run):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_page"))
    created = mocker.patch.object(demisto, "incidents")
    verdicts.get_verdicts_command(client, {}, params)
    assert created.call_count == 0
    assert clean_last_run == {}


def test_get_verdicts_command_from_a_given_report(client, params, requests_mock):
    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    verdicts.get_verdicts_command(client, {"from_report_id": "412000"}, params)
    assert mock.last_request.qs["minreportid"] == ["412000"]


def test_get_verdicts_command_when_nothing_matches(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    result = verdicts.get_verdicts_command(client, {}, params)
    assert result.readable_output == "No verdicts matched the configured filters."


def test_reset_cursor_command(mocker, client, params, requests_mock, clean_last_run, clean_context):
    """The reset goes through the integration context: XSOAR 6 does not
    reliably keep setLastRun() from a command other than fetch-incidents."""
    clean_last_run.update({"report_cursor": 999, "seen": {"k": "2026-03-26T08:00:00Z"}})
    verdicts.reset_cursor_command({})
    assert clean_last_run["report_cursor"] == 999  # untouched until the next fetch

    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    mocker.patch.object(demisto, "incidents")
    params["first_report_id"] = 400000
    verdicts.fetch_incidents_command(client, params)
    assert mock.request_history[0].qs["minreportid"] == ["400000"]
    assert "cursor_override" not in clean_context


def test_reset_cursor_command_to_a_given_report(mocker, client, params, requests_mock, clean_last_run, clean_context):
    clean_last_run["report_cursor"] = 12
    clean_context["session"] = {"access": "cached"}
    verdicts.reset_cursor_command({"from_report_id": "412000"})
    assert clean_context["session"] == {"access": "cached"}  # the auth cache survives

    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    mocker.patch.object(demisto, "incidents")
    verdicts.fetch_incidents_command(client, params)
    assert mock.request_history[0].qs["minreportid"] == ["412000"]
    assert clean_last_run["report_cursor"] == 412000
    assert "cursor_override" not in clean_context

    verdicts.fetch_incidents_command(client, params)  # applied once, not on every run
    assert mock.request_history[-1].qs["minreportid"] == ["412000"]


def test_fetch_fails_when_the_server_ignores_min_report_id(client, params, requests_mock):
    """Company admins and users get minReportId silently dropped; without the
    check every fetch would start again from the first report in history."""
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_page"))
    with pytest.raises(DemistoException, match="system admin"):
        verdicts.collect_reports(client, params, {"report_cursor": 500000})


def test_test_module(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    assert verdicts.test_module_command(client, params) == "ok"


def test_test_module_requires_an_installation_id(client, params, requests_mock):
    """It is part of every dedupe key, so an empty one makes incidents from two
    installations collide."""
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    params["installation_id"] = "  "
    with pytest.raises(DemistoException, match="Installation ID is required"):
        verdicts.test_module_command(client, params)


def test_test_module_rejects_an_unknown_verdict(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    params["verdicts"] = "MALWARE,NOPE"
    with pytest.raises(DemistoException, match="not a tLab verdict"):
        verdicts.test_module_command(client, params)


def test_test_module_rejects_a_bad_severity_map(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    params["severity_map"] = "MALWARE:9"
    with pytest.raises(DemistoException, match="not an XSOAR severity"):
        verdicts.test_module_command(client, params)


def test_build_client_defaults_to_tlab_account():
    client = verdicts.build_client({"url": BASE, "credentials": {"identifier": "svc", "password": "k"}})
    assert client._auth_mode == AUTH_TLAB_ACCOUNT


# ------------------------------------------------------------ pack structure
# These guard the wiring between content items. Every one of them fails only
# at runtime on a live tenant otherwise, which is the worst place to find out.


def _yaml(path: Path):
    import yaml

    return yaml.safe_load(path.read_text())


def test_every_declared_test_playbook_exists():
    declared = set()
    for integration in PACK.glob("Integrations/*/*.yml"):
        declared |= set(_yaml(integration).get("tests") or [])
    existing = {_yaml(p)["name"] for p in PACK.glob("TestPlaybooks/*.yml")}
    assert declared - existing == set()


def test_incident_type_points_at_a_playbook_that_exists():
    incident_type = json.loads((PACK / "IncidentTypes/incidenttype-tLab_Anti-APT_Verdict.json").read_text())
    playbooks = {_yaml(p)["name"] for p in PACK.glob("Playbooks/*.yml")}
    assert incident_type["playbookId"] in playbooks


def test_incident_type_points_at_a_layout_that_exists():
    incident_type = json.loads((PACK / "IncidentTypes/incidenttype-tLab_Anti-APT_Verdict.json").read_text())
    layouts = {json.loads(p.read_text())["id"] for p in PACK.glob("Layouts/*.json")}
    assert incident_type["layout"] in layouts


def _pack_commands() -> dict:
    """Command name -> the brand that provides it."""
    out = {}
    for integration in PACK.glob("Integrations/*/*.yml"):
        data = _yaml(integration)
        for command in data["script"].get("commands") or []:
            out[command["name"]] = data["name"]
    return out


def _playbook_commands(path: Path):
    for task in _yaml(path)["tasks"].values():
        script = task["task"].get("script") or ""
        if "|||" in script:
            brand, _, command = script.partition("|||")
            yield brand, command


@pytest.mark.parametrize(
    "playbook", sorted(PACK.glob("Playbooks/*.yml")) + sorted(PACK.glob("TestPlaybooks/*.yml")), ids=lambda p: p.stem
)
def test_playbook_only_calls_commands_the_pack_provides(playbook):
    """A typo in a playbook's command name is silent until someone runs it."""
    provided = _pack_commands()
    for brand, command in _playbook_commands(playbook):
        if brand == "Builtin":
            continue  # core commands, not ours to declare
        assert command in provided, f"{playbook.name} calls unknown command {command}"
        assert provided[command] == brand, (
            f"{playbook.name} calls {command} on brand {brand}, but it lives in {provided[command]}"
        )


@pytest.mark.parametrize(
    "playbook", sorted(PACK.glob("Playbooks/*.yml")) + sorted(PACK.glob("TestPlaybooks/*.yml")), ids=lambda p: p.stem
)
def test_playbook_tasks_are_reachable_and_terminate(playbook):
    """An unreachable task is dead content; a dangling next task hangs the run."""
    tasks = _yaml(playbook)["tasks"]
    reachable, stack = set(), ["0"]
    while stack:
        current = stack.pop()
        if current in reachable:
            continue
        reachable.add(current)
        for targets in (tasks[current].get("nexttasks") or {}).values():
            for target in targets:
                assert target in tasks, f"{playbook.name}: task {current} points at missing task {target}"
                stack.append(target)
    assert reachable == set(tasks), f"{playbook.name}: unreachable tasks {set(tasks) - reachable}"


@pytest.mark.parametrize(
    "playbook", sorted(PACK.glob("Playbooks/*.yml")) + sorted(PACK.glob("TestPlaybooks/*.yml")), ids=lambda p: p.stem
)
def test_playbook_conditions_actually_branch(playbook):
    """A condition whose branches all land on the same task looks like thought
    without being any. Either the branches differ or the condition is noise."""
    for task_id, task in _yaml(playbook)["tasks"].items():
        if task["type"] != "condition":
            continue
        targets = {t for group in (task.get("nexttasks") or {}).values() for t in group}
        assert len(targets) > 1, f"{playbook.name}: condition {task_id} sends every branch to {targets}"

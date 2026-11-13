"""Tests for the tLab Anti-APT Feed integration.

The typing tests carry most of the weight here. Fetching is mechanical; the
thing that can quietly ruin a customer's Threat Intel Management is a typer
that calls "kernel32.dll" a domain or publishes the sandbox's own subnet.
"""

import json
from pathlib import Path

import pytest

import demistomock as demisto
import TLabAntiAPTFeed as feed
from CommonServerPython import (
    Common,
    DemistoException,
    EntityRelationship,
    FeedIndicatorType,
    ThreatIntel,
)
from TLabAntiAPTFeed import AUTH_SOURCE_KEY, AUTH_TLAB_ACCOUNT, TLabClient

BASE = "https://tlab.example.com"
DATA = Path(__file__).parent / "test_data"
SHA256 = "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"
NETS = feed.DEFAULT_EXCLUDED_NETWORKS


def load(name: str):
    return json.loads((DATA / f"{name}.json").read_text())


@pytest.fixture
def client():
    return TLabClient(base_url=BASE, auth_mode=AUTH_SOURCE_KEY, credentials={"password": "key"}, verify=False)


@pytest.fixture
def params():
    return {
        "url": BASE,
        "min_indicator_level": "SUSPICIOUS",
        "max_reports_per_fetch": 50,
        "maturation_lookback_hours": 0,
        "create_relationships": False,
    }


@pytest.fixture(autouse=True)
def clean_context(mocker):
    """Integration context is process-global in demistomock; isolate each test."""
    store: dict = {}
    mocker.patch.object(demisto, "getIntegrationContext", side_effect=lambda: dict(store))
    mocker.patch.object(demisto, "setIntegrationContext", side_effect=lambda v: store.clear() or store.update(v))
    return store


# ------------------------------------------------------------------ typing


@pytest.mark.parametrize(
    "value,expected",
    [
        ("203.0.113.5", FeedIndicatorType.IP),
        ("2001:db8::1", FeedIndicatorType.IPv6),
        ("https://evil.example.com/gate.php", FeedIndicatorType.URL),
        ("ftp://files.example.net/x", FeedIndicatorType.URL),
        ("attacker@example.com", FeedIndicatorType.Email),
        ("evil.example.com", FeedIndicatorType.Domain),
        ("xn--80ak6aa92e.com", FeedIndicatorType.Domain),
        ("a" * 32, FeedIndicatorType.File),
        ("b" * 40, FeedIndicatorType.File),
        ("c" * 64, FeedIndicatorType.File),
        ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", FeedIndicatorType.Registry),
        ("HKEY_CURRENT_USER/Environment", FeedIndicatorType.Registry),
    ],
)
def test_type_value_recognises(value, expected):
    assert feed.type_value(value, NETS) == expected


@pytest.mark.parametrize(
    "value",
    [
        "kernel32.dll",  # a file name, not a domain
        "setup.exe",
        "payload.zip",  # .zip is a real TLD, but this is an archive
        "install.sh",
        "lib.so",
        "script.py",
        "update.cab",
        "notadomain.invalidtld",
        "10.0.0.5",  # RFC1918
        "192.168.56.101",  # a sandbox host-only network
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.251",
        "::1",
        "fe80::1",
        "",
        "   ",
        "plainword",
        "a" * (feed.MAX_VALUE_LENGTH + 1),
    ],
)
def test_type_value_rejects(value):
    assert feed.type_value(value, NETS) is None


def test_com_is_a_domain_not_an_executable():
    """.com is the most common TLD in the world; rejecting it as a DOS
    executable extension would drop the majority of real C2 domains."""
    assert feed.type_value("c2.badguys.com", NETS) == FeedIndicatorType.Domain


def test_private_addresses_can_be_opted_in():
    assert feed.type_value("10.0.0.5", NETS, allow_private=True) == FeedIndicatorType.IP


def test_custom_excluded_network_wins():
    assert feed.type_value("203.0.113.5", ["203.0.113.0/24"]) is None


def test_truncated_value_is_rejected():
    """The server truncates at MAX_VALUE_LENGTH, so a value of exactly that
    size is probably cut mid-token and cannot be trusted."""
    assert feed.type_value("a" * feed.MAX_VALUE_LENGTH + ".com", NETS) is None


# ------------------------------------------------------------------ extraction


def test_sample_file_indicator(params):
    report = load("reports_page")["content"][0]
    indicator = feed.sample_file_indicator(report, params, "https://tlab.example.com/reports/412839")
    assert indicator["value"] == SHA256
    assert indicator["type"] == FeedIndicatorType.File
    assert indicator["score"] == Common.DBotScore.BAD
    assert indicator["fields"]["malwarefamily"] == "Emotet"
    assert indicator["fields"]["tlabscore"] == 91.5
    assert indicator["fields"]["associatedfilenames"] == ["invoice.exe"]


def test_sample_file_indicator_without_hash_is_skipped(params):
    assert feed.sample_file_indicator({"sampleReportId": 1, "file": {}}, params) is None


def test_extract_from_threat_indicators(params):
    found, signatures, filenames = feed.extract_from_threat_indicators(load("threat_indicators"), params, "SUSPICIOUS", NETS)
    by_value = {i["value"]: i for i in found}

    assert {"evil.example.com", "203.0.113.5", "https://evil.example.com/gate.php"} <= by_value.keys()
    assert by_value["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]["type"] == FeedIndicatorType.Registry

    # Excluded by type, level or address space.
    assert "192.168.56.101" not in by_value  # private
    assert "svchost.exe" not in by_value  # PROCESS
    assert "kernel32.dll" not in by_value  # not a domain
    assert by_value.get("benign.example.org") is None  # INFO, below the threshold

    assert signatures == ["Trojan.Win32.Emotet.abc"]
    assert filenames == []  # include_filenames is off


def test_file_names_only_collected_when_enabled(params):
    params["include_filenames"] = True
    _, _, filenames = feed.extract_from_threat_indicators(load("threat_indicators"), params, "SUSPICIOUS", NETS)
    assert filenames == ["C:\\Users\\admin\\AppData\\payload.dll"]


def test_info_level_included_when_threshold_lowered(params):
    found, _, _ = feed.extract_from_threat_indicators(load("threat_indicators"), params, "INFO", NETS)
    assert {"benign.example.org"} <= {i["value"] for i in found}


def test_malicious_only_threshold(params):
    found, _, _ = feed.extract_from_threat_indicators(load("threat_indicators"), params, "MALICIOUS", NETS)
    values = {i["value"] for i in found}
    assert {"evil.example.com"} <= values
    assert "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" not in values  # SUSPICIOUS


def test_attack_ids_from_threat_indicators_are_validated(params):
    found, _, _ = feed.extract_from_threat_indicators(load("threat_indicators"), params, "SUSPICIOUS", NETS)
    patterns = {i["value"] for i in found if i["type"] == feed.ATTACK_PATTERN_TYPE}
    assert patterns == {"T1071"}  # "not-a-technique" dropped


def test_extract_attack_patterns():
    patterns = feed.extract_attack_patterns(load("attack_matrix"))
    assert {p["value"] for p in patterns} == {"T1071", "T1027.002"}
    assert patterns[0]["fields"]["description"] == "Application Layer Protocol"
    assert patterns[0]["score"] == ThreatIntel.ObjectsScore.ATTACK_PATTERN


def test_extract_attack_patterns_ignores_malformed_ids():
    assert feed.extract_attack_patterns({"techniques": [{"id": "TA0011"}, {"id": ""}]}) == []


# ------------------------------------------------------------------ relationships


def test_relationships_skipped_on_old_server(mocker, params):
    mocker.patch.object(feed, "supports_relationships", return_value=False)
    indicators = [{"value": "evil.example.com", "type": FeedIndicatorType.Domain}]
    feed.build_relationships(SHA256, indicators, True)
    assert "relationships" not in indicators[0]


def test_relationships_built(mocker):
    mocker.patch.object(feed, "supports_relationships", return_value=True)
    indicators = [
        {"value": "evil.example.com", "type": FeedIndicatorType.Domain},
        {"value": "T1071", "type": feed.ATTACK_PATTERN_TYPE},
    ]
    feed.build_relationships(SHA256, indicators, True)
    assert indicators[0]["relationships"][0]["name"] == EntityRelationship.Relationships.COMMUNICATES_WITH
    assert indicators[1]["relationships"][0]["name"] == EntityRelationship.Relationships.USES


# ------------------------------------------------------------------ cursor


def test_next_cursor_advances_past_highest_id():
    assert feed.next_cursor([{"sampleReportId": 7}, {"sampleReportId": 3}], 0) == 8


def test_next_cursor_never_moves_backwards():
    assert feed.next_cursor([{"sampleReportId": 3}], 100) == 100


def test_next_cursor_on_empty_page():
    assert feed.next_cursor([], 42) == 42


def test_discovery_sends_cursor_and_ascending_sort(client, params, requests_mock):
    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    feed.discovery_page(client, 500, 50, params)
    query = mock.last_request.qs
    assert query["minreportid"] == ["500"]
    assert query["sort"] == ["samplereportid,asc"]
    assert query["completeness"] == ["complete"]


def test_maturation_sends_descending_update_time(client, params, requests_mock):
    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    feed.maturation_page(client, 24, 50, params)
    query = mock.last_request.qs
    assert query["sort"] == ["updatetime,desc"]
    assert "datefrom" in query
    assert "minreportid" not in query


def test_partial_reports_excluded_by_default(params):
    assert feed._completeness_filter(params) == ["COMPLETE"]


def test_partial_reports_can_be_included(params):
    params["include_partial"] = True
    assert feed._completeness_filter(params) == ["COMPLETE", "PARTIALLY_COMPLETE"]


# ------------------------------------------------------------------ fetch


def _wire(requests_mock, reports="reports_page"):
    requests_mock.get(f"{BASE}/sample_reports", json=load(reports))
    requests_mock.get(f"{BASE}/sample_reports/412839/threat_indicators", json=load("threat_indicators"))
    requests_mock.get(f"{BASE}/sample_reports/412840/threat_indicators", json={"indicators": []})
    requests_mock.get(f"{BASE}/sample_reports/412839/attack_matrix", json=load("attack_matrix"))
    requests_mock.get(f"{BASE}/sample_reports/412840/attack_matrix", json={"techniques": []})


def test_fetch_indicators_collects_and_advances(client, params, requests_mock):
    _wire(requests_mock)
    indicators, cursor = feed.fetch_indicators(client, params)
    values = {i["value"] for i in indicators}
    assert {SHA256, "evil.example.com"} <= values
    assert cursor == 412841


def test_fetch_indicators_deduplicates_across_reports(client, params, requests_mock):
    _wire(requests_mock)
    requests_mock.get(f"{BASE}/sample_reports/412840/threat_indicators", json=load("threat_indicators"))
    indicators, _ = feed.fetch_indicators(client, params)
    domains = [i for i in indicators if i["value"] == "evil.example.com"]
    assert len(domains) == 1


def test_fetch_indicators_survives_a_failing_report(client, params, requests_mock):
    """One report with a broken threat_indicators response must not sink the run."""
    _wire(requests_mock)
    requests_mock.get(f"{BASE}/sample_reports/412839/threat_indicators", status_code=500, json={"error": "boom"})
    indicators, cursor = feed.fetch_indicators(client, params)
    assert SHA256 in {i["value"] for i in indicators}  # the sample itself still lands
    assert cursor == 412841


def test_attack_patterns_only_fetched_when_enabled(client, params, requests_mock):
    _wire(requests_mock)
    indicators, _ = feed.fetch_indicators(client, params)
    assert "T1027.002" not in {i["value"] for i in indicators}

    params["fetch_attack_patterns"] = True
    indicators, _ = feed.fetch_indicators(client, params)
    assert "T1027.002" in {i["value"] for i in indicators}


def test_feed_tags_and_tlp_applied(client, params, requests_mock):
    _wire(requests_mock)
    params["feedTags"] = "tlab,sandbox"
    params["tlp_color"] = "AMBER"
    indicators, _ = feed.fetch_indicators(client, params)
    assert indicators[0]["fields"]["tags"] == ["tlab", "sandbox"]
    assert indicators[0]["fields"]["trafficlightprotocol"] == "AMBER"


def test_first_report_id_seeds_the_cursor(client, params, requests_mock):
    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    params["first_report_id"] = 400000
    feed.fetch_indicators(client, params)
    assert mock.request_history[0].qs["minreportid"] == ["400000"]


def test_cursor_from_context_wins_over_a_lower_first_report_id(client, params, requests_mock, clean_context):
    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    clean_context["report_cursor"] = 500000
    params["first_report_id"] = 400000
    feed.fetch_indicators(client, params)
    assert mock.request_history[0].qs["minreportid"] == ["500000"]


def test_first_report_id_raises_a_stored_cursor(client, params, requests_mock, clean_context):
    mock = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    clean_context["report_cursor"] = 12
    params["first_report_id"] = 400000
    feed.fetch_indicators(client, params)
    assert mock.request_history[0].qs["minreportid"] == ["400000"]


def test_maturation_pass_runs_when_configured(client, params, requests_mock, clean_context):
    _wire(requests_mock, "reports_empty")
    clean_context["report_cursor"] = 500000
    params["maturation_lookback_hours"] = 24
    feed.fetch_indicators(client, params)
    # Discovery plus maturation, rather than discovery alone.
    sorts = [r.qs["sort"][0] for r in requests_mock.request_history if r.path == "/sample_reports"]
    assert sorts == ["samplereportid,asc", "updatetime,desc"]


def test_maturation_only_takes_reports_below_the_cursor(client, params, requests_mock, clean_context):
    """Anything at or above the cursor is discovery's job; taking it here would
    double the per-report API cost for no gain."""
    _wire(requests_mock)
    clean_context["report_cursor"] = 1  # both fixture reports are far above this
    params["maturation_lookback_hours"] = 24
    indicators, _ = feed.fetch_indicators(client, params)
    samples = [i for i in indicators if i["type"] == FeedIndicatorType.File and i["value"] == SHA256]
    assert len(samples) == 1


def test_preview_skips_the_maturation_pass(client, params, requests_mock):
    _wire(requests_mock)
    params["maturation_lookback_hours"] = 24
    feed.fetch_indicators(client, params, preview=True)
    sorts = [r.qs["sort"][0] for r in requests_mock.request_history if r.path == "/sample_reports"]
    assert sorts == ["samplereportid,asc"]


# ------------------------------------------------------------------ commands


def test_fetch_indicators_command_batches_and_saves_cursor(mocker, client, params, requests_mock, clean_context):
    _wire(requests_mock)
    created = mocker.patch.object(demisto, "createIndicators")
    feed.fetch_indicators_command(client, params)
    assert created.call_count == 1
    assert clean_context["report_cursor"] == 412841


def test_fetch_indicators_command_splits_large_batches(mocker, client, params, requests_mock):
    mocker.patch.object(feed, "fetch_indicators", return_value=([{"value": str(i)} for i in range(4500)], 1))
    created = mocker.patch.object(demisto, "createIndicators")
    feed.fetch_indicators_command(client, params)
    assert [len(call.args[0]) for call in created.call_args_list] == [2000, 2000, 500]


def test_cursor_not_saved_when_creation_fails(mocker, client, params, requests_mock, clean_context):
    """A half-written batch must be re-fetched, not silently skipped."""
    _wire(requests_mock)
    mocker.patch.object(demisto, "createIndicators", side_effect=RuntimeError("server down"))
    with pytest.raises(RuntimeError):
        feed.fetch_indicators_command(client, params)
    assert "report_cursor" not in clean_context


def test_get_indicators_command_honours_limit(client, params, requests_mock):
    _wire(requests_mock)
    result = feed.get_indicators_command(client, {"limit": "2"}, params)
    assert len(result.outputs) == 2
    assert "tLab Anti-APT indicators (2)" in result.readable_output


def test_get_indicators_command_does_not_move_the_cursor(mocker, client, params, requests_mock, clean_context):
    _wire(requests_mock)
    created = mocker.patch.object(demisto, "createIndicators")
    feed.get_indicators_command(client, {"limit": "5"}, params)
    assert created.call_count == 0
    assert "report_cursor" not in clean_context


def test_get_indicators_command_on_empty_feed(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    result = feed.get_indicators_command(client, {}, params)
    assert result.readable_output == "No indicators found."


def test_maturation_skips_reports_below_first_report_id(client, params, requests_mock, clean_context):
    _wire(requests_mock)
    # Discovery past the cursor finds nothing; maturation returns older reports.
    requests_mock.get(f"{BASE}/sample_reports", [{"json": load("reports_empty")}, {"json": load("reports_page")}])
    clean_context["report_cursor"] = 500000
    params["maturation_lookback_hours"] = 24
    params["first_report_id"] = 450000
    indicators, _ = feed.fetch_indicators(client, params)
    assert indicators == []


def test_reset_cursor_command(clean_context):
    clean_context["report_cursor"] = 999
    clean_context["session"] = {"access": "cached"}
    feed.reset_cursor_command()
    assert clean_context == {"session": {"access": "cached"}}


def test_test_module(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    assert feed.test_module_command(client, params) == "ok"


def test_test_module_rejects_a_bad_cidr(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    params["excluded_networks"] = "10.0.0.0/8,not-a-network"
    with pytest.raises(DemistoException, match="not a valid CIDR"):
        feed.test_module_command(client, params)


# ------------------------------------------------------------------ params


def test_param_bool_respects_an_explicit_false():
    """`params.get(key) or True` would make this flag unsettable."""
    assert feed.param_bool({"create_relationships": False}, "create_relationships", True) is False
    assert feed.param_bool({"create_relationships": "false"}, "create_relationships", True) is False
    assert feed.param_bool({}, "create_relationships", True) is True
    assert feed.param_bool({"create_relationships": ""}, "create_relationships", True) is True


def test_build_client_defaults_to_tlab_account():
    client = feed.build_client({"url": "https://10.0.0.5/api", "credentials": {"identifier": "svc", "password": "k"}})
    assert client._auth_mode == AUTH_TLAB_ACCOUNT
    # Without an explicit Auth server URL, tlab-auth is reached through the omni portal.
    assert client._auth_url == "https://10.0.0.5:8002/api"


def test_build_client_passes_explicit_auth_url():
    client = feed.build_client({"url": BASE, "auth_url": "http://10.0.0.5:8033/api", "credentials": {"password": "k"}})
    assert client._auth_url == "http://10.0.0.5:8033/api"

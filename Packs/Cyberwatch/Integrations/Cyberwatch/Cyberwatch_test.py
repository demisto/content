import json

import requests_mock
from Cyberwatch import Client, fetch_incidents
import demistomock as demisto
import datetime as _dt
import pytest


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


BASE_URL = "http://fake_cyberwatch_url.local"

client = Client(base_url=BASE_URL, verify=False, auth=("fake_api_key", "fake_api_secret_key"), proxy=False)

# Test Module and Ping


def test_test_module_ok(mocker):
    from Cyberwatch import test_module

    mock_response = util_load_json("test_data/test_module.json")

    # Case OK
    mocker.patch.object(Client, "_http_request", return_value=mock_response)
    response = test_module(client)
    assert response == "ok"


def test_test_module_error(mocker):
    from Cyberwatch import test_module

    # Case error
    mocker.patch.object(Client, "_http_request", return_value=None, status_code=401)
    try:
        test_module(client)
    except Exception as e:
        assert str(e) == "Authorization Error: please check your API Key and Secret Key"


def test_test_module_by_testing_ping(mocker):
    from Cyberwatch import test_module

    mock_response = util_load_json("test_data/test_module.json")

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + "/api/v3/ping", json=mock_response, status_code=200)

        response = test_module(client)
        assert response == "ok"


# Iso 8601 converter


def test_iso8601_to_human_when_zulu(mocker):
    from Cyberwatch import iso8601_to_human

    assert iso8601_to_human("2019-09-10T14:59:23.000Z") == "2019-09-10T14:59:23"


def test_iso8601_to_human_when_iso8601(mocker):
    from Cyberwatch import iso8601_to_human

    assert iso8601_to_human("2019-09-10T16:59:23.000+02:00") == "2019-09-10T14:59:23"


def test_iso8601_to_human_when_null(mocker):
    from Cyberwatch import iso8601_to_human

    assert iso8601_to_human(None) == ""


# CVEs


def test_list_cves_command_with_no_cves(mocker):
    from Cyberwatch import list_cves_command

    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/vulnerabilities/cve_announcements",
            headers={"x-per-page": "100", "x-total": "0"},
            json={},
            status_code=200,
        )
        try:
            list_cves_command(client, {})
        except Exception as e:
            assert str(e) == "No CVEs found"


def test_list_cves_command_with_cves_only_one_page(mocker):
    from Cyberwatch import list_cves_command

    mock_response = util_load_json("test_data/test_list_cve_announcements.json")

    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/vulnerabilities/cve_announcements?page=1",
            headers={"x-per-page": "5", "x-total": "10"},
            json=mock_response,
            status_code=200,
        )

        response = list_cves_command(client, {"page": "1"})

        assert len(response.raw_response) == 5


def test_list_cves_command_with_cves_all_pages(mocker):
    from Cyberwatch import list_cves_command

    mock_response = util_load_json("test_data/test_list_cve_announcements.json")

    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/vulnerabilities/cve_announcements?page=1",
            headers={"x-per-page": "5", "x-total": "10"},
            json=mock_response,
            status_code=200,
        )
        m.get(
            BASE_URL + "/api/v3/vulnerabilities/cve_announcements?page=2",
            headers={"x-per-page": "5", "x-total": "10"},
            json=mock_response,
            status_code=200,
        )

        response = list_cves_command(client, {})

        assert len(response.raw_response) == 10


def test_list_cves_command_with_cves_all_pages_with_hard_limit(mocker):
    from Cyberwatch import list_cves_command

    mock_response = util_load_json("test_data/test_list_cve_announcements.json")

    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/vulnerabilities/cve_announcements?page=1",
            headers={"x-per-page": "5", "x-total": "10"},
            json=mock_response,
            status_code=200,
        )
        m.get(
            BASE_URL + "/api/v3/vulnerabilities/cve_announcements?page=2",
            headers={"x-per-page": "5", "x-total": "10"},
            json=mock_response,
            status_code=200,
        )

        response = list_cves_command(client, {"hard_limit": "5", "per_page": "5"})

        assert len(response.raw_response) == 5


def test_fetch_cve_command_found(mocker):
    from Cyberwatch import fetch_cve_command

    mock_response = util_load_json("test_data/test_fetch_cve_CVE-2021-44228.json")

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + "/api/v3/vulnerabilities/cve_announcements/CVE-2021-44228", json=mock_response)

        response = fetch_cve_command(client, {"cve_code": "CVE-2021-44228"})

        assert response.raw_response == mock_response


def test_fetch_cve_command_no_cve_code(mocker):
    from Cyberwatch import fetch_cve_command

    mock_response = util_load_json("test_data/test_list_cve_announcements.json")

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + "/api/v3/vulnerabilities/cve_announcements/", json=mock_response)

        try:
            fetch_cve_command(client, {})
        except Exception as e:
            assert str(e) == "Please provide a CVE cve_code"


# Assets


def test_list_assets_command_with_no_assets(mocker):
    from Cyberwatch import list_assets_command

    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/vulnerabilities/servers", headers={"x-per-page": "100", "x-total": "0"}, json={}, status_code=200
        )
        try:
            list_assets_command(client, {})
        except Exception as e:
            assert str(e) == "No assets found"


def test_list_assets_command_with_assets_only_one_page(mocker):
    from Cyberwatch import list_assets_command

    mock_response = util_load_json("test_data/test_list_servers.json")

    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/vulnerabilities/servers?page=1",
            headers={"x-per-page": "5", "x-total": "10"},
            json=mock_response,
            status_code=200,
        )

        response = list_assets_command(client, {"page": "1"})

        assert len(response.raw_response) == 5


def test_list_assets_command_with_assets_all_pages(mocker):
    from Cyberwatch import list_assets_command

    mock_response = util_load_json("test_data/test_list_servers.json")

    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/vulnerabilities/servers?page=1",
            headers={"x-per-page": "5", "x-total": "10"},
            json=mock_response,
            status_code=200,
        )
        m.get(
            BASE_URL + "/api/v3/vulnerabilities/servers?page=2",
            headers={"x-per-page": "5", "x-total": "10"},
            json=mock_response,
            status_code=200,
        )

        response = list_assets_command(client, {})

        assert len(response.raw_response) == 10


def test_fetch_asset_command_found(mocker):
    from Cyberwatch import fetch_asset_command

    mock_response = util_load_json("test_data/test_fetch_server.json")

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + "/api/v3/vulnerabilities/servers/0", json=mock_response)

        response = fetch_asset_command(client, {"id": "0"})

        assert response.raw_response == mock_response


def test_fetch_asset_full_command_found(mocker):
    from Cyberwatch import fetch_asset_full_command

    mock_response_part1 = util_load_json("test_data/test_fetch_server_full_part1.json")
    mock_response_part2 = util_load_json("test_data/test_fetch_server_full_part2.json")
    mock_response = util_load_json("test_data/test_fetch_server_full.json")

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + "/api/v3/vulnerabilities/servers/0", json=mock_response_part1)
        m.get(BASE_URL + "/api/v3/assets/servers/0", json=mock_response_part2)

        response = fetch_asset_full_command(client, {"id": "0"})

        assert response.raw_response == mock_response


def test_fetch_asset_command_no_id(mocker):
    from Cyberwatch import fetch_asset_command

    mock_response = util_load_json("test_data/test_list_servers.json")

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + "/api/v3/vulnerabilities/servers/", json=mock_response)

        try:
            fetch_asset_command(client, {})
        except Exception as e:
            assert str(e) == "Please provide an asset ID"


# Security issues


def test_list_security_issues_command_with_no_security_issues(mocker):
    from Cyberwatch import list_security_issues_command

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + "/api/v3/security_issues", headers={"x-per-page": "100", "x-total": "0"}, json={}, status_code=200)
        try:
            list_security_issues_command(client, {})
        except Exception as e:
            assert str(e) == "No security issues found"


def test_list_security_issues_command_with_security_issues_only_one_page(mocker):
    from Cyberwatch import list_security_issues_command

    mock_response = util_load_json("test_data/test_list_security_issues.json")

    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/security_issues?page=1",
            headers={"x-per-page": "5", "x-total": "10"},
            json=mock_response,
            status_code=200,
        )

        response = list_security_issues_command(client, {"page": "1"})

        assert len(response.raw_response) == 5


def test_list_security_issues_command_with_security_issues_all_pages(mocker):
    from Cyberwatch import list_security_issues_command

    mock_response = util_load_json("test_data/test_list_security_issues.json")

    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/security_issues?page=1",
            headers={"x-per-page": "5", "x-total": "10"},
            json=mock_response,
            status_code=200,
        )
        m.get(
            BASE_URL + "/api/v3/security_issues?page=2",
            headers={"x-per-page": "5", "x-total": "10"},
            json=mock_response,
            status_code=200,
        )

        response = list_security_issues_command(client, {})

        assert len(response.raw_response) == 10


def test_fetch_security_issue_command_found(mocker):
    from Cyberwatch import fetch_security_issue_command

    mock_response = util_load_json("test_data/test_fetch_security_issue.json")

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + "/api/v3/security_issues/0", json=mock_response)

        response = fetch_security_issue_command(client, {"id": "0"})

        assert response.raw_response == mock_response


def test_fetch_security_issue_command_no_id(mocker):
    from Cyberwatch import fetch_security_issue_command

    mock_response = util_load_json("test_data/test_list_security_issues.json")

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + "/api/v3/vulnerabilities/security_issues/", json=mock_response)

        try:
            fetch_security_issue_command(client, {})
        except Exception as e:
            assert str(e) == "Please provide a Security Issues ID"


def test__as_list_edge_cases():
    from Cyberwatch import _as_list

    # Scalar string stays scalar (wrapped in a list)
    assert _as_list("a,b") == ["a,b"]

    # Iterable is returned unchanged
    assert _as_list(["x", "y"]) == ["x", "y"]


def test_to_utc_variants(mocker):
    """
    • No-timezone     → assume UTC and make it *aware*
    • Explicit “Z”    → already UTC, keep value
    • +02:00 offset   → convert back to UTC (-2 h)
    """
    from Cyberwatch import to_utc

    # naïve (no tz) string
    naive_str = "2025-06-02T14:30:00"
    naive_dt = to_utc(naive_str)
    assert naive_dt.tzinfo is _dt.UTC
    assert naive_dt.isoformat() == "2025-06-02T14:30:00+00:00"

    # explicit “Z” (UTC) string
    zulu_str = "2025-06-02T14:30:00Z"
    zulu_dt = to_utc(zulu_str)
    assert zulu_dt == naive_dt
    assert zulu_dt.tzinfo is _dt.UTC

    # offset string (+02:00 should roll back 2 h)
    offset_str = "2025-06-02T16:30:00+02:00"
    offset_dt = to_utc(offset_str)
    assert offset_dt == naive_dt


def _freeze_now(mocker, year=2025, month=6, day=2, h=12):
    import Cyberwatch as _cw

    fixed = _dt.datetime(year, month, day, h, 0, 0, tzinfo=_dt.UTC)

    class _FixedDateTime(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed if tz is None else fixed.astimezone(tz)

    mocker.patch.object(_cw, "datetime", _FixedDateTime)


def _make_lr(
    *,
    last_success: int = 0,
    cycle_start: int | None = None,
    server_id: int | None = None,
    cve_id: str | None = None,
) -> dict:
    """Build a last-run dict matching the new fetch_incidents contract."""
    return {
        "last_success": last_success,
        "cycle_start": cycle_start,
        "server_id": server_id,
        "cve_id": cve_id,
    }


def test_initial_last_run(mocker):
    """
    _initial_last_run should:
      * convert `first_fetch` into last_success (seconds)
      * set cycle_start to the frozen 'now' timestamp (seconds)
      * set server_id and cve_id to None
    """
    import Cyberwatch as _cw
    from Cyberwatch import _initial_last_run

    _freeze_now(mocker, year=2025, month=6, day=30, h=12)

    first_fetch = "7 days"
    expected_ms, _ = _cw.parse_date_range(first_fetch, to_timestamp=True)
    expected_last_success = int(expected_ms / 1000)

    result = _initial_last_run(first_fetch)

    assert result == {
        "last_success": expected_last_success,
        "cycle_start": int(_dt.datetime(2025, 6, 30, 12, 0, tzinfo=_dt.UTC).timestamp()),
        "server_id": None,
        "cve_id": None,
    }


def test_fetch_incidents_one_incident(mocker):
    """One CVE present on one asset ➜ one incident pushed."""
    _freeze_now(mocker)
    import Cyberwatch as _cw

    frozen_ts = int(_cw.datetime.now(_dt.UTC).timestamp())

    mocker.patch.object(
        Client,
        "get_assets",
        return_value=util_load_json("test_data/test_fetch_incident_assets_one.json"),
    )
    mocker.patch.object(
        Client,
        "get_one_asset",
        return_value=util_load_json("test_data/test_fetch_incident_full_asset_one.json"),
    )

    mocker.patch.object(demisto, "getLastRun", return_value=_make_lr())

    pushed: list[dict] = []
    mocker.patch.object(demisto, "incidents", side_effect=pushed.extend)
    set_lr = mocker.patch.object(demisto, "setLastRun")

    fetch_incidents(client, {"max_fetch": "50"})

    assert [i["name"] for i in pushed] == ["CVE-2025-0001 on srv1"]

    set_lr.assert_called_once()
    lr = set_lr.call_args[0][0]
    assert lr["last_success"] == frozen_ts
    assert lr["cycle_start"] is None
    assert lr["server_id"] is None
    assert lr["cve_id"] is None


def test_fetch_incidents_respects_max_fetch(mocker):
    """Multiple CVEs on one asset, but max_fetch=2 ➜ two incidents pushed per cycle."""
    _freeze_now(mocker, year=2025, month=6, day=10)
    import Cyberwatch as _cw

    cycle_ts = int(_cw.datetime.now(_dt.UTC).timestamp())

    mocker.patch.object(
        Client,
        "get_assets",
        return_value=util_load_json("test_data/test_fetch_incident_assets_one.json"),
    )
    mocker.patch.object(
        Client,
        "get_one_asset",
        return_value=util_load_json("test_data/test_fetch_incident_full_asset_five.json"),
    )

    last_run = _make_lr()  # start from epoch
    collected: list[str] = []

    expected_batches = [
        ("CVE-2025-0001", "CVE-2025-0002"),
        ("CVE-2025-0003", "CVE-2025-0004"),
        ("CVE-2025-0005",),
    ]

    for batch in expected_batches:
        mocker.patch.object(demisto, "getLastRun", return_value=last_run)

        pushed: list[dict] = []
        mocker.patch.object(demisto, "incidents", side_effect=pushed.extend)
        set_lr = mocker.patch.object(demisto, "setLastRun")

        fetch_incidents(client, {"max_fetch": "2"})

        names = [i["name"] for i in pushed]
        assert names == [f"{cve} on srv1" for cve in batch]
        collected.extend(names)

        set_lr.assert_called_once()
        last_run = set_lr.call_args[0][0]  # feed into next loop

        if len(batch) == 2:  # still hit max_fetch
            assert last_run["last_success"] == 0
            assert last_run["cycle_start"] == cycle_ts
            assert last_run["server_id"] == 912
            assert last_run["cve_id"] == batch[-1]
        else:  # cycle finished
            assert last_run == {
                "last_success": cycle_ts,
                "cycle_start": None,
                "server_id": None,
                "cve_id": None,
            }

    assert collected == [f"CVE-2025-000{i} on srv1" for i in range(1, 6)]


def test_fetch_incidents_skips_ignored_by_default(mocker):
    _freeze_now(mocker, year=2025, month=6, day=10)
    import Cyberwatch as _cw

    frozen_ts = int(_cw.datetime.now(_dt.UTC).timestamp())

    mocker.patch.object(
        Client,
        "get_assets",
        return_value=util_load_json("test_data/test_fetch_incident_assets_one.json"),
    )
    mocker.patch.object(
        Client,
        "get_one_asset",
        return_value=util_load_json("test_data/test_fetch_incident_full_asset_ignored.json"),
    )

    mocker.patch.object(demisto, "getLastRun", return_value=_make_lr())
    pushed: list[dict] = []
    mocker.patch.object(demisto, "incidents", side_effect=pushed.extend)
    set_lr = mocker.patch.object(demisto, "setLastRun")

    fetch_incidents(client, {})

    assert pushed == []
    set_lr.assert_called_once()
    lr = set_lr.call_args[0][0]
    assert lr["last_success"] == frozen_ts
    assert lr["cycle_start"] is None


def test_fetch_incidents_ingests_ignored_when_requested(mocker):
    _freeze_now(mocker)

    mocker.patch.object(
        Client,
        "get_assets",
        return_value=util_load_json("test_data/test_fetch_incident_assets_one.json"),
    )
    mocker.patch.object(
        Client,
        "get_one_asset",
        return_value=util_load_json("test_data/test_fetch_incident_full_asset_ignored.json"),
    )

    mocker.patch.object(demisto, "getLastRun", return_value=_make_lr())

    pushed: list[dict] = []
    mocker.patch.object(demisto, "incidents", side_effect=pushed.extend)
    mocker.patch.object(demisto, "setLastRun")

    fetch_incidents(
        client,
        {"cve_filters": '{"ignored": true}', "max_fetch": "10"},
    )

    assert len(pushed) == 1
    assert pushed[0]["name"].startswith("CVE-2025-9999")


def test_fetch_incidents_uses_last_run_timestamp(mocker):
    _freeze_now(mocker)

    mocker.patch.object(
        Client,
        "get_assets",
        return_value=util_load_json("test_data/test_fetch_incident_assets_one.json"),
    )
    mocker.patch.object(
        Client,
        "get_one_asset",
        return_value=util_load_json("test_data/test_fetch_incident_full_asset_two_cves.json"),
    )

    lr_ts = int(_dt.datetime(2025, 6, 1, tzinfo=_dt.UTC).timestamp())
    mocker.patch.object(demisto, "getLastRun", return_value=_make_lr(last_success=lr_ts))

    pushed: list[dict] = []
    mocker.patch.object(demisto, "incidents", side_effect=pushed.extend)
    mocker.patch.object(demisto, "setLastRun")

    fetch_incidents(client, {"max_fetch": "10"})

    assert len(pushed) == 1
    assert pushed[0]["name"].startswith("CVE-2025-0002")


def test_fetch_incidents_filter_prioritized_true(mocker):
    _freeze_now(mocker)

    mocker.patch.object(
        Client,
        "get_assets",
        return_value=util_load_json("test_data/test_fetch_incident_assets_one.json"),
    )
    mocker.patch.object(
        Client,
        "get_one_asset",
        return_value=util_load_json("test_data/test_fetch_incident_full_asset_prioritized.json"),
    )

    mocker.patch.object(demisto, "getLastRun", return_value=_make_lr())

    pushed: list[dict] = []
    mocker.patch.object(demisto, "incidents", side_effect=pushed.extend)
    mocker.patch.object(demisto, "setLastRun")

    fetch_incidents(
        client,
        {"cve_filters": '{"prioritized": true}', "max_fetch": "10"},
    )

    assert [i["name"] for i in pushed] == ["CVE-2025-1111 on srv1"]


def test_fetch_incidents_filter_min_scores(mocker):
    _freeze_now(mocker)

    mocker.patch.object(
        Client,
        "get_assets",
        return_value=util_load_json("test_data/test_fetch_incident_assets_one.json"),
    )
    mocker.patch.object(
        Client,
        "get_one_asset",
        return_value=util_load_json("test_data/test_fetch_incident_full_asset_scores.json"),
    )

    mocker.patch.object(demisto, "getLastRun", return_value=_make_lr())

    pushed: list[dict] = []
    mocker.patch.object(demisto, "incidents", side_effect=pushed.extend)
    mocker.patch.object(demisto, "setLastRun")

    fetch_incidents(
        client,
        {"cve_filters": '{"min_cvss": 9, "min_epss": 0.5}', "max_fetch": "10"},
    )

    assert [i["name"] for i in pushed] == ["CVE-2025-HIGH on srv1"]


# ---------------------------------------------------------------------------
# Declarative Data commands
# ---------------------------------------------------------------------------


def test_send_declarative_data_asset_command_success(mocker):
    from Cyberwatch import send_declarative_data_asset_command

    # Host exists
    mocker.patch.object(Client, "get_assets", return_value=[{"id": 123, "hostname": "myHost"}])

    # Validate payload sent to upload
    def _fake_upload(blob, timeout=90):
        assert "HOSTNAME:myHost" in blob
        assert "METADATA:metavalue" in blob
        return {"server_id": 123, "status": "ok"}

    mocker.patch.object(Client, "upload_declarative_data", side_effect=_fake_upload)

    res = send_declarative_data_asset_command(client, {"hostname": "myHost", "data": '{"metadata": "metavalue"}'})

    assert res.outputs_prefix == "Cyberwatch.DeclarativeDataUpload"
    assert res.outputs.get("server_id") == 123


def test_send_declarative_data_asset_command_host_not_found(mocker):
    from Cyberwatch import send_declarative_data_asset_command, DemistoException

    mocker.patch.object(Client, "get_assets", return_value=[])
    with pytest.raises(DemistoException, match="Hostname 'nohost' not found"):
        send_declarative_data_asset_command(client, {"hostname": "nohost", "data": "{}"})


def test_send_declarative_data_asset_command_bad_json(mocker):
    from Cyberwatch import send_declarative_data_asset_command

    mocker.patch.object(Client, "_http_request")  # should not be called

    try:
        send_declarative_data_asset_command(client, {"hostname": "h1", "data": "{NOTJSON"})
    except Exception as e:
        assert "Invalid JSON" in str(e)


def test_get_declarative_data_asset_command_success(mocker):
    """
    /api/v3/servers/{id}/info returns TEXT, so client.get_declarative_data returns a string.
    Command should wrap it under Cyberwatch.DeclarativeData.raw
    """
    from Cyberwatch import get_declarative_data_asset_command

    text_blob = "HOSTNAME:SrvA\nCATEGORY:Server\n"
    # Client.get_declarative_data already wraps _http_request with resp_type="text"
    mocker.patch.object(Client, "_http_request", return_value=text_blob)

    res = get_declarative_data_asset_command(client, {"id": "42"})
    assert res.outputs_prefix == "Cyberwatch.DeclarativeData"
    assert res.outputs == {"id": 42, "raw": text_blob}
    assert "SrvA" in res.readable_output


def test_list_sysadmin_assets_command_one_page(mocker):
    from Cyberwatch import list_sysadmin_assets_command

    mock_response = util_load_json("test_data/test_list_sysadmin_servers.json")
    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/assets/servers?page=1",
            headers={"x-per-page": "2", "x-total": "2"},
            json=mock_response,
            status_code=200,
        )
        res = list_sysadmin_assets_command(client, {"page": "1"})
        assert len(res.raw_response) == 2
        # ensure readable fields are present
        assert "Cyberwatch Sysadmin Assets" in res.readable_output


def test_list_sysadmin_assets_command_all_pages(mocker):
    from Cyberwatch import list_sysadmin_assets_command

    # Two pages of one element each
    mock_page = util_load_json("test_data/test_list_sysadmin_servers_page.json")
    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/assets/servers?page=1",
            headers={"x-per-page": "1", "x-total": "2"},
            json=mock_page,
            status_code=200,
        )
        m.get(
            BASE_URL + "/api/v3/assets/servers?page=2",
            headers={"x-per-page": "1", "x-total": "2"},
            json=mock_page,
            status_code=200,
        )
        res = list_sysadmin_assets_command(client, {})
        assert len(res.raw_response) == 2


def test_list_sysadmin_assets_command_empty(mocker):
    from Cyberwatch import list_sysadmin_assets_command

    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/assets/servers",
            headers={"x-per-page": "50", "x-total": "0"},
            json={},
            status_code=200,
        )
        try:
            list_sysadmin_assets_command(client, {})
        except Exception as e:
            assert str(e) == "No Sysadmin assets found"


def test_fetch_sysadmin_asset_command_found(mocker):
    from Cyberwatch import fetch_sysadmin_asset_command

    mock_asset = util_load_json("test_data/test_fetch_sysadmin_server.json")
    with requests_mock.Mocker() as m:
        m.get(BASE_URL + "/api/v3/assets/servers/10", json=mock_asset, status_code=200)
        res = fetch_sysadmin_asset_command(client, {"id": "10"})
        assert res.raw_response == mock_asset
        assert res.outputs_prefix == "Cyberwatch.SysadminAsset"


# ---------------- Compliance ---------------- #


def test_list_compliance_assets_command_one_page(mocker):
    from Cyberwatch import list_compliance_assets_command

    mock_response = util_load_json("test_data/test_list_compliance_assets.json")
    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/compliance/assets?page=1",
            headers={"x-per-page": "2", "x-total": "2"},
            json=mock_response,
            status_code=200,
        )
        res = list_compliance_assets_command(client, {"page": "1"})
        assert len(res.raw_response) == 2
        assert "Cyberwatch Compliance Assets" in res.readable_output


def test_list_compliance_assets_command_all_pages(mocker):
    from Cyberwatch import list_compliance_assets_command

    mock_page = util_load_json("test_data/test_list_compliance_assets_page.json")
    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/compliance/assets?page=1",
            headers={"x-per-page": "1", "x-total": "2"},
            json=mock_page,
            status_code=200,
        )
        m.get(
            BASE_URL + "/api/v3/compliance/assets?page=2",
            headers={"x-per-page": "1", "x-total": "2"},
            json=mock_page,
            status_code=200,
        )
        res = list_compliance_assets_command(client, {})
        assert len(res.raw_response) == 2


def test_list_compliance_assets_command_empty(mocker):
    from Cyberwatch import list_compliance_assets_command

    with requests_mock.Mocker() as m:
        m.get(
            BASE_URL + "/api/v3/compliance/assets",
            headers={"x-per-page": "50", "x-total": "0"},
            json={},
            status_code=200,
        )
        try:
            list_compliance_assets_command(client, {})
        except Exception as e:
            assert str(e) == "No Compliance assets found"


def test_fetch_compliance_asset_command_found(mocker):
    from Cyberwatch import fetch_compliance_asset_command

    mock_asset = util_load_json("test_data/test_fetch_compliance_asset.json")
    with requests_mock.Mocker() as m:
        m.get(BASE_URL + "/api/v3/compliance/servers/77", json=mock_asset, status_code=200)
        res = fetch_compliance_asset_command(client, {"id": "77"})
        assert res.raw_response == mock_asset
        assert res.outputs_prefix == "Cyberwatch.ComplianceAsset"

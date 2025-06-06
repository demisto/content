import json
import pytest
from datetime import datetime, UTC
from CommonServerPython import DBotScoreReliability, DemistoException
import demistomock as demisto


@pytest.mark.parametrize("argument", ["cve_id", "cve"])
def test_http_request_json_negative(requests_mock, argument):
    from VulnDB import Client, vulndb_get_cve_command

    base_path = "https://vulndb.cyberriskanalytics.com"
    requests_mock.post(f"{base_path}/oauth/token", json={"access_token": "access_token"})
    cve_id = "2014-1234"
    requests_mock.get(
        f"{base_path}/api/v1/vulnerabilities/{cve_id}/find_by_cve_id",
        json={"details": "You have exceeded your API usage for the month. Please contact support"},
    )
    client = Client(False, False, f"{base_path}/api/v1", "client_id", "client_secret", 60)
    with pytest.raises(DemistoException, match="You have exceeded your API usage for the month"):
        vulndb_get_cve_command({argument: cve_id}, client, DBotScoreReliability.C)


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    "min_disclosure_date,ignore_deprecated,expected_result, last_id",
    [
        (datetime(2025, 5, 23, 12, 0, 0, 0, UTC), True, ["1@2025-05-31T00:00:00Z", "5@2025-05-30T18:00:00Z"], "1"),
        (
            datetime(2025, 5, 23, 12, 0, 0, 0, UTC),
            False,
            ["1@2025-05-31T00:00:00Z", "5@2025-05-30T18:00:00Z", "9@2025-05-31T00:00:00Z"],
            "9",
        ),
        (
            datetime.min.replace(tzinfo=UTC),
            True,
            ["1@2025-05-31T00:00:00Z", "2@2025-05-31T00:00:00Z", "5@2025-05-30T18:00:00Z", "6@2025-05-30T18:00:00Z"],
            "2",
        ),
        (
            datetime.min.replace(tzinfo=UTC),
            False,
            [
                "1@2025-05-31T00:00:00Z",
                "2@2025-05-31T00:00:00Z",
                "5@2025-05-30T18:00:00Z",
                "6@2025-05-30T18:00:00Z",
                "9@2025-05-31T00:00:00Z",
                "10@2025-05-31T00:00:00Z",
            ],
            "10",
        ),
    ],
)
def test_vulndb_fetch_incidents_command(mocker, min_disclosure_date, ignore_deprecated, expected_result, last_id):
    from VulnDB import Client, vulndb_fetch_incidents_command

    incidents = util_load_json("test_data/fetch-incidents_api_response.json")
    mocker.patch.object(Client, "_http_request", return_value=incidents)
    mocker.patch.object(demisto, "getLastRun", return_value={"start_time": "2025-05-30T18:00:00Z", "last_id": "4"})
    client = Client(False, False, "", "", "", 60)
    last_run, incidents = vulndb_fetch_incidents_command(
        100, datetime(2025, 5, 21, 0, 0, 0, 0, UTC), True, True, min_disclosure_date, ignore_deprecated, client
    )
    assert "start_time" in last_run
    assert "last_id" in last_run
    assert incidents is not None
    assert len(incidents) == len(expected_result)
    assert {incident["dbotMirrorId"] for incident in incidents} == set(expected_result)
    assert last_run["start_time"] == "2025-05-31T00:00:00Z"
    assert last_run["last_id"] == last_id

"""Symantec Endpoint Security Threat Intel- Unit Tests file

Pytest Unit Tests: all function names must start with "test_"
"""

import json
import pytest
from CommonServerPython import *
from datetime import datetime, timedelta
from SymantecICDM import (
    Client,
    icdm_fetch_incidents_command,
    fetch_incidents_command,
    ensure_max_age,
    file_reputation_command,
    url_reputation_command,
    domain_reputation_command,
    ip_reputation_command,
    ensure_argument,
    is_filtered,
    symantec_protection_file_command,
    symantec_protection_cve_command,
    symantec_protection_network_command,
    get_network_indicator_by_type,
)

BASE_RELIABILITY = DBotScoreReliability.B

DATE_TIME = datetime.now(tz=timezone.utc).replace(second=0, microsecond=0)
AN_HOUR_AGO = DATE_TIME - timedelta(hours=1)
TWO_MONTHS_AGO = DATE_TIME - timedelta(days=60)


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    "value, output",
    [
        (AN_HOUR_AGO, AN_HOUR_AGO),
        (TWO_MONTHS_AGO, DATE_TIME - timedelta(days=29, hours=23, minutes=59)),
    ],
)
def test_ensure_max_age(value: datetime, output: datetime):
    """
    Given:
        - Mocked date
    When:
        - sent to ensure_max_age
    Then:
        - ensure the age matches the expected output
    """
    value = value.replace(second=0, microsecond=0)
    result = ensure_max_age(value)
    result = result.replace(second=0, microsecond=0)
    assert result == output


def test_icdm_fetch_incidents_command(mocker):
    client = Client("", "")
    incidents = util_load_json("test_data/icdm_incidents_without_events.json")
    mocker.patch.object(Client, "_http_request", return_value=incidents)
    result = icdm_fetch_incidents_command(
        client, 100, datetime(2023, 4, 26, 0, 0, 0, tzinfo=timezone.utc)
    )

    assert result.outputs == incidents.get("incidents")

    expected_hr = (
        "### Symantec Endpoint Security EDR Incidents\n"
        "|ref_incident_uid|type|conclusion|created|modified|\n"
        "|---|---|---|---|---|\n"
        "| 102106 | INCIDENT_UPDATE | Suspicious Activity | 2023-04-26T15:44:19.345+00:00 | 2023-04-26T23:38:48.634+00:00 |\n"
        "| 102109 | INCIDENT_CREATION | Suspicious Activity | 2023-04-26T21:28:00.467+00:00 | 2023-04-26T21:52:51.550+00:00 |\n"
        "| 102110 | INCIDENT_CREATION | Suspicious Activity | 2023-04-26T21:46:10.400+00:00 | 2023-04-26T22:01:58.648+00:00 |\n"
    )

    assert result.readable_output == expected_hr


def test_fetch_incidents_command(mocker):
    client = Client("", "")
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=util_load_json("test_data/icdm_incidents_without_events.json"),
    )

    last_run, incidents = fetch_incidents_command(
        client, 100, datetime(2023, 4, 26, 0, 0, 0, tzinfo=timezone.utc)
    )
    expected_incidents = util_load_json("test_data/outputs/icdm_incidents_output.json")
    assert last_run == {"last_fetch": 1682545570.4}
    assert incidents == expected_incidents


@pytest.mark.parametrize(
    "response, result", [({"access_token": "YXNhbXBsZWFjY2Vzc3Rva2VudGNvZGU="}, True)]
)
def test_client_authenticate(response, result, mocker):
    client = Client("", "")
    mocker.patch.object(Client, "_http_request", return_value=response)
    assert client.authenticate() == result
    assert client._session_token == response.get("access_token")


@pytest.mark.parametrize(
    "file, output",
    [
        (
            "eec3f761f7eabe9ed569f39e896be24c9bbb8861b15dbde1b3d539505cd9dd8d",
            {
                "indicator": "eec3f761f7eabe9ed569f39e896be24c9bbb8861b15dbde1b3d539505cd9dd8d",
                "reputation": "BAD",
                "actors": ["Waterbug"],
            },
        )
    ],
)
def test_file_reputation_command(file, output, mocker):
    client = Client("", "")
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=util_load_json("test_data/file_insight_reputation_response.json"),
    )
    response = file_reputation_command(client, {"file": file}, BASE_RELIABILITY)
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize(
    "url, output",
    [
        (
            "elblogdeloscachanillas.com.mx%2Fs3sy8rq10%2Fophn.png",
            {
                "indicator": "elblogdeloscachanillas.com.mx%2Fs3sy8rq10%2Fophn.png",
                "reputation": "BAD",
                "risk_level": 10,
                "categories": ["Malicious Sources/Malnets"],
                "first_seen": None,
                "last_seen": None,
            },
        )
    ],
)
def test_url_reputation_command(url, output, mocker):
    client = Client("", "")
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=util_load_json("test_data/url_insight_reputation_response.json"),
    )
    response = url_reputation_command(client, {"url": url}, BASE_RELIABILITY)
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize(
    "domain, output",
    [
        (
            "elblogdeloscachanillas.com.mx",
            {
                "indicator": "elblogdeloscachanillas.com.mx",
                "reputation": "BAD",
                "risk_level": 10,
                "categories": ["Malicious Sources/Malnets"],
                "first_seen": "2019-08-30",
                "last_seen": "2024-01-24",
            },
        )
    ],
)
def test_domain_reputation_command(domain, output, mocker):
    client = Client("", "")
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=util_load_json(
            "test_data/domain_insight_reputation_response.json"
        ),
    )

    response = domain_reputation_command(client, {"domain": domain}, BASE_RELIABILITY)
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize(
    "ip, output",
    [
        (
            "8.8.8.8",
            {
                "indicator": "8.8.8.8",
                "reputation": "GOOD",
                "risk_level": 2,
                "categories": ["Web Infrastructure"],
                "first_seen": "2023-07-10",
                "last_seen": "2023-12-18",
            },
        )
    ],
)
def test_ip_reputation_command(ip, output, mocker):
    client = Client("", "")
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=util_load_json("test_data/ip_insight_reputation_response.json"),
    )
    response = ip_reputation_command(client, {"ip": ip}, BASE_RELIABILITY)
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize(
    "file, output",
    [
        (
            "eec3f761f7eabe9ed569f39e896be24c9bbb8861b15dbde1b3d539505cd9dd8d",
            util_load_json("test_data/file_protection_response.json"),
        )
    ],
)
def test_symantec_protection_file_command(file, output, mocker):
    client = Client("", "")
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=util_load_json("test_data/file_protection_response.json"),
    )
    response = symantec_protection_file_command(client, {"file": file})
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize(
    "network, output",
    [
        (
            "eec3f761f7eabe9ed569f39e896be24c9bbb8861b15dbde1b3d539505cd9dd8d",
            util_load_json("test_data/network_protection_response.json"),
        )
    ],
)
def test_symantec_protection_network_command(network, output, mocker):
    client = Client("", "")
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=util_load_json("test_data/network_protection_response.json"),
    )
    response = symantec_protection_network_command(client, {"network": network})
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize(
    "cve, output",
    [
        (
            "eec3f761f7eabe9ed569f39e896be24c9bbb8861b15dbde1b3d539505cd9dd8d",
            util_load_json("test_data/cve_protection_response.json"),
        )
    ],
)
def test_symantec_protection_cve_command(cve, output, mocker):
    client = Client("", "")
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=util_load_json("test_data/cve_protection_response.json"),
    )
    response = symantec_protection_cve_command(client, {"cve": cve})
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize("args, name, output", [({"ip": "8.8.8.8"}, "ip", ["8.8.8.8"])])
def test_ensure_argument(args, name, output):
    assert ensure_argument(args, name) == output


@pytest.mark.parametrize("args, name", [({}, "ip"), ({"ip": ""}, "ip")])
def test_ensure_argument_exception(args, name):
    with pytest.raises(ValueError):
        ensure_argument(args, name)


@pytest.mark.parametrize(
    "value, filters, output",
    [("support.paloaltonetworks.com", ["paloaltonetworks.com"], True)],
)
def test_is_filtered(value: str, filters: list[str], output: bool):
    assert is_filtered(value, filters) == output


@pytest.mark.parametrize(
    "arg_type, indicator, score",
    [
        (
            DBotScoreType.IP,
            "8.8.8.8",
            Common.DBotScore.GOOD,
        ),
        (
            DBotScoreType.URL,
            "https://google.com",
            Common.DBotScore.GOOD,
        ),
        (
            DBotScoreType.DOMAIN,
            "google.com",
            Common.DBotScore.GOOD,
        ),
    ],
)
def test_get_network_indicator_by_type(
        arg_type: str, indicator: str, score: int):
    dbot_score = Common.DBotScore(
        indicator=indicator,
        indicator_type=arg_type,
        integration_name='INTEGRATION_NAME',
        score=score,
        reliability=DBotScoreReliability.A,
        malicious_description=None,
    )
    assert isinstance(get_network_indicator_by_type(type=arg_type, indicator=indicator, dbot_score=dbot_score), Common.Indicator)


@pytest.mark.parametrize("type, indicator, score", [("", "", Common.DBotScore.GOOD, )])
def test_get_network_indicator_by_type_exception(type: str, indicator: str, score: Common.DBotScore):
    with pytest.raises(DemistoException):
        get_network_indicator_by_type(type, indicator, score)

import SEKOIAIntelligenceCenter
from CommonServerPython import *
import pytest
import os
import io
import json

MOCK_URL = "https://api.sekoia.io"


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture(scope="session")
def client():
    api_key = os.environ.get("SEKOIAIO_APIKEY", "aa")
    headers = {"Authorization": f"Bearer {api_key}"}
    client = SEKOIAIntelligenceCenter.Client(
        base_url=MOCK_URL,
        headers=headers,
    )
    return client


@pytest.mark.parametrize(
    "input, output",
    [
        ("[network-traffic:dst_ref.value = 'buike.duckdns.org']", "buike.duckdns.org"),
        ("[ipv4-addr:value = '198.51.100.1/32' OR ipv4-addr:value = '203.0.113.33/32']", "198.51.100.1/32"),
        (
            "[network-traffic:dst_ref.value = 'buike.duckdns.org' AND network-traffic:dst_port = 30303]",
            "buike.duckdns.org",
        ),
        ("[email-addr:value = 'eicar@sekoia.io']", "eicar@sekoia.io"),
        ("[filename:value = 'sessionmanagermodule.dll']", "sessionmanagermodule.dll"),
        ("[ipv4-addr:value = '206.189.85.18']", "206.189.85.18"),
        (
            "[url:value = 'http://177.22.84.44:49467/.i']",
            "http://177.22.84.44:49467/.i",
        ),
    ],
)
def test_extract_indicator_from_pattern(input, output):
    SEKOIAIntelligenceCenter.extract_indicator_from_pattern(input) == output


@pytest.mark.parametrize(
    "indicator_type, indicator_value, json_test_file",
    [
        ("email-addr", "eicar@sekoia.io", "test_data/observable.json"),
        ("email-addr", "does-not-exist@sekoia.io", "test_data/observable_unknown.json"),
    ],
)
def test_get_observables(
    client, requests_mock, indicator_value, indicator_type, json_test_file
):
    mock_response = util_load_json(json_test_file)
    requests_mock.get(
        MOCK_URL
        + f"/v2/inthreat/observables?match[value]={indicator_value}&match[type]={indicator_type}",
        json=mock_response,
    )

    args = {"value": indicator_value, "type": indicator_type}
    result = SEKOIAIntelligenceCenter.get_observable_command(client=client, args=args)

    assert result.outputs["items"] == mock_response["items"]
    assert result.outputs["indicator"] == args


def test_test_module_ok(client, requests_mock):
    response = {
        "csrf": "aaa",
        "fresh": False,
        "iat": 123456,
        "identity": "apikey:123456",
        "jti": "123456",
        "nbf": 123456,
        "type": "access",
        "user_claims": None,
    }

    requests_mock.get(MOCK_URL + "/v1/apiauth/auth/validate", json=response)
    assert SEKOIAIntelligenceCenter.test_module(client) == "ok"


def test_test_module_nok(client, requests_mock):
    response = {"message": "The token is invalid", "code": "T300"}

    requests_mock.get(MOCK_URL + "/v1/apiauth/auth/validate", json=response)

    assert "Authorization Error" in SEKOIAIntelligenceCenter.test_module(client)


# This test only runs if SEKOIA.IO API_KEY is provided
@pytest.mark.skipif("{'SEKOIAIO_APIKEY'}.issubset(os.environ.keys()) == False")
def test_get_validate_resource_with_credentials(client):

    result = client.get_validate_resource()

    assert result == "ok"


# This test only runs if SEKOIA.IO API_KEY is provided
@pytest.mark.skipif("{'SEKOIAIO_APIKEY'}.issubset(os.environ.keys()) == False")
def test_get_observables_with_credentials(client):

    args = {"value": "eicar@sekoia.io", "type": "email-addr"}
    result = SEKOIAIntelligenceCenter.get_observable_command(client=client, args=args)

    assert result.outputs["items"] != []
    assert result.outputs["indicator"] == args


@pytest.mark.parametrize(
    "indicator_type, indicator_value, json_test_file",
    [
        ("email-addr", "eicar@sekoia.io", "test_data/indicator.json"),
        ("email-addr", "does-not-exist@sekoia.io", "test_data/indicator_unknown.json"),
    ],
)
def test_get_indicator(
    client, requests_mock, indicator_value, indicator_type, json_test_file
):
    mock_response = util_load_json(json_test_file)
    requests_mock.get(
        MOCK_URL
        + f"/v2/inthreat/indicators?value={indicator_value}&type={indicator_type}",
        json=mock_response,
    )
    args = {"value": {indicator_value}, "type": {indicator_type}}

    result = SEKOIAIntelligenceCenter.get_indicator_command(client=client, args=args)

    assert result.outputs["items"] == mock_response["items"]
    assert result.outputs["indicator"] == args


# This test only runs if SEKOIA.IO API_KEY is provided
@pytest.mark.skipif("{'SEKOIAIO_APIKEY'}.issubset(os.environ.keys()) == False")
def test_get_indicator_with_credentials(client):
    args = {"value": "eicar@sekoia.io", "type": "email-addr"}

    result = SEKOIAIntelligenceCenter.get_indicator_command(client=client, args=args)

    assert result.outputs["items"] != []
    assert result.outputs["indicator"] == args


@pytest.mark.parametrize(
    "command, indicator_type, indicator_value",
    [
        (SEKOIAIntelligenceCenter.get_observable_command, "", "ipv4-addr"),
        (SEKOIAIntelligenceCenter.get_observable_command, "1.1.1.1", ""),
        (SEKOIAIntelligenceCenter.get_indicator_command, "1.1.1.1", ""),
        (SEKOIAIntelligenceCenter.get_indicator_command, "", "ipv4-addr"),
        (SEKOIAIntelligenceCenter.get_indicator_context_command, "1.1.1.1", ""),
        (SEKOIAIntelligenceCenter.get_indicator_context_command, "", "ipv4-addr"),
    ],
)
def test_get_indicator_context_incomplete(
    client, command, indicator_type, indicator_value
):

    args = {"value": indicator_value, "type": indicator_type}
    with pytest.raises(ValueError):
        command(client=client, args=args)


@pytest.mark.parametrize(
    "indicator_type, indicator_value, json_test_file",
    [
        ("email-addr", "eicar@sekoia.io", "test_data/indicator_context_email.json"),
        (
            "file",
            "a275bf8cb0866f0024d8172f8b8d2e87eaed9d2a170a5fb59c3c52b6e0bba2c0",
            "test_data/indicator_context_file.json",
        ),
        (
            "filename",
            "sessionmanagermodule.dll",
            "test_data/indicator_context_filename.json",
        ),
        ("ipv4-addr", "206.189.85.18", "test_data/indicator_context_ip.json"),
        ("ipv4-addr", "1.1.1.1", "test_data/indicator_context_unknown.json"),
        ("url", "http://177.22.84.44:49467/.i", "test_data/indicator_context_url.json"),
        (
            "domain-name",
            "buike.duckdns.org",
            "test_data/indicator_context_domain_name.json",
        ),
    ],
)
def test_get_indicator_context(
    client, requests_mock, indicator_type, indicator_value, json_test_file
):
    mock_response = util_load_json(json_test_file)
    requests_mock.get(
        MOCK_URL
        + f"/v2/inthreat/indicators/context?value={indicator_value}&type={indicator_type}",
        json=mock_response,
    )

    args = {"value": indicator_value, "type": indicator_type}
    command_results = SEKOIAIntelligenceCenter.get_indicator_context_command(client=client, args=args)
    for result in command_results:
        assert result.outputs != []
        assert result.to_context != []


# This test only runs if SEKOIA.IO API_KEY is provided
@pytest.mark.skipif("{'SEKOIAIO_APIKEY'}.issubset(os.environ.keys()) == False")
@pytest.mark.parametrize(
    "indicator_type, indicator_value",
    [
        ("email-addr", "eicar@sekoia.io"),
        ("file", "a275bf8cb0866f0024d8172f8b8d2e87eaed9d2a170a5fb59c3c52b6e0bba2c0"),
        ("filename", "sessionmanagermodule.dll"),
        ("ipv4-addr", "206.189.85.18"),
        ("ipv4-addr", "1.1.1.1"),
        ("url", "http://177.22.84.44:49467/.i"),
        ("domain-name", "buike.duckdns.org"),
    ],
)
def test_get_indicator_context_with_credentials(
    client, indicator_value, indicator_type
):
    args = {"value": indicator_value, "type": indicator_type}
    command_results = SEKOIAIntelligenceCenter.get_indicator_context_command(client=client, args=args)

    for result in command_results:
        assert result.outputs != []
        assert result.to_context != []


@pytest.mark.parametrize(
    "input, output",
    [
        (80, DBotScoreReliability.A_PLUS),
        (60, DBotScoreReliability.A),
        (40, DBotScoreReliability.B),
        (20, DBotScoreReliability.C),
        (1, DBotScoreReliability.D),
        (0, DBotScoreReliability.E),
        (-1, DBotScoreReliability.F),
    ],
)
def test_get_reliability_score(input: int, output: str):
    assert SEKOIAIntelligenceCenter.get_reliability_score(input) == output


@pytest.mark.parametrize(
    "input",
    [
        ("red"),
        ("amber"),
        ("green"),
        ("white"),
    ],
)
def test_get_tlp(input):
    marking_definition: str = "marking-definition--123"
    stix_bundle: dict[list[dict]] = {
        "objects": [
            {
                "id": "abc",
                "object_marking_refs": [marking_definition],
            },
            {
                "id": marking_definition,
                "definition": {"tlp": input},
                "definition_type": "tlp",
            },
        ]
    }
    assert SEKOIAIntelligenceCenter.get_tlp([marking_definition], stix_bundle) == input


def test_get_tlp_not_found():
    marking_definition: str = "marking-definition--123"
    stix_bundle: dict[list[dict]] = {
        "objects": [
            {
                "id": "abc",
                "object_marking_refs": [marking_definition],
            },
            {
                "id": "efg",
                "definition": {"tlp": "white"},
            },
        ]
    }
    assert SEKOIAIntelligenceCenter.get_tlp([marking_definition], stix_bundle) == "red"


@pytest.mark.parametrize(
    "input, output",
    [
        ("anomalous-activity", Common.DBotScore.BAD),
        ("", Common.DBotScore.NONE),
    ],
)
def test_get_reputation_score(input: list, output: int):
    assert SEKOIAIntelligenceCenter.get_reputation_score([input]) == output

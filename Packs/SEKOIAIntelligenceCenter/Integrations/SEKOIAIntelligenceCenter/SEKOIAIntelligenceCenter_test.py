from SEKOIAIntelligenceCenter import (
    Client,
    get_observables_command,
    get_indicator_command,
    get_indicator_context_command,
)
import pytest
import os
import io
import json

MOCK_URL = "https://api.sekoia.io"


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_get_observables(requests_mock):

    mock_response = util_load_json("test_data/observable.json")
    requests_mock.get(
        MOCK_URL + "/v2/inthreat/observables?match[value]=eicar@sekoia.io&match[type]=email-addr", json=mock_response
    )

    api_key = "aa"
    headers = {"Authorization": f"Bearer {api_key}"}

    client = Client(
        base_url=MOCK_URL,
        headers=headers,
    )

    args = {"value": "eicar@sekoia.io", "type": "email-addr"}

    result = get_observables_command(client=client, args=args)

    assert result.outputs["items"] == mock_response["items"]
    assert result.outputs["indicator"] == args


# This test only runs if SEKOIA.IO API_KEY is provided
@pytest.mark.skipif("{'SEKOIAIO_APIKEY'}.issubset(os.environ.keys()) == False")
def test_module_with_credentials():

    api_key = os.environ["SEKOIAIO_APIKEY"]
    headers = {"Authorization": f"Bearer {api_key}"}

    client = Client(
        base_url=MOCK_URL,
        headers=headers,
    )

    result = client.get_validate_resource()

    assert "apikey" in result["identity"]


# This test only runs if SEKOIA.IO API_KEY is provided
@pytest.mark.skipif("{'SEKOIAIO_APIKEY'}.issubset(os.environ.keys()) == False")
def test_get_observables_with_credentials():

    api_key = os.environ["SEKOIAIO_APIKEY"]

    headers = {"Authorization": f"Bearer {api_key}"}

    client = Client(
        base_url=MOCK_URL,
        headers=headers,
        verify=True,
    )

    args = {"value": "eicar@sekoia.io", "type": "email-addr"}

    result = get_observables_command(client=client, args=args)

    assert result.outputs["items"] != []
    assert result.outputs["indicator"] == args


def test_get_indicator(requests_mock):
    mock_response = util_load_json("test_data/indicator.json")
    requests_mock.get(MOCK_URL + "/v2/inthreat/indicators?value=eicar@sekoia.io&type=email-addr", json=mock_response)

    api_key = "aa"

    headers = {"Authorization": f"Bearer {api_key}"}

    client = Client(
        base_url=MOCK_URL,
        headers=headers,
        verify=True,
    )

    args = {"value": "eicar@sekoia.io", "type": "email-addr"}

    result = get_indicator_command(client=client, args=args)

    assert result.outputs["items"] == mock_response["items"]
    assert result.outputs["indicator"] == args

def test_get_indicator_empty_response(requests_mock):
    mock_response = util_load_json("test_data/indicator.json")
    mock_response =  {'items': [], 'has_more': False}
    requests_mock.get(MOCK_URL + "/v2/inthreat/indicators?value=does-not-exist@sekoia.io&type=email-addr", json=mock_response)

    api_key = "aa"

    headers = {"Authorization": f"Bearer {api_key}"}

    client = Client(
        base_url=MOCK_URL,
        headers=headers,
        verify=True,
    )

    args = {"value": "does-not-exist@sekoia.io", "type": "email-addr"}

    result = get_indicator_command(client=client, args=args)

    assert result.outputs["items"] == mock_response["items"]
    assert result.outputs["indicator"] == args


# This test only runs if SEKOIA.IO API_KEY is provided
@pytest.mark.skipif("{'SEKOIAIO_APIKEY'}.issubset(os.environ.keys()) == False")
def test_get_indicator_with_credentials():
    api_key = os.environ["SEKOIAIO_APIKEY"]
    headers = {"Authorization": f"Bearer {api_key}"}

    client = Client(
        base_url=MOCK_URL,
        headers=headers,
    )

    args = {"value": "eicar@sekoia.io", "type": "email-addr"}

    result = get_indicator_command(client=client, args=args)

    assert result.outputs["items"] != []
    assert result.outputs["indicator"] == args


def test_get_indicator_context(requests_mock):
    mock_response = util_load_json("test_data/indicator_context.json")
    requests_mock.get(MOCK_URL + "/v2/inthreat/indicators/context?value=eicar@sekoia.io&type=email-addr", json=mock_response)

    api_key = "aa"
    headers = {"Authorization": f"Bearer {api_key}"}
    client = Client(
        base_url=MOCK_URL,
        headers=headers,
    )

    args = {"value": "eicar@sekoia.io", "type": "email-addr"}
    result = get_indicator_context_command(client=client, args=args)

    assert result.outputs["items"] == mock_response["items"]
    assert result.outputs["indicator"] == args


# This test only runs if SEKOIA.IO API_KEY is provided
@pytest.mark.skipif("{'SEKOIAIO_APIKEY'}.issubset(os.environ.keys()) == False")
def test_get_indicator_context_with_credentials():
    api_key = os.environ["SEKOIAIO_APIKEY"]
    headers = {"Authorization": f"Bearer {api_key}"}

    client = Client(base_url=MOCK_URL, headers=headers, proxy=True)

    args = {"value": "eicar@sekoia.io", "type": "email-addr"}
    result = get_indicator_context_command(client=client, args=args)

    assert result.outputs["items"] != []
    assert result.outputs["indicator"] == args

from datetime import datetime, timedelta
import json
from typing import cast, Any


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_fetch_incidents(mocker):
    from decyfir import Client, fetch_incidents

    date_format = "%Y-%m-%dT%H:%M:%SZ"
    raw_mock_response = util_load_json("test_data/raw_alerts.json")

    client = Client(
        base_url="test_url",
        verify=False,
    )
    mocker.patch.object(Client, "request_decyfir_api", return_value=raw_mock_response["alerts"])
    last_fetch = (datetime.now() - timedelta(days=80)).strftime(date_format)
    last_run = {"last_fetch": last_fetch}

    _, new_incidents = fetch_incidents(
        client=client,
        last_run=last_run,
        first_fetch="90 days",
        decyfir_api_key="api_key",
        incident_type="Attack Surface",
        max_fetch="1",
    )

    assert ("rawJSON" in new_incidents[0]) is True
    incident = cast(dict[str, Any], new_incidents[0])
    custom_fields: dict = dict(incident.get("customFields") or {})
    assert ("decyfirdatadetails" in custom_fields) is True


def test_get_take_down_list(mocker):
    from decyfir import Client, get_take_down_list

    mock_response = util_load_json("test_data/take_down_list.json")

    raw_mock_response = util_load_json("test_data/raw_take_down_list.json")
    client = Client(
        base_url="test_url",
        verify=False,
    )
    mocker.patch.object(Client, "take_down_list_data", return_value=raw_mock_response)
    da = get_take_down_list(client=client, decyfir_api_key="api_key", args={"size": "1"})
    assert da[0] == mock_response["take_down_list"]


def test_initiate_take_down_request(mocker):
    from decyfir import Client, initiate_take_down_request

    mock_response = util_load_json("test_data/raw_init_take_down.json")
    client = Client(
        base_url="test_url",
        verify=False,
    )

    mocker.patch.object(Client, "initiate_take_down", return_value=mock_response)
    da = initiate_take_down_request(client=client, decyfir_api_key="api_key", args={"uid": "63ac266713b0752aa7865100"})

    assert ("Error" in da) is False

    # assert da[0] == "Take Down Request Created Successfully - TIcket ID: T00001"

import json
import urllib

import pytest

import demistomock as demisto

from TrustwaveFusion import (
    Client,
    get_ticket_command,
    add_ticket_comment_command,
    close_ticket_command,
    get_finding_command,
    get_asset_command,
    get_updated_tickets_command,
    search_tickets_command,
    search_findings_command,
    search_assets_command,
    arg_to_timestamp,
    arg_to_datestring,
    fetch_incidents,
)


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_quote_param(param):
    return urllib.parse.quote(param, safe="")


def test_test_module(requests_mock):
    json_response = util_load_json("test_data/trustwave_describe.json")
    requests_mock.get("http://api.example.com/v2/describe", json=json_response)
    client = Client("http://api.example.com")

    # Must import here to not confuse pytest
    from TrustwaveFusion import test_module

    response = test_module(client)
    assert response == "ok"

    requests_mock.get("http://api.example.com/v2/describe",
                      status_code=401)

    response = test_module(client)
    assert response == "Authorization Error: make sure API Key is correctly set"


def test_get_ticket_command(requests_mock):
    json_response = util_load_json("test_data/trustwave_get_ticket.json")
    test_id = "INA1976568"
    requests_mock.get(
        f"http://api.example.com/v2/tickets/{test_id}", json=json_response
    )

    client = Client("http://api.example.com")

    args = {"id": test_id}
    response = get_ticket_command(client, args)
    assert response.outputs_prefix == "Trustwave.Ticket"
    assert response.raw_response["number"] == test_id


def test_get_ticket_command_not_found(requests_mock):
    test_id = "missing_id"
    requests_mock.get(
        f"http://api.example.com/v2/tickets/{test_id}", json={}, status_code=404
    )

    client = Client("http://api.example.com")

    args = {"id": test_id}
    response = get_ticket_command(client, args)
    assert response.raw_response is None
    assert "not found" in response.readable_output


def test_add_ticket_comment_command(requests_mock):
    requests_mock.post(
        "http://api.example.com/v1/tickets/IN1234/comments", text="", status_code=201
    )

    client = Client("http://api.example.com")

    args = {"id": "IN1234"}
    response = add_ticket_comment_command(client, args)
    assert response == "Success"


def test_close_ticket_command(requests_mock):
    requests_mock.post(
        "http://api.example.com/v1/tickets/IN1234/close", text="", status_code=202
    )

    client = Client("http://api.example.com")

    args = {"id": "IN1234"}
    response = close_ticket_command(client, args)
    assert response == "Success"


def test_get_finding_command(requests_mock):
    json_response = util_load_json("test_data/trustwave_get_finding.json")
    test_id = "765432:THREAT:@AXv0k6GhG2zTcaogE1vG"
    requests_mock.get(
        f"http://api.example.com/v2/findings/{util_quote_param(test_id)}",
        json=json_response,
    )

    client = Client("http://api.example.com")
    args = {"id": test_id}
    response = get_finding_command(client, args)
    assert response.raw_response["id"] == test_id


def test_get_finding_command_not_found(requests_mock):
    test_id = "missing"
    requests_mock.get(
        f"http://api.example.com/v2/findings/{util_quote_param(test_id)}",
        status_code=404,
        json={},
    )

    client = Client("http://api.example.com")
    args = {"id": test_id}
    response = get_finding_command(client, args)
    assert response.readable_output == "Finding missing not found"


def test_get_asset_command(requests_mock):
    json_response = util_load_json("test_data/trustwave_get_asset.json")
    test_id = "765432:DNA#DEVICE:AW2X-hCmXdgvNlcDpVGf"
    requests_mock.get(
        f"http://api.example.com/v2/assets/{util_quote_param(test_id)}",
        json=json_response,
    )

    client = Client("http://api.example.com")
    args = {"id": test_id}
    response = get_asset_command(client, args)
    assert response.raw_response["id"] == test_id

    test_id = "bogus"
    requests_mock.get(
        f"http://api.example.com/v2/assets/{util_quote_param(test_id)}",
        status_code=404,
        json={},
    )
    args = {"id": test_id}
    response = get_asset_command(client, args)
    assert response.readable_output == f"Asset {test_id} not found"


def test_get_updated_tickets_command(requests_mock):
    json_response = util_load_json("test_data/trustwave_search_tickets.json")
    requests_mock.get(
        "http://api.example.com/v2/tickets?updatedSince=2021-12-29T16%3A00%3A00Z&type=INCIDENT&pageSize=10",
        json=json_response,
    )
    client = Client("http://api.example.com")
    args = {
        "since": "2021-12-29T16:00:00Z",
        "fetch_limit": 10,
    }
    response = get_updated_tickets_command(client, args)
    assert len(response.raw_response) == 2
    assert "number" in response.raw_response[0]


def test_search_tickets_command(requests_mock):
    json_response = util_load_json("test_data/trustwave_search_tickets.json")
    requests_mock.get(
        "http://api.example.com/v2/tickets?pageSize=10&priority=HIGH",
        json=json_response,
    )
    client = Client("http://api.example.com")
    args = {
        "priority": "HIGH",
        "limit": 10,
    }
    response = search_tickets_command(client, args)
    assert len(response.raw_response) == 2
    assert "number" in response.raw_response[0]


def test_search_findings_command(requests_mock):
    json_response = util_load_json("test_data/trustwave_search_findings.json")
    requests_mock.get(
        "http://api.example.com/v2/findings?pageSize=10&priority=HIGH",
        json=json_response,
    )
    client = Client("http://api.example.com")
    args = {
        "priority": "HIGH",
        "limit": 10,
    }
    response = search_findings_command(client, args)
    assert len(response.raw_response) == 2
    assert "detail" in response.raw_response[0]


def test_search_assets_command(requests_mock):
    json_response = util_load_json("test_data/trustwave_search_assets.json")

    requests_mock.get(
        "http://api.example.com/v2/assets?pageSize=10&name=qa-20211026-ngfw-vfw-fw",
        json=json_response,
    )
    client = Client("http://api.example.com")
    args = {
        "name": "qa-20211026-ngfw-vfw-fw",
        "limit": 10,
    }
    response = search_assets_command(client, args)
    assert len(response.raw_response) == 1
    assert "cidr" in response.raw_response[0]
    assert response.raw_response[0]["id"] == "765432:DNA#DEVICE:AW2X-hCmXdgvNlcDpVGf"


def test_fetch_incidents(requests_mock, mocker):
    json_response = util_load_json("test_data/trustwave_search_tickets.json")
    requests_mock.get(
        "http://api.example.com/v2/tickets?pageSize=10&createdSince=2022-01-31T13%3A00%3A00Z&sortField=createdOn&sortDescending=false",  # noqa: E501
        json=json_response,
    )
    mocker.patch.object(demisto, "incidents")
    mocker.patch.object(demisto, "params",
                        return_value={"ticket_types": ["INCIDENT"]})

    client = Client("http://api.example.com")
    fetch_incidents(client, 10, 1643634000)
    demisto.params.assert_called_once()
    assert demisto.incidents.call_count == 1
    assert len(demisto.incidents.call_args) == 2


def test_fetch_incidents_last_fetch(requests_mock, mocker):
    json_response = util_load_json("test_data/trustwave_search_tickets.json")
    requests_mock.get(
        "http://api.example.com/v2/tickets?pageSize=10&createdSince=2022-01-22T03%3A03%3A20Z&sortField=createdOn&sortDescending=false",  # noqa: E501
        json=json_response,
    )
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'getLastRun',
                        return_value={"last_fetch": 1642820600}
                        )

    client = Client("http://api.example.com")
    fetch_incidents(client, 10, 1642734000)
    assert demisto.getLastRun.call_count == 1
    assert demisto.incidents.call_count == 1
    assert len(demisto.incidents.call_args) == 2


def test_arg_to_timestamp():
    with pytest.raises(ValueError):
        ts = arg_to_timestamp(None, "name", required=True)
    ts = arg_to_timestamp(None, "name", required=False)
    assert ts is None

    ts = arg_to_timestamp("123", "name")
    assert ts == 123

    ts = arg_to_timestamp(123.234, "name")
    assert ts == 123

    with pytest.raises(ValueError):
        ts = arg_to_timestamp("bogus", "name")

    ts = arg_to_timestamp("2022-01-31T13:00:00Z", "name")
    assert ts == 1643634000

    with pytest.raises(ValueError):
        ts = arg_to_timestamp({}, "name")


def test_arg_to_datestring():
    datestr = arg_to_datestring(1606813200.278321, "name")
    assert datestr == "2020-12-01T09:00:00Z"

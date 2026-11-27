import json
import pytest

from CSCTakedowns import (
    Client,
    fetchthephishkitdatawithticketid_command,
    fetchthescreenshotdatawithticketid_command,
    gethtmlsourcecodeforaticket_command,
    listofworklogsforticketid_command,
    listtakedownevents_command,
    listtakedowneventswithfilters_command,
    updatetheactionwithticketid_command,
)

SERVER_URL = "https://test_url.com"  # pragma: allowlist secret


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(server_url=SERVER_URL, verify=None, proxy=None, headers=None, auth=None)


def test_fetchthephishkitdatawithticketid_command(client, requests_mock):
    """
    When:
    Given:
    Then:
    """
    args = {"ticketId": "123"}
    mock_response_request = util_load_json("./test_data/fetchthephishkitdatawithticketid_request.json")
    mock_results = util_load_json("./test_data/fetchthephishkitdatawithticketid_command.json")
    requests_mock.get(f"{SERVER_URL}/takedowns/{args['ticketId']}/phishkit", json=mock_response_request)
    results = fetchthephishkitdatawithticketid_command(client=client, args=args)
    assert results.outputs_prefix == "CSCTakedowns"
    assert results.raw_response == mock_results["CSCTakedowns"]


def test_fetchthescreenshotdatawithticketid_command(client, requests_mock):
    """
    When:
    Given:
    Then:
    """
    args = {"ticketId": "123"}
    mock_response_request = util_load_json("./test_data/fetchthescreenshotdatawithticketid_request.json")
    mock_results = util_load_json("./test_data/fetchthescreenshotdatawithticketid_command.json")
    requests_mock.get(f"{SERVER_URL}/takedowns/{args['ticketId']}/screenshot", json=mock_response_request)
    results = fetchthescreenshotdatawithticketid_command(client=client, args=args)
    assert results.outputs_prefix == "CSCTakedowns"
    assert results.raw_response == mock_results["CSCTakedowns"]


def test_gethtmlsourcecodeforaticket_command(client, requests_mock):
    """
    When:
    Given:
    Then:
    """
    args = {"ticketId": "0"}
    mock_response_request = util_load_json("./test_data/gethtmlsourcecodeforaticket_request.json")
    mock_results = util_load_json("./test_data/gethtmlsourcecodeforaticket_command.json")
    requests_mock.get(f"{SERVER_URL}/takedowns/html/{args['ticketId']}", json=mock_response_request)
    results = gethtmlsourcecodeforaticket_command(client=client, args=args)
    assert results.outputs_prefix == "CSCTakedowns"
    assert results.raw_response == mock_results["CSCTakedowns"]


def test_listofworklogsforticketid_command(client, requests_mock):
    """
    When:
    Given:
    Then:
    """
    args = {"ticketId": "0"}
    mock_response_request = util_load_json("./test_data/listofworklogsforticketid_request.json")
    mock_results = util_load_json("./test_data/listofworklogsforticketid_command.json")
    requests_mock.get(f"{SERVER_URL}/takedowns/{args['ticketId']}/worklogs", json=mock_response_request)
    results = listofworklogsforticketid_command(client=client, args=args)
    assert results.outputs_prefix == "CSCTakedowns"
    assert results.raw_response == mock_results["CSCTakedowns"]


def test_listtakedowneventswithfilters_command(client, requests_mock):
    """
    When:
    Given:
    Then:
    """
    args = {"fromDate": "2026-01-01", "toDate": "2026-03-01", "page": 1, "limit": 101}
    mock_response_request = util_load_json("./test_data/listtakedowneventswithfilters_request.json")
    mock_results = util_load_json("./test_data/listtakedowneventswithfilters_command.json")
    requests_mock.get(f"{SERVER_URL}/takedowns/filtered-list", json=mock_response_request)
    results = listtakedowneventswithfilters_command(client=client, args=args)
    assert results.outputs_prefix == "CSCTakedowns"
    assert results.raw_response == mock_results["CSCTakedowns"]


def test_listtakedownevents_command(client, requests_mock):
    """
    When:
    Given:
    Then:
    """
    args = {"fromDate": "2026-01-01", "toDate": "2026-03-01", "page": 1, "limit": 101}
    mock_response_request = util_load_json("./test_data/listtakedownevents_request.json")
    mock_results = util_load_json("./test_data/listtakedownevents_command.json")
    requests_mock.get(f"{SERVER_URL}/takedowns/list", json=mock_response_request)
    results = listtakedownevents_command(client=client, args=args)
    assert results.outputs_prefix == "CSCTakedowns"
    assert results.raw_response == mock_results["CSCTakedowns"]


def test_updatetheactionwithticketid_command(client, requests_mock):
    """
    When:
    Given:
    Then:
    """
    args = {"action": "OPEN"}
    mock_response_request = util_load_json("./test_data/updatetheactionwithticketid_request.json")
    mock_results = util_load_json("./test_data/updatetheactionwithticketid_command.json")
    requests_mock.put(f"{SERVER_URL}/takedowns/control", json=mock_response_request)
    results = updatetheactionwithticketid_command(client=client, args=args)
    assert results.outputs_prefix == "CSCTakedowns"
    assert results.raw_response == mock_results["CSCTakedowns"]

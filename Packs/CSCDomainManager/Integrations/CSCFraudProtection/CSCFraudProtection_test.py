import pytest
import json
from CSCFraudProtection import (
    Client,
    fetchthephishkitdatawithticketid_command,
    listtakedowneventswithfilters_command,
    getlistofbrands_command,
    getlistoffraudtypes_command,
    retrievelistofdetectionswithinspecifiedtimeframe_command,
    getfilteredlistofmonitoringresultsspecifiedtime_command,
    getlistofmonitoringresultsspecifiedtime_command,
    fetchthescreenshotdatawithticketid_command,
    gethtmlsourcecodeforaticket_command,
    listofworklogsforticketid_command,
    updatetheactionwithticketid_command,
    retrievephishkitwitheventid_command,
    startorstopmonitoringforaspecificevent_command,
    listtakedownevents_command,
    retrieveeventscreenshotwitheventid_command,
    performanactiononasingletarget_command,
    controldetectionflowbyeventidandaction_command,
)

SERVER_URL = "https://test_url.com"  # pragma: allowlist secret


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(server_url=SERVER_URL, verify=None, proxy=None, headers=None, auth=None)


def test_fetchthephishkitdatawithticketid_command(client, requests_mock):
    args = {"ticketId": "123"}
    mock_response = util_load_json("./test_data/fetchthephishkitdatawithticketid_request.json")
    mock_results = util_load_json("./test_data/fetchthephishkitdatawithticketid_command.json")

    requests_mock.get(f"{SERVER_URL}/takedowns/{args['ticketId']}/phishkit", json=mock_response)
    results = fetchthephishkitdatawithticketid_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_fetchthescreenshotdatawithticketid_command(client, requests_mock):
    args = {"ticketId": "123"}
    mock_response = util_load_json("./test_data/fetchthescreenshotdatawithticketid_request.json")
    mock_results = util_load_json("./test_data/fetchthescreenshotdatawithticketid_command.json")

    requests_mock.get(f"{SERVER_URL}/takedowns/{args['ticketId']}/screenshot", json=mock_response)
    results = fetchthescreenshotdatawithticketid_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_gethtmlsourcecodeforaticket_command(client, requests_mock):
    args = {"ticketId": "123"}
    mock_response = util_load_json("./test_data/gethtmlsourcecodeforaticket_request.json")
    mock_results = util_load_json("./test_data/gethtmlsourcecodeforaticket_command.json")

    requests_mock.get(f"{SERVER_URL}/takedowns/html/{args['ticketId']}", json=mock_response)
    results = gethtmlsourcecodeforaticket_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_listofworklogsforticketid_command(client, requests_mock):
    args = {"ticketId": "123"}
    mock_response = util_load_json("./test_data/listofworklogsforticketid_request.json")
    mock_results = util_load_json("./test_data/listofworklogsforticketid_command.json")

    requests_mock.get(f"{SERVER_URL}/takedowns/{args['ticketId']}/worklogs", json=mock_response)
    results = listofworklogsforticketid_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_listtakedowneventswithfilters_command(client, requests_mock):
    args = {"fromDate": "2026-01-01", "toDate": "2026-03-01", "page": 1, "limit": 101}
    mock_response = util_load_json("./test_data/listtakedowneventswithfilters_request.json")
    mock_results = util_load_json("./test_data/listtakedowneventswithfilters_command.json")

    requests_mock.get(f"{SERVER_URL}/takedowns/filtered-list", json=mock_response)
    results = listtakedowneventswithfilters_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_updatetheactionwithticketid_command(client, requests_mock):
    args = {"action": "OPEN"}
    mock_response = util_load_json("test_data/updatetheactionforticketid_request.json")
    mock_results = util_load_json("test_data/updatetheactionforticketid_command.json")

    requests_mock.put(f"{SERVER_URL}/takedowns/control", json=mock_response)
    results = updatetheactionwithticketid_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_retrievephishkitwitheventid_command(client, requests_mock):
    args = {"eventId": "123"}
    mock_response = util_load_json("test_data/retrievephishkitwitheventid_request.json")
    mock_results = util_load_json("test_data/retrievephishkitwitheventid_command.json")

    requests_mock.get(f"{SERVER_URL}/detections/{args['eventId']}/phishkit", json=mock_response)
    results = retrievephishkitwitheventid_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_getlistofbrands_command(client, requests_mock):
    mock_response = util_load_json("./test_data/getlistofbrands_request.json")
    mock_results = util_load_json("./test_data/getlistofbrands_command.json")

    requests_mock.get(f"{SERVER_URL}/brands", json=mock_response)
    results = getlistofbrands_command(client, {})

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_getlistoffraudtypes_command(client, requests_mock):
    mock_response = util_load_json("./test_data/getlistoffraudtypes_request.json")
    mock_results = util_load_json("./test_data/getlistoffraudtypes_command.json")

    requests_mock.get(f"{SERVER_URL}/fraud-types", json=mock_response)
    results = getlistoffraudtypes_command(client, {})

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_retrievelistofdetectionswithinspecifiedtimeframe_command(client, requests_mock):
    args = {"fromDate": "2026-01-01", "toDate": "2026-03-01"}
    mock_response = util_load_json("./test_data/retrievelistofdetectionswithinspecifiedtimeframe_request.json")
    mock_results = util_load_json("./test_data/retrievelistofdetectionswithinspecifiedtimeframe_command.json")

    requests_mock.get(f"{SERVER_URL}/detections/list", json=mock_response)
    results = retrievelistofdetectionswithinspecifiedtimeframe_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_getfilteredlistofmonitoringresultsspecifiedtime_command(client, requests_mock):
    args = {"fromDate": "2026-01-01", "toDate": "2026-03-01", "brand": "BrandA", "fraudType": "FraudTypeA"}
    mock_response = util_load_json("./test_data/getfilteredlistofmonitoringresultsspecifiedtime_request.json")
    mock_results = util_load_json("./test_data/getfilteredlistofmonitoringresultsspecifiedtime_command.json")

    requests_mock.get(f"{SERVER_URL}/monitoring/filtered-list", json=mock_response)
    results = getfilteredlistofmonitoringresultsspecifiedtime_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_getlistofmonitoringresultsspecifiedtime_command(client, requests_mock):
    args = {"fromDate": "2026-01-01", "toDate": "2026-03-01"}
    mock_response = util_load_json("./test_data/getlistofmonitoringresultsspecifiedtime_request.json")
    mock_results = util_load_json("./test_data/getlistofmonitoringresultsspecifiedtime_command.json")

    requests_mock.get(f"{SERVER_URL}/monitoring/list", json=mock_response)
    results = getlistofmonitoringresultsspecifiedtime_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_controldetectionflowbyeventidandaction_command(client, requests_mock):
    args = {"action": "OPEN"}
    mock_response = util_load_json("./test_data/controldetectionflowbyeventidandaction_request.json")
    mock_results = util_load_json("./test_data/controldetectionflowbyeventidandaction_command.json")

    requests_mock.put(f"{SERVER_URL}/detections/control", json=mock_response)
    results = controldetectionflowbyeventidandaction_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_retrieveeventscreenshotwitheventid_command(client, requests_mock):
    args = {"eventId": "123"}
    mock_response = util_load_json("./test_data/retrieveeventscreenshotwitheventid_request.json")
    mock_results = util_load_json("./test_data/retrieveeventscreenshotwitheventid_command.json")

    requests_mock.get(f"{SERVER_URL}/detections/{args['eventId']}/screenshot", json=mock_response)
    results = retrieveeventscreenshotwitheventid_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_performanactiononasingletarget_command(client, requests_mock):
    args = {"eventId": "123"}
    mock_response = util_load_json("./test_data/performanactiononasingletarget_request.json")
    mock_results = util_load_json("./test_data/performanactiononasingletarget_command.json")

    requests_mock.post(f"{SERVER_URL}/actions/addone", json=mock_response)
    results = performanactiononasingletarget_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_gethtmlsourcecodeforaticketid_command(client, requests_mock):
    args = {"ticketId": "123"}
    mock_response = util_load_json("./test_data/gethtmlsourcecodeforaticket_request.json")
    mock_results = util_load_json("./test_data/gethtmlsourcecodeforaticket_command.json")

    requests_mock.get(f"{SERVER_URL}/takedowns/html/{args['ticketId']}", json=mock_response)
    results = gethtmlsourcecodeforaticket_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_updatetheactionforticketid_command(client, requests_mock):
    args = {"ticketId": "123", "action": "OPEN"}
    mock_response = util_load_json("./test_data/updatetheactionforticketid_request.json")
    mock_results = util_load_json("./test_data/updatetheactionforticketid_command.json")

    requests_mock.put(f"{SERVER_URL}/takedowns/control", json=mock_response)
    results = updatetheactionwithticketid_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_startorstopmonitoringforaspecificevent_command(client, requests_mock):
    args = {"eventId": "123", "action": "START"}
    mock_response = util_load_json("./test_data/startorstopmonitoringforaspecificevent_request.json")
    mock_results = util_load_json("./test_data/startorstopmonitoringforaspecificevent_command.json")

    requests_mock.put(f"{SERVER_URL}/monitoring/control", json=mock_response)
    results = startorstopmonitoringforaspecificevent_command(client, args)

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]


def test_listtakedownevents_command(client, requests_mock):
    mock_response = util_load_json("./test_data/listtakedownevents_request.json")
    mock_results = util_load_json("./test_data/listtakedownevents_command.json")

    requests_mock.get(f"{SERVER_URL}/takedowns/list", json=mock_response)
    results = listtakedownevents_command(client, {})

    assert results.outputs_prefix == "CSCFraudProtection"
    assert results.raw_response == mock_results["CSCFraudProtection"]

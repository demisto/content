import json
import os

import pytest
from unittest import mock
from CommonServerPython import DemistoException
from SolarWinds import BASE_URL

SERVER_DOMAIN = "dummy.server"
PORT_DOMAIN = "1111"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    """Fixture for client class"""
    from SolarWinds import Client

    return Client(SERVER_DOMAIN, PORT_DOMAIN, False, False, {"identifier": "dummy_username", "password": "dummy_password"})


def test_test_module_success(client, requests_mock):
    """Test for successful execution of test_module function"""
    from SolarWinds import test_module

    requests_mock.get(BASE_URL.format(SERVER_DOMAIN, PORT_DOMAIN) + "/Query", json={"results": []}, status_code=200)
    assert test_module(client, {}) == "ok"


def test_test_module_authentication_failure(client, requests_mock):
    """Test for authentication failure case of test_module function"""
    from SolarWinds import test_module

    requests_mock.get(BASE_URL.format(SERVER_DOMAIN, PORT_DOMAIN) + "/Query", json={"results": []}, status_code=403)
    with pytest.raises(DemistoException):
        test_module(client, {})


@pytest.mark.parametrize(
    "args", [{"page": 1, "limit": 5, "sort_order": "ascending"}, {"page": 1, "limit": 5, "sort_order": "descending"}]
)
def test_validate_common_arguments_success(args):
    """Test cases for success scenarios of validate_common_arguments function"""
    from SolarWinds import validate_common_arguments

    validate_common_arguments(args)


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"page": -1}, "PAGE"),
        ({"page": None}, "PAGE"),
        ({"limit": 0}, "LIMIT"),
        ({"limit": None}, "LIMIT"),
        ({"sort_order": "dummy"}, "SORT_ORDER"),
    ],
)
def test_validate_common_arguments_failure_negative_and_zero(args, error_msg):
    """Test cases for failure scenarios of validate_common_arguments function"""
    from SolarWinds import validate_common_arguments, ERR_MSG

    with pytest.raises(ValueError, match=ERR_MSG[error_msg]):
        validate_common_arguments(args)


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"page": "dummy"}, "PAGE"),
        ({"limit": "dummy"}, "LIMIT"),
    ],
)
def test_validate_common_arguments_failure_string_arg(args, error_msg):
    """Test cases for failure scenarios of validate_common_arguments function"""
    from SolarWinds import validate_common_arguments

    with pytest.raises(ValueError):
        validate_common_arguments(args)


@pytest.mark.parametrize(
    "args,query",
    [
        ({}, " ORDER BY EventID ASC WITH ROWS 1 TO 50"),
        ({"page": 5, "limit": 4}, " ORDER BY EventID ASC WITH ROWS 21 TO 24"),
        ({"sort_key": "EventTime"}, " ORDER BY EventTime ASC WITH ROWS 1 TO 50"),
        ({"acknowledged": "True"}, " WHERE Acknowledged = True ORDER BY EventID ASC WITH ROWS 1 TO 50"),
        ({"event_type": "warning"}, " WHERE ( EventTypeName = 'warning' ) ORDER BY EventID ASC WITH ROWS 1 TO 50"),
        (
            {"event_type": "warning,node up"},
            " WHERE ( EventTypeName = 'warning' OR EventTypeName = 'node up' ) ORDER BY EventID ASC WITH ROWS 1 TO 50",
        ),
        ({"node": "temporary"}, " WHERE ( Node = 'temporary' ) ORDER BY EventID ASC WITH ROWS 1 TO 50"),
        ({"node": "temporary,dummy"}, " WHERE ( Node = 'temporary' OR Node = 'dummy' ) ORDER BY EventID ASC WITH ROWS 1 TO 50"),
        (
            {"acknowledged": "True", "event_type": "warning"},
            " WHERE Acknowledged = True AND ( EventTypeName = 'warning' ) ORDER BY EventID ASC WITH ROWS 1 TO 50",
        ),
        (
            {"node": "temporary", "event_type": "warning"},
            " WHERE ( EventTypeName = 'warning' ) AND ( Node = 'temporary' ) ORDER BY EventID ASC WITH ROWS 1 TO 50",
        ),
        ({"event_id": "1, 2"}, " WHERE ( EventID = 1 OR EventID = 2 ) ORDER BY " "EventID ASC WITH ROWS 1 TO 50"),
    ],
)
def test_validate_and_prepare_query_for_event_list_success(args, query):
    """Test cases for success scenarios of validate_and_prepare_query_for_event_list function"""
    from SolarWinds import validate_and_prepare_query_for_event_list, QUERY_PARAM

    expected_query = QUERY_PARAM["GET_EVENTS"] + query
    response_query = validate_and_prepare_query_for_event_list(args)
    assert expected_query == response_query


@pytest.mark.parametrize("args,error_msg", [({"event_id": ", "}, "ID_ERROR"), ({"event_id": "1, "}, "ID_ERROR")])
def test_validate_and_prepare_query_for_event_list_failure(args, error_msg):
    """Test cases for failure scenarios of validate_and_prepare_query_for_event_list function"""
    from SolarWinds import validate_and_prepare_query_for_event_list, ERR_MSG

    with pytest.raises(ValueError, match=ERR_MSG[error_msg].format("event_id")):
        validate_and_prepare_query_for_event_list(args)


def test_convert_events_outputs_to_hr():
    """Test case for convert_events_outputs_to_hr function"""
    from SolarWinds import convert_events_outputs_to_hr

    expected_response = util_load_json("test_data/test_swis_event_list_success.json")
    hr_response = convert_events_outputs_to_hr(expected_response["outputs"])
    assert hr_response == expected_response["readable"]


def test_convert_events_outputs_to_hr_no_events():
    """Test case of convert_events_outputs_to_hr function for no events in response from api"""
    from SolarWinds import convert_events_outputs_to_hr, ERR_MSG

    hr_response = convert_events_outputs_to_hr([])
    assert hr_response == ERR_MSG["NO_RECORDS_FOUND"].format("event(s)")


@mock.patch("SolarWinds.Client.http_request")
def test_swis_event_list_success(http_request, client):
    """Test case for success scenarios of swis-event-list command"""
    from SolarWinds import swis_event_list_command

    expected_response = util_load_json("test_data/test_swis_event_list_success.json")
    http_request.return_value = expected_response["http_mock"]
    response = swis_event_list_command(client, {})
    assert response.outputs == expected_response["outputs"]
    assert response.readable_output == expected_response["readable"]


@mock.patch("SolarWinds.Client.http_request")
def test_swis_event_list_no_data(http_request, client):
    """Test case for no data found in response of swis-event-list command"""
    from SolarWinds import swis_event_list_command, ERR_MSG

    http_request.return_value = {"results": []}
    response = swis_event_list_command(client, {})
    assert response.readable_output == ERR_MSG["NO_RECORDS_FOUND"].format("event(s)")
    assert response.outputs == []


@mock.patch("SolarWinds.Client.http_request")
def test_swis_event_list_failure(client):
    """Test case for failure scenarios of swis-event-list command"""
    from SolarWinds import swis_event_list_command, ERR_MSG

    with pytest.raises(ValueError, match=ERR_MSG["ACKNOWLEDGED"]):
        swis_event_list_command(client, {"acknowledged": "dummy"})


@pytest.mark.parametrize(
    "args,query",
    [
        ({}, " ORDER BY AlertActiveID ASC WITH ROWS 1 TO 50"),
        ({"page": 5, "limit": 4}, " ORDER BY AlertActiveID ASC WITH ROWS 21 TO 24"),
        ({"sort_key": "AlertID"}, " ORDER BY AlertID ASC WITH ROWS 1 TO 50"),
        ({"type": "Node"}, " WHERE ( ObjectType = 'Node' ) ORDER BY AlertActiveID ASC WITH ROWS 1 TO 50"),
        ({"severity": "Notice"}, " WHERE ( Severity = 4 ) ORDER BY AlertActiveID ASC WITH ROWS 1 TO 50"),
        (
            {"alert_id": "1, 2"},
            " WHERE ( AlertActiveID = 1 OR AlertActiveID = 2 ) ORDER BY " "AlertActiveID ASC WITH ROWS 1 TO 50",
        ),
    ],
)
def test_validate_and_prepare_query_for_alert_list_success(args, query):
    """Test cases for success scenarios of validate_and_prepare_query_for_alert_list function"""
    from SolarWinds import validate_and_prepare_query_for_list_alerts, QUERY_PARAM

    expected_query = QUERY_PARAM["LIST_ALERTS"] + query
    response_query = validate_and_prepare_query_for_list_alerts(args)
    assert expected_query == response_query


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"alert_id": ", "}, "ID_ERROR"),
        ({"alert_id": "1, "}, "ID_ERROR"),
    ],
)
def test_validate_and_prepare_query_for_alert_list_failure(args, error_msg):
    """Test cases for failure scenarios of validate_and_prepare_query_for_event_list function"""
    from SolarWinds import validate_and_prepare_query_for_list_alerts, ERR_MSG

    with pytest.raises(ValueError, match=ERR_MSG[error_msg].format("alert_id")):
        validate_and_prepare_query_for_list_alerts(args)


def test_convert_alerts_outputs_to_hr():
    """Test case for convert_alerts_outputs_to_hr function"""
    from SolarWinds import convert_alerts_outputs_to_hr

    with open("test_data/test_swis_alert_list_success_context.json") as data:
        expected_res = json.load(data)

    with open("test_data/test_swis_alert_list_success.md") as data:
        expected_hr = data.read()
    hr_response = convert_alerts_outputs_to_hr(expected_res)
    assert hr_response == expected_hr


def test_convert_alerts_outputs_to_hr_no_alerts():
    """Test case of convert_alerts_outputs_to_hr function for no alerts in response from api"""
    from SolarWinds import convert_alerts_outputs_to_hr, ERR_MSG

    hr_response = convert_alerts_outputs_to_hr([])
    assert hr_response == ERR_MSG["NO_RECORDS_FOUND"].format("alert(s)")


@mock.patch("SolarWinds.Client.http_request")
def test_swis_alert_list_success(http_request, client):
    """Test case for success scenarios of swis-alert-list command"""
    from SolarWinds import swis_alert_list_command

    with open("test_data/swis_alert_list_raw_response.json") as data:
        mock_response = json.load(data)

    with open("test_data/test_swis_alert_list_success_context.json") as data:
        expected_res = json.load(data)

    with open("test_data/test_swis_alert_list_success.md") as data:
        expected_hr = data.read()

    http_request.return_value = mock_response
    response = swis_alert_list_command(client, {})
    assert response.outputs == expected_res
    assert response.readable_output == expected_hr


@mock.patch("SolarWinds.Client.http_request")
def test_swis_alert_list_no_data(http_request, client):
    """Test case for no data found in response of swis-alert-list command"""
    from SolarWinds import swis_alert_list_command, ERR_MSG

    http_request.return_value = {"results": []}
    response = swis_alert_list_command(client, {})
    assert response.readable_output == ERR_MSG["NO_RECORDS_FOUND"].format("alert(s)")
    assert response.outputs == []


@mock.patch("SolarWinds.Client.http_request")
def test_swis_alert_list_failure(client):
    """Test case for failure scenarios of swis-alert-list command"""
    from SolarWinds import swis_alert_list_command, ERR_MSG, SEVERITIES_MAP

    expected_output = ERR_MSG["SEVERITIES_ERROR"].format(SEVERITIES_MAP)
    with pytest.raises(ValueError) as err:
        _ = swis_alert_list_command(client, {"severity": "dummy"})
    assert str(err.value) == expected_output


def test_convert_query_output_to_hr_success():
    from SolarWinds import convert_query_output_to_hr

    expected_response = util_load_json(os.path.join(os.path.dirname(__file__), "test_data", "test_swis_query_success" ".json"))
    hr_response = convert_query_output_to_hr(expected_response.get("http_mock").get("results"))
    assert hr_response == expected_response.get("readable")


def test_convert_query_output_to_hr_no_data():
    from SolarWinds import convert_query_output_to_hr, ERR_MSG

    hr_response = convert_query_output_to_hr([])
    assert hr_response == ERR_MSG["NO_RECORDS_FOUND"].format("record(s)")


@pytest.mark.parametrize(
    "args",
    [
        (
            {
                "query": "SELECT NodeID, ObjectSubType, IPAddress, IPAddressType, DynamicIP, Caption, NodeDescription, "
                "Description,FROM Orion.Nodes"
            }
        ),
    ],
)
@mock.patch("SolarWinds.Client.http_request")
def test_swis_query_success(http_request, client, args):
    from SolarWinds import swis_query_command

    expected_response = util_load_json(os.path.join(os.path.dirname(__file__), "test_data", "test_swis_query_success" ".json"))
    http_request.return_value = expected_response["http_mock"]
    response = swis_query_command(client, args)
    assert response.outputs == expected_response.get("http_mock").get("results")


@pytest.mark.parametrize(
    "args",
    [
        ({"query": "SELECT TOP 2 EngineID, AlertID, Name FROM Orion.Alerts"}),
    ],
)
@mock.patch("SolarWinds.Client.http_request")
def test_swis_query_failure_no_data(http_request, client, args):
    from SolarWinds import swis_query_command, ERR_MSG

    http_request.return_value = {"results": []}
    response = swis_query_command(client, args)
    assert response.readable_output == ERR_MSG["NO_RECORDS_FOUND"].format("record(s)")
    assert response.outputs == []


@pytest.mark.parametrize(
    "args",
    [
        ({"query": ""}),
    ],
)
@mock.patch("SolarWinds.Client.http_request")
def test_swis_query_failure_no_query_argument(client, args):
    from SolarWinds import swis_query_command, ERR_MSG

    with pytest.raises(ValueError, match=ERR_MSG["REQUIRED_ARGUMENT"]):
        swis_query_command(client, args)


@mock.patch("SolarWinds.Client.http_request")
def test_fetch_incidents_alerts_success(http_request, client):
    from SolarWinds import fetch_incidents

    expected_response = util_load_json(os.path.join(os.path.dirname(__file__), "test_data", "test_fetch_incidents" ".json"))[
        "alerts"
    ]
    params = {
        "fetch_type": "Alert",
        "max_fetch": "5",
        "first_fetch": "2 days ago",
        "severities": ["CRITICAL"],
        "object_types": ["Node"],
    }
    raw_response = util_load_json(
        os.path.join(os.path.dirname(__file__), "test_data", "test_fetch_incidents_raw_response" ".json")
    )["alerts"]
    http_request.return_value = raw_response

    _, incidents = fetch_incidents(client, {}, params, is_test=False)

    assert incidents == expected_response["incidents"]


@mock.patch("SolarWinds.Client.http_request")
def test_fetch_incidents_events_success(http_request, client):
    from SolarWinds import fetch_incidents

    expected_response = util_load_json(os.path.join(os.path.dirname(__file__), "test_data", "test_fetch_incidents" ".json"))[
        "events"
    ]
    params = {"fetch_type": "Event", "max_fetch": "5", "first_fetch": "2 days ago", "event_types": ["Alert Triggered"]}
    raw_response = util_load_json(
        os.path.join(os.path.dirname(__file__), "test_data", "test_fetch_incidents_raw_response" ".json")
    )["events"]
    http_request.return_value = raw_response

    _, incidents = fetch_incidents(client, {}, params, is_test=False)

    assert incidents == expected_response["incidents"]


@pytest.mark.parametrize(
    "args",
    [
        {"max_fetch": "5", "first_fetch": "2 days ago", "severities": ["Critical"]},
        {"max_fetch": "999", "first_fetch": "2021/04/09", "severities": ["Critical", "Notice"]},
    ],
)
def test_validate_fetch_incidents_parameters_success(args):
    """Test cases for success scenarios of validate_fetch_incidents_parameters_success"""
    from SolarWinds import validate_fetch_incidents_parameters

    validate_fetch_incidents_parameters(args)


@pytest.mark.parametrize(
    "args, message",
    [
        ({"max_fetch": "3", "first_fetch": "2 days ago", "severities": ["new"]}, "SEVERITIES_ERROR"),
    ],
)
def test_validate_fetch_incidents_parameters_severity(args, message):
    """Test cases for failure scenarios of validate_fetch_incidents_parameters_success"""
    from SolarWinds import validate_fetch_incidents_parameters, ERR_MSG, SEVERITIES_MAP

    with pytest.raises(ValueError) as e:
        validate_fetch_incidents_parameters(args)
    assert str(e.value) == ERR_MSG[message].format(SEVERITIES_MAP)


@pytest.mark.parametrize(
    "args, message",
    [
        ({"max_fetch": "-1"}, "INVALID_MAX_FETCH"),
        ({"max_fetch": "1500"}, "INVALID_MAX_FETCH"),
    ],
)
def test_validate_fetch_incidents_parameters_maxfetch(args, message):
    """Test cases for failure scenarios of validate_fetch_incidents_parameters_success"""
    from SolarWinds import validate_fetch_incidents_parameters, ERR_MSG

    with pytest.raises(ValueError, match=ERR_MSG[message]):
        validate_fetch_incidents_parameters(args)

import asyncio
import json
from http import HTTPStatus
from unittest.mock import MagicMock

import pytest
from CommonServerPython import *

# import demistomock as demisto
from fastapi import Request
from fastapi.testclient import TestClient
from GenericWebhook import (
    MAX_FOUND_IDS,
    app,
    filter_duplicate_incidents,
    get_duplication_keys,
    get_mirroring,
    main,
    parse_incidents,
)


@pytest.fixture
def client():
    return TestClient(app)


def test_handle_post_single_incident(mocker, client):
    """
    Given: A bodu that is one incident
    When: Sending a post request
    Then: The body is parsed properly
    """
    incident_data = {
        "name": "Test Incident",
        "type": "Test Type",
        "occurred": "2024-03-17T12:00:00Z",
        "rawJson": {"key": "value"},
    }
    return_incidents = [{"name": "something"}]

    create_incidents = mocker.patch.object(demisto, "createIncidents", return_value=return_incidents)
    response = client.post("/", json=incident_data)

    called_arg = create_incidents.call_args_list[0].args[0]
    assert isinstance(called_arg, list)
    assert len(called_arg) == 1
    assert response.status_code == HTTPStatus.OK
    assert response.json() == return_incidents


def test_handle_post_multiple_incident(mocker, client):
    """
    Given: A bodu that is an array of incidents
    When: Sending a post request
    Then: The body is parsed properly
    """
    incident_data = [
        {"name": "Test Incident", "type": "Test Type", "occurred": "2024-03-17T12:00:00Z", "raw_json": {"key": "value"}},
        {"name": "Test Incident2", "type": "Test Type", "occurred": "2024-03-17T12:00:00Z", "raw_json": {"key": "value"}},
    ]
    return_incidents = [{"name": "something"}]

    create_incidents = mocker.patch.object(demisto, "createIncidents", return_value=return_incidents)
    response = client.post("/", json=incident_data)

    called_arg = create_incidents.call_args_list[0].args[0]
    assert isinstance(called_arg, list)
    assert len(called_arg) == 2
    assert response.status_code == HTTPStatus.OK
    assert response.json() == return_incidents


def test_handle_post_with_invalid_credentials(mocker, client):
    """
    Given: a server that expects a user and password
    When: Calling post with bad credentials
    Then:a 401 response code is recieved
    """
    mocker.patch.object(demisto, "params", return_value={"credentials": {"identifier": "user", "password": "pass"}})
    response = client.post("/", json=[{"name": "Test Incident"}], auth=("invalid_username", "invalid_password"))
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.text == "Authorization failed."


def test_handle_post_with_valid_credentials(mocker, client):
    """
    Given: a server that expects a user and password
    When: Calling post with proper credentials
    Then:a 200 response code is recieved
    """
    mocker.patch.object(demisto, "params", return_value={"credentials": {"identifier": "user", "password": "pass"}})
    response = client.post("/", json=[{"name": "Test Incident"}], auth=("user", "pass"))
    assert response.status_code == HTTPStatus.OK
    assert response.text == "[]"


def test_handle_post_with_missing_data(mocker, client):
    """
    Given: A request with no body
    When: Post is called
    Then: A readable error message is returned
    """
    mocker.patch.object(demisto, "error")
    response = client.post("/")
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "Request, and rawJson field if exists must be in JSON format" in response.text


def test_handle_post_with_invalid_json(mocker, client):
    """
    Given: A request with a bad body
    When: Post is called
    Then: A readable error message is returned
    """
    mocker.patch.object(demisto, "error")
    response = client.post("/", data="invalid_json")
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "Request, and rawJson field if exists must be in JSON format" in response.text


@pytest.mark.parametrize(
    "body",
    [
        {"name": "Test Incident 1", "type": "Test Type 1", "occurred": "2024-03-17T12:00:00Z", "rawJson": {"key": "value"}},
        {"name": "Test Incident 1", "type": "Test Type 1", "occurred": "2024-03-17T12:00:00Z", "key": "value"},
        {"name": "Test Incident 1", "type": "Test Type 1", "occurred": "2024-03-17T12:00:00Z", "raw_json": {"key": "value"}},
    ],
)
def test_parse_request(body):
    """
    Given: two inputs, either with raw_json being real json or a string representation of json
    When: calling parse_body
    Then: The body is parsed the same
    """
    # Prepare a mock Request object with JSON data
    mock_request = MagicMock(spec=Request)

    async def mockbody():
        return body

    mock_request.json = mockbody

    # Call the parse_incidents function with the mock Request
    result = asyncio.run(parse_incidents(mock_request))

    # Check if the function returns a list of dictionaries with the parsed incidents
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["name"] == "Test Incident 1"
    assert result[0]["type"] == "Test Type 1"
    assert result[0]["occurred"] == "2024-03-17T12:00:00Z"
    assert result[0]["rawJson"]["key"] == "value"


@pytest.mark.parametrize(
    "params, expected",
    [
        (
            {"mirror_direction": "Incoming", "mirror_tags": "tag1", "mirror_instance": "inst1"},
            {"mirror_direction": "In", "mirror_tags": "tag1", "mirror_instance": "inst1"},
        ),
        (
            {"mirror_direction": "Outgoing", "mirror_tags": "", "mirror_instance": ""},
            {"mirror_direction": "Out", "mirror_tags": "", "mirror_instance": ""},
        ),
        (
            {"mirror_direction": "None", "mirror_tags": "", "mirror_instance": ""},
            {"mirror_direction": None, "mirror_tags": "", "mirror_instance": ""},
        ),
        (
            {},
            {"mirror_direction": None, "mirror_tags": "", "mirror_instance": ""},
        ),
    ],
)
def test_get_mirroring(mocker, params, expected):
    """
    Given: Various mirror_direction param values
    When: get_mirroring is called
    Then: The correct mirror dict is returned
    """
    mocker.patch.object(demisto, "params", return_value=params)
    assert get_mirroring() == expected


@pytest.mark.parametrize(
    "params, expected",
    [
        ({"duplication_key": "incidentId,alertId"}, ["incidentId", "alertId"]),
        ({"duplication_key": "singleKey"}, ["singleKey"]),
        ({"duplication_key": ""}, []),
        ({}, []),
    ],
)
def test_get_duplication_keys(mocker, params, expected):
    """
    Given: Various duplication_key param values
    When: get_duplication_keys is called
    Then: The correct list of keys is returned
    """
    mocker.patch.object(demisto, "params", return_value=params)
    assert get_duplication_keys() == expected


def test_filter_duplicate_incidents_no_duplicates(mocker):
    """
    Given: Incidents with no previously seen IDs
    When: filter_duplicate_incidents is called
    Then: All incidents pass through and context is updated
    """
    mocker.patch.object(demisto, "get", side_effect=lambda obj, key: obj.get(key))
    incidents = [
        {"rawJson": {"incidentId": "1"}},
        {"rawJson": {"incidentId": "2"}},
    ]
    context: dict = {}
    result = filter_duplicate_incidents(incidents, ["incidentId"], {}, context)
    assert len(result) == 2
    assert set(context["found_ids"]) == {"incidentId:1", "incidentId:2"}


def test_filter_duplicate_incidents_with_duplicates(mocker):
    """
    Given: Incidents where one ID was already seen
    When: filter_duplicate_incidents is called
    Then: The duplicate is filtered out
    """
    mocker.patch.object(demisto, "get", side_effect=lambda obj, key: obj.get(key))
    mocker.patch.object(demisto, "debug")
    integration_context = {"found_ids": '["incidentId:1"]'}
    incidents = [
        {"rawJson": {"incidentId": "1"}},
        {"rawJson": {"incidentId": "2"}},
    ]
    context: dict = {}
    result = filter_duplicate_incidents(incidents, ["incidentId"], integration_context, context)
    assert len(result) == 1
    assert result[0]["rawJson"]["incidentId"] == "2"


def test_filter_duplicate_incidents_no_matching_key(mocker):
    """
    Given: Incidents whose rawJson does not contain any duplication key
    When: filter_duplicate_incidents is called
    Then: All incidents pass through (no composite key means no dedup)
    """
    mocker.patch.object(demisto, "get", side_effect=lambda obj, key: obj.get(key))
    incidents = [
        {"rawJson": {"other": "x"}},
        {"rawJson": {"other": "y"}},
    ]
    context: dict = {}
    result = filter_duplicate_incidents(incidents, ["incidentId"], {}, context)
    assert len(result) == 2
    assert "found_ids" not in context


def test_main_test_module(mocker):
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "params", return_value={"longRunningPort": "444"})
    results = mocker.patch.object(demisto, "results")
    main()
    assert results.call_args_list[0].args[0] == "ok"


def test_main_long_running(mocker):
    """
    We have an autorecovery mechanism here that when the app fails with an exception it should be restarted five seconds later
    """
    mocker.patch.object(demisto, "error")

    mocker.patch.object(demisto, "command", return_value="long-running-execution")
    mocker.patch.object(
        demisto, "params", return_value={"longRunningPort": "444", "certificate": "something", "key": "something"}
    )
    mocker.patch.object(demisto, "results")
    mocker.patch("time.sleep")
    uvicornmock = MagicMock(side_effect=[Exception("restart once"), Exception("Twice"), BaseException("Hack to get out")])
    mocker.patch("uvicorn.run", uvicornmock)
    try:
        main()
        raise AssertionError
    except BaseException:
        """ This is kind of a hack to stop the while true loop"""

    assert len(uvicornmock.call_args_list) == 3


def test_filter_duplicate_incidents_found_ids_limit(mocker):
    """
    Given: An integration context already holding MAX_FOUND_IDS entries
    When: filter_duplicate_incidents is called with new incidents
    Then: found_ids in context does not exceed MAX_FOUND_IDS (oldest entries are evicted)
    """
    mocker.patch.object(demisto, "get", side_effect=lambda obj, key: obj.get(key))

    existing_ids = [f"incidentId:{i}" for i in range(MAX_FOUND_IDS)]
    integration_context = {"found_ids": json.dumps(existing_ids)}

    new_incidents = [{"rawJson": {"incidentId": f"{MAX_FOUND_IDS + j}"}} for j in range(10)]
    context: dict = {}
    result = filter_duplicate_incidents(new_incidents, ["incidentId"], integration_context, context)

    assert len(result) == 10
    assert len(context["found_ids"]) == MAX_FOUND_IDS
    # newest entries must be present; last 10 of parsed_ids are evicted (tail of new_ids + parsed_ids slice)
    for j in range(10):
        assert f"incidentId:{MAX_FOUND_IDS + j}" in context["found_ids"]
    for i in range(MAX_FOUND_IDS - 10, MAX_FOUND_IDS):
        assert f"incidentId:{i}" not in context["found_ids"]


def test_filter_duplicate_incidents_found_ids_within_limit(mocker):
    """
    Given: An integration context with fewer than MAX_FOUND_IDS entries
    When: filter_duplicate_incidents is called with new incidents that keep the total under the limit
    Then: all entries are preserved and found_ids grows by the number of new incidents
    """
    mocker.patch.object(demisto, "get", side_effect=lambda obj, key: obj.get(key))

    existing_ids = [f"incidentId:{i}" for i in range(100)]
    integration_context = {"found_ids": json.dumps(existing_ids)}

    new_incidents = [{"rawJson": {"incidentId": f"{100 + j}"}} for j in range(5)]
    context: dict = {}
    result = filter_duplicate_incidents(new_incidents, ["incidentId"], integration_context, context)

    assert len(result) == 5
    assert len(context["found_ids"]) == 105

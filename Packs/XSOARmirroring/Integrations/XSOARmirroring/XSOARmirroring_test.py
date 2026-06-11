from datetime import datetime, timedelta, UTC

import dateparser
import pytest
from CommonServerPython import DemistoException, EntryType
from XSOARmirroring import (
    MODIFIED_ENDPOINT_UNSUPPORTED_DATE_KEY,
    XSOAR_DATE_FORMAT,
    Client,
    fetch_incidents,
    get_mapping_fields_command,
    get_modified_remote_data_command,
    update_remote_system_command,
    validate_and_prepare_basic_params,
)


def generate_dummy_client():
    class Client:
        def __init__(self):
            pass

        def get_incident_fields(self):
            pass

        def get_incident_types(self):
            pass

        def get_incident(self):
            pass

        def update_incident(self):
            pass

    return Client


INCIDENT_FIELDS = [
    {
        "group": 0,
        "associatedToAll": True,
        "name": "field1",
        "type": "type1",
        "description": "description1",
        "cliName": "cliName1",
        "content": False,
        "system": True,
    },
    {
        "group": 0,
        "associatedTypes": ["test"],
        "name": "field2",
        "type": "type2",
        "description": "description2",
        "cliName": "cliName2",
        "content": True,
        "system": True,
    },
]
INCIDENT_TYPES = [{"name": "Something"}, {"name": "test"}]


def test_mirroring(mocker):
    """
    Given:
        - Two incident types and fields.

    When:
        - one field is associated to all while the second is associated to one.

    Then:
        - A correct mapping dict is created, with a "Default Scheme" included
    """
    client = generate_dummy_client()
    mocker.patch.object(client, "get_incident_fields", return_value=INCIDENT_FIELDS)
    mocker.patch.object(client, "get_incident_types", return_value=INCIDENT_TYPES)
    response = get_mapping_fields_command(client).extract_mapping()
    assert len(response) == 3
    assert "Default Mapping" in str(response)
    assert response["Default Mapping"] == {"cliName1": "field1 - type1"}
    assert response["test"] == {"CustomFields": {"cliName2": "field2 - type2"}, "cliName1": "field1 - type1"}
    assert response["Something"] == {"cliName1": "field1 - type1"}


INCIDENTS = [
    {"id": 1, "created": (datetime.now() - timedelta(minutes=10)).strftime(XSOAR_DATE_FORMAT)},
    {"id": 2, "created": (datetime.now() - timedelta(minutes=8)).strftime(XSOAR_DATE_FORMAT)},
    {"id": 3, "created": (datetime.now() - timedelta(minutes=5)).strftime(XSOAR_DATE_FORMAT)},
]

INCIDENTS_IN_CONTEXT = {
    "XSOARMirror_mirror_reset": {
        4: True,
        5: True,
        6: True,
    }
}

INCIDENTS_MIRRORING_PLAYBOOK_ID = [
    {"id": 1, "created": (datetime.now() - timedelta(minutes=10)).strftime(XSOAR_DATE_FORMAT), "playbookId": "test"}
]

REMOTE_INCIDENT = {
    "id": 1,
    "created": (datetime.now() - timedelta(minutes=10)).strftime(XSOAR_DATE_FORMAT),
    "CustomFields": {"custom_field": "some_custom_field"},
}


def test_fetch_incidents(mocker):
    """
    Given:
        - List of incidents.

    When:
        - Running the fetch_incidents and getting these incidents.

    Then:
        - Ensure
            1. The incidents result and the last_fetch in the LastRun object as expected.
            2. The integration context is updated as expected.
    """
    mocker.patch.object(Client, "search_incidents", return_value=INCIDENTS)
    mock_integration_context = mocker.patch("XSOARmirroring.set_to_integration_context_with_retries")

    first_fetch = dateparser.parse("3 days").strftime(XSOAR_DATE_FORMAT)
    client = Client("")

    next_run, incidents_result = fetch_incidents(
        client=client,
        max_results=3,
        last_run={},
        last_fetch=first_fetch,
        first_fetch_time=first_fetch,
        query="",
        mirror_direction="None",
        mirror_tag=[],
        fetch_incident_history=True,
    )

    assert len(incidents_result) == 3
    assert dateparser.parse(next_run["last_fetch"]) == dateparser.parse(INCIDENTS[-1]["created"])
    assert mock_integration_context.call_args.kwargs["context"] == {"XSOARMirror_mirror_reset": {1: True, 2: True, 3: True}}


def test_fetch_incidents_with_integration_context(mocker):
    """
    Given:
        - List of incidents + List of incident IDs in context (from previous fetch).

    When:
        - Running the fetch_incidents and getting these incidents.

    Then:
        - Ensure
            1. The incidents result and the last_fetch in the LastRun object as expected.
            2. The integration context is updated as expected.
    """
    mocker.patch.object(Client, "search_incidents", return_value=INCIDENTS)
    mocker.patch("XSOARmirroring.get_integration_context", return_value=INCIDENTS_IN_CONTEXT)
    mock_integration_context = mocker.patch("XSOARmirroring.set_to_integration_context_with_retries")

    first_fetch = dateparser.parse("3 days").strftime(XSOAR_DATE_FORMAT)
    client = Client("")

    next_run, incidents_result = fetch_incidents(
        client=client,
        max_results=3,
        last_run={},
        last_fetch=first_fetch,
        first_fetch_time=first_fetch,
        query="",
        mirror_direction="None",
        mirror_tag=[],
        fetch_incident_history=True,
    )

    assert len(incidents_result) == 3
    assert dateparser.parse(next_run["last_fetch"]) == dateparser.parse(INCIDENTS[-1]["created"])
    assert mock_integration_context.call_args.kwargs["context"] == {
        "XSOARMirror_mirror_reset": {
            4: True,
            5: True,
            6: True,
            1: True,
            2: True,
            3: True,
        }
    }


@pytest.mark.parametrize("mirror_playbook_id", (True, False))
def test_fetch_incidents_mirror_playbook_id(mocker, mirror_playbook_id: bool):
    """
    Given:
        - a list of incidents.

    When:
        - Running the fetch_incidents and getting this incident, with the *implicit* default `mirror_playbook_id = True`.

    Then:
        - Ensure the incident result does not contain playbookId field if and only if `mirror_playbook_id` is False.
    """
    mocker.patch.object(Client, "search_incidents", side_effect=[INCIDENTS_MIRRORING_PLAYBOOK_ID, []])

    first_fetch = dateparser.parse("3 days").strftime(XSOAR_DATE_FORMAT)
    client = Client("dummy token")

    next_run, incidents_result = fetch_incidents(
        client=client,
        max_results=3,
        last_run={},
        first_fetch_time=first_fetch,
        last_fetch="",
        query="",
        mirror_direction="None",
        mirror_tag=[],
        mirror_playbook_id=mirror_playbook_id,
    )

    assert len(incidents_result) == 1
    assert ("playbookId" in incidents_result[0]) is mirror_playbook_id


def test_update_remote_system(mocker):
    """
    Given:
        - Old incident and fields that were changed.

    When:
        - Running the update_remote_system_command.

    Then:
        - Ensure the incident was updated.
    """
    args = {"incidentChanged": True, "remoteId": 1, "delta": {"custom_field": "updated_field"}}
    client = generate_dummy_client()
    mocker.patch.object(client, "get_incident", return_value=REMOTE_INCIDENT)
    result = mocker.patch.object(client, "update_incident")
    update_remote_system_command(client, args, {})
    assert result.call_args.kwargs["incident"]["CustomFields"]["custom_field"] == args["delta"]["custom_field"]


@pytest.mark.parametrize(
    "params, expected_url",
    [
        (
            {"credentials_api_key": {"identifier": "key_id", "password": "test_password"}, "url": "https://my-example.com"},
            "https://my-example.com/xsoar",
        ),
        (
            {"credentials_api_key": {"identifier": "key_id", "password": "test_password"}, "url": "https://my-example.com/xsoar"},
            "https://my-example.com/xsoar",
        ),
        (
            {"credentials_api_key": {"identifier": "", "password": "test_password"}, "url": "https://my-example.com"},
            "https://my-example.com",
        ),
        ({"credentials_api_key": {"identifier": ""}, "url": "https://my-example.com"}, "https://my-example.com"),
    ],
)
def test_validate_and_prepare_basic_params(params, expected_url):
    """
    Given:
        Case a: parameters with API Key ID (key_id) and a URL not containing the 'xsoar' suffix.
        Case b: parameters with API Key ID (key_id) and a URL containing the 'xsoar' suffix.
        Case c: parameters with no API Key ID (key_id) and a URL not containing the 'xsoar' suffix.
        Case c: parameters with no API Key.

    Whe:
        Validating and preparing the basic params of api_key_id, api_key, base_url

    Then:
        Case a: Make sure the base url receives the 'xsoar' suffix
        Case b: Make sure the base url keeps the 'xsoar' suffix
        Case c: Make sure the base url does not receive the 'xsoar' suffix
        Case d: An exception is thrown with message of: 'API Key must be provided'
    """
    if not params.get("credentials_api_key").get("password"):
        with pytest.raises(DemistoException) as e:
            validate_and_prepare_basic_params(params)

            assert e.message == "API Key must be provided."
    else:
        _, _, full_base_url = validate_and_prepare_basic_params(params)
        assert full_base_url == expected_url


# test_dedup_incidents parametrize arguments
case_incidents_with_different_times = (
    "2023-09-26T15:13:45.000000Z",
    # responses from search_incidents
    [
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:14:45Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:15:45Z"},
            {"id": "4", "version": 8, "created": "2023-09-26T15:16:45Z"},
            {"id": "5", "version": 8, "created": "2023-09-26T15:17:45Z"},
        ],
        [],
    ],  # max fetch
    5,  # incidents_last_fetch_ids
    [],
    (
        # expected incident result
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:14:45Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:15:45Z"},
            {"id": "4", "version": 8, "created": "2023-09-26T15:16:45Z"},
            {"id": "5", "version": 8, "created": "2023-09-26T15:17:45Z"},
        ],
        # expected incidents_last_fetch_ids result
        ["5"],
        dateparser.parse("2023-09-26T15:17:45Z"),
    ),
)


case_incidents_with_the_same_times = (
    "2023-09-26T15:13:45.000000Z",
    # responses from search_incidents
    [
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "4", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "5", "version": 8, "created": "2023-09-26T15:13:45Z"},
        ],
        [],
    ],  # max fetch
    5,  # incidents_last_fetch_ids
    [],
    (
        # expected incident result
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "4", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "5", "version": 8, "created": "2023-09-26T15:13:45Z"},
        ],
        # expected incidents_last_fetch_ids result
        ["1", "2", "3", "4", "5"],
        dateparser.parse("2023-09-26T15:13:45Z"),
    ),
)


case_with_empty_response_with_incidents_last_fetch_ids = (
    "2023-09-26T15:13:41.000000Z",
    # responses from search_incidents
    [[], []],  # max fetch
    5,  # incidents_last_fetch_ids
    ["1", "2", "3", "4", "5"],
    (
        # expected incident result
        [],
        # expected incidents_last_fetch_ids result
        ["1", "2", "3", "4", "5"],
        dateparser.parse("2023-09-26T15:13:41Z"),
    ),
)


case_with_empty_response_without_incidents_last_fetch_ids = (
    "2023-09-26T15:13:41.000000Z",
    # responses from search_incidents
    [[], []],  # max fetch
    5,  # incidents_last_fetch_ids
    [],
    (
        # expected incident result
        [],
        # expected incidents_last_fetch_ids result
        [],
        dateparser.parse("2023-09-26T15:13:41Z"),
    ),
)

case_with_more_then_one_API_call_with_incidents_last_fetch_ids = (
    "2023-09-26T15:13:41.000000Z",
    # responses from search_incidents
    [
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:41Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:42Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:43Z"},
            {"id": "4", "version": 8, "created": "2023-09-26T15:13:44Z"},
            {"id": "5", "version": 8, "created": "2023-09-26T15:13:45Z"},
        ],
        [
            {"id": "5", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "6", "version": 8, "created": "2023-09-26T15:13:46Z"},
            {"id": "7", "version": 8, "created": "2023-09-26T15:13:47Z"},
            {"id": "8", "version": 8, "created": "2023-09-26T15:13:48Z"},
            {"id": "9", "version": 8, "created": "2023-09-26T15:13:49Z"},
        ],
    ],
    5,  # max fetch
    ["1"],  # incidents_last_fetch_ids
    (  # expected incident result
        [
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:42Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:43Z"},
            {"id": "4", "version": 8, "created": "2023-09-26T15:13:44Z"},
            {"id": "5", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "6", "version": 8, "created": "2023-09-26T15:13:46Z"},
        ],
        # expected incidents_last_fetch_ids result
        ["6"],
        dateparser.parse("2023-09-26T15:13:46Z"),
    ),
)

case_with_an_incident_that_was_fetched = (
    "2023-09-26T15:13:41.000000Z",
    # responses from search_incidents
    [
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:41Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:42Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:43Z"},
        ],
        [],
    ],
    5,  # max fetch
    ["1"],  # incidents_last_fetch_ids
    (
        # expected incident result
        [
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:42Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:43Z"},
        ],
        # expected incidents_last_fetch_ids result
        ["3"],
        dateparser.parse("2023-09-26T15:13:43Z"),
    ),
)


case_with_an_incident_that_was_fetched_and_there_are_more_with_the_same_time = (
    "2023-09-26T15:13:41.000000Z",
    # responses from search_incidents
    [
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:41Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:41Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:41Z"},
        ],
        [],
        dateparser.parse("2023-09-26T15:13:41Z"),
    ],
    5,  # max fetch
    ["1"],  # incidents_last_fetch_ids
    (
        # expected incident result
        [
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:41Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:41Z"},
        ],
        # expected incidents_last_fetch_ids result
        ["1", "2", "3"],
        dateparser.parse("2023-09-26T15:13:41Z"),
    ),
)

case_incidents_not_utc_time = (
    "2023-11-09T03:25:05.000000Z",
    # responses from search_incidents
    [
        [
            {"id": "1", "version": 8, "created": "2023-11-09T06:25:06.828698605+03:00"},
            {"id": "2", "version": 8, "created": "2023-11-09T06:26:06.828698605+03:00"},
        ],
        [],
    ],  # max fetch
    5,  # incidents_last_fetch_ids
    [],
    (
        # expected incident result
        [
            {"id": "1", "version": 8, "created": "2023-11-09T06:25:06.828698605+03:00"},
            {"id": "2", "version": 8, "created": "2023-11-09T06:26:06.828698605+03:00"},
        ],
        # expected incidents_last_fetch_ids result
        ["2"],
        dateparser.parse("2023-11-09T03:26:06.828698605Z"),
    ),
)


@pytest.mark.parametrize(
    "last_fetch, incident_to_return , max_fetch, incidents_last_fetch_ids, expected_result",
    [
        case_incidents_with_different_times,
        case_incidents_with_the_same_times,
        case_with_empty_response_with_incidents_last_fetch_ids,
        case_with_empty_response_without_incidents_last_fetch_ids,
        case_with_more_then_one_API_call_with_incidents_last_fetch_ids,
        case_with_an_incident_that_was_fetched,
        case_with_an_incident_that_was_fetched_and_there_are_more_with_the_same_time,
        case_incidents_not_utc_time,
    ],
)
def test_dedup_incidents_with_seconds_timestamp(
    mocker,
    last_fetch,
    incident_to_return,
    max_fetch,
    incidents_last_fetch_ids,
    expected_result,
):
    """
    Given:
        - Case 1: All incidents from the current fetch cycle have different timestamp.
        - Case 2: All incidents from the current fetch cycle have the same timestamp and were not fetched.
        - Case 3: All incidents from the previous fetch cycle were fetched. No new incidents received from API response.
        - Case 4: Empty response without incidents_last_fetch_ids provided.
        - Case 5: More than one API call received with incidents_last_fetch_ids provided.
        - Case 6: An incident that was already fetched in the previous run is received again.
        - Case 7: Incidents with equal time stamp to an incident that was already fetched were received.
    When:
        - Using the dedup mechanism while fetching incidents.
    Then:
        - Verify that the dedup mechanism correctly handles the different test cases by comparing the expected and actual results.
    """
    from XSOARmirroring import get_and_dedup_incidents

    client = Client("")
    mocker.patch.object(Client, "search_incidents", side_effect=incident_to_return)
    assert get_and_dedup_incidents(client, incidents_last_fetch_ids, "", max_fetch, last_fetch) == expected_result


def test_get_incident_entries_without_entries(mocker):
    """
    Given:
        - incident_id and date.

    When:
        - Running the get_incident_entries request.

    Then:
        - Ensure that an empty list is returned when there is no entries.
    """
    from XSOARmirroring import Client

    client = Client(base_url="https://test.com")
    mocker.patch.object(
        client,
        "_http_request",
        return_value={
            "closed": "2023-09-20T10:54:00.669862412Z",
            "closingUserId": "DBot",
            "created": "2023-09-20T09:07:46.457488661Z",
            "details": "",
        },
    )
    result = client.get_incident_entries(
        incident_id="1",
        from_date="1696494896",
        max_results=1,
        categories=None,
        tags_and_operator=True,
        tags=None,
    )
    assert result is not None
    assert result == []


# ── get-modified-remote-data tests ────────────────────────────────────────────


def test_get_modified_remote_data_returns_ids(mocker):
    """
    Given:
        - A lastUpdate timestamp and a remote server that returns two modified incident IDs.
        - No unsupported-endpoint flag in integration context.

    When:
        - Running get_modified_remote_data_command.

    Then:
        - The response contains exactly those two incident IDs.
        - The stale flag is NOT written (no failure occurred).
    """
    last_update = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
    args = {"lastUpdate": last_update.isoformat()}

    mocker.patch("XSOARmirroring.get_integration_context", return_value={})
    mocker.patch("XSOARmirroring.set_to_integration_context_with_retries")
    mocker.patch.object(
        Client,
        "get_modified_incidents",
        return_value=["101", "202"],
    )

    client = Client(base_url="https://test.com")
    result = get_modified_remote_data_command(client, args)

    assert result.modified_incident_ids == ["101", "202"]


def test_get_modified_remote_data_empty_response(mocker):
    """
    Given:
        - A lastUpdate timestamp and a remote server that returns no modified incidents.
        - No unsupported-endpoint flag in integration context.

    When:
        - Running get_modified_remote_data_command.

    Then:
        - The response contains an empty list of incident IDs.
    """
    last_update = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
    args = {"lastUpdate": last_update.isoformat()}

    mocker.patch("XSOARmirroring.get_integration_context", return_value={})
    mocker.patch("XSOARmirroring.set_to_integration_context_with_retries")
    mocker.patch.object(
        Client,
        "get_modified_incidents",
        return_value=[],
    )

    client = Client(base_url="https://test.com")
    result = get_modified_remote_data_command(client, args)

    assert result.modified_incident_ids == []


def test_get_modified_remote_data_passes_correct_timestamp(mocker):
    """
    Given:
        - A specific lastUpdate ISO8601 timestamp.
        - No unsupported-endpoint flag in integration context.

    When:
        - Running get_modified_remote_data_command.

    Then:
        - The client's get_modified_incidents is called with the correct epoch seconds derived from lastUpdate.
    """
    last_update = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
    expected_epoch = int(last_update.timestamp())
    args = {"lastUpdate": last_update.isoformat()}

    mocker.patch("XSOARmirroring.get_integration_context", return_value={})
    mocker.patch("XSOARmirroring.set_to_integration_context_with_retries")
    mock_get_modified = mocker.patch.object(
        Client,
        "get_modified_incidents",
        return_value=["999"],
    )

    client = Client(base_url="https://test.com")
    get_modified_remote_data_command(client, args)

    mock_get_modified.assert_called_once_with(from_timestamp=expected_epoch)


def test_get_modified_incidents_client_method(mocker):
    """
    Given:
        - A mock HTTP response from /incidents/modified returning a list of incident IDs.

    When:
        - Calling client.get_modified_incidents with a from_timestamp.

    Then:
        - The method returns the list of incident IDs as-is.
    """
    client = Client(base_url="https://test.com")
    mocker.patch.object(
        client,
        "_http_request",
        return_value=["101", "202", "303"],
    )

    result = client.get_modified_incidents(from_timestamp=1740830400)

    assert sorted(result) == ["101", "202", "303"]


def test_get_modified_incidents_client_method_empty_response(mocker):
    """
    Given:
        - A mock HTTP response from /incidents/modified returning an empty dict.

    When:
        - Calling client.get_modified_incidents.

    Then:
        - The method returns an empty list.
    """
    client = Client(base_url="https://test.com")
    mocker.patch.object(
        client,
        "_http_request",
        return_value={},
    )

    result = client.get_modified_incidents(from_timestamp=1740830400)

    assert result == []


@pytest.mark.parametrize("status_code", [303, 404])
def test_get_modified_remote_data_unsupported_endpoint_handled_gracefully(mocker, status_code):
    """
    Given:
        - client.get_modified_incidents raises a DemistoException with a 303 or 404 response,
          indicating the remote machine does not support the /public/v1/incidents/modified endpoint.
        - No unsupported-endpoint flag is set in integration context yet.

    When:
        - Running get_modified_remote_data_command.

    Then:
        - demisto.error is called twice: once for the general log and once for the user-facing message.
        - The user-facing error message mentions the unsupported endpoint and actionable guidance.
        - demisto.results is called with an ERROR entry whose Contents explains the issue.
        - Today's UTC date is persisted to integration context under MODIFIED_ENDPOINT_UNSUPPORTED_DATE_KEY.
        - sys.exit(0) is called to terminate gracefully.
    """
    import sys
    from unittest.mock import MagicMock

    last_update = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
    args = {"lastUpdate": last_update.isoformat()}

    mock_res = MagicMock()
    mock_res.status_code = status_code
    exc = DemistoException("Endpoint not found", res=mock_res)

    integration_context: dict = {}
    mocker.patch("XSOARmirroring.get_integration_context", return_value=integration_context)
    mock_set_context = mocker.patch("XSOARmirroring.set_to_integration_context_with_retries")
    mocker.patch.object(Client, "get_modified_incidents", side_effect=exc)
    mock_error = mocker.patch("demistomock.error")
    mock_results = mocker.patch("demistomock.results")
    mock_exit = mocker.patch.object(sys, "exit", side_effect=SystemExit)

    client = Client(base_url="https://test.com")

    with pytest.raises(SystemExit):
        get_modified_remote_data_command(client, args)

    # demisto.error should be called twice: general log + user-facing message
    assert mock_error.call_count == 2
    all_error_msgs = " ".join(call[0][0] for call in mock_error.call_args_list)
    assert "/public/v1/incidents/modified" in all_error_msgs
    assert str(status_code) in all_error_msgs

    # demisto.results should carry an ERROR entry with the actionable message
    mock_results.assert_called_once()
    result_entry = mock_results.call_args[0][0]
    assert result_entry["Type"] == EntryType.ERROR  # 4
    contents = result_entry["Contents"]
    assert "/public/v1/incidents/modified" in contents
    assert "XSOAR 8" in contents

    mock_exit.assert_called_once_with(0)

    # The unsupported-endpoint flag must have been persisted to integration context
    today_utc = datetime.now(tz=UTC).strftime("%Y-%m-%d")
    assert integration_context.get(MODIFIED_ENDPOINT_UNSUPPORTED_DATE_KEY) == today_utc
    mock_set_context.assert_called_once()


@pytest.mark.parametrize("status_code", [303, 404])
def test_get_modified_remote_data_circuit_breaker_skips_call_when_flag_set(mocker, status_code):
    """
    Given:
        - The integration context already contains today's UTC date under MODIFIED_ENDPOINT_UNSUPPORTED_DATE_KEY,
          meaning the endpoint was found unsupported earlier today.

    When:
        - Running get_modified_remote_data_command.

    Then:
        - client.get_modified_incidents is NOT called (no HTTP request is made).
        - demisto.results is called with an ERROR entry containing the cached error message.
        - sys.exit(0) is called to terminate gracefully.
    """
    import sys

    last_update = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
    args = {"lastUpdate": last_update.isoformat()}
    today_utc = datetime.now(tz=UTC).strftime("%Y-%m-%d")

    mocker.patch(
        "XSOARmirroring.get_integration_context",
        return_value={MODIFIED_ENDPOINT_UNSUPPORTED_DATE_KEY: today_utc},
    )
    mock_get_modified = mocker.patch.object(Client, "get_modified_incidents")
    mock_results = mocker.patch("demistomock.results")
    mocker.patch("demistomock.debug")
    mocker.patch("demistomock.error")
    mock_exit = mocker.patch.object(sys, "exit", side_effect=SystemExit)

    client = Client(base_url="https://test.com")

    with pytest.raises(SystemExit):
        get_modified_remote_data_command(client, args)

    # No HTTP call should have been made
    mock_get_modified.assert_not_called()

    # An ERROR entry must be returned with the cached message
    mock_results.assert_called_once()
    result_entry = mock_results.call_args[0][0]
    assert result_entry["Type"] == EntryType.ERROR
    assert "/public/v1/incidents/modified" in result_entry["Contents"]

    mock_exit.assert_called_once_with(0)


def test_get_modified_remote_data_circuit_breaker_retries_next_day(mocker):
    """
    Given:
        - The integration context contains yesterday's UTC date under MODIFIED_ENDPOINT_UNSUPPORTED_DATE_KEY.

    When:
        - Running get_modified_remote_data_command.

    Then:
        - client.get_modified_incidents IS called (the flag is stale — different day).
        - The response contains the returned incident IDs.
    """
    from datetime import timedelta

    last_update = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
    args = {"lastUpdate": last_update.isoformat()}
    yesterday_utc = (datetime.now(tz=UTC) - timedelta(days=1)).strftime("%Y-%m-%d")

    mocker.patch(
        "XSOARmirroring.get_integration_context",
        return_value={MODIFIED_ENDPOINT_UNSUPPORTED_DATE_KEY: yesterday_utc},
    )
    mocker.patch("XSOARmirroring.set_to_integration_context_with_retries")
    mock_get_modified = mocker.patch.object(
        Client,
        "get_modified_incidents",
        return_value=["42"],
    )

    client = Client(base_url="https://test.com")
    result = get_modified_remote_data_command(client, args)

    mock_get_modified.assert_called_once()
    assert result.modified_incident_ids == ["42"]


def test_get_modified_remote_data_clears_flag_on_success(mocker):
    """
    Given:
        - The integration context contains a stale unsupported-endpoint flag (from a previous day).
        - The remote server now responds successfully.

    When:
        - Running get_modified_remote_data_command.

    Then:
        - The MODIFIED_ENDPOINT_UNSUPPORTED_DATE_KEY key is removed from integration context.
        - set_to_integration_context_with_retries is called to persist the cleared context.
        - The response contains the returned incident IDs.
    """
    from datetime import timedelta

    last_update = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
    args = {"lastUpdate": last_update.isoformat()}
    yesterday_utc = (datetime.now(tz=UTC) - timedelta(days=1)).strftime("%Y-%m-%d")

    integration_context = {MODIFIED_ENDPOINT_UNSUPPORTED_DATE_KEY: yesterday_utc}
    mocker.patch("XSOARmirroring.get_integration_context", return_value=integration_context)
    mock_set_context = mocker.patch("XSOARmirroring.set_to_integration_context_with_retries")
    mocker.patch.object(Client, "get_modified_incidents", return_value=["77"])

    client = Client(base_url="https://test.com")
    result = get_modified_remote_data_command(client, args)

    # Flag must have been removed
    assert MODIFIED_ENDPOINT_UNSUPPORTED_DATE_KEY not in integration_context
    mock_set_context.assert_called_once()
    assert result.modified_incident_ids == ["77"]


def test_get_modified_remote_data_no_flag_cleared_when_context_clean(mocker):
    """
    Given:
        - The integration context has no unsupported-endpoint flag.
        - The remote server responds successfully.

    When:
        - Running get_modified_remote_data_command.

    Then:
        - set_to_integration_context_with_retries is NOT called (nothing to clear).
        - The response contains the returned incident IDs.
    """
    last_update = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
    args = {"lastUpdate": last_update.isoformat()}

    mocker.patch("XSOARmirroring.get_integration_context", return_value={})
    mock_set_context = mocker.patch("XSOARmirroring.set_to_integration_context_with_retries")
    mocker.patch.object(Client, "get_modified_incidents", return_value=["55"])

    client = Client(base_url="https://test.com")
    result = get_modified_remote_data_command(client, args)

    mock_set_context.assert_not_called()
    assert result.modified_incident_ids == ["55"]

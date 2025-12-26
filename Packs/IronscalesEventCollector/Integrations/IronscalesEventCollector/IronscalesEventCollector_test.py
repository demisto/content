import demistomock as demisto
import pytest
from pytest_mock import MockerFixture
from datetime import datetime, timedelta, UTC
from IronscalesEventCollector import (
    DATEPARSER_SETTINGS,
    Client,
    arg_to_datetime,
    enrich_events_with_mailbox_details,
    fetch_events_command,
    get_events_command,
    incident_to_events,
    main,
)


@pytest.fixture
def client(mocker):
    def mock_get_incident(inc_id):
        return {
            "incident_id": inc_id,
            "first_reported_date": f"{4 - inc_id} days ago",
            "reports": [
                {
                    "name": "first_name",
                }
            ],
        }

    mocked_client = mocker.Mock()
    mocked_client.all_incident = False
    mocked_client.get_incident_ids.return_value = [0, 1, 3, 4]
    mocked_client.get_incident.side_effect = mock_get_incident
    return mocked_client


def test_fetch_events_by_fetch_time(client: Client):
    """
    Given: A mock Ironscales client.
    When: Running fetch-events, where `max_fetch` param is 1 and `first_fetch` param is "2 days ago".
    Then: Ensure only the first event that occured up to 2 days ago is returned.
    """
    events, last_id, _ = fetch_events_command(
        client,
        first_fetch=arg_to_datetime("2 days ago", settings=DATEPARSER_SETTINGS),  # type: ignore
        max_fetch=1,
    )
    assert len(events) == 1
    assert events[0]["incident_id"] == 3
    assert last_id == 3


def test_fetch_events_by_last_id(client: Client):
    """
    Given: A mock Ironscales client.
    When: Running fetch-events, where `max_fetch` param is 10 and the last fetched incident id is 1.
    Then: Ensure incidents 3 and 4 are returned as events.
    """
    res, last_run, _ = fetch_events_command(
        client,
        first_fetch=arg_to_datetime("2 days ago", settings=DATEPARSER_SETTINGS),  # type: ignore
        max_fetch=10,
        last_id=1,
    )
    assert res[0]["incident_id"] == 3
    assert res[-1]["incident_id"] == 4


def test_get_events(client: Client):
    """
    Given: A mock Ironscales client.
    When: Running get-events with a limit of 1, while there are four open incidents.
    Then: Ensure only one event is returned.
    """
    _, events = get_events_command(client, {"limit": 1})
    assert len(events) == 1
    assert events[0]["incident_id"] == 0


def test_incident_to_events():
    """
    Given: A mock Ironscales incident data that aggregates two reports.
    When: Calling incident_to_events().
    Then: Ensure there are two events returned, where each of them
        consists of the incident data and a single report data.
    """
    dummy_incident = {
        "incident_id": 1,
        "first_reported_date": "2023-05-11T11:39:53.104571.0Z",
        "reports": [
            {
                "name": "dummy name 1",
                "email": "test@paloaltonetworks.com",
                "headers": [
                    {"name": "header1", "value": "value1"},
                ],
            },
            {
                "name": "dummy name 2",
                "email": "test2@paloaltonetworks.com",
                "headers": [
                    {"name": "header2", "value": "value2"},
                ],
            },
        ],
        "links": [
            {"url": "http://www.ironscales.com/", "name": "tests"},
        ],
        "attachments": [{"file_name": "dummy file", "file_size": 1024, "md5": "a36544c75d1253d8dd32070908adebd0"}],
    }
    events = incident_to_events(dummy_incident)
    assert len(events) == 2
    assert "reports" not in events[0]
    assert "reports" not in events[1]
    assert events[0]["incident_id"] == events[1]["incident_id"]
    assert events[0]["links"] == events[1]["links"]
    assert events[0]["attachments"] == events[1]["attachments"]
    assert events[0]["headers"][0]["name"] == "header1"
    assert events[1]["headers"][0]["name"] == "header2"
    assert events[0]["headers"][0]["value"] == "value1"
    assert events[1]["headers"][0]["value"] == "value2"


@pytest.mark.parametrize(
    "params, is_valid, result_msg",
    [
        ({"max_fetch": "1", "first_fetch": "", "url": ""}, True, "ok"),
        ({"max_fetch": "not a number", "first_fetch": "3 days", "url": ""}, False, '"not a number" is not a valid number'),
        ({"max_fetch": "1", "first_fetch": "not a date", "url": ""}, False, '"not a date" is not a valid date'),
    ],
)
def test_test_module(mocker: MockerFixture, params: dict, is_valid: bool, result_msg: str):
    """
    Given: different assignments for integration parameters.
    When: Running test-module command.
    Then: Make sure the correct message is returned.
    """
    mocker.patch.object(Client, "get_jwt_token", return_value="mock_token")
    mocker.patch.object(Client, "get_incident_ids", return_value=[])
    mocker.patch.object(Client, "get_incident")
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "params", return_value=params)
    demisto_result = mocker.patch.object(demisto, "results")
    return_error = mocker.patch("IronscalesEventCollector.return_error")
    main()
    result = (demisto_result if is_valid else return_error).call_args[0][0]
    assert result_msg in result


###### get all incidents tests #######


def test_no_incidents(mocker: MockerFixture):
    """
    Given: No incidents to pull
    When: pulling incidents
    Then: return empty list
    """
    mocker.patch.object(Client, "get_jwt_token", return_value="mocked_jwt")
    client = Client(
        company_id="1",
        base_url="test_url",
        verify_certificate=True,
        proxy=False,
        api_key="test",
        scopes=[""],
        all_incident=True,
    )

    mocker.patch.object(client, "_http_request", return_value={"total_pages": 1, "incidents": []})

    start_time = datetime.now(UTC) - timedelta(days=1)
    result = client.get_all_incident_ids(start_time)
    assert result == []


def test_single_page_with_incidents(mocker: MockerFixture):
    """
    Given: Single page to pull incidents from
    When: running get_all_incidents
    Then: return the incidents on this page
    """
    mocker.patch.object(Client, "get_jwt_token", return_value="mocked_jwt")
    client = Client(
        company_id="1",
        base_url="test_url",
        verify_certificate=True,
        proxy=False,
        api_key="test",
        scopes=[""],
        all_incident=True,
    )
    mocker.patch.object(
        client,
        "_http_request",
        return_value={
            "total_pages": 1,
            "incidents": [
                {"incidentID": 1, "created": "2025-07-04T10:39:05.260833Z"},
                {"incidentID": 2, "created": "2025-07-04T10:39:05.260833Z"},
            ],
        },
    )

    start_time = datetime.now(UTC) - timedelta(days=1)
    result = client.get_all_incident_ids(start_time)
    assert result == [1, 2]


def test_multiple_pages(mocker: MockerFixture):
    """
    Given: Multiple page to pull incidents from
    When: running get_all_incidents
    Then: return the incidents from all of the pages
    """
    mocker.patch.object(Client, "get_jwt_token", return_value="mocked_jwt")
    client = Client(
        company_id="1",
        base_url="test_url",
        verify_certificate=True,
        proxy=False,
        api_key="test",
        scopes=[""],
        all_incident=True,
    )
    responses = [
        {"total_pages": 2, "incidents": [{"incidentID": 1, "created": "2019-08-24T14:15:22.0Z"}]},
        {"total_pages": 2, "incidents": [{"incidentID": 2, "created": "2019-08-24T14:15:22.0Z"}]},
        {"total_pages": 2, "incidents": []},
    ]

    mocker.patch.object(client, "_http_request", side_effect=responses)

    start_time = datetime.now(UTC) - timedelta(days=1)
    result = client.get_all_incident_ids(start_time)
    assert result == [1, 2]


def test_respects_max_fetch(mocker: MockerFixture):
    """
    Given: More incidents then max_fetch
    When: pulling all incidents
    Then: stop at max_fetch
    """
    mocker.patch.object(Client, "get_jwt_token", return_value="mocked_jwt")
    client = Client(
        company_id="1",
        base_url="test_url",
        verify_certificate=True,
        proxy=False,
        api_key="test",
        scopes=[""],
        all_incident=True,
    )

    def ids_generator():
        i = 1
        while i < 100:
            yield {
                "total_pages": 50,
                "incidents": [
                    {"incidentID": i, "created": "2019-08-24T14:15:22.0Z"},
                    {"incidentID": i + 1, "created": "2019-08-24T14:15:22.0Z"},
                ],
            }
            i += 2

    mocker.patch.object(client, "_http_request", side_effect=ids_generator())
    mocker.patch.object(
        client,
        "get_incident",
        side_effect=lambda x: {"incident_id": x, "first_reported_date": f"{str(2019+x)}-08-24T14:15:22.0Z"},
    )
    mocker.patch("IronscalesEventCollector.incident_to_events", side_effect=lambda x: [x])

    res, last_run, last_timestamp_ids = fetch_events_command(
        client,
        first_fetch=arg_to_datetime("2 days ago", settings=DATEPARSER_SETTINGS),  # type: ignore
        max_fetch=10,
    )
    assert len(res) == 10
    assert res[0].get("incident_id") == 1
    assert last_run == -1
    assert last_timestamp_ids == [10]


def test_all_incidents_last_id(mocker: MockerFixture):
    """
    Given: A page where we already seen some of the incidents in it
    When: running fetch_events_command with all_incidents = True and we already pulled some incidents
    Then: pull only new incidents
    """
    mocker.patch.object(Client, "get_jwt_token", return_value="mocked_jwt")
    client = Client(
        company_id="1",
        base_url="test_url",
        verify_certificate=True,
        proxy=False,
        api_key="test",
        scopes=[""],
        all_incident=True,
    )

    responses = [
        {
            "total_pages": 2,
            "incidents": [
                {"incidentID": 1, "created": "2019-08-24T14:15:22.0Z"},
                {"incidentID": 2, "created": "2019-08-24T14:15:22.0Z"},
            ],
        },
        {
            "total_pages": 2,
            "incidents": [
                {"incidentID": 3, "created": "2019-08-24T14:15:22.0Z"},
                {"incidentID": 4, "created": "2019-08-24T14:15:22.0Z"},
            ],
        },
        {"total_pages": 2, "incidents": []},
    ]

    mocker.patch.object(client, "_http_request", side_effect=responses)
    mocker.patch.object(
        client,
        "get_incident",
        side_effect=lambda x: {"incident_id": x, "first_reported_date": f"{str(2019+x)}-08-24T14:15:22.0Z"},
    )
    mocker.patch("IronscalesEventCollector.incident_to_events", side_effect=lambda x: [x])

    res, _, _ = fetch_events_command(
        client,
        first_fetch=arg_to_datetime("2 days ago", settings=DATEPARSER_SETTINGS),  # type: ignore
        max_fetch=10,
        last_id=1,
        last_timestamp_ids=[1],
    )
    assert len(res) == 3
    assert res[0].get("incident_id") == 2


def test_all_incidents_last_id_complex(mocker: MockerFixture):
    """
    Tests that the fetch_events_command function correctly handles pagination
    and incident deduplication when fetching all incidents.

    Given:
        - A scenario where the current page contains some incidents that were already fetched
          (their IDs are included in last_timestamp_ids).

    When:
        - Running fetch_events_command with `all_incidents=True`
        - A `last_id` is provided to indicate the last seen incident
        - `max_fetch=10` is set to limit the number of new incidents to fetch

    Then:
        - Previously fetched incidents (based on ID) are ignored
        - Only new incidents are returned
        - The number of fetched incidents does not exceed max_fetch
    """
    mocker.patch.object(Client, "get_jwt_token", return_value="mocked_jwt")
    client = Client(
        company_id="1",
        base_url="test_url",
        verify_certificate=True,
        proxy=False,
        api_key="test",
        scopes=[""],
        all_incident=True,
    )

    def ids_generator():
        i = 1
        while i < 100:
            yield {
                "total_pages": 50,
                "incidents": [
                    {"incidentID": i, "created": "2019-08-24T14:15:22.0Z"},
                    {"incidentID": i + 1, "created": "2019-08-24T14:15:22.0Z"},
                ],
            }
            i += 2

    mocker.patch.object(client, "_http_request", side_effect=ids_generator())
    mocker.patch.object(
        client,
        "get_incident",
        side_effect=lambda x: {"incident_id": x, "first_reported_date": f"{str(2019+x)}-08-24T14:15:22.0Z"},
    )
    mocker.patch("IronscalesEventCollector.incident_to_events", side_effect=lambda x: [x])

    res, _, _ = fetch_events_command(
        client,
        first_fetch=arg_to_datetime("2 days ago", settings=DATEPARSER_SETTINGS),  # type: ignore
        max_fetch=10,
        last_id=2,
        last_timestamp_ids=[1, 2],
    )
    assert len(res) == 10
    assert res[0].get("incident_id") == 3


def test_last_run_from_context(mocker: MockerFixture):
    """
    Tests that the integration correctly resumes fetching incidents from the last saved state.

    Given:
        - The integration previously ran and stored `last_id` and `last_incident_time` in the context.
        - The command being executed is 'fetch-events'.
        - The Client is mocked to return sequential incidents from an HTTP request.

    When:
        - Running the `main()` function (which eventually triggers `fetch-events` logic).

    Then:
        - The integration should use the values from `getLastRun` to avoid re-fetching already seen incidents.
        - No errors raise
    """
    import IronscalesEventCollector

    mocker.patch.object(IronscalesEventCollector, "send_events_to_xsiam")
    mocker.patch.object(demisto, "setLastRun")

    mocker.patch.object(demisto, "getLastRun", return_value={"last_id": 5, "last_incident_time": "2019-08-24T14:15:22.0Z"})
    mocker.patch.object(Client, "get_jwt_token", return_value="mock_token")
    mocker.patch.object(Client, "get_incident_ids", return_value=[])
    mocker.patch.object(Client, "get_incident")

    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(
        demisto,
        "params",
        return_value={"max_fetch": "10", "first_fetch": "3 days", "url": "", "collect_all_incidents": True},
    )

    def ids_generator():
        i = 1
        while i < 100:
            yield {"total_pages": 100, "incidents": [{"incidentID": i}, {"incidentID": i + 1}]}
            i += 2

    mocker.patch.object(Client, "_http_request", side_effect=ids_generator())
    mocker.patch.object(Client, "get_incident", side_effect=lambda x: x)
    mocker.patch("IronscalesEventCollector.incident_to_events", side_effect=lambda x: [{x: 1}])
    main()


def test_sort_incidents(mocker: MockerFixture):
    """
    Tests that incidents returned by get_all_incident_ids are sorted by their creation timestamps.

    Given:
        - Multiple pages of incident data, with incidents returned in non-chronological order.
        - Each incident has a `created` timestamp.

    When:
        - Calling `get_all_incident_ids'.

    Then:
        - The function returns incident IDs sorted in ascending order based on their `created` timestamps.
        - The number of incidents returned matches the total number of incidents across all pages.
    """
    mocker.patch.object(Client, "get_jwt_token", return_value="mocked_jwt")
    client = Client(
        company_id="1",
        base_url="test_url",
        verify_certificate=True,
        proxy=False,
        api_key="test",
        scopes=[""],
        all_incident=True,
    )

    responses = [
        {
            "total_pages": 2,
            "incidents": [
                {"incidentID": 1, "created": "2019-08-24T14:15:22.0Z"},
                {"incidentID": 13, "created": "2019-08-24T14:15:25.0Z"},
            ],
        },
        {
            "total_pages": 2,
            "incidents": [
                {"incidentID": 5, "created": "2019-08-24T14:15:20.0Z"},
                {"incidentID": 2, "created": "2019-08-24T14:15:00.0Z"},
            ],
        },
        {"total_pages": 2, "incidents": []},
    ]

    mocker.patch.object(client, "_http_request", side_effect=responses)
    mocker.patch.object(
        client,
        "get_incident",
        side_effect=lambda x: {"incident_id": x, "first_reported_date": f"{str(2019+x)}-08-24T14:15:22.0Z"},
    )
    mocker.patch("IronscalesEventCollector.incident_to_events", side_effect=lambda x: [x])

    start_time = datetime.now(UTC) - timedelta(days=1)
    result = client.get_all_incident_ids(start_time)
    assert result == [2, 5, 1, 13]
    assert len(result) == 4


def test_same_timestamp(mocker: MockerFixture):
    """
    Given: A page where we already seen some of the incidents in it
    When: running fetch_events_command with all_incidents = True and we already pulled some incidents
    Then: pull only new incidents
    """
    mocker.patch.object(Client, "get_jwt_token", return_value="mocked_jwt")
    client = Client(
        company_id="1",
        base_url="test_url",
        verify_certificate=True,
        proxy=False,
        api_key="test",
        scopes=[""],
        all_incident=True,
    )

    responses = [
        {
            "total_pages": 2,
            "incidents": [
                {"incidentID": 1, "created": "2024-08-24T14:15:12.0Z"},
                {"incidentID": 2, "created": "2024-08-24T14:15:20.0Z"},
            ],
        },
        {
            "total_pages": 2,
            "incidents": [
                {"incidentID": 3, "created": "2024-08-24T14:15:22.0Z"},
                {"incidentID": 4, "created": "2024-08-24T14:15:22.0Z"},
            ],
        },
        {"total_pages": 2, "incidents": []},
    ]
    times = ["2024-08-24T14:15:12.0Z", "2024-08-24T14:15:20.0Z", "2024-08-24T14:15:22.0Z", "2024-08-24T14:15:22.0Z"]

    mocker.patch.object(client, "_http_request", side_effect=responses)
    mocker.patch.object(client, "get_incident", side_effect=lambda x: {"incident_id": x, "first_reported_date": times[x - 1]})
    mocker.patch("IronscalesEventCollector.incident_to_events", side_effect=lambda x: [x])

    res, last_run, last_timestamp_ids = fetch_events_command(
        client,
        first_fetch=arg_to_datetime("2019-08-24T14:15:02.0Z", settings=DATEPARSER_SETTINGS),  # type: ignore
        max_fetch=10,
        last_id=0,
        last_timestamp_ids=[0],
    )
    assert len(res) == 4
    assert res[0].get("incident_id") == 1
    assert last_timestamp_ids == [3, 4]


def test_unknown_incident_id(mocker: MockerFixture):
    """
    Given: A page where we already seen some of the incidents in it
    When: running fetch_events_command with all_incidents = True and we already pulled some incidents
    Then: pull only new incidents
    """
    mocker.patch.object(Client, "get_jwt_token", return_value="mocked_jwt")
    client = Client(
        company_id="1",
        base_url="test_url",
        verify_certificate=True,
        proxy=False,
        api_key="test",
        scopes=[""],
        all_incident=True,
    )

    responses = [
        {
            "total_pages": 2,
            "incidents": [
                {"incidentID": 1, "created": "2024-08-24T14:15:12.0Z"},
                {"incidentID": 2, "created": "2024-08-24T14:15:20.0Z"},
            ],
        },
        {
            "total_pages": 2,
            "incidents": [
                {"incidentID": 3, "created": "2024-08-24T14:15:22.0Z"},
                {"incidentID": 4, "created": "2024-08-24T14:15:22.0Z"},
            ],
        },
        {"total_pages": 2, "incidents": []},
    ]

    def new_get_incident(incident):
        if incident != 3:
            return {"incident_id": incident, "first_reported_date": times[incident - 1]}
        raise ValueError("Incident 13500 not found for company")

    times = ["2024-08-24T14:15:12.0Z", "2024-08-24T14:15:20.0Z", "2024-08-24T14:15:22.0Z", "2024-08-24T14:15:22.0Z"]

    mocker.patch.object(client, "_http_request", side_effect=responses)
    mocker.patch.object(client, "get_incident", side_effect=new_get_incident)
    mocker.patch("IronscalesEventCollector.incident_to_events", side_effect=lambda x: [x])

    res, last_run, last_timestamp_ids = fetch_events_command(
        client,
        first_fetch=arg_to_datetime("2019-08-24T14:15:02.0Z", settings=DATEPARSER_SETTINGS),  # type: ignore
        max_fetch=10,
        last_id=0,
        last_timestamp_ids=[0],
    )
    assert len(res) == 3
    assert res[-1].get("incident_id") == 4
    assert last_timestamp_ids == [4]


def test_enrich_events_with_mailbox_details_empty_events(mocker: MockerFixture, client: Client):
    """
    Given: An empty list of events.
    When: Running enrich_events_with_mailbox_details.
    Then: The function should return early without making any API calls.
    """
    events = []
    enrich_events_with_mailbox_details(client, events)

    mock_get_mailbox_mitigation_details = mocker.patch.object(client, "get_mailbox_mitigation_details")
    # Ensure no API calls were made
    assert mock_get_mailbox_mitigation_details.call_count == 0


def test_enrich_events_with_mailbox_details_single_page(mocker: MockerFixture, client: Client):
    """
    Given: A list of events from multiple incidents and a single page of mailbox mitigation details.
    When: Running enrich_events_with_mailbox_details.
    Then: Each event should be enriched with the corresponding mailbox mitigations.
    """
    # Mock events from two different incidents
    events = [
        {"incident_id": 100, "name": "event1"},
        {"incident_id": 200, "name": "event2"},
        {"incident_id": 300, "name": "event3"},
    ]

    # Mock API response with mitigations for both incidents
    mock_response = {
        "page": 1,
        "total_pages": 1,
        "mitigations": [
            {
                "incidentID": 100,
                "mitigationID": 1,
                "mailboxEmail": "user1@example.com",
                "subject": "Phishing Email 1",
            },
            {
                "incidentID": 100,
                "mitigationID": 2,
                "mailboxEmail": "user2@example.com",
                "subject": "Phishing Email 2",
            },
            {
                "incidentID": 200,
                "mitigationID": 3,
                "mailboxEmail": "user3@example.com",
                "subject": "Phishing Email 3",
            },
        ],
        "messages": [],
    }

    mocker.patch.object(client, "get_mailbox_mitigation_details", return_value=mock_response)

    enrich_events_with_mailbox_details(client, events)

    # Verify that events from incident 100 has 2 mitigations
    assert len(events[0]["mitigations"]) == 2
    assert events[0]["mitigations"][0]["mailbox_email"] == "user1@example.com"
    assert events[0]["mitigations"][1]["mailbox_email"] == "user2@example.com"

    # Verify that events from incident 200 has 1 mitigation
    assert len(events[1]["mitigations"]) == 1
    assert events[1]["mitigations"][0]["mailbox_email"] == "user3@example.com"

    # Verify that event from incident 300 has 0 mitigation
    assert len(events[2]["mitigations"]) == 0


def test_enrich_events_with_mailbox_details_multiple_pages(mocker: MockerFixture, client: Client):
    """
    Given: A list of events and multiple pages of mailbox mitigation details.
    When: Running enrich_events_with_mailbox_details.
    Then: The function should paginate through all pages and enrich events with all mitigations.
    """
    events = [
        {"incident_id": 100, "name": "event1"},
        {"incident_id": 200, "name": "event2"},
    ]

    # Mock API responses for multiple pages
    page1_response = {
        "page": 1,
        "total_pages": 3,
        "mitigations": [
            {
                "incidentID": 100,
                "mitigationID": 1,
                "mailboxEmail": "user1@example.com",
                "subject": "Email 1",
            },
        ],
        "messages": [],
    }

    page2_response = {
        "page": 2,
        "total_pages": 3,
        "mitigations": [
            {
                "incidentID": 100,
                "mitigationID": 2,
                "mailboxEmail": "user2@example.com",
                "subject": "Email 2",
            },
            {
                "incidentID": 200,
                "mitigationID": 3,
                "mailboxEmail": "user3@example.com",
                "subject": "Email 3",
            },
        ],
        "messages": [],
    }

    page3_response = {
        "page": 3,
        "total_pages": 3,
        "mitigations": [
            {
                "incidentID": 200,
                "mitigationID": 4,
                "mailboxEmail": "user4@example.com",
                "subject": "Email 4",
            },
        ],
        "messages": [],
    }

    mocker.patch.object(client, "get_mailbox_mitigation_details", side_effect=[page1_response, page2_response, page3_response])

    enrich_events_with_mailbox_details(client, events)

    # Verify incident 100 has 2 mitigations from pages 1 and 2
    assert len(events[0]["mitigations"]) == 2
    assert events[0]["mitigations"][0]["mailbox_email"] == "user1@example.com"
    assert events[0]["mitigations"][1]["mailbox_email"] == "user2@example.com"

    # Verify incident 200 has 2 mitigations from pages 2 and 3
    assert len(events[1]["mitigations"]) == 2
    assert events[1]["mitigations"][0]["mailbox_email"] == "user3@example.com"
    assert events[1]["mitigations"][1]["mailbox_email"] == "user4@example.com"


def test_enrich_events_with_mailbox_details_no_mitigations(mocker: MockerFixture, client: Client):
    """
    Given: A list of events and an API response with no mitigations.
    When: Running enrich_events_with_mailbox_details.
    Then: Events should have empty mitigations lists.
    """
    events = [
        {"incident_id": 100, "name": "event1"},
        {"incident_id": 200, "name": "event2"},
    ]

    mock_response = {
        "page": 1,
        "total_pages": 1,
        "mitigations": [],
        "messages": [],
    }

    mocker.patch.object(client, "get_mailbox_mitigation_details", return_value=mock_response)

    enrich_events_with_mailbox_details(client, events)

    # Verify all events have empty mitigations
    assert events[0]["mitigations"] == []
    assert events[1]["mitigations"] == []


def test_enrich_events_with_mailbox_details_field_transformation(mocker: MockerFixture, client: Client):
    """
    Given: A list of events and mailbox mitigation details with camelCase fields.
    When: Running enrich_events_with_mailbox_details.
    Then: The mitigation fields should be transformed to snake_case.
    """
    events = [{"incident_id": 100, "name": "event1"}]

    mock_response = {
        "page": 1,
        "total_pages": 1,
        "mitigations": [
            {
                "incidentID": 100,
                "mitigationID": 1,
                "incidentState": "resolved",
                "remediatedTime": "2019-08-24T14:15:22Z",
                "mailboxId": 123,
                "mailboxEmail": "user@example.com",
                "subject": "Test Subject",
                "senderEmail": "sender@example.com",
                "senderIP": "192.168.1.1",
                "reportedBy": "reporter@example.com",
                "resolution": "deleted",
                "spfResult": "pass",
            },
        ],
        "messages": [],
    }

    mocker.patch.object(client, "get_mailbox_mitigation_details", return_value=mock_response)

    enrich_events_with_mailbox_details(client, events)

    # Verify snake_case transformation and incidentID removal
    mitigation = events[0]["mitigations"][0]
    assert "incidentID" not in mitigation
    assert mitigation["mitigation_id"] == 1
    assert mitigation["incident_state"] == "resolved"
    assert mitigation["remediated_time"] == "2019-08-24T14:15:22Z"
    assert mitigation["mailbox_id"] == 123
    assert mitigation["mailbox_email"] == "user@example.com"
    assert mitigation["sender_email"] == "sender@example.com"
    assert mitigation["sender_ip"] == "192.168.1.1"
    assert mitigation["reported_by"] == "reporter@example.com"
    assert mitigation["spf_result"] == "pass"

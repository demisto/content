import json
from datetime import datetime, timedelta
import demistomock as demisto
import pytest
from CommonServerPython import DemistoException
from freezegun import freeze_time
from OktaASA import OktaASAClient

""" CONSTANTS """
MOCK_SERVER_URL = "https://server_url/"
KEY_ID = "key_id"
KEY_SECRET = "key_secret"


@freeze_time("2025-02-02 15:22:13 UTC")
def generate_results(
    descending=True,
    start_date=datetime.now(),
    range_number_start: int = 0,
    range_number_end: int = 1000,
):
    """
    Generates results from the API 1000 results every time.

    Args:
        descending (bool): Whether to return results in descending order.
        start_date (datetime.datetime): The starting date for the timestamps.

    Returns:
        List: A List of results with the following keys:
            id (int): A unique identifier for the result.
            timestamp (datetime.datetime): The timestamp for the result.
    """
    results = []
    for i in range(range_number_start, range_number_end):
        timestamp = start_date + timedelta(seconds=i)
        results.append({"id": str(i), "timestamp": timestamp})

    if descending:
        results.reverse()

    return results


def get_mock_client():
    return OktaASAClient(
        key_id=KEY_SECRET,
        key_secret=KEY_ID,
        base_url=MOCK_SERVER_URL,
        verify=True,
        proxy=False,
    )


def util_load_json(path: str):
    """Loads the contents of a JSON file with the given path.

    Args:
        path (str): Path to JSON file.

    Returns:
        Decoded JSON file contents.
    """
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_test_module_command(mocker):
    """
    Given:
    - test module command (fetches detections)

    When:
    - Pressing test button

    Then:
    - Test module passed
    """
    from OktaASA import OktaASAClient, test_module

    search_events_command_mocker = mocker.patch.object(OktaASAClient, "search_events", return_value=(None, None, None))
    client = get_mock_client()
    res = test_module(client=client)
    assert res == "ok"
    assert search_events_command_mocker.call_count == 1
    search_events_command_mocker.assert_called_with(limit=50, add_time_mapping=False)


def test_test_module_arguments(mocker):
    """
    Given:
    - test module command (fetches detections)

    When:
    - Pressing test button

    Then:
    - The get_events_command method is called with the correct arguments.
    """
    import OktaASA
    from OktaASA import test_module

    client = get_mock_client()
    get_events_command_mocker = mocker.patch.object(OktaASA, "get_events_command")
    result = test_module(client=client)
    assert result == "ok"
    assert get_events_command_mocker.call_count == 1
    get_events_command_mocker.assert_called_with(client=client)


def test_generate_token_if_required_hard_is_false_and_integration_context_is_empty(
    mocker,
):
    """
    Given:
    - OktaASAClient, empty integration context.

    When:
    - Call the generate_token_if_required method

    Then:
    - the generate_token_if_required method functionality works as expected
      and the get_token_request method is called.
    """
    from OktaASA import OktaASAClient

    client = get_mock_client()
    getIntegrationContext_mocker = mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    setIntegrationContext_mocker = mocker.patch.object(demisto, "setIntegrationContext")
    get_token_request_mocker = mocker.patch.object(
        OktaASAClient,
        "get_token_request",
        return_value={
            "bearer_token": "x",
            "expires_at": "2025-02-02T16:03:08.015338722Z",
            "team_name": "x",
        },
    )
    client.generate_token_if_required()
    assert get_token_request_mocker.call_count == 1
    assert getIntegrationContext_mocker.call_count == 1
    assert setIntegrationContext_mocker.call_count == 1


@freeze_time("2025-02-02 17:22:13 UTC")
def test_generate_token_if_required_hard_is_false_and_integration_context_is_not_empty_need_to_replace(
    mocker,
):
    """
    Given:
    - OktaASAClient, with integration context.

    When:
    - Call the generate_token_if_required method

    Then:
    - the generate_token_if_required method functionality works as expected
      and the get_token_request method is called since the token is expired.
    """
    from OktaASA import OktaASAClient

    client = get_mock_client()
    getIntegrationContext_mocker = mocker.patch.object(
        demisto,
        "getIntegrationContext",
        return_value={
            "bearer_token": "x",
            "expires_at": "2025-02-02T16:03:08.015338722Z",
            "team_name": "x",
        },
    )
    setIntegrationContext_mocker = mocker.patch.object(demisto, "setIntegrationContext")
    get_token_request_mocker = mocker.patch.object(
        OktaASAClient,
        "get_token_request",
        return_value={
            "bearer_token": "x",
            "expires_at": "2025-02-02T17:03:08.015338722Z",
            "team_name": "x",
        },
    )
    client.generate_token_if_required()
    assert get_token_request_mocker.call_count == 1
    assert getIntegrationContext_mocker.call_count == 1
    assert setIntegrationContext_mocker.call_count == 1


@freeze_time("2025-02-02 15:22:13 UTC")
def test_generate_token_if_required_hard_is_false_and_integration_context_is_not_empty_dont_need_to_replace(
    mocker,
):
    """
    Given:
    - OktaASAClient, with integration context.

    When:
    - Call the generate_token_if_required method

    Then:
    - the generate_token_if_required method functionality works as expected
      and the get_token_request method is not called since the token is not expired.
    """

    from OktaASA import OktaASAClient

    client = get_mock_client()
    getIntegrationContext_mocker = mocker.patch.object(
        demisto,
        "getIntegrationContext",
        return_value={
            "bearer_token": "x",
            "expires_at": "2025-02-02T16:03:08.015338722Z",
            "team_name": "x",
        },
    )
    setIntegrationContext_mocker = mocker.patch.object(demisto, "setIntegrationContext")
    get_token_request_mocker = mocker.patch.object(
        OktaASAClient,
        "get_token_request",
        return_value={
            "bearer_token": "x",
            "expires_at": "2025-02-02T17:03:08.015338722Z",
            "team_name": "x",
        },
    )
    client.generate_token_if_required()
    assert get_token_request_mocker.call_count == 0
    assert getIntegrationContext_mocker.call_count == 1
    assert setIntegrationContext_mocker.call_count == 1


@freeze_time("2025-02-02 15:22:13 UTC")
def test_generate_token_if_required_hard_is_true_and_integration_context_is_not_empty_dont_need_to_replace(
    mocker,
):
    """
    Given:
    - OktaASAClient, with integration context.

    When:
    - Call the generate_token_if_required method

    Then:
    - the generate_token_if_required method functionality works as expected
      and the get_token_request method is called since the argument is hard=true.
    """
    from OktaASA import OktaASAClient

    client = get_mock_client()
    getIntegrationContext_mocker = mocker.patch.object(
        demisto,
        "getIntegrationContext",
        return_value={
            "bearer_token": "x",
            "expires_at": "2025-02-02T16:03:08.015338722Z",
            "team_name": "x",
        },
    )
    setIntegrationContext_mocker = mocker.patch.object(demisto, "setIntegrationContext")
    get_token_request_mocker = mocker.patch.object(
        OktaASAClient,
        "get_token_request",
        return_value={
            "bearer_token": "x",
            "expires_at": "2025-02-02T17:03:08.015338722Z",
            "team_name": "x",
        },
    )
    client.generate_token_if_required(hard=True)
    assert get_token_request_mocker.call_count == 1
    assert getIntegrationContext_mocker.call_count == 1
    assert setIntegrationContext_mocker.call_count == 1


def test_execute_audit_events_request_exception(
    mocker,
):
    """
    Given:
    - OktaASAClient.

    When:
    - Call the execute_audit_events_request method

    Then:
    - A non-401 error is received and raised.
    """

    class MockException:
        def __init__(self, status_code, text) -> None:
            self.status_code = status_code
            self.text = text

    from OktaASA import OktaASAClient

    client = get_mock_client()
    generate_token_if_required_mocker = mocker.patch.object(
        OktaASAClient,
        "generate_token_if_required",
    )
    get_audit_events_request_mocker = mocker.patch.object(
        OktaASAClient,
        "get_audit_events_request",
        side_effect=[DemistoException("Authentication token expired", res=MockException(500, text=""))],
    )
    with pytest.raises(DemistoException):
        client.execute_audit_events_request(offset=None, count=None, descending=None, prev=None)
    assert get_audit_events_request_mocker.call_count == 1
    assert generate_token_if_required_mocker.call_count == 1


def test_search_events_limit_lower_then_1000_with_no_offset(mocker):
    """
    Given:
    - OktaASAClient and limit lower then 1000.

    When:
    - Call the search_events method

    Then:
    - A list with the requested number of events returned and the correct offset.
    """
    from OktaASA import OktaASAClient

    client = get_mock_client()
    generate_token_if_required_mocker = mocker.patch.object(
        OktaASAClient,
        "generate_token_if_required",
    )
    response = util_load_json("test_data/response_10_items_descending_true.json")
    get_audit_events_request_mocker = mocker.patch.object(
        OktaASAClient,
        "get_audit_events_request",
        return_value={"list": response.get("list"), "related_objects": response.get("related_objects")},
    )
    results, id, _ = client.search_events(limit=10, offset=None)
    assert generate_token_if_required_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 10
    assert len(results) == 10
    assert id == "1"


def test_search_events_limit_lower_then_1000_with_offset(mocker):
    """
    Given:
    - OktaASAClient and limit lower then 1000.

    When:
    - Call the search_events method

    Then:
    - A list with the requested number of events returned and the correct offset.
    - The events format is enhanced correctly.
    """
    from OktaASA import OktaASAClient

    client = get_mock_client()
    generate_token_if_required_mocker = mocker.patch.object(
        OktaASAClient,
        "generate_token_if_required",
    )
    response = util_load_json("test_data/response_10_items_descending_default.json")
    get_audit_events_request_mocker = mocker.patch.object(
        OktaASAClient,
        "get_audit_events_request",
        return_value={"list": response.get("list"), "related_objects": response.get("related_objects")},
    )
    results, id, _ = client.search_events(limit=10, offset="0")
    assert generate_token_if_required_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 10
    assert len(results) == 10
    assert id == "10"
    for log in results:
        assert isinstance(log.get("server"), dict)
        assert isinstance(log.get("project"), dict)
        assert isinstance(log.get("user"), dict)


@freeze_time("2025-02-02 15:22:13 UTC")
def test_search_events_limit_higher_then_1000_without_offset(mocker):
    """
    Given:
    - OktaASAClient and limit lower then 1000.

    When:
    - Call the search_events method

    Then:
    - A list with the requested number of events returned and the correct offset.
    """
    from OktaASA import OktaASAClient

    client = get_mock_client()
    generate_token_if_required_mocker = mocker.patch.object(
        OktaASAClient,
        "generate_token_if_required",
    )
    get_audit_events_request_mocker = mocker.patch.object(
        OktaASAClient,
        "get_audit_events_request",
        side_effect=[
            {"list": generate_results(True, datetime.now(), range_number_start=0, range_number_end=1000), "related_objects": {}},
            {
                "list": generate_results(
                    False,
                    datetime.now() + timedelta(seconds=1000),
                    range_number_start=1000,
                    range_number_end=2000,
                ),
                "related_objects": {},
            },
            {
                "list": generate_results(
                    False,
                    datetime.now() + timedelta(seconds=2000),
                    range_number_start=2000,
                    range_number_end=2999,
                ),
                "related_objects": {},
            },
        ],
    )
    results, id, _ = client.search_events(limit=2999, offset=None)
    assert generate_token_if_required_mocker.call_count == 3
    assert get_audit_events_request_mocker.call_count == 3
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("offset") is None
    assert get_audit_events_request_mocker.call_args_list[1].args[0].get("offset") == "999"
    assert get_audit_events_request_mocker.call_args_list[2].args[0].get("offset") == "1999"
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 1000
    assert get_audit_events_request_mocker.call_args_list[1].args[0].get("count") == 1000
    assert get_audit_events_request_mocker.call_args_list[2].args[0].get("count") == 999
    assert len(results) == 2999
    assert id == "2998"


@freeze_time("2025-02-02 15:22:13 UTC")
def test_search_events_limit_higher_then_1000_with_offset(mocker):
    """
    Given:
    - OktaASAClient and limit higher then 1000.

    When:
    - Call the search_events method

    Then:
    - A list with the requested number of events returned and the correct offset.
    """
    from OktaASA import OktaASAClient

    client = get_mock_client()
    generate_token_if_required_mocker = mocker.patch.object(
        OktaASAClient,
        "generate_token_if_required",
    )
    get_audit_events_request_mocker = mocker.patch.object(
        OktaASAClient,
        "get_audit_events_request",
        side_effect=[
            {
                "list": generate_results(False, datetime.now(), range_number_start=0, range_number_end=1000),
                "related_objects": {},
            },
            {
                "list": generate_results(
                    False,
                    datetime.now() + timedelta(seconds=1000),
                    range_number_start=1000,
                    range_number_end=2000,
                ),
                "related_objects": {},
            },
            {
                "list": generate_results(
                    False,
                    datetime.now() + timedelta(seconds=2000),
                    range_number_start=2000,
                    range_number_end=2999,
                ),
                "related_objects": {},
            },
        ],
    )
    results, id, _ = client.search_events(limit=2999, offset="5000")
    assert generate_token_if_required_mocker.call_count == 3
    assert get_audit_events_request_mocker.call_count == 3
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("offset") == "5000"
    assert get_audit_events_request_mocker.call_args_list[1].args[0].get("offset") == "999"
    assert get_audit_events_request_mocker.call_args_list[2].args[0].get("offset") == "1999"
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 1000
    assert get_audit_events_request_mocker.call_args_list[1].args[0].get("count") == 1000
    assert get_audit_events_request_mocker.call_args_list[2].args[0].get("count") == 999
    assert len(results) == 2999
    assert id == "2998"


@freeze_time("2025-02-02 15:22:13 UTC")
def test_search_events_limit_1000_without_offset(mocker):
    """
    Given:
    - OktaASAClient and limit 1000 without offset.

    When:
    - Call the search_events method

    Then:
    - A list with the requested number of events returned and the correct offset.
    """
    from OktaASA import OktaASAClient

    client = get_mock_client()
    generate_token_if_required_mocker = mocker.patch.object(
        OktaASAClient,
        "generate_token_if_required",
    )
    get_audit_events_request_mocker = mocker.patch.object(
        OktaASAClient,
        "get_audit_events_request",
        side_effect=[
            {"list": generate_results(False, datetime.now(), range_number_start=0, range_number_end=1000), "related_object": {}}
        ],
    )
    results, id, _ = client.search_events(limit=1000, offset=None)
    assert generate_token_if_required_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("offset") is None
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 1000
    assert len(results) == 1000
    assert id == "0"


@freeze_time("2025-02-02 15:22:13 UTC")
def test_search_events_limit_1001_second_page_is_empty(mocker):
    """
    Given:
    - OktaASAClient and limit 10000 and the second page is empty.

    When:
    - Call the search_events method

    Then:
    - A list with the requested number of events returned and the correct offset.
    """
    from OktaASA import OktaASAClient

    client = get_mock_client()
    generate_token_if_required_mocker = mocker.patch.object(
        OktaASAClient,
        "generate_token_if_required",
    )
    get_audit_events_request_mocker = mocker.patch.object(
        OktaASAClient,
        "get_audit_events_request",
        side_effect=[
            {"list": generate_results(False, datetime.now(), range_number_start=0, range_number_end=1000), "related_objects": {}},
            {"list": [], "related_objects": {}},
        ],
    )
    results, id, _ = client.search_events(limit=1001, offset=None)
    assert generate_token_if_required_mocker.call_count == 2
    assert get_audit_events_request_mocker.call_count == 2
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("offset") is None
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 1000
    assert len(results) == 1000
    assert id == "0"


def test_search_events_first_page_is_empty_without_offset(mocker):
    """
    Given:
    - OktaASAClient and limit 1000 and the first page is empty without offset.

    When:
    - Call the search_events method

    Then:
    - A list with the requested number of events returned and the correct offset.
    """
    from OktaASA import OktaASAClient

    client = get_mock_client()
    generate_token_if_required_mocker = mocker.patch.object(
        OktaASAClient,
        "generate_token_if_required",
    )
    get_audit_events_request_mocker = mocker.patch.object(
        OktaASAClient, "get_audit_events_request", side_effect=[{"list": [], "related_objects": []}]
    )
    results, id, timestamp = client.search_events(limit=1000, offset=None)
    assert generate_token_if_required_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("offset") is None
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 1000
    assert len(results) == 0
    assert id is None
    assert timestamp is None


def test_search_events_first_page_is_empty_with_offset(mocker):
    """
    Given:
    - OktaASAClient and limit 1000 and the first page is empty with offset.

    When:
    - Call the search_events method

    Then:
    - A list with the requested number of events returned and the correct offset.
    """
    from OktaASA import OktaASAClient

    client = get_mock_client()
    generate_token_if_required_mocker = mocker.patch.object(
        OktaASAClient,
        "generate_token_if_required",
    )
    get_audit_events_request_mocker = mocker.patch.object(
        OktaASAClient,
        "get_audit_events_request",
        side_effect=[{"list": [], "related_objects": {}}],
    )
    results, id, timestamp = client.search_events(limit=1000, offset="offset")
    assert generate_token_if_required_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("offset") == "offset"
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 1000
    assert len(results) == 0
    assert id == "offset"
    assert timestamp is None


def test_process_and_enrich_event(mocker):
    """
    Given:
    - Individual event and related_objects from oktaASA endpoint.

    When:
    - Call the process_and_enrich_event method

    Then:
    - The event is enriched with related object data and _time field.
    """
    from OktaASA import process_and_enrich_event

    response = util_load_json("test_data/response_10_items_descending_true.json")
    event = response.get("list")[0]
    related_objects = response.get("related_objects")

    enriched_event = process_and_enrich_event(event, related_objects, add_time=True)

    # Check that _time field was added
    assert "_time" in enriched_event

    # Check that related objects were enriched at top level
    assert isinstance(enriched_event.get("server"), dict)
    assert isinstance(enriched_event.get("project"), dict)
    assert isinstance(enriched_event.get("user"), dict)

    # Check original_link_id preservation
    assert enriched_event["server"]["original_link_id"] == "server_1"
    assert enriched_event["project"]["original_link_id"] == "project_1"
    assert enriched_event["user"]["original_link_id"] == "user_1"


def test_process_and_enrich_event_no_time_mapping():
    """
    Given:
    - Event and related objects with add_time=False

    When:
    - Call process_and_enrich_event with add_time=False

    Then:
    - No _time field is added but related objects are still enriched
    """
    from OktaASA import process_and_enrich_event

    response = util_load_json("test_data/single_event_basic.json")
    event = response.get("list")[0]
    related_objects = response.get("related_objects")

    enriched_event = process_and_enrich_event(event, related_objects, add_time=False)

    assert "_time" not in enriched_event
    assert enriched_event["server"]["name"] == "web-server-01"
    assert enriched_event["server"]["original_link_id"] == "srv_123"


def test_process_and_enrich_event_empty_details():
    """
    Given:
    - Event with empty details

    When:
    - Call process_and_enrich_event

    Then:
    - Only _time field is added, no related objects processed
    """
    from OktaASA import process_and_enrich_event

    response = util_load_json("test_data/event_empty_details.json")
    event = response.get("list")[0]
    related_objects = response.get("related_objects")

    enriched_event = process_and_enrich_event(event, related_objects, add_time=True)

    assert "_time" in enriched_event
    assert "server" not in enriched_event


def test_process_and_enrich_event_non_string_references():
    """
    Given:
    - Event with non-string values in details

    When:
    - Call process_and_enrich_event

    Then:
    - Non-string values are ignored, only string IDs are processed
    """
    from OktaASA import process_and_enrich_event

    response = util_load_json("test_data/event_non_string_references.json")
    event = response.get("list")[0]
    related_objects = response.get("related_objects")

    enriched_event = process_and_enrich_event(event, related_objects, add_time=True)

    assert enriched_event["server"]["name"] == "web-server-01"
    assert enriched_event["details"]["count"] == 5
    assert enriched_event["details"]["active"] is True


def test_process_and_enrich_event_missing_related_objects():
    """
    Given:
    - Event referencing IDs not in related_objects

    When:
    - Call process_and_enrich_event

    Then:
    - Missing references are ignored, existing ones are processed
    """
    from OktaASA import process_and_enrich_event

    response = util_load_json("test_data/event_missing_related_objects.json")
    event = response.get("list")[0]
    related_objects = response.get("related_objects")

    enriched_event = process_and_enrich_event(event, related_objects, add_time=True)

    assert enriched_event["server"]["name"] == "web-server-01"
    assert "project" not in enriched_event
    assert enriched_event["details"]["project"] == "proj_missing"  # Original preserved


def test_process_and_enrich_event_malformed_related_data():
    """
    Given:
    - Related objects with missing type or object fields

    When:
    - Call process_and_enrich_event

    Then:
    - Malformed related objects are skipped.
    """
    from OktaASA import process_and_enrich_event

    response = util_load_json("test_data/event_malformed_related_data.json")
    event = response.get("list")[0]
    related_objects = response.get("related_objects")

    enriched_event = process_and_enrich_event(event, related_objects, add_time=True)

    assert enriched_event["server"]["name"] == "web-server-01"
    assert "project" not in enriched_event  # Skipped due to missing type


def test_process_and_enrich_event_multiple_events_shared_objects():
    """
    Given:
    - Four events from multiple_events_shared_objects.json:
      1. John SSH to srv_web01 in proj_prod using client_laptop01
      2. Jane SSH to srv_web01 in proj_prod using client_laptop02 (shared server & project)
      3. John file transfer to srv_db01 in proj_prod using client_laptop01 (shared user, project, client)
      4. Bob command execution on srv_web02 in proj_staging using client_desktop01 (all unique)
    - A shared related_objects pool containing all servers, projects, users, and clients

    When:
    - Call process_and_enrich_event on each event with the shared related_objects

    Then:
    - Each event is enriched with its specific related objects from the shared pool
    - Shared objects (srv_web01, proj_prod, usr_john) are correctly resolved for multiple events
    - Different object combinations are properly handled per event
    - All original_link_id fields are preserved for traceability
    """
    from OktaASA import process_and_enrich_event

    response = util_load_json("test_data/multiple_events_shared_objects.json")
    events = response.get("list")
    related_objects = response.get("related_objects")

    # Process first event (john accessing web-server-01 in prod)
    event1 = process_and_enrich_event(events[0], related_objects, add_time=True)
    assert event1["server"]["name"] == "web-server-01"
    assert event1["server"]["ip"] == "10.0.1.10"
    assert event1["project"]["name"] == "production-environment"
    assert event1["user"]["email"] == "john.doe@company.com"
    assert event1["client"]["name"] == "john-macbook-pro"
    assert event1["server"]["original_link_id"] == "srv_web01"

    # Process second event (jane accessing same web-server-01 in same prod project)
    event2 = process_and_enrich_event(events[1], related_objects, add_time=True)
    assert event2["server"]["name"] == "web-server-01"  # Same server as event1
    assert event2["project"]["name"] == "production-environment"  # Same project as event1
    assert event2["user"]["email"] == "jane.smith@company.com"  # Different user
    assert event2["client"]["name"] == "jane-macbook-air"  # Different client

    # Process third event (john accessing different server in same project)
    event3 = process_and_enrich_event(events[2], related_objects, add_time=True)
    assert event3["server"]["name"] == "database-server-01"  # Different server
    assert event3["project"]["name"] == "production-environment"  # Same project
    assert event3["user"]["email"] == "john.doe@company.com"  # Same user as event1
    assert event3["client"]["name"] == "john-macbook-pro"  # Same client as event1

    # Process fourth event (different user, server, and project)
    event4 = process_and_enrich_event(events[3], related_objects, add_time=True)
    assert event4["server"]["name"] == "web-server-02"
    assert event4["project"]["name"] == "staging-environment"
    assert event4["user"]["email"] == "bob.wilson@company.com"
    assert event4["client"]["name"] == "bob-workstation"


def test_process_and_enrich_event_called_with_correct_arguments_for_test_module(mocker):
    """
    Given:
    - command name.

    When:
    - Call the process_and_enrich_event method via search_events

    Then:
    - The process_and_enrich_event called with correct arguments according to the command.
    """
    import OktaASA

    mocker.patch.object(
        OktaASAClient,
        "generate_token_if_required",
    )
    response = util_load_json("test_data/response_10_items_descending_true.json")
    mocker.patch.object(
        OktaASAClient,
        "get_audit_events_request",
        side_effect=[
            {"list": response.get("list"), "related_objects": response.get("related_objects")},
            {"list": [], "related_objects": {}},
        ],
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "params", return_value={"url": "test"})
    mocker_process_and_enrich_event = mocker.patch.object(
        OktaASA, "process_and_enrich_event", side_effect=lambda e, r, add_time: e
    )
    OktaASA.main()
    # Should be called once per event in the response (10 events)
    assert mocker_process_and_enrich_event.call_count == 10


def test_process_and_enrich_event_called_with_correct_arguments_for_get_event(mocker):
    """
    Given:
    - command name.

    When:
    - Call the process_and_enrich_event method via search_events

    Then:
    - The process_and_enrich_event called with correct arguments according to the command.
    """
    import OktaASA

    mocker.patch.object(
        OktaASAClient,
        "generate_token_if_required",
    )
    response = util_load_json("test_data/response_10_items_descending_true.json")
    mocker.patch.object(
        OktaASAClient,
        "get_audit_events_request",
        side_effect=[
            {"list": response.get("list"), "related_objects": response.get("related_objects")},
            {"list": [], "related_objects": {}},
        ],
    )
    mocker.patch.object(demisto, "command", return_value="okta-asa-get-events")
    mocker.patch.object(demisto, "params", return_value={"url": "test"})
    mocker.patch.object(demisto, "args", return_value={"should_push_events": "False"})
    mocker_process_and_enrich_event = mocker.patch.object(
        OktaASA, "process_and_enrich_event", side_effect=lambda e, r, add_time: e
    )
    OktaASA.main()
    # Should be called once per event in the response (10 events)
    assert mocker_process_and_enrich_event.call_count == 10


def test_process_and_enrich_event_called_with_correct_arguments_for_fetch_events(mocker):
    """
    Given:
    - command name.

    When:
    - Call the process_and_enrich_event method via search_events

    Then:
    - The process_and_enrich_event called with correct arguments according to the command.
    """
    import OktaASA

    mocker.patch.object(
        OktaASAClient,
        "generate_token_if_required",
    )
    response = util_load_json("test_data/response_10_items_descending_true.json")
    mocker.patch.object(OktaASA, "send_events_to_xsiam")
    mocker.patch.object(
        OktaASAClient,
        "get_audit_events_request",
        side_effect=[
            {"list": response.get("list"), "related_objects": response.get("related_objects")},
            {"list": [], "related_objects": {}},
        ],
    )
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(
        demisto, "params", return_value={"should_push_events": "True", "url": "test", "max_audit_events_per_fetch": "1"}
    )
    mocker_process_and_enrich_event = mocker.patch.object(
        OktaASA, "process_and_enrich_event", side_effect=lambda e, r, add_time: e
    )
    OktaASA.main()
    # Should be called once per event in the response (10 events)
    assert mocker_process_and_enrich_event.call_count == 10

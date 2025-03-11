from OktaASA import OktaASAClient
import demistomock as demisto
from freezegun import freeze_time
from CommonServerPython import DemistoException
import pytest
import json
from datetime import datetime, timedelta

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

    search_events_command_mocker = mocker.patch.object(
        OktaASAClient, "search_events", return_value=(None, None, None)
    )
    client = get_mock_client()
    res = test_module(client=client)
    assert res == "ok"
    assert search_events_command_mocker.call_count == 1
    search_events_command_mocker.assert_called_with(limit=50)


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
    get_events_command_mocker.assert_called_with(
        client=client
    )


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
    getIntegrationContext_mocker = mocker.patch.object(
        demisto, "getIntegrationContext", return_value={}
    )
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
        side_effect=[
            DemistoException(
                "Authentication token expired", res=MockException(500, text="")
            )
        ],
    )
    with pytest.raises(DemistoException):
        client.execute_audit_events_request(
            offset=None, count=None, descending=None, prev=None
        )
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
        OktaASAClient, "get_audit_events_request", return_value=response.get("list")
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
    """
    from OktaASA import OktaASAClient

    client = get_mock_client()
    generate_token_if_required_mocker = mocker.patch.object(
        OktaASAClient,
        "generate_token_if_required",
    )
    response = util_load_json("test_data/response_10_items_descending_default.json")
    get_audit_events_request_mocker = mocker.patch.object(
        OktaASAClient, "get_audit_events_request", return_value=response.get("list")
    )
    results, id, _ = client.search_events(limit=10, offset="0")
    assert generate_token_if_required_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 10
    assert len(results) == 10
    assert id == "10"


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
            generate_results(
                True, datetime.now(), range_number_start=0, range_number_end=1000
            ),
            generate_results(
                False,
                datetime.now() + timedelta(seconds=1000),
                range_number_start=1000,
                range_number_end=2000,
            ),
            generate_results(
                False,
                datetime.now() + timedelta(seconds=2000),
                range_number_start=2000,
                range_number_end=2999,
            ),
        ],
    )
    results, id, _ = client.search_events(limit=2999, offset=None)
    assert generate_token_if_required_mocker.call_count == 3
    assert get_audit_events_request_mocker.call_count == 3
    assert (
        get_audit_events_request_mocker.call_args_list[0].args[0].get("offset") is None
    )
    assert (
        get_audit_events_request_mocker.call_args_list[1].args[0].get("offset") == "999"
    )
    assert (
        get_audit_events_request_mocker.call_args_list[2].args[0].get("offset")
        == "1999"
    )
    assert (
        get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 1000
    )
    assert (
        get_audit_events_request_mocker.call_args_list[1].args[0].get("count") == 1000
    )
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
            generate_results(
                False, datetime.now(), range_number_start=0, range_number_end=1000
            ),
            generate_results(
                False,
                datetime.now() + timedelta(seconds=1000),
                range_number_start=1000,
                range_number_end=2000,
            ),
            generate_results(
                False,
                datetime.now() + timedelta(seconds=2000),
                range_number_start=2000,
                range_number_end=2999,
            ),
        ],
    )
    results, id, _ = client.search_events(limit=2999, offset="5000")
    assert generate_token_if_required_mocker.call_count == 3
    assert get_audit_events_request_mocker.call_count == 3
    assert (
        get_audit_events_request_mocker.call_args_list[0].args[0].get("offset")
        == "5000"
    )
    assert (
        get_audit_events_request_mocker.call_args_list[1].args[0].get("offset") == "999"
    )
    assert (
        get_audit_events_request_mocker.call_args_list[2].args[0].get("offset")
        == "1999"
    )
    assert (
        get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 1000
    )
    assert (
        get_audit_events_request_mocker.call_args_list[1].args[0].get("count") == 1000
    )
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
            generate_results(
                False, datetime.now(), range_number_start=0, range_number_end=1000
            )
        ],
    )
    results, id, _ = client.search_events(limit=1000, offset=None)
    assert generate_token_if_required_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_count == 1
    assert (
        get_audit_events_request_mocker.call_args_list[0].args[0].get("offset") is None
    )
    assert (
        get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 1000
    )
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
            generate_results(
                False, datetime.now(), range_number_start=0, range_number_end=1000
            ),
            [],
        ],
    )
    results, id, _ = client.search_events(limit=1001, offset=None)
    assert generate_token_if_required_mocker.call_count == 2
    assert get_audit_events_request_mocker.call_count == 2
    assert (
        get_audit_events_request_mocker.call_args_list[0].args[0].get("offset") is None
    )
    assert (
        get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 1000
    )
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
        OktaASAClient, "get_audit_events_request", side_effect=[[]]
    )
    results, id, timestamp = client.search_events(limit=1000, offset=None)
    assert generate_token_if_required_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_count == 1
    assert (
        get_audit_events_request_mocker.call_args_list[0].args[0].get("offset") is None
    )
    assert (
        get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 1000
    )
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
        OktaASAClient, "get_audit_events_request", side_effect=[[]]
    )
    results, id, timestamp = client.search_events(limit=1000, offset="offset")
    assert generate_token_if_required_mocker.call_count == 1
    assert get_audit_events_request_mocker.call_count == 1
    assert (
        get_audit_events_request_mocker.call_args_list[0].args[0].get("offset")
        == "offset"
    )
    assert (
        get_audit_events_request_mocker.call_args_list[0].args[0].get("count") == 1000
    )
    assert len(results) == 0
    assert id == "offset"
    assert timestamp is None

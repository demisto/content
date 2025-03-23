from freezegun import freeze_time
import demistomock as demisto
import json
import pytest


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def mock_params(mocker, params=None):
    if params is None:
        params = {
            "first_fetch": "3 days",
            "max_fetch": "2",
            "insecure": True,
            "proxy": False,
            "base_url": '"https://mock.darktrace.com"',
            "public_creds": {"password": "example_pub"},
            "private_creds": {"password": "example_pri"},
        }
    mocker.patch.object(demisto, "params", return_value=params)


@pytest.fixture(autouse=True)
def client(mocker):
    from DarktraceEventCollector import Client

    mocker.patch.object(Client, "_http_request", return_value=None)
    mocker.patch.object(Client, "parse_respone", return_value=util_load_json("test_data/mocked_get_events.json"))
    return Client(base_url="https://mock.darktrace.com", verify=False, proxy=False, auth=("example_pub", "example_pri"))


"""*****COMMAND FUNCTIONS****"""


def test_fetch_events_max_fetch(client):
    """
    Given: A mock Darktrace client.
    When: Running fetch-events with a max_fetch of 2, while there are three events.
    Then: Ensure only two events is returned.
    """
    from DarktraceEventCollector import fetch_events

    mock_start_time = 1
    mock_end_time = 2
    max_fetch = 2
    events, _ = fetch_events(client=client, max_fetch=max_fetch, last_run={}, start_time=mock_start_time, end_time=mock_end_time)
    assert len(events) == 2


def test_fetch_events_with_last_run(client):
    """
    Given: A mock Darktrace client.
    When: Running fetch-events with a max_fetch of 2 and last run, while there are three events.
    Then: Ensure only last two events is returned.
    """
    from DarktraceEventCollector import fetch_events

    mock_start_time = 1
    mock_end_time = 2
    max_fetch = 2
    events, _ = fetch_events(
        client=client, max_fetch=max_fetch, last_run={"last_fetch_pid": 11111}, start_time=mock_start_time, end_time=mock_end_time
    )
    assert len(events) == 2
    assert events == client.parse_respone.return_value[1:]


def test_get_events_command_limit(client):
    """
    Given: A mock Darktrace client.
    When: Running get_events_command with a limit of 2, while there are three events.
    Then: Ensure only two events is returned.
    """
    from DarktraceEventCollector import get_events_command

    mock_args = {"limit": "2"}
    mock_first_fetch_time = 1687009200
    events, _ = get_events_command(client=client, args=mock_args, first_fetch_time_timestamp=mock_first_fetch_time)
    assert len(events) == 2


@freeze_time("2023-06-20 13:40:00 UTC")
@pytest.mark.parametrize(
    "mock_date,expected_res",
    [("3 days", 1687009200), ("2021-01-01T00:00:00Z", 1609459200), ("1609459200", 1609459200)],
    ids=["XSOAR_FORMAT", "ISO_FORMAT", "TIME_STAMP_FORMAT"],
)
def test_convert_to_timestamp(mock_date, expected_res):
    """
    Given: A mock Darktrace client.
    When: Running get_events_command with a limit of 2, while there are three events.
    Then: Ensure only two events is returned.
    """
    from DarktraceEventCollector import convert_to_timestamp
    from CommonServerPython import arg_to_datetime

    parsed_date = convert_to_timestamp(date=arg_to_datetime(mock_date))
    assert parsed_date == expected_res


@freeze_time("2023-06-20 13:40:00 UTC")
def test_test_module_ok(client, mocker):
    from DarktraceEventCollector import test_module, convert_to_timestamp
    from CommonServerPython import arg_to_datetime

    params = {"max_fetch": "1", "first_fetch": "3 days"}

    mock_params(mocker, params)
    assert test_module(client, convert_to_timestamp(arg_to_datetime(params.get("first_fetch"))), last_run={}) == "ok"


@pytest.mark.parametrize(
    "params,error_msg",
    [
        ({"max_fetch": "1", "first_fetch": ""}, 'Failed to execute test-module command.\nError:\n"" is not a valid date'),
        (
            {"max_fetch": "not a number", "first_fetch": "3 days"},
            'Failed to execute test-module command.\nError:\n"not a number" is not a valid number',
        ),
        (
            {"max_fetch": "1", "first_fetch": "not a date"},
            'Failed to execute test-module command.\nError:\n"not a date" is not a valid date',
        ),
    ],
    ids=["empty_str_first_fetch", "invalid_max_fetch", "invalid_first_fetch"],
)
def test_test_module_failure(mocker, params, error_msg):
    """
    Given: different assignments for integration parameters.
    When: Running test-module command.
    Then: Make sure the correct message is returned.
    """
    from DarktraceEventCollector import main

    mock_params(mocker, params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    return_error = mocker.patch("DarktraceEventCollector.return_error")
    main()
    assert return_error.call_args[0][0] == error_msg

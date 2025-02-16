import datetime

from freezegun import freeze_time
import json
import pytest
import demistomock as demisto
from pytest_mock import MockerFixture
from pathlib import Path
MOCK_BASEURL = "https://example.protect.jamfcloud.com"
MOCK_CLIENT_ID = "example_client_id"
MOCK_CLIENT_PASSWORD = "example_pass"
MOCK_TIME_UTC_NOW = "2024-01-01T00:00:00.000000Z"


def util_load_json(path: str) -> dict:
    return json.loads(Path(path).read_text())


@pytest.fixture(autouse=True)
def client(mocker: MockerFixture, with_alert_next_page=False, with_audit_next_page=False, with_computer_next_page=False):
    from JamfProtectEventCollector import Client
    mocked_alerts = util_load_json('test_data/raw_alerts.json')
    mocked_audits = util_load_json('test_data/raw_audits.json')
    mocked_computers = util_load_json('test_data/raw_computers.json')
    mocker.patch.object(Client, '_http_request',
                        side_effect=[mocked_alerts, mocked_audits, mocked_computers])
    mocker.patch.object(Client, '_login', return_value="ExampleToken")
    return Client(base_url=MOCK_BASEURL, verify=False, proxy=False, client_id=MOCK_CLIENT_ID,
                  client_password=MOCK_CLIENT_PASSWORD)


"""*****COMMAND FUNCTIONS****"""


def test_test_module(client, mocker: MockerFixture):
    """
    Given: A mock JamfProtect client.
    When: Running test_module with different parameter configurations.
    Then: Ensure the function returns "ok" when at least one fetch option is enabled,
          and raises an exception when neither option is selected.
    """
    from JamfProtectEventCollector import test_module, DemistoException

    mocker.patch('JamfProtectEventCollector.fetch_events')
    mocker.patch('JamfProtectEventCollector.fetch_assets')

    params = {"isFetchEvents": True, "isFetchAssets": True}
    assert test_module(client, params) == "ok"

    params = {"isFetchEvents": True, "isFetchAssets": False}
    assert test_module(client, params) == "ok"

    params = {"isFetchEvents": False, "isFetchAssets": True}
    assert test_module(client, params) == "ok"

    params = {"isFetchEvents": False, "isFetchAssets": False}
    with pytest.raises(DemistoException, match="At least one option must be enabled: 'Fetch Events' or 'Fetch Assets'."):
        test_module(client, params)


def test_get_events_with_limit(client):
    """
    Given: A mock JamfProtect client.
    When: Running get-events with a limit of 2, while there are three events.
    Then: Ensure only two events is returned per type.
    """
    from JamfProtectEventCollector import get_events_command

    limit = 2
    args = {"limit": str(limit)}

    _, events = get_events_command(client=client, args=args)
    assert len(events[0].raw_response) == limit
    assert len(events[1].raw_response) == limit


def test_get_events_wrong_dates(client):
    """
    Given: A mock JamfProtect client.
    When: Running get-events with a wrong start and end date.
    Then: Ensure an error is returned.
    """
    from JamfProtectEventCollector import get_events_command

    start_date = "2023-01-02T00:00:00Z"
    end_date = "2023-01-01T00:00:00Z"
    error_msg = "Either the start date is missing or it is greater than the end date. Please provide valid dates."

    args = {"start_date": start_date, "end_date": end_date}
    with pytest.raises(ValueError) as e1:
        get_events_command(client=client, args=args)
    args = {"end_date": end_date}
    with pytest.raises(ValueError) as e2:
        get_events_command(client=client, args=args)
    assert error_msg in e1.value.args[0]
    assert error_msg in e2.value.args[0]


def test_get_assets_command(client, mocker):
    """
    Given: A mock JamfProtect client.
    When: Running get_assets_command with a limit of 2, while there are three assets.
    Then: Ensure only two assets are returned.
    """
    from JamfProtectEventCollector import get_assets_command

    limit = 2
    args = {"limit": str(limit)}

    assets, command_results = get_assets_command(client=client, args=args)

    assert len(assets) == limit
    assert "Jamf Protect Computers Assets" in command_results.readable_output


@freeze_time(MOCK_TIME_UTC_NOW)
def test_calculate_fetch_dates_with_arguments(client):
    """
    Given: A mock JamfProtect client.
    When: Running CalculateFetchDates with start and end date arguments.
    Then: Ensure the returned start date is the same as the start date argument,
     and the end date is the same as the end date argument.
    """
    from JamfProtectEventCollector import calculate_fetch_dates
    start_date_arg = "2023-01-01T00:00:00Z"
    end_date_arg = "2023-01-02T00:00:00Z"
    start_date, end_date = calculate_fetch_dates(start_date=start_date_arg, end_date=end_date_arg, last_run={})
    assert start_date == start_date_arg
    assert end_date == end_date_arg


@freeze_time(MOCK_TIME_UTC_NOW)
def test_calculate_fetch_dates_with_last_run(client):
    """
    Given: A mock JamfProtect client and last run key.
    When: Running CalculateFetchDates with last run.
    Then: Ensure the returned start date is the last fetch time, and the end date is the current time.
    """
    import dateparser
    from JamfProtectEventCollector import calculate_fetch_dates, DATE_FORMAT

    last_fetch_time = (dateparser.parse(MOCK_TIME_UTC_NOW) - datetime.timedelta(minutes=1)).strftime(DATE_FORMAT)
    last_run = {"last_fetch": last_fetch_time}
    start_date, end_date = calculate_fetch_dates(start_date="", last_run=last_run)

    assert start_date == last_fetch_time
    assert end_date == MOCK_TIME_UTC_NOW


@freeze_time(MOCK_TIME_UTC_NOW)
def test_calculate_fetch_dates_without_arguments(client):
    """
    Given: A mock JamfProtect client.
    When: Running CalculateFetchDates with no arguments.
    Then: Ensure the returned start date is 1 minute before the current time, and the end date is the current time.
    """
    import dateparser
    from JamfProtectEventCollector import calculate_fetch_dates, DATE_FORMAT

    start_date, end_date = calculate_fetch_dates(start_date="", last_run={})
    assert start_date == (dateparser.parse(MOCK_TIME_UTC_NOW) - datetime.timedelta(minutes=1)).strftime(DATE_FORMAT)
    assert end_date == MOCK_TIME_UTC_NOW


@pytest.mark.parametrize("with_alert_next_page", [True, False])
@pytest.mark.parametrize("with_audit_next_page", [True, False])
def test_nextTrigger(
    with_alert_next_page: bool,
    with_audit_next_page: bool,
    mocker: MockerFixture
):
    """
    Given: A mock JamfProtect client.
    When: Running fetch_events with different next pages for alerts and audits.
    Then: Ensure the nextTrigger is set to 0 when there are no next pages, and the next page is set when there are next pages.
    """
    from JamfProtectEventCollector import fetch_events, Client
    mocked_alerts = util_load_json('test_data/raw_alerts.json')
    mocked_audits = util_load_json('test_data/raw_audits.json')

    if with_alert_next_page:
        mocked_alerts["data"]["listAlerts"]["pageInfo"]["next"] = "example_next_page"
    if with_audit_next_page:
        mocked_audits["data"]["listAuditLogsByDate"]["pageInfo"]["next"] = "example_next_page"

    mocker.patch.object(Client, '_http_request',
                        side_effect=[mocked_alerts, mocked_audits])
    mocker.patch.object(Client, '_login', return_value="ExampleToken")
    client = Client(base_url=MOCK_BASEURL, verify=False, proxy=False, client_id=MOCK_CLIENT_ID,
                    client_password=MOCK_CLIENT_PASSWORD)

    _, next_run = fetch_events(client, 1, 1)

    if with_alert_next_page:
        assert next_run.get("nextTrigger") == "0"
        assert next_run.get("alert", {}).get("next_page") == "example_next_page"
    if not with_alert_next_page:
        assert not next_run.get("alert", {}).get("next_page")

    if with_audit_next_page:
        assert next_run.get("nextTrigger") == "0"
        assert next_run.get("audit", {}).get("next_page") == "example_next_page"
    if not with_audit_next_page:
        assert not next_run.get("audit", {}).get("next_page")


@pytest.mark.parametrize("with_computer_next_page", [True, False])
def test_assets_nextTrigger(with_computer_next_page: bool, mocker: MockerFixture):
    """
    Given: A mock JamfProtect client.
    When: Running fetch_assets with different next pages.
    Then: Ensure the nextTrigger is set to 0 when there are no next pages, a
          nd the next page and snapshot id are set when there are next pages.
    """
    from JamfProtectEventCollector import fetch_assets, Client
    mocked_computers = util_load_json('test_data/raw_computers.json')

    if with_computer_next_page:
        mocked_computers["data"]["listComputers"]["pageInfo"]["next"] = "example_next_page"

    mocker.patch.object(Client, '_http_request',
                        side_effect=[mocked_computers])
    mocker.patch.object(Client, '_login', return_value="ExampleToken")
    client = Client(base_url=MOCK_BASEURL, verify=False, proxy=False, client_id=MOCK_CLIENT_ID,
                    client_password=MOCK_CLIENT_PASSWORD)

    _, next_run, _, _ = fetch_assets(client, {}, 1)

    if with_computer_next_page:
        assert next_run.get("nextTrigger") == "0"
        assert next_run.get("next_page") == "example_next_page"
        assert next_run.get("snapshot_id")
    else:
        assert not next_run.get("next_page")
        assert not next_run.get("snapshot_id")


def test_next_trigger(mocker):
    """
    Test a situation that audit and alert have a next page
    but computer events are empty. Validate that after the code fix no variables are
    referenced before undefined error raises.
    """
    mocker.patch.object(demisto, 'getLastRun', return_value={'alert': {'next_page': 'value1'},
                                                             'audit': {'next_page': 'value2'}})
    from JamfProtectEventCollector import fetch_events, Client
    client = Client(base_url=MOCK_BASEURL, verify=False, proxy=False, client_id=MOCK_CLIENT_ID,
                    client_password=MOCK_CLIENT_PASSWORD)
    mocker.patch('JamfProtectEventCollector.get_events_for_type', return_value=([], {}))
    fetch_events(client, 1, 1)


def mock_set_last_run(last_run):
    return last_run


def test_alerts_and_next_page_audits_and_next_page(mocker):
    from JamfProtectEventCollector import main, parse_response
    mock_last_run = {
        "alert": {
            "last_fetch": MOCK_TIME_UTC_NOW,
            "next_page": "next_page_alerts"
        },
        "audit": {
            "last_fetch": MOCK_TIME_UTC_NOW,
            "next_page": "next_page_audits"
        }
    }
    expected_mock_last_run = {
        "alert": {
            "last_fetch": "2024-01-01T14:33:12.000000Z",
            "next_page": "next_page_alerts"
        },
        "audit": {
            "last_fetch": "2024-01-01T14:17:38.552096Z",
            "next_page": "next_page_audits"
        },
        'next_trigger_for': ['alert', 'audit'],
        "nextTrigger": "0"
    }
    mocker.patch('JamfProtectEventCollector.get_events', side_effect=[
        (parse_response(util_load_json('test_data/raw_alerts.json'))[1], {"next": 'next_page_alerts'}),
        (parse_response(util_load_json('test_data/raw_audits.json'))[1], {"next": 'next_page_audits'}),
    ])
    mocker.patch.object(demisto, 'params', return_value={})
    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run)
    mock_next_run = mocker.patch.object(demisto, 'setLastRun', side_effect=mock_set_last_run)
    mocker.patch('JamfProtectEventCollector.send_events_to_xsiam')

    main()

    assert mock_next_run.call_args.args[0] == expected_mock_last_run


@freeze_time(MOCK_TIME_UTC_NOW)
def test_no_alerts_and_no_next_page_no_audits_and_no_next_page(mocker):
    from JamfProtectEventCollector import main
    mock_last_run = {
        "alert": {
            "last_fetch": "2023-01-01T00:00:00.000000Z",
            "next_page": "next_page_alerts"
        },
        "audit": {
            "last_fetch": "2023-01-01T00:00:00.000000Z",
            "next_page": "next_page_audits"
        }
    }
    expected_mock_last_run = {
        "alert": {
            "last_fetch": MOCK_TIME_UTC_NOW,
        },
        "audit": {
            "last_fetch": MOCK_TIME_UTC_NOW,
        },
    }
    mocker.patch('JamfProtectEventCollector.get_events', side_effect=[
        ([], {}),
        ([], {}),
    ])
    mocker.patch.object(demisto, 'params', return_value={})
    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run)
    mock_next_run = mocker.patch.object(demisto, 'setLastRun', side_effect=mock_set_last_run)
    mocker.patch('JamfProtectEventCollector.send_events_to_xsiam')

    main()

    assert mock_next_run.call_args.args[0] == expected_mock_last_run


def test_alerts_and_no_next_page_audits_and_no_next_page(mocker):
    from JamfProtectEventCollector import main, parse_response
    mock_last_run = {
        "alert": {
            "last_fetch": MOCK_TIME_UTC_NOW,
            "next_page": "next_page_alerts"
        },
        "audit": {
            "last_fetch": MOCK_TIME_UTC_NOW,
            "next_page": "next_page_audits"
        }
    }
    expected_mock_last_run = {
        "alert": {
            "last_fetch": "2024-01-01T14:33:12.000000Z",
        },
        "audit": {
            "last_fetch": "2024-01-01T14:17:38.552096Z",
        }
    }
    mocker.patch('JamfProtectEventCollector.get_events', side_effect=[
        (parse_response(util_load_json('test_data/raw_alerts.json'))[1], {}),
        (parse_response(util_load_json('test_data/raw_audits.json'))[1], {}),
    ])
    mocker.patch.object(demisto, 'params', return_value={'fetch_all_computers': False})
    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run)
    mock_next_run = mocker.patch.object(demisto, 'setLastRun', side_effect=mock_set_last_run)
    mocker.patch('JamfProtectEventCollector.send_events_to_xsiam')

    main()

    assert mock_next_run.call_args.args[0] == expected_mock_last_run


@freeze_time(MOCK_TIME_UTC_NOW)
def test_no_alerts_and_next_page_no_audits_and_no_next_page(mocker):
    from JamfProtectEventCollector import main
    mock_last_run = {
        "alert": {
            "last_fetch": "2023-01-01T00:00:00.000000Z",
            "next_page": "next_page_alerts"
        },
        "audit": {
            "last_fetch": "2023-01-01T00:00:00.000000Z",
        }
    }
    expected_mock_last_run = {
        "alert": {
            "last_fetch": MOCK_TIME_UTC_NOW,
        },
        "audit": {
            "last_fetch": MOCK_TIME_UTC_NOW,
        }
    }
    mocker.patch('JamfProtectEventCollector.get_events', side_effect=[
        ([], {'next': 'next_page_alerts'}),
        ([], {}),
    ])
    mocker.patch.object(demisto, 'params', return_value={})
    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run)
    mock_next_run = mocker.patch.object(demisto, 'setLastRun', side_effect=mock_set_last_run)
    mocker.patch('JamfProtectEventCollector.send_events_to_xsiam')

    main()

    assert mock_next_run.call_args.args[0] == expected_mock_last_run


def test_add_fields_to_events_with_non_computer_events():
    """
    Given: A list of non-computer events and an event type.
    When: Calling the add_fields_to_events function.
    Then: Ensure the '_time' field and 'source_log_type' field are added to each event.
    """
    from JamfProtectEventCollector import add_fields_to_events
    events = [
        {"id": 1, "date": "2022-01-01T00:00:00Z"},
        {"id": 2, "created": "2022-01-02T00:00:00Z"}
    ]
    event_type = "alert"

    updated_events = add_fields_to_events(events, event_type)

    assert len(updated_events) == 2
    assert updated_events[0]["_time"] == "2022-01-01T00:00:00Z"
    assert updated_events[0]["source_log_type"] == "alert"
    assert updated_events[1]["_time"] == "2022-01-02T00:00:00Z"
    assert updated_events[1]["source_log_type"] == "alert"


def test_add_fields_to_events_with_computer_events():
    """
    Given: A list of computer events and an event type.
    When: Calling the add_fields_to_events function.
    Then: Ensure only the 'source_log_type' field is added to each event.
    """
    from JamfProtectEventCollector import add_fields_to_events
    events = [
        {"id": 1, "created": "2022-01-02T00:00:00Z", "name": "Computer 1"},
        {"id": 2, "created": "2022-01-02T00:00:00Z", "name": "Computer 2"}
    ]
    event_type = "computers"

    updated_events = add_fields_to_events(events, event_type)

    assert len(updated_events) == 2
    assert "_time" not in updated_events[0]
    assert updated_events[0]["source_log_type"] == "computers"
    assert "_time" not in updated_events[1]
    assert updated_events[1]["source_log_type"] == "computers"

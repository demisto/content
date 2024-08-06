import datetime

from freezegun import freeze_time
import json
import pytest
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
    assert len(events[2].raw_response) == limit


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
    start_date, end_date = calculate_fetch_dates(start_date=start_date_arg, end_date=end_date_arg, last_run_key="", last_run={})
    assert start_date == start_date_arg
    assert end_date == end_date_arg


@freeze_time(MOCK_TIME_UTC_NOW)
@pytest.mark.parametrize("last_run_key", ["alert", "audit", "computers"])
def test_calculate_fetch_dates_with_last_run(client, last_run_key):
    """
    Given: A mock JamfProtect client and last run key.
    When: Running CalculateFetchDates with last run.
    Then: Ensure the returned start date is the last fetch time, and the end date is the current time.
    """
    import dateparser
    from JamfProtectEventCollector import calculate_fetch_dates, DATE_FORMAT

    last_fetch_time = (dateparser.parse(MOCK_TIME_UTC_NOW) - datetime.timedelta(minutes=1)).strftime(DATE_FORMAT)
    last_run = {last_run_key: {"last_fetch": last_fetch_time}}
    start_date, end_date = calculate_fetch_dates(start_date="", last_run_key=last_run_key, last_run=last_run)

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

    start_date, end_date = calculate_fetch_dates(start_date="", last_run_key="", last_run={})
    assert start_date == (dateparser.parse(MOCK_TIME_UTC_NOW) - datetime.timedelta(minutes=1)).strftime(DATE_FORMAT)
    assert end_date == MOCK_TIME_UTC_NOW


@pytest.mark.parametrize("with_alert_next_page", [True, False])
@pytest.mark.parametrize("with_audit_next_page", [True, False])
@pytest.mark.parametrize("with_computer_next_page", [True, False])
def test_nextTrigger(
    with_alert_next_page: bool,
    with_audit_next_page: bool,
    with_computer_next_page: bool,
    mocker: MockerFixture
):
    """
    Given: A mock JamfProtect client.
    When: Running fetch_events with different next pages for alerts, audits and computers.
    Then: Ensure the nextTrigger is set to 0 when there are no next pages, and the next page is set when there are next pages.
    """
    from JamfProtectEventCollector import fetch_events, Client
    mocked_alerts = util_load_json('test_data/raw_alerts.json')
    mocked_audits = util_load_json('test_data/raw_audits.json')
    mocked_computers = util_load_json('test_data/raw_computers.json')
    if with_alert_next_page:
        mocked_alerts["data"]["listAlerts"]["pageInfo"]["next"] = "example_next_page"
    if with_audit_next_page:
        mocked_audits["data"]["listAuditLogsByDate"]["pageInfo"]["next"] = "example_next_page"
    if with_computer_next_page:
        mocked_computers["data"]["listComputers"]["pageInfo"]["next"] = "example_next_page"
    mocker.patch.object(Client, '_http_request',
                        side_effect=[mocked_alerts, mocked_audits, mocked_computers])
    mocker.patch.object(Client, '_login', return_value="ExampleToken")
    client = Client(base_url=MOCK_BASEURL, verify=False, proxy=False, client_id=MOCK_CLIENT_ID,
                    client_password=MOCK_CLIENT_PASSWORD)

    _, _, _, next_run = fetch_events(client, 1, 1, 1)
    if with_alert_next_page:
        assert next_run.get("nextTrigger") == "0"
        assert next_run.get("alert").get("next_page") == "example_next_page"
    if not with_alert_next_page:
        assert not next_run.get("alert").get("next_page")
    if with_audit_next_page:
        assert next_run.get("nextTrigger") == "0"
        assert next_run.get("audit").get("next_page") == "example_next_page"
    if not with_audit_next_page:
        assert not next_run.get("audit").get("next_page")
    if with_computer_next_page:
        assert next_run.get("nextTrigger") == "0"
        assert next_run.get("computer").get("next_page") == "example_next_page"
    if not with_computer_next_page:
        assert not next_run.get("computer").get("next_page")

import datetime

from freezegun import freeze_time
import demistomock as demisto
import json
import pytest

MOCK_BASEURL = "https://example.protect.jamfcloud.com"
MOCK_CLIENT_ID = "example_client_id"
MOCK_CLIENT_PASSWORD = "example_pass"
MOCK_TIME_UTC_NOW = "2024-01-01T00:00:00Z"


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def mock_params(mocker, params=None):
    if params is None:
        params = {'max_fetch': '2', 'insecure': True,
                  'proxy': False, 'base_url': MOCK_BASEURL,
                  'client_id': {'password': MOCK_CLIENT_ID, },
                  'client_password': {
                      'password': MOCK_CLIENT_PASSWORD}
                  }
    mocker.patch.object(demisto, "params", return_value=params)


@pytest.fixture(autouse=True)
def client(mocker):
    from JamfProtectEventCollector import Client

    mocker.patch.object(Client, '_http_request',
                        side_effect=[util_load_json('test_data/raw_alerts.json'), util_load_json('test_data/raw_audits.json')])
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
    Then: Ensure the returned start date is the same as the start date argument, and the end date is the same as the end date argument.
    """
    from JamfProtectEventCollector import calculate_fetch_dates
    start_date_arg = "2023-01-01T00:00:00Z"
    end_date_arg = "2023-01-02T00:00:00Z"
    start_date, end_date = calculate_fetch_dates(start_date=start_date_arg, end_date=end_date_arg, last_run_key="", last_run={})
    assert start_date == start_date_arg
    assert end_date == end_date_arg


@freeze_time(MOCK_TIME_UTC_NOW)
@pytest.mark.parametrize("last_run_key", ["alert", "audit"])
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

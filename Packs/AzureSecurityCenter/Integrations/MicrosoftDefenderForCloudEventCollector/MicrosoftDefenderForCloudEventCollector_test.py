import demistomock as demisto
from MicrosoftDefenderForCloudEventCollector import *
from datetime import datetime
import json
import pytest

ALERTS_API_RAW = 'test_data/ListAlerts.json'
ALERTS_TO_SORT = 'test_data/AlertsToSort.json'

client = MsClient(
    server="url", tenant_id="tenant", auth_id="auth_id", enc_key="enc_key", app_name="APP_NAME", verify="verify",
    proxy="proxy", self_deployed="self_deployed", subscription_id="subscription_id", ok_codes=(1, 3),
    certificate_thumbprint=None, private_key=None)


def read_json_util(path: str):
    with open(path, 'r') as f:
        json_file = json.load(f)

    return json_file


def test_find_next_run_with_no_new_events():
    """
        Given:
        - The events list from the api call and the last run

        When:
        - No new events were fetched from ms defender for cloud

        Then:
        - Check that the last_run reamains as before
    """
    events = []
    last_run = '2023-01-01T15:36:50.6288854Z'
    assert find_next_run(events, last_run=last_run) == last_run


def test_find_next_run_with_new_events():
    """
        Given:
        - The events list from the api call and the last run

        When:
        - New events have arrived from the ms defender for cloud

        Then:
        - Check that the last_run is set to be the latest detectedTimeUTC
    """
    events = [{'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
              {'properties': {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}},
              {'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}},
              {'properties': {'startTimeUtc': '2023-01-01T15:33:50.6281114Z'}}]
    last_run = '2023-01-01T15:36:50.6288854Z'
    assert find_next_run(events, last_run=last_run) == '2023-01-01T15:38:50.6222254Z'


def test_handle_last_run(mocker):
    """
        Given:
        - The First fetch time

        When:
        - It is not the first fetch and last_run param is already set.

        Then:
        - Check that the last_run is set by the previos next run.
    """
    mocker.patch.object(demisto, 'getLastRun', return_value='2023-01-01T15:35:51.179633Z')
    assert '2023-01-01T15:35:51.179633Z' == handle_last_run('3 days')


def test_handle_last_run_first_fetch_time(mocker):
    """
        Given:
        - The First fetch time

        When:
        - It is the first fetch and last_run param was not set yet.

        Then:
        - Check that the last_run is set by the first_fetch argument.
    """
    t = datetime(year=2023, month=1, day=8, hour=14, minute=44, second=5)
    mocker.patch('MicrosoftDefenderForCloudEventCollector.arg_to_datetime', return_value=t)
    assert '2023-01-08T14:44:05.000000Z' == handle_last_run({'first_fetch': 123})


def test_get_events(mocker):
    """
        Given:
        - Limit argument is given

        When:
        - Calling the get events commnad

        Then:
        - Check that the correct amount of events is returned and that the proper CommandResults is returned.
    """
    mocker.patch.object(MsClient, 'get_event_list', return_value=read_json_util(ALERTS_API_RAW))
    limit = 30
    events, cr = get_events(client, 'fake_last_run', limit=limit)
    assert len(events) == 81
    assert len(cr.outputs) == 30
    assert 'Microsft Defender For Cloud - List Alerts' in cr.readable_output


def test_add_time_key_to_events(mocker):
    events = read_json_util(ALERTS_TO_SORT)
    events_with_time = add_time_key_to_events(events)
    for event in events_with_time:
        assert '_time' in event


@pytest.mark.parametrize('dup_digested_time_id, list_after_filter',
                         [(['4'], [])]
def test_filter_out_previosly_digested_events(dup_digested_time_id, list_after_filter):
    events = [{'id': '1', 'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
              {'id': '2', 'properties': {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}},
              {'id': '3', 'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}},
              {'id': '4', 'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}},
              {'id': '5', 'properties': {'startTimeUtc': '2023-01-01T15:33:50.6281114Z'}}]
    list_after_filter = [{'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
                         {'properties': {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}}]
    dup_digested_time_id = ['4']
    filter_out_previosly_digested_events(
        events, {'last_run': '2023-01-01T15:35:50.6288854Z', 'dup_digested_time_id': dup_digested_time_id}) == list_after_filter


def test_filter_out_previosly_digested_events_with_same_time():
    events = [{'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
              {'properties': {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}},
              {'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}},
              {'properties': {'startTimeUtc': '2023-01-01T15:33:50.6281114Z'}}]
    list_after_filter = [{'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
                         {'properties': {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}}]
    filter_out_previosly_digested_events(events, '2023-01-01T15:35:50.6288854Z') == list_after_filter

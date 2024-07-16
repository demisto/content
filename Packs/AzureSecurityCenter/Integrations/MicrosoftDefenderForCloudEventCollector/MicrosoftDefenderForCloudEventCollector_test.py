from MicrosoftDefenderForCloudEventCollector import (MsClient,
                                                     find_next_run,
                                                     get_events,
                                                     filter_out_previosly_digested_events,
                                                     add_time_key_to_events,
                                                     check_events_were_filtered_out,
                                                     handle_last_run)
import json
import pytest
import demistomock as demisto  # noqa: F401

ALERTS_API_RAW = 'test_data/ListAlerts.json'
ALERTS_TO_SORT = 'test_data/AlertsToSort.json'


client = MsClient(
    server="url", tenant_id="tenant", auth_id="auth_id", enc_key="enc_key", verify="verify",
    proxy="proxy", self_deployed="self_deployed", subscription_id="subscription_id", ok_codes=(1, 3),
    certificate_thumbprint=None, private_key=None)


def read_json_util(path: str):
    """
    Read json util functions
    """
    with open(path) as f:
        json_file = json.load(f)

    return json_file


@pytest.mark.parametrize('events, last_run, expected_res',
                         [([], {}, {}),
                          ([], {'last_run': '2023-01-01T15:36:50.6288854Z', 'dup_digested_time_id': [1, 2, 3]},
                           {'last_run': '2023-01-01T15:36:50.6288854Z', 'dup_digested_time_id': [1, 2, 3]}),
                          ([{'id': 6, 'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}}],
                           {},
                           {'last_run': '2023-01-01T15:38:50.6222254Z', 'dup_digested_time_id': [6]}),
                          ([{'id': 6, 'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}}],
                           {'last_run': '2023-01-01T15:34:50.6288854Z', 'dup_digested_time_id': []},
                           {'last_run': '2023-01-01T15:38:50.6222254Z', 'dup_digested_time_id': [6]})])
def test_find_next_run_with_no_new_events(events, last_run, expected_res):
    """
        Given:
        - The events list from the api call and the last run

        When:
        - No new events were fetched from ms defender for cloud

        Then:
        - Check that the last_run reamains as before
    """
    next_time = find_next_run(events, last_run=last_run)
    assert next_time == expected_res


def test_find_next_run_with_new_events():
    """
        Given:
        - The events list from the api call and the last run

        When:
        - New events have arrived from the ms defender for cloud and no events with the same time.

        Then:
        - Check that the last_run is set to be the latest detectedTimeUTC
    """
    events = [{'id': 6, 'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
              {'id': 7, 'properties': {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}},
              {'id': 8, 'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}},
              {'id': 9, 'properties': {'startTimeUtc': '2023-01-01T15:33:50.6281114Z'}}]
    last_run = {'last_run': '2023-01-01T15:31:50.6288854Z', 'dup_digested_time_id': [1, 2, 3]}
    expected_result = {'last_run': '2023-01-01T15:38:50.6222254Z', 'dup_digested_time_id': [6]}
    assert find_next_run(events, last_run=last_run) == expected_result


def test_find_next_run_with_new_events_and_duplicate_start_time():
    """
        Given:
        - The events list from the api call and the last run

        When:
        - New events have arrived from the ms defender for cloud and some of them have the same startTimeUtc

        Then:
        - Check that the last_run is set to be the latest detectedTimeUTC and that the event ids with the same
            startTimeUtc are added to the dup_digested_time_id
    """
    events = [{'id': 1, 'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
              {'id': 2, 'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
              {'id': 3, 'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
              {'id': 4, 'properties': {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}},
              {'id': 5, 'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}},
              {'id': 6, 'properties': {'startTimeUtc': '2023-01-01T15:33:50.6281114Z'}}]
    last_run = {'last_run': '2023-01-01T15:31:50.6281114Z', 'dup_digested_time_id': [7, 8, 9]}
    expected_result = {'last_run': '2023-01-01T15:38:50.6222254Z', 'dup_digested_time_id': [1, 2, 3]}
    next_run = find_next_run(events, last_run=last_run)
    assert next_run == expected_result


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
    events, cr = get_events(client, {}, limit=limit)
    assert len(events) == 30
    assert len(cr.outputs) == 30
    assert 'Microsft Defender For Cloud - List Alerts' in cr.readable_output


def test_add_time_key_to_events(mocker):
    """
    Check that the _time field was added to the events
    """
    events = read_json_util(ALERTS_TO_SORT)
    events_with_time = add_time_key_to_events(events)
    for event in events_with_time:
        assert '_time' in event


@pytest.mark.parametrize('dup_digested_time_id, list_after_filter',
                         [
                             (['4'], [{'id': '1', 'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
                                      {'id': '2', 'properties': {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}},
                                      {'id': '3', 'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}}]),
                             (['4', '3'], [{'id': '1', 'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
                                           {'id': '2', 'properties': {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}},
                                           ]),
                             ([], [{'id': '1', 'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
                                   {'id': '2', 'properties': {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}},
                                   {'id': '3', 'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}},
                                   {'id': '4', 'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}}
                                   ]
                              ),
                             ([4, 5, 6, 7], [{'id': '1', 'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
                                             {'id': '2', 'properties': {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}},
                                             {'id': '3', 'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}},
                                             {'id': '4', 'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}}])
                         ]
                         )
def test_filter_out_previosly_digested_events(dup_digested_time_id, list_after_filter):
    """
    Given:
        A list of events from the API call

    When:
        Some of the events have the same time as the previos last run

    Then:
        filter out from the events all the events that were already previosly digested
        as stated in the dup_digested_time_id, and leave only new events to prevent duplicates.
    """
    events = [{'id': '1', 'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
              {'id': '2', 'properties': {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}},
              {'id': '3', 'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}},
              {'id': '4', 'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}},
              {'id': '5', 'properties': {'startTimeUtc': '2023-01-01T15:31:50.6281114Z'}}]
    filtered_events = filter_out_previosly_digested_events(
        events, {'last_run': '2023-01-01T15:35:50.6288854Z', 'dup_digested_time_id': dup_digested_time_id})
    assert filtered_events == list_after_filter


def test_filter_out_previosly_digested_events_no_last_run():
    """
    Given:
        A list of events from the API call

    When:
        No last run was given.

    Then:
        Check that no events were filtered out.
    """
    events = [{'id': '1', 'properties': {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
              {'id': '2', 'properties': {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}},
              {'id': '3', 'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}},
              {'id': '4', 'properties': {'startTimeUtc': '2023-01-01T15:35:50.6288854Z'}},
              {'id': '5', 'properties': {'startTimeUtc': '2023-01-01T15:33:50.6281114Z'}}]
    filter_out_previosly_digested_events(events, {}) == events


def test_filter_out_previosly_digested_events_no_events():
    """
    Given:
        - An empty list of evetns and a last_run

    When:
        - Filtering out previosly digested events

    Then:
        - Check that an empty event list is returned
    """
    assert filter_out_previosly_digested_events([], {'fake': 'fake'}) == []


@pytest.mark.parametrize('events, filtered_events, res', [([1, 2, 3], [1, 2], True),
                                                          ([], [], False),
                                                          ([1, 2, 3], [1, 2, 3, 4], False)])
def test_check_events_were_filtered_out(events, filtered_events, res):
    """
    Given:
        A list of events and a list of filtered events

    When:
        Checking if events were filtered out

    Then:
        Return true if events were filtered out and false otherwise.
    """
    assert check_events_were_filtered_out(events, filtered_events) == res


@pytest.mark.parametrize('http_response, get_events_response', [({'value': []}, []),
                                                                ({'value': [{'id': '1', 'properties':
                                                                             {'startTimeUtc': '2023-01-01T15:38:50.6222254Z'}},
                                                                            {'id': '2', 'properties':
                                                                             {'startTimeUtc': '2023-01-01T15:37:50.62866664Z'}}]},
                                                                 []),
                                                                ({'value': [{'id': '1', 'properties':
                                                                             {'startTimeUtc': '2023-01-01T15:42:50.6222254Z'}},
                                                                            {'id': '2', 'properties':
                                                                             {'startTimeUtc': '2023-01-01T15:41:50.62866664Z'}}]},
                                                                 [{'id': '1', 'properties':
                                                                   {'startTimeUtc': '2023-01-01T15:42:50.6222254Z'}},
                                                                  {'id': '2', 'properties':
                                                                   {'startTimeUtc': '2023-01-01T15:41:50.62866664Z'}}])
                                                                ])
def test_get_event_list(http_response, get_events_response):
    """
    Given:
        - A mocked response from the ms.http_request and a lasat run

    When:
        - Collecting events from the API

    Then:
        - Validate that the function flow workes corectlly.
    """
    class MockHttpRequest:
        def http_request(self, **kwargs):
            return http_response

    client.ms_client = MockHttpRequest()
    last_run = {'last_run': '2023-01-01T15:40:50.6222254Z', 'dup_digested_time_id': [1, 2, 3]}
    assert client.get_event_list(last_run) == get_events_response


@pytest.mark.parametrize('last_run, expected_res', [({}, {'last_run': 'fake_first_fetch_time', 'dup_digested_time_id': []}),
                                                    ({'last_run': '2023-01-01T15:40:50.6222254Z',
                                                      'dup_digested_time_id': [1, 2, 3]},
                                                     {'last_run': '2023-01-01T15:40:50.6222254Z',
                                                      'dup_digested_time_id': [1, 2, 3]})])
def test_handle_last_run(last_run, expected_res, mocker):
    """
    Given:
        - first_fetch_time (str) and a last run object

    When:
        - We want to determine the last_run object

    Then:
        - Verity that if the last run object was empty it will be set to the first_fetch_time
            else return the last_run object.
    """
    mocker.patch.object(demisto, 'getLastRun', return_value=last_run)
    assert handle_last_run('fake_first_fetch_time') == expected_res

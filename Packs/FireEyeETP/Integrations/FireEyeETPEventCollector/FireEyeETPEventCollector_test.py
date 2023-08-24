from datetime import datetime, timezone, timedelta
import json
import pytest
import FireEyeETPEventCollector
from freezegun import freeze_time


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


LAST_RUN_MULTIPLE_EVENT = {'Last Run': {
    "alerts": {
        "last_fetch_last_ids": ['a', 'b'],
        'last_fetch_timestamp': '2023-07-19T12:37:00.028000'
    },
    "email_trace": {
        "last_fetch_last_ids": [],
        'last_fetch_timestamp': '2023-07-19T12:20:00.020000'
    },
    "activity_log": {
        "last_fetch_last_ids": [],
        'last_fetch_timestamp': '2023-07-19T12:20:00.020000'
    }

}}
LAST_RUN_ONE_EVENT = {'Last Run': {
    "alerts": {
        "last_fetch_last_ids": ['a', 'b'],
        'last_fetch_timestamp': '2023-07-19T12:37:00.028000'
    },
}}

LAST_RUN_EMPTY: dict = {}
LAST_RUN_DICT_CASES = [
    (LAST_RUN_MULTIPLE_EVENT,  # case when multiple events exists.
     [
         FireEyeETPEventCollector.EventType('alerts', 25, outbound=False),
         FireEyeETPEventCollector.EventType('email_trace', 25, outbound=False),
         FireEyeETPEventCollector.EventType('activity_log', 25, outbound=False),
     ],
     LAST_RUN_MULTIPLE_EVENT),  # expected
    (LAST_RUN_ONE_EVENT,  # case when only one event exists
     [FireEyeETPEventCollector.EventType('alerts', 25, outbound=False)],
     LAST_RUN_ONE_EVENT)  # expected

]


@ pytest.mark.parametrize('last_run_dict, event_types_to_run, expected', LAST_RUN_DICT_CASES)
def test_last_run(last_run_dict, event_types_to_run, expected):
    """
        Given: mocked last run dictionary and events to fetch
        When: trying to fetch events
        Then: validate last run creation and save.
    """
    last_run = FireEyeETPEventCollector.get_last_run_from_dict(last_run_dict, event_types_to_run)
    assert len(last_run.event_types) == len(expected.get('Last Run', {}))
    assert {e.name for e in event_types_to_run} - set(last_run.__dict__.keys()) == set()
    new_dict = last_run.to_demisto_last_run()
    assert new_dict['Last Run'].keys() == expected['Last Run'].keys()


def mock_client():
    return FireEyeETPEventCollector.Client(
        base_url='test.com',
        verify_certificate=False,
        proxy=False,
        api_key='api-key',
        outbound_traffic=False,
        hide_sensitive=True
    )


@ freeze_time("2023-07-18 11:34:30")
@ pytest.mark.parametrize('hide_sensitive, alert_expected, trace_expected, activity_expected', (
                          pytest.param(True,
                                       'formatted_response_hidden_true', 'formatted_response_hidden_true',
                                       'formatted_response', id="Hide sensitive"),
                          pytest.param(False,
                                       'formatted_response_hidden_false', 'formatted_response_hidden_false',
                                       'formatted_response', id="Do not hide sensitive")
                          ))
def test_fetch_alerts(mocker, hide_sensitive, alert_expected, trace_expected, activity_expected):
    """
    Given: mocked client, mocked responses and expected event structure,
    When: fetching incidents
    Then: Testing the formatted events are as required.
    """
    client = mock_client()
    client.hide_sensitive = hide_sensitive
    mocked_alert_data = util_load_json('test_data/alerts.json')
    mocked_trace_data = util_load_json('test_data/email_trace.json')
    mocked_activity_data = util_load_json('test_data/activity_log.json')
    event_types_to_run = [
        FireEyeETPEventCollector.EventType('alerts', 25, outbound=False),
        FireEyeETPEventCollector.EventType('email_trace', 1000, outbound=False),
        FireEyeETPEventCollector.EventType('activity_log', 25, outbound=False)
    ]
    collector = FireEyeETPEventCollector.EventCollector(client, event_types_to_run)
    mocker.patch.object(FireEyeETPEventCollector.Client, 'get_alerts', side_effect=[
                        mocked_alert_data['ok_response_single_data'], {'data': []}])
    mocker.patch.object(FireEyeETPEventCollector.Client, 'get_email_trace', side_effect=[
                        mocked_trace_data['ok_response_single_data'], {'data': []}])
    mocker.patch.object(FireEyeETPEventCollector.Client, 'get_activity_log', side_effect=[
                        mocked_activity_data['ok_response'], {'data': []}])
    next_run, events = collector.fetch_command(
        demisto_last_run=LAST_RUN_MULTIPLE_EVENT,
        first_fetch=datetime.now(),
    )
    assert events[0] == mocked_alert_data[alert_expected]
    assert events[1] == mocked_trace_data[trace_expected]
    assert events[2] == mocked_activity_data[activity_expected]


FAKE_ISO_DATE_CASES = [
    ("2023-08-01T14:15:26.123456+0000Z",  # 6 digit milliseconds + tz+ Z
     datetime(2023, 8, 1, 14, 15, 26, 123456, tzinfo=timezone.utc)),
    ("2023-08-01T14:15:26+0000Z",   # No milliseconds + tz+ Z
     datetime(2023, 8, 1, 14, 15, 26, tzinfo=timezone.utc)),
    ("2023-08-01T14:15:26+0000",   # 6 digit milliseconds + tz , No Z
     datetime(2023, 8, 1, 14, 15, 26, tzinfo=timezone.utc)),
    ("2023-08-01 14:15:26+0000Z", None),  # Invalid format, missing 'T', expecting ValueError
    ("2023-08-01T14:15:26Z",  # No milliseconds + tz+ Z
     datetime(2023, 8, 1, 14, 15, 26, tzinfo=timezone.utc)),
    ("2023-08-01T14:15:26.123Z",  # 3 digit milliseconds + Z
     datetime(2023, 8, 1, 14, 15, 26, 123, tzinfo=timezone.utc)),
    ("2023-08-01T14:15:26.123+0000Z",  # 3 digit milliseconds + tz+ Z
     datetime(2023, 8, 1, 14, 15, 26, 123, tzinfo=timezone.utc))
]


@pytest.mark.parametrize("input_str, expected_dt", FAKE_ISO_DATE_CASES)
def test_parse_special_iso_format(input_str, expected_dt):
    """
    Given: date string in differents formats
    When: trying to convert from response to datetime
    Then: make sure parsing is correct.
    """
    if expected_dt is None:
        with pytest.raises(ValueError):
            FireEyeETPEventCollector.parse_special_iso_format(input_str)
    else:
        assert FireEyeETPEventCollector.parse_special_iso_format(input_str) == expected_dt


class TestLastRun:
    @pytest.fixture
    def last_run(self):
        """
            Given: event_typess
            When: trying to create last run
            Then: make sure last run created with the events.
        """
        # Create a LastRun instance with dummy event types
        event_types = [FireEyeETPEventCollector.EventType('alerts', 25, outbound=False),
                       FireEyeETPEventCollector.EventType('email_trace', 25, outbound=False),
                       FireEyeETPEventCollector.EventType('activity_log', 25, outbound=False)
                       ]
        return FireEyeETPEventCollector.LastRun(event_types=event_types)

    def test_to_demisto_last_run_empty(self, last_run):
        # Test to_demisto_last_run method when there are no event types.
        last_run.event_types = []
        assert last_run.to_demisto_last_run() == {}


@ freeze_time("2023-07-30 11:34:30")
def test_get_command(mocker):
    mocked_alert_data = util_load_json('test_data/alerts.json')
    mocked_trace_data = util_load_json('test_data/email_trace.json')
    mocked_activity_data = util_load_json('test_data/activity_log.json')
    event_types_to_run = [
        FireEyeETPEventCollector.EventType('alerts', 25, outbound=False),
        FireEyeETPEventCollector.EventType('email_trace', 1000, outbound=False),
        FireEyeETPEventCollector.EventType('activity_log', 25, outbound=False)
    ]
    collector = FireEyeETPEventCollector.EventCollector(mock_client(), event_types_to_run)
    mocker.patch.object(FireEyeETPEventCollector.Client, 'get_alerts', side_effect=[
                        mocked_alert_data['ok_response_single_data'], {'data': []}])
    mocker.patch.object(FireEyeETPEventCollector.Client, 'get_email_trace', side_effect=[
                        mocked_trace_data['ok_response_single_data'], {'data': []}])
    mocker.patch.object(FireEyeETPEventCollector.Client, 'get_activity_log', side_effect=[
                        mocked_activity_data['ok_response'], {'data': []}])
    next_run, events = collector.get_events_command(
        start_time=datetime.now() - timedelta(days=20)
    )
    assert events.readable_output


PAGINATION_CASES = [
    ('activity_log', 'test_data/activity_log.json', 'get_activity_log', 3),  # 2 calls of activity log (4 events, one dup)
    ('alerts', 'test_data/alerts.json', 'get_alerts', 3),  # 2 calls of alerts (4 events, one dup)
    ('email_trace', 'test_data/email_trace.json', 'get_email_trace', 3)  # 2 calls of trace (4 events, one dup)
]


@ freeze_time("2023-08-02 11:34:30")
@pytest.mark.parametrize("event_name, res_mock_path, func_to_mock, expected_res", PAGINATION_CASES)
def test_pagination(mocker, event_name, res_mock_path, func_to_mock, expected_res):
    """
    Given: a Mocked response of calls to API
    When: Running fetch on activity log type
    Then: Validate we fetch correct number of results, meaning:
        1. No dups
        2. All events arrived
    """
    collector = FireEyeETPEventCollector.EventCollector(
        mock_client(),
        [FireEyeETPEventCollector.EventType(event_name, 4, outbound=False)]
    )

    mocked_data = util_load_json(res_mock_path)
    mocker.patch.object(FireEyeETPEventCollector.Client, func_to_mock,
                        side_effect=mocked_data['paging_response'] + [{'data': []}])

    # using timedelta with milliseconds due to a freeze_time issue.
    events, md = collector.get_events_command(
        start_time=datetime.now() - timedelta(days=2, milliseconds=1)
    )
    assert len(events)

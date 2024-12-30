from datetime import datetime, timedelta, UTC
import json
import pytest
import FireEyeETPEventCollector
from freezegun import freeze_time


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


LAST_RUN_MULTIPLE_EVENT = {
    "Last Run": {
        "alerts": {
            "last_fetch_last_ids": ["a", "b"],
            "last_fetch_timestamp": "2023-07-19T12:37:00.028000",
        },
        "email_trace": {
            "last_fetch_last_ids": [],
            "last_fetch_timestamp": "2023-07-19T12:20:00.020000",
        },
        "activity_log": {
            "last_fetch_last_ids": [],
            "last_fetch_timestamp": "2023-07-19T12:20:00.020000",
        },
    }
}
LAST_RUN_ONE_EVENT = {
    "Last Run": {
        "alerts": {
            "last_fetch_last_ids": ["a", "b"],
            "last_fetch_timestamp": "2023-07-19T12:37:00.028000",
        },
    }
}

LAST_RUN_EMPTY: dict = {}
LAST_RUN_DICT_CASES = [
    (
        LAST_RUN_MULTIPLE_EVENT,  # case when multiple events exists.
        [
            FireEyeETPEventCollector.EventType("alerts", 25, outbound=False),
            FireEyeETPEventCollector.EventType("email_trace", 25, outbound=False),
            FireEyeETPEventCollector.EventType("activity_log", 25, outbound=False),
        ],
        LAST_RUN_MULTIPLE_EVENT,
    ),  # expected
    (
        LAST_RUN_ONE_EVENT,  # case when only one event exists
        [FireEyeETPEventCollector.EventType("alerts", 25, outbound=False)],
        LAST_RUN_ONE_EVENT,
    ),  # expected
]


@pytest.mark.parametrize(
    "last_run_dict, event_types_to_run, expected", LAST_RUN_DICT_CASES
)
def test_last_run(last_run_dict, event_types_to_run, expected):
    """
    Given: mocked last run dictionary and events to fetch
    When: trying to fetch events
    Then: validate last run creation and save.
    """
    last_run = FireEyeETPEventCollector.get_last_run_from_dict(
        last_run_dict, event_types_to_run
    )
    assert len(last_run.event_types) == len(expected.get("Last Run", {}))
    assert {e.name for e in event_types_to_run} - set(last_run.__dict__.keys()) == set()
    new_dict = last_run.to_demisto_last_run()
    assert new_dict["Last Run"].keys() == expected["Last Run"].keys()


def mock_client():
    return FireEyeETPEventCollector.Client(
        base_url="test.com",
        verify_certificate=False,
        proxy=False,
        api_key="api-key",
        outbound_traffic=False,
        hide_sensitive=True,
    )


@freeze_time("2023-07-18T11:34")
@pytest.mark.parametrize(
    "hide_sensitive, alert_expected, trace_expected, activity_expected",
    (
        pytest.param(
            True,
            "formatted_response_hidden_true",
            "formatted_response_hidden_true",
            "formatted_response",
            id="Hide sensitive",
        ),
        pytest.param(
            False,
            "formatted_response_hidden_false",
            "formatted_response_hidden_false",
            "formatted_response",
            id="Do not hide sensitive",
        ),
    ),
)
def test_fetch_alerts(
    mocker, hide_sensitive, alert_expected, trace_expected, activity_expected
):
    """
    Given: mocked client, mocked responses and expected event structure,
    When: fetching incidents
    Then: Testing the formatted events are as required.
    """
    client = mock_client()
    client.hide_sensitive = hide_sensitive
    mocked_alert_data = util_load_json("test_data/alerts.json")
    mocked_trace_data = util_load_json("test_data/email_trace.json")
    mocked_activity_data = util_load_json("test_data/activity_log.json")
    event_types_to_run = [
        FireEyeETPEventCollector.EventType("alerts", 25, outbound=False),
        FireEyeETPEventCollector.EventType("email_trace", 200, outbound=False),
        FireEyeETPEventCollector.EventType("activity_log", 2, outbound=False),
    ]
    collector = FireEyeETPEventCollector.EventCollector(client, event_types_to_run)
    mocker.patch.object(
        FireEyeETPEventCollector.Client,
        "get_alerts",
        side_effect=[mocked_alert_data["ok_response_single_data"], {"data": []}],
    )
    mocker.patch.object(
        FireEyeETPEventCollector.Client,
        "get_email_trace",
        side_effect=[mocked_trace_data["ok_response_single_data"], {"data": []}],
    )
    mocker.patch.object(
        FireEyeETPEventCollector.Client,
        "get_activity_log",
        side_effect=[mocked_activity_data["ok_response"], {"data": []}],
    )
    next_run, events = collector.fetch_command(
        demisto_last_run=LAST_RUN_MULTIPLE_EVENT,
        first_fetch=datetime.now(),
    )
    assert events[0] == mocked_alert_data[alert_expected]
    assert events[1] == mocked_trace_data[trace_expected]
    assert events[2] == mocked_activity_data[activity_expected]


FAKE_ISO_DATE_CASES = [
    (
        "2023-08-01T14:15:26.123456+0000Z",  # 6 digit milliseconds + tz+ Z
        datetime(2023, 8, 1, 14, 15, 26, 123456, tzinfo=UTC),
    ),
    (
        "2023-08-01T14:15:26+0000Z",  # No milliseconds + tz+ Z
        datetime(2023, 8, 1, 14, 15, 26, tzinfo=UTC),
    ),
    (
        "2023-08-01T14:15:26+0000",  # 6 digit milliseconds + tz , No Z
        datetime(2023, 8, 1, 14, 15, 26, tzinfo=UTC),
    ),
    (
        "2023-08-01 14:15:26+0000Z",  # missing 'T'
        datetime(2023, 8, 1, 14, 15, 26, tzinfo=UTC),
    ),
    (
        "2023-08-01T14:15:26Z",  # No milliseconds + tz+ Z
        datetime(2023, 8, 1, 14, 15, 26, tzinfo=UTC),
    ),
    (
        "2023-08-01T14:15:26.123Z",  # 3 digit milliseconds + Z
        datetime(2023, 8, 1, 14, 15, 26, 123000, tzinfo=UTC),
    ),
    (
        "2023-08-01T14:15:26.123+0000Z",  # 3 digit milliseconds + tz+ Z
        datetime(2023, 8, 1, 14, 15, 26, 123, tzinfo=UTC),
    ),
    ("2023-11-07T09:00", datetime(2023, 11, 7, 9, 0)),  # No seconds
]


@pytest.mark.parametrize("input_str, expected_dt", FAKE_ISO_DATE_CASES)
def test_parse_special_iso_format(input_str, expected_dt):
    """
    Given: date string in differents formats
    When: trying to convert from response to datetime
    Then: make sure parsing is correct.
    """

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
        event_types = [
            FireEyeETPEventCollector.EventType("alerts", 25, outbound=False),
            FireEyeETPEventCollector.EventType("email_trace", 25, outbound=False),
            FireEyeETPEventCollector.EventType("activity_log", 25, outbound=False),
        ]
        return FireEyeETPEventCollector.LastRun(event_types=event_types)

    def test_to_demisto_last_run_empty(self, last_run):
        # Test to_demisto_last_run method when there are no event types.
        last_run.event_types = []
        assert last_run.to_demisto_last_run() == {}


@freeze_time("2023-07-30 11:34:30")
def test_get_command(mocker):
    mocked_alert_data = util_load_json("test_data/alerts.json")
    mocked_trace_data = util_load_json("test_data/email_trace.json")
    mocked_activity_data = util_load_json("test_data/activity_log.json")
    event_types_to_run = [
        FireEyeETPEventCollector.EventType("alerts", 25, outbound=False),
        FireEyeETPEventCollector.EventType("email_trace", 1000, outbound=False),
        FireEyeETPEventCollector.EventType("activity_log", 25, outbound=False),
    ]
    collector = FireEyeETPEventCollector.EventCollector(
        mock_client(), event_types_to_run
    )
    mocker.patch.object(
        FireEyeETPEventCollector.Client,
        "get_alerts",
        side_effect=[mocked_alert_data["ok_response_single_data"], {"data": []}],
    )
    mocker.patch.object(
        FireEyeETPEventCollector.Client,
        "get_email_trace",
        side_effect=[mocked_trace_data["ok_response_single_data"], {"data": []}],
    )
    mocker.patch.object(
        FireEyeETPEventCollector.Client,
        "get_activity_log",
        side_effect=[mocked_activity_data["ok_response"], {"data": []}],
    )
    next_run, events = collector.get_events_command(
        start_time=datetime.now() - timedelta(days=20)
    )
    assert events.readable_output


PAGINATION_CASES = [
    (
        "activity_log",
        "test_data/activity_log.json",
        "get_activity_log",
        3,
    ),  # 2 calls of activity log (4 events, one dup)
    (
        "alerts",
        "test_data/alerts.json",
        "get_alerts",
        3,
    ),  # 2 calls of alerts (4 events, one dup)
    (
        "email_trace",
        "test_data/email_trace.json",
        "get_email_trace",
        3,
    ),  # 2 calls of trace (4 events, one dup)
]


@freeze_time("2023-08-02 11:34:30")
@pytest.mark.parametrize(
    "event_name, res_mock_path, func_to_mock, expected_res", PAGINATION_CASES
)
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
        [FireEyeETPEventCollector.EventType(event_name, 4, outbound=False)],
    )

    mocked_data = util_load_json(res_mock_path)
    mocker.patch.object(
        FireEyeETPEventCollector.Client,
        func_to_mock,
        side_effect=mocked_data["paging_response"] + [{"data": []}],
    )

    # using timedelta with milliseconds due to a freeze_time issue.
    events, md = collector.get_events_command(
        start_time=datetime.now() - timedelta(days=2, milliseconds=1)
    )
    assert len(events)


@pytest.mark.parametrize(
    "max_fetch, limit_args, expected",
    [
        pytest.param(
            "",
            None,
            FireEyeETPEventCollector.DEFAULT_MAX_FETCH,
            id="both empty, using default",
        ),
        pytest.param(0, 10, 10, id="empty configuration, args override"),
        pytest.param(10, 0, 0, id="existing configuration, empty args override"),
        pytest.param(50, None, 50, id="param overrides default"),
        pytest.param(0, None, 0, id="param stay empty on purpose"),
        pytest.param(80, 75, 75, id="args overrides param"),
        pytest.param("", "invalid", None, id="limit invalid"),
        pytest.param("a", "", None, id="configured max_fetch invalid"),
    ],
)
def test_get_max_events_to_fetch(max_fetch, limit_args, expected):
    """
    Given: max_fetch and limit_args parameters
    When: setting the max events to fetch
    then: calculate the max events to fetch based on the parameters passed in
    """
    if expected is None:
        with pytest.raises(ValueError):
            FireEyeETPEventCollector._get_max_events_to_fetch(max_fetch, limit_args)
    else:
        assert (
            FireEyeETPEventCollector._get_max_events_to_fetch(max_fetch, limit_args)
            == expected
        )


@pytest.mark.parametrize(
    "input_dt,expected",
    [
        (datetime(2023, 1, 15, 14, 30, 45, 123456), "2023-01-15T14:30:45.123"),
        (datetime(2023, 1, 15, 14, 30, 45, 123), "2023-01-15T14:30:45.123"),
        (datetime(2023, 1, 15, 14, 30, 45), "2023-01-15T14:30:45.000"),
    ],
)
def test_parse_date_for_api_3_digits(input_dt, expected):
    output = FireEyeETPEventCollector.parse_date_for_api_3_digits(input_dt)
    assert output == expected


@pytest.mark.parametrize(
    "event_names,new_max", [(["alerts"], 50), (["email_trace"], 100)]
)
def test_set_events_max_multiple(mocker, event_names, new_max):
    """Test setting client max fetch for multiple events.

    Given
        - A list of event names
        - A new max fetch value

    When
        - Calling set_events_max with the event names and new max

    Then
        - The client_max_fetch should be updated for those events
    """
    FireEyeETPEventCollector.set_events_max(event_names, new_max)

    for name in event_names:
        event = next(e for e in FireEyeETPEventCollector.ALL_EVENTS if e.name == name)
        assert event.client_max_fetch == new_max


def test_limit_zero_skip_fetch_flow(mocker):
    """
    Given: 2 events with limit set to zero and one event with actual number.
    When: running the fetch flow
    Then: validates the flow was only running for the event with limit.
    """

    event_types = [
        FireEyeETPEventCollector.EventType("alerts", 0, outbound=False),
        FireEyeETPEventCollector.EventType("email_trace", 0, outbound=False),
        FireEyeETPEventCollector.EventType("activity_log", 25, outbound=False),
    ]
    last_run = FireEyeETPEventCollector.LastRun(event_types=event_types)
    collector = FireEyeETPEventCollector.EventCollector(mock_client(), event_types)
    get_events_mock = mocker.patch.object(
        collector, "get_events", return_value=(last_run, [])
    )
    mocker.patch.object(
        FireEyeETPEventCollector.LastRun, "to_demisto_last_run", return_value={}
    )

    collector.fetch_command(demisto_last_run=LAST_RUN_MULTIPLE_EVENT)
    get_events_mock.assert_called_once()

    get_events_mock.reset_mock()
    collector.get_events_command(start_time=datetime(2023, 1, 15, 14, 30, 45, 123000))
    get_events_mock.assert_called_once()

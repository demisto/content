from freezegun import freeze_time

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import pytest
import pytz
from typing import Tuple
from urllib.parse import parse_qs, urlparse
from TrendMicroVisionOneEventCollector import DATE_FORMAT, Client, DEFAULT_MAX_LIMIT, LastRunLogsTimeFields, UrlSuffixes, LogTypes


BASE_URL = 'https://api.xdr.trendmicro.com'


@pytest.fixture()
def client() -> Client:
    return Client(
        base_url=BASE_URL,
        api_key='api-key',
        proxy=False,
        verify=True
    )


def get_url_params(url: str) -> Dict[str, str]:
    parsed_url = urlparse(url)
    query_parameters = parse_qs(parsed_url.query)
    return {
        key: value[0] for key, value in query_parameters.items()
    }


def create_any_type_logs(start: int, end: int, created_time_field: str, id_field_name: str, extra_seconds: int = 0):
    return [
        {
            id_field_name: i,
            created_time_field: (
                datetime.now(tz=pytz.utc) - timedelta(seconds=i + extra_seconds)
            ).strftime(DATE_FORMAT) if created_time_field != 'eventTime' else int(
                (datetime.now(tz=pytz.utc) - timedelta(seconds=i + extra_seconds)).timestamp()
            ) * 1000
        } for i in range(start + 1, end + 1)
    ]


def create_logs_mocks(
    url: str,
    num_of_events: int,
    created_time_field: str,
    id_field_name: str,
    url_suffix,
    top: int = 10,
    extra_seconds: int = 0,
):

    url_params = get_url_params(url)
    top = arg_to_number(url_params.get('top')) or top
    fetched_amount_of_events = arg_to_number(url_params.get('fetchedAmountOfEvents')) or 0

    if fetched_amount_of_events >= num_of_events:
        return {'items': []}

    logs = create_any_type_logs(
        start=fetched_amount_of_events,
        end=min(fetched_amount_of_events + top, num_of_events),
        created_time_field=created_time_field,
        id_field_name=id_field_name,
        extra_seconds=extra_seconds
    )
    fetched_amount_of_events += len(logs)

    return {
        'items': logs,
        'nextLink': f'{BASE_URL}/v3.0{url_suffix}?top={top}&fetchedAmountOfEvents={fetched_amount_of_events}'
    }


def _http_request_side_effect_decorator(
    num_of_workbench_logs: int = 0,
    num_of_oat_logs: int = 0,
    num_of_search_detection_logs: int = 0,
    num_of_audit_logs: int = 0
):
    def _http_request_side_effect(**kwargs):
        full_url = kwargs.get('full_url') or ''
        params = kwargs.get('params') or {}
        if UrlSuffixes.WORKBENCH.value in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_workbench_logs,
                url_suffix=UrlSuffixes.WORKBENCH.value,
                created_time_field='createdDateTime',
                id_field_name='id',
                top=10,
                extra_seconds=60
            )
        if UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_oat_logs,
                url_suffix=UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value,
                created_time_field='detectedDateTime',
                id_field_name='uuid',
                top=params.get('top') or 200,
                extra_seconds=150
            )
        if UrlSuffixes.SEARCH_DETECTIONS.value in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_search_detection_logs,
                url_suffix=UrlSuffixes.SEARCH_DETECTIONS.value,
                created_time_field='eventTime',
                id_field_name='uuid',
                top=params.get('top') or DEFAULT_MAX_LIMIT,
                extra_seconds=300
            )
        else:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_audit_logs,
                url_suffix=UrlSuffixes.AUDIT.value,
                created_time_field='loggedDateTime',
                id_field_name='loggedUser',
                top=params.get('top') or 200,
                extra_seconds=20
            )

    return _http_request_side_effect


def start_freeze_time(timestamp):
    _start_freeze_time = freeze_time(timestamp)
    _start_freeze_time.start()


class TestFetchEvents:

    @pytest.mark.parametrize(
        "last_run, integration_params, expected_updated_last_run, datetime_string_freeze_time, "
        "num_of_workbench_logs, num_of_oat_logs, num_of_search_detection_logs, num_of_audit_logs, "
        "num_of_expected_events",
        [
            (
                {},
                {'limit': 100, 'first_fetch': '1 month ago'},
                {
                    'audit_logs_time': '2023-01-01T14:59:39Z',
                    'oat_detection_logs_time': '2023-01-01T14:57:30Z',
                    'search_detection_logs_time': '2023-01-01T14:55:00Z',
                    'workbench_logs_time': '2023-01-01T14:59:00Z'
                },
                '2023-01-01T15:00:00Z',
                50,
                50,
                50,
                50,
                200
            ),
            (
                {
                    'audit_logs_time': '2023-01-01T14:59:39Z',
                    'oat_detection_logs_time': '2023-01-01T14:57:30Z',
                    'search_detection_logs_time': '2023-01-01T14:55:00Z',
                    'workbench_logs_time': '2023-01-01T14:59:00Z'
                },
                {'limit': 100},
                {
                    'audit_logs_time': '2023-01-01T15:04:39Z',
                    'oat_detection_logs_time': '2023-01-01T15:02:30Z',
                    'search_detection_logs_time': '2023-01-01T15:00:00Z',
                    'workbench_logs_time': '2023-01-01T15:04:00Z'
                },
                '2023-01-01T15:05:00Z',
                50,
                50,
                50,
                50,
                200
            ),
            (
                {
                    'audit_logs_time': '2023-01-01T15:04:39Z',
                    'oat_detection_logs_time': '2023-01-01T15:02:30Z',
                    'search_detection_logs_time': '2023-01-01T15:00:00Z',
                    'workbench_logs_time': '2023-01-01T15:04:00Z'
                },
                {'max_fetch': 20},
                {
                    'audit_logs_time': '2023-01-01T15:10:09Z',
                    'oat_detection_logs_time': '2023-01-01T15:08:00Z',
                    'search_detection_logs_time': '2023-01-01T15:05:30Z',
                    'workbench_logs_time': '2023-01-01T15:09:30Z'
                },
                '2023-01-01T15:10:30Z',
                4,
                9,
                81,
                55,
                4 + 9 + 20 + 20
            ),
            (
                {
                    'audit_logs_time': '2023-01-01T15:10:09Z',
                    'oat_detection_logs_time': '2023-01-01T15:08:00Z',
                    'search_detection_logs_time': '2023-01-01T15:05:30Z',
                    'workbench_logs_time': '2023-01-01T15:09:30Z'
                },
                {'max_fetch': 1000},
                {
                    'audit_logs_time': '2023-01-01T15:15:21Z',
                    'oat_detection_logs_time': '2023-01-01T15:13:12Z',
                    'search_detection_logs_time': '2023-01-01T15:10:42Z',
                    'workbench_logs_time': '2023-01-01T15:14:42Z'
                },
                '2023-01-01T15:15:42Z',
                1400,
                1123,
                356,
                879,
                1000 + 1000 + 356 + 879
            ),
            (
                {
                    'audit_logs_time': '2023-01-01T15:15:21Z',
                    'oat_detection_logs_time': '2023-01-01T15:13:12Z',
                    'search_detection_logs_time': '2023-01-01T15:10:42Z',
                    'workbench_logs_time': '2023-01-01T15:14:42Z'
                },
                {'max_fetch': 1000},
                {
                    'audit_logs_time': '2023-01-01T15:20:24Z',
                    'oat_detection_logs_time': '2023-01-01T15:20:45Z',
                    'search_detection_logs_time': '2023-01-01T15:15:45Z',
                    'workbench_logs_time': '2023-01-01T15:20:45Z'
                },
                '2023-01-01T15:20:45Z',
                0,
                0,
                50,
                14,
                14 + 50
            ),
        ],
    )
    def test_fetch_events_main(
        self,
        mocker,
        client: Client,
        last_run: Dict,
        integration_params: Dict,
        expected_updated_last_run: Dict,
        datetime_string_freeze_time: str,
        num_of_workbench_logs: int,
        num_of_oat_logs: int,
        num_of_search_detection_logs: int,
        num_of_audit_logs: int,
        num_of_expected_events: int
    ):
        """
        Note: the max_fetch is per single log!

        Given:
            - Case A: last_run={}, max_fetch=100, num_of_workbench_logs=50, num_of_oat_logs=50,
                      num_of_search_detection_logs=50, num_of_audit_logs=50
            - Case B: last_run=last run from Case A, max_fetch=100, num_of_workbench_logs=50, num_of_oat_logs=50,
                      num_of_search_detection_logs=50, num_of_audit_logs=50
            - Case C: last_run=last run from Case B, max_fetch=20, num_of_workbench_logs=4, num_of_oat_logs=9,
                      num_of_search_detection_logs=81, num_of_audit_logs=55
            - Case D: last_run=last run from Case C, max_fetch=1000, num_of_workbench_logs=1400, num_of_oat_logs=1123,
                      num_of_search_detection_logs=356, num_of_audit_logs=879
            - Case E: last_run=last run from Case D, max_fetch=1000, num_of_workbench_logs=0, num_of_oat_logs=0,
                      num_of_search_detection_logs=50, num_of_audit_logs=14
        When:
            - fetch-events through the main flow
        Then:
            - workbench, oat and search detection logs last run time is the last log time + 1 second added to it.
            - make sure the audit log last time is the last log without +1 second to it.
            - make sure the expected_events_length is correct according to the limit of number of events from each type.
            - make sure that if there aren't any events of a certain log-type, it would take the datetime.now

        """
        from TrendMicroVisionOneEventCollector import main

        start_freeze_time(datetime_string_freeze_time)
        mocker.patch.object(demisto, 'params', return_value=integration_params)
        mocker.patch.object(demisto, 'command', return_value='fetch-events')
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run)
        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(
                num_of_workbench_logs=num_of_workbench_logs,
                num_of_oat_logs=num_of_oat_logs,
                num_of_search_detection_logs=num_of_search_detection_logs,
                num_of_audit_logs=num_of_audit_logs
            )
        )

        set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun', return_value=last_run)
        send_events_to_xsiam_mocker = mocker.patch('TrendMicroVisionOneEventCollector.send_events_to_xsiam')
        main()

        assert set_last_run_mocker.call_args.args[0] == expected_updated_last_run
        assert send_events_to_xsiam_mocker.call_count == 1
        assert len(send_events_to_xsiam_mocker.call_args.kwargs['events']) == num_of_expected_events


@pytest.mark.parametrize(
    "last_run_time, first_fetch, log_type_time_field_name, start_time, expected_start_and_end_date_times",
    [
        (
            None,
            '3 years',
            LastRunLogsTimeFields.WORKBENCH.value,
            '2023-01-01T15:20:45Z',
            ('2020-01-01T15:20:45Z', '2023-01-01T15:20:45Z')
        ),
        (
            None,
            '3 years',
            LastRunLogsTimeFields.AUDIT.value,
            '2023-01-01T15:20:45Z',
            ('2022-07-05T15:20:45Z', '2023-01-01T15:20:45Z')
        ),
        (
            None,
            '3 years ago',
            LastRunLogsTimeFields.OBSERVED_ATTACK_TECHNIQUES.value,
            '2023-01-01T15:20:45Z',
            ('2020-01-01T15:20:45Z', '2020-12-31T15:20:45Z')
        ),
        (
            None,
            '1 month ago',
            LastRunLogsTimeFields.OBSERVED_ATTACK_TECHNIQUES.value,
            '2023-01-01T15:20:45Z',
            ('2022-12-01T15:20:45Z', '2023-01-01T15:20:45Z')
        ),
        (
            '2023-01-01T15:00:00Z',
            '1 month ago',
            LastRunLogsTimeFields.SEARCH_DETECTIONS.value,
            '2023-01-01T15:20:45Z',
            ('2023-01-01T15:00:00Z', '2023-01-01T15:20:45Z')
        )
    ],
)
def test_get_datetime_range(
    last_run_time: str | None,
    first_fetch: str,
    log_type_time_field_name: str,
    start_time: str,
    expected_start_and_end_date_times: Tuple[str, str],
):
    """
    Given:
        - Case A: last_run_time=None, first_fetch=3 years ago, log_type_time_field_name=workbench_logs_time,
                  start_time=2023-01-01T15:20:45Z
        - Case B: last_run_time=None, first_fetch=3 years ago, log_type_time_field_name=audit_logs_time,
                  start_time=2023-01-01T15:20:45Z
        - Case C: last_run_time=None, first_fetch=3 years ago, log_type_time_field_name=oat_detection_logs_time,
                  start_time=2023-01-01T15:20:45Z
        - Case D: last_run_time=None, first_fetch=1 month ago, log_type_time_field_name=oat_detection_logs_time,
                  start_time=2023-01-01T15:20:45Z
        - Case E: last_run_time=2023-01-01T15:00:00Z, first_fetch=1 month ago,
                  log_type_time_field_name=search_detection_logs_time, start_time=2023-01-01T15:20:45Z
    When:
        - running get datetime range
    Then:
        - Case A: make sure start time is 3 years ago and end time is "now".
        - Case B: make sure the start time is 180 days ago and end time is "now"
        - Case C: make sure the start time is 3 years ago and the time is 1 year after.
        - Case D: make sure the start time is 1 month ago and end time is "now"
        - Case E: make sure the start time is the last_run_time and end time is "now"
    """
    from TrendMicroVisionOneEventCollector import get_datetime_range
    start_freeze_time(start_time)

    assert get_datetime_range(
        last_run_time=last_run_time, first_fetch=first_fetch, log_type_time_field_name=log_type_time_field_name
    ) == expected_start_and_end_date_times


def test_module_main_flow(mocker):
    """
    Given:
        - 1 log of each type
    When:
        - test-module through main
    Then:
        - make sure that test-module returns 'ok'
        - make sure send_events_to_xsiam function was not called
    """
    from TrendMicroVisionOneEventCollector import main

    start_freeze_time('2023-01-01T15:20:45Z')

    mocker.patch.object(demisto, 'params', return_value={'first_fetch': '1 year ago'})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(
        BaseClient,
        '_http_request',
        side_effect=_http_request_side_effect_decorator(
            num_of_workbench_logs=1,
            num_of_oat_logs=1,
            num_of_search_detection_logs=1,
            num_of_audit_logs=1
        )
    )

    return_results_mocker = mocker.patch('TrendMicroVisionOneEventCollector.return_results')
    send_events_to_xsiam_mocker = mocker.patch('TrendMicroVisionOneEventCollector.send_events_to_xsiam')

    main()

    assert not send_events_to_xsiam_mocker.called
    assert return_results_mocker.call_args.args[0] == 'ok'


@pytest.mark.parametrize(
    "args, expected_outputs",
    [
        (
            {
                'from_time': '2023-01-01T15:00:45Z',
                'to_time': '2023-01-01T15:20:45Z',
                'log_type': f'{LogTypes.AUDIT.value},{LogTypes.SEARCH_DETECTIONS.value},'
                            f'{LogTypes.OBSERVED_ATTACK_TECHNIQUES.value},{LogTypes.WORKBENCH.value}'
            },
            [
                {'Id': 1, 'Time': '2023-01-01T15:19:44Z', 'Type': 'Workbench'},
                {'Id': 1, 'Time': '2023-01-01T15:18:14Z', 'Type': 'Observed Attack Technique'},
                {'Id': 1, 'Time': '2023-01-01T15:15:44Z', 'Type': 'Search Detection'},
                {'Id': 1, 'Time': '2023-01-01T15:20:24Z', 'Type': 'Audit'}
            ]
        ),
        (
            {'from_time': '2023-01-01T15:00:45Z', 'to_time': '2023-01-01T15:20:45Z', 'log_type': LogTypes.AUDIT.value},
            [
                {'Id': 1, 'Time': '2023-01-01T15:20:24Z', 'Type': 'Audit'}
            ]
        ),
        (
            {
                'from_time': '2023-01-01T15:00:45Z',
                'to_time': '2023-01-01T15:20:45Z',
                'log_type': LogTypes.OBSERVED_ATTACK_TECHNIQUES.value
            },
            [
                {'Id': 1, 'Time': '2023-01-01T15:18:14Z', 'Type': 'Observed Attack Technique'},
            ]
        ),
        (
            {
                'from_time': '2023-01-01T15:00:45Z',
                'to_time': '2023-01-01T15:20:45Z',
                'log_type': LogTypes.SEARCH_DETECTIONS.value
            },
            [
                {'Id': 1, 'Time': '2023-01-01T15:15:44Z', 'Type': 'Search Detection'},
            ]
        ),
        (
            {
                'from_time': '2023-01-01T15:00:45Z',
                'to_time': '2023-01-01T15:20:45Z',
                'log_type': LogTypes.WORKBENCH.value
            },
            [
                {'Id': 1, 'Time': '2023-01-01T15:19:44Z', 'Type': 'Workbench'},
            ]
        ),
    ],
)
def test_get_events_command_main_flow(mocker, args: Dict, expected_outputs: List[Dict]):
    """
    Given:
        - Case A: log_type=all
        - Case B: log_type=audit_logs
        - Case C: log_type=oat_detection_logs
        - Case D: log_type=search_detection_logs
        - Case E: log_type=workbench_logs
    When:
        - running trend-micro-vision-one-get-events through main
    Then:
        - make sure when log_type=all, all events are returned.
        - make sure for each log type only the correct log will be returned.
    """
    from TrendMicroVisionOneEventCollector import main

    start_freeze_time('2023-01-01T15:20:45Z')

    mocker.patch.object(demisto, 'params', return_value={'first_fetch': '1 year ago'})
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'command', return_value='trend-micro-vision-one-get-events')
    mocker.patch.object(
        BaseClient,
        '_http_request',
        side_effect=_http_request_side_effect_decorator(
            num_of_workbench_logs=1,
            num_of_oat_logs=1,
            num_of_search_detection_logs=1,
            num_of_audit_logs=1
        )
    )

    return_results_mocker = mocker.patch('TrendMicroVisionOneEventCollector.return_results')

    main()

    assert return_results_mocker.call_args.args[0].outputs == expected_outputs
    args['log_type']
    assert "events for log_types=" in return_results_mocker.call_args.args[0].readable_output

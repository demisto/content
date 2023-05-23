from freezegun import freeze_time

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import pytest
import pytz
from urllib.parse import parse_qs, urlparse
from TrendMicroVisionOneEventCollector import DATE_FORMAT, Client, DEFAULT_MAX_LIMIT


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


def create_any_type_logs(start: int, end: int, created_time_field: str):
    return [
        {
            'id': i,
            created_time_field: (
                datetime.now(tz=pytz.utc) - timedelta(seconds=i)
            ).strftime(DATE_FORMAT) if created_time_field != 'eventTime' else int(
                (datetime.now(tz=pytz.utc) - timedelta(seconds=i)).timestamp()
            ) * 1000
        } for i in range(start + 1, end + 1)
    ]


def create_logs_mocks(url: str, num_of_events: int, created_time_field: str, url_suffix, top: int = 10):

    url_params = get_url_params(url)
    top = arg_to_number(url_params.get('top')) or top
    fetched_amount_of_events = arg_to_number(url_params.get('fetchedAmountOfEvents')) or 0

    if fetched_amount_of_events >= num_of_events:
        return {'items': []}

    logs = create_any_type_logs(
        start=fetched_amount_of_events,
        end=min(fetched_amount_of_events + top, num_of_events),
        created_time_field=created_time_field
    )
    fetched_amount_of_events += len(logs)

    return {
            'items': logs,
            'nextLink': f'{BASE_URL}/v3.0/{url_suffix}?top={top}&fetchedAmountOfEvents={fetched_amount_of_events}'
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
        if 'workbench/alerts' in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_workbench_logs,
                url_suffix='workbench/alerts',
                created_time_field='createdDateTime',
                top=10
            )
        if 'oat/detections' in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_oat_logs,
                url_suffix='oat/detections',
                created_time_field='detectedDateTime',
                top=params.get('top') or 200
            )
        if 'search/detections' in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_search_detection_logs,
                url_suffix='search/detections',
                created_time_field='eventTime',
                top=params.get('top') or DEFAULT_MAX_LIMIT
            )
        else:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_audit_logs,
                url_suffix='audit/logs',
                created_time_field='loggedDateTime',
                top=params.get('top') or 200
            )

    return _http_request_side_effect


def start_freeze_time(timestamp):
    _start_freeze_time = freeze_time(timestamp)
    _start_freeze_time.start()


class TestFetchEvents:

    @pytest.mark.parametrize(
        "last_run, integration_params, expected_updated_last_run, datetime_string_freeze_time, "
        "num_of_workbench_logs, num_of_oat_logs, num_of_search_detection_logs, num_of_audit_logs",
        [
            (
                {},
                {'limit': 100, 'first_fetch': '1 month ago'},
                {
                    'workbench_logs_time': '2023-01-01T15:00:00Z',
                    'oat_detection_logs_time': '2023-01-01T15:00:00Z',
                    'search_detection_logs_time': '2023-01-01T15:00:00Z',
                    'audit_logs_time': '2023-01-01T14:59:59Z'
                },
                '2023-01-01T15:00:00Z',
                50,
                50,
                50,
                50
            ),
            (
                {
                    'workbench_logs_time': '2023-01-01T15:00:00Z',
                    'oat_detection_logs_time': '2023-01-01T15:00:00Z',
                    'search_detection_logs_time': '2023-01-01T15:00:00Z',
                    'audit_logs_time': '2023-01-01T14:59:59Z'
                },
                {'limit': 100},
                {
                    'workbench_logs_time': '2023-01-01T15:05:00Z',
                    'oat_detection_logs_time': '2023-01-01T15:05:00Z',
                    'search_detection_logs_time': '2023-01-01T15:05:00Z',
                    'audit_logs_time': '2023-01-01T15:04:59Z'
                },
                '2023-01-01T15:05:00Z',
                50,
                50,
                50,
                50
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
        num_of_audit_logs: int
    ):
        """
        Note: the limit is per single log!

        Given:
            - Case A: last_run={}, limit=100, num_of_workbench_logs=50, num_of_oat_logs=50,
                      num_of_search_detection_logs=50, num_of_audit_logs=50
            - Case B: last_run=last run from Case A, limit=100, num_of_workbench_logs=50, num_of_oat_logs=50,
                      num_of_search_detection_logs=50, num_of_audit_logs=50
        When:
            - fetch-events through the main flow
        Then:
            - workbench, oat and search detection logs last run time is the last log time + 1 second added to it.
            - make sure the audit log last time is the last log without +1 second to it.
            - make sure the expected_events_length is the sum of all the logs.

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
        assert len(send_events_to_xsiam_mocker.call_args.kwargs['events']) == \
               num_of_workbench_logs + num_of_oat_logs + num_of_search_detection_logs + num_of_audit_logs

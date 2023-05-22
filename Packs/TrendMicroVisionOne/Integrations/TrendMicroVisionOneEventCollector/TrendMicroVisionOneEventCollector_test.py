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


def _http_request_side_effect_decorator(num_of_events):
    def _http_request_side_effect(**kwargs):
        full_url = kwargs.get('full_url') or ''
        params = kwargs.get('params') or {}
        if 'workbench/alerts' in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_events,
                url_suffix='workbench/alerts',
                created_time_field='createdDateTime',
                top=10
            )
        if 'oat/detections' in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_events,
                url_suffix='oat/detections',
                created_time_field='detectedDateTime',
                top=params.get('top') or 200
            )
        if 'search/detections' in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_events,
                url_suffix='search/detections',
                created_time_field='eventTime',
                top=params.get('top') or DEFAULT_MAX_LIMIT
            )
        else:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_events,
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
        "last_run, integration_params, expected_updated_last_run, "
        "num_of_events_for_each_log_type, expected_events_length, datetime_string_freeze_time",
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
                50,
                200,
                '2023-01-01T15:00:00Z'
            ),
        ],
    )
    def test_fetch_events_main(
        self,
        mocker, client: Client,
        last_run: Dict,
        integration_params: Dict,
        expected_updated_last_run: Dict,
        num_of_events_for_each_log_type: int,
        expected_events_length: int,
        datetime_string_freeze_time: str
    ):
        """
        Given:
            - Case A: last_run={}, limit=100, num_of_events_for_each_log_type=50
        When:
            - fetch-events through the main flow
        Then:
            - Case A:
                1. workbench, oat and search detection logs last run time is the last log + 1 second added to it.
                2. make sure the audit log last time is the last log without +1 second to it.
                3. make sure the expected_events_length = 200
        """
        from TrendMicroVisionOneEventCollector import main

        start_freeze_time(datetime_string_freeze_time)
        mocker.patch.object(demisto, 'params', return_value=integration_params)
        mocker.patch.object(demisto, 'command', return_value='fetch-events')
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run)
        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(num_of_events=num_of_events_for_each_log_type)
        )

        set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun', return_value=last_run)
        send_events_to_xsiam_mocker = mocker.patch('TrendMicroVisionOneEventCollector.send_events_to_xsiam')
        main()

        assert set_last_run_mocker.call_args.args[0] == expected_updated_last_run
        assert len(send_events_to_xsiam_mocker.call_args.kwargs['events']) == expected_events_length

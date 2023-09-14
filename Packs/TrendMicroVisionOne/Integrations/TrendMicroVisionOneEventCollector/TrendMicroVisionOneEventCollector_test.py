from freezegun import freeze_time

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import pytest
import pytz
from urllib.parse import parse_qs, urlparse
from TrendMicroVisionOneEventCollector import (
    DATE_FORMAT, Client, DEFAULT_MAX_LIMIT, LastRunLogsStartTimeFields, UrlSuffixes, LogTypes
)


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


def create_any_type_logs(
    start: int,
    end: int,
    created_time_field: str,
    id_field_name: str,
    last_event_fetch_time: str | None,
    extra_seconds: int = 0,
    ascending_order: bool = False,
):
    """
    Create mocks of any type of log based on multiple parameters
    """
    last_event_fetch_time = last_event_fetch_time or (datetime.now() - timedelta(minutes=1)).strftime(DATE_FORMAT)
    if ascending_order:
        return [
            {
                id_field_name: i,
                created_time_field: (  # type: ignore
                    dateparser.parse(last_event_fetch_time) + timedelta(seconds=i + extra_seconds)  # type: ignore
                ).strftime(DATE_FORMAT) if created_time_field != 'eventTime' else int(
                    (dateparser.parse(last_event_fetch_time) + timedelta(seconds=i + extra_seconds)).timestamp()  # type: ignore
                ) * 1000
            } for i in range(start + 1, end + 1)
        ]
    # descending order
    return [
        {
            id_field_name: end - i + 1,
            created_time_field: (
                datetime.now(tz=pytz.utc) - timedelta(seconds=i + start + extra_seconds)
            ).strftime(DATE_FORMAT) if created_time_field != 'eventTime' else int(
                (datetime.now(tz=pytz.utc) - timedelta(seconds=i + start + extra_seconds)).timestamp()
            ) * 1000
        } for i in range(start + 1, end + 1)
    ]


def create_logs_mocks(
    url: str,
    num_of_events: int,
    created_time_field: str,
    id_field_name: str,
    last_event_fetch_time: str | None,
    url_suffix,
    top: int = 10,
    extra_seconds: int = 0,
) -> Dict:
    """
    Create mocks of any type of log, then returns the logs and pagination link if needed to proceed.
    """
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
        last_event_fetch_time=last_event_fetch_time,
        extra_seconds=extra_seconds,
        ascending_order=url_suffix in [UrlSuffixes.AUDIT.value, UrlSuffixes.WORKBENCH.value]
    )
    fetched_amount_of_events += len(logs)

    response = {
        'items': logs,
    }

    if fetched_amount_of_events < num_of_events:
        response['nextLink'] = f'{BASE_URL}/v3.0{url_suffix}?top={top}&fetchedAmountOfEvents={fetched_amount_of_events}'

    return response


def _http_request_side_effect_decorator(
    last_workbench_time: str | None = None,
    last_oat_time: str | None = None,
    last_search_detection_logs: str | None = None,
    last_audit_log_time: str | None = None,
    num_of_workbench_logs: int = 0,
    num_of_oat_logs: int = 0,
    num_of_search_detection_logs: int = 0,
    num_of_audit_logs: int = 0
):
    """
    general side effect function for creating logs from any type.
    """
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
                last_event_fetch_time=last_workbench_time
            )
        if UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_oat_logs,
                url_suffix=UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value,
                created_time_field='detectedDateTime',
                id_field_name='uuid',
                top=params.get('top') or 200,
                last_event_fetch_time=last_oat_time
            )
        if UrlSuffixes.SEARCH_DETECTIONS.value in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_search_detection_logs,
                url_suffix=UrlSuffixes.SEARCH_DETECTIONS.value,
                created_time_field='eventTime',
                id_field_name='uuid',
                top=params.get('top') or DEFAULT_MAX_LIMIT,
                last_event_fetch_time=last_search_detection_logs
            )
        else:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_audit_logs,
                url_suffix=UrlSuffixes.AUDIT.value,
                created_time_field='loggedDateTime',
                id_field_name='loggedUser',
                top=params.get('top') or 200,
                last_event_fetch_time=last_audit_log_time
            )

    return _http_request_side_effect


def start_freeze_time(timestamp):
    _start_freeze_time = freeze_time(timestamp)
    _start_freeze_time.start()


class TestFetchEvents:

    def test_fetch_events_main_flow_no_new_logs(self, mocker):
        """
        Given:
           - no logs from any kind
           - last_run = {
                'workbench_start_time': '2023-01-01T14:00:00Z',
                'found_workbench_logs': [],
                'oat_detection_start_time': '2023-01-01T14:00:00Z',
                'dedup_found_oat_logs': [],
                'pagination_found_oat_logs': [],
                'oat_detection_next_link': '',
                'search_detection_start_time': '2023-01-01T14:00:00Z',
                'dedup_found_search_detection_logs': [],
                'pagination_found_search_detection_logs': [],
                'search_detection_next_link': '',
                'audit_start_time': '2023-01-01T14:00:00Z',
                'found_audit_logs': []
            }
           - max_fetch = 1000

        When:
           - running fetch-events through the main flow

        Then:
           - make sure no events are returned
           - make sure no last run time remains the same for every log.

        """
        from TrendMicroVisionOneEventCollector import main

        start_freeze_time('2023-01-01T15:00:00Z')

        mocker.patch.object(demisto, 'params', return_value={"max_fetch": 1000})
        mocker.patch.object(demisto, 'command', return_value='fetch-events')
        mocker.patch.object(
            demisto,
            'getLastRun',
            return_value={
                'workbench_start_time': '2023-01-01T14:00:00Z',
                'found_workbench_logs': [],
                'oat_detection_start_time': '2023-01-01T14:00:00Z',
                'dedup_found_oat_logs': [],
                'pagination_found_oat_logs': [],
                'oat_detection_next_link': '',
                'search_detection_start_time': '2023-01-01T14:00:00Z',
                'dedup_found_search_detection_logs': [],
                'pagination_found_search_detection_logs': [],
                'search_detection_next_link': '',
                'audit_start_time': '2023-01-01T14:00:00Z',
                'found_audit_logs': []
            }
        )
        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(
                last_workbench_time="2023-01-01T14:00:00Z",
                last_audit_log_time="2023-01-01T14:00:00Z",
                last_oat_time="2023-01-01T14:00:00Z",
                last_search_detection_logs="2023-01-01T14:00:00Z"
            )
        )

        set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun')
        send_events_to_xsiam_mocker = mocker.patch('TrendMicroVisionOneEventCollector.send_events_to_xsiam')
        main()

        assert set_last_run_mocker.call_args.args[0] == {
            'workbench_start_time': '2023-01-01T14:00:01Z',
            'found_workbench_logs': [],
            'oat_detection_start_time': '2023-01-01T14:00:01Z',
            'dedup_found_oat_logs': [],
            'pagination_found_oat_logs': [],
            'oat_detection_next_link': '',
            'search_detection_start_time': '2023-01-01T14:00:01Z',
            'dedup_found_search_detection_logs': [],
            'pagination_found_search_detection_logs': [],
            'search_detection_next_link': '',
            'audit_start_time': '2023-01-01T14:00:01Z',
            'found_audit_logs': []
        }

        assert send_events_to_xsiam_mocker.call_count == 1
        # 1000 workbench + 1000 oat + 500 search detections + 500 audit logs
        assert len(send_events_to_xsiam_mocker.call_args.kwargs['events']) == 0

    def test_fetch_events_main_flow_no_last_run(self, mocker):
        """
        Given:
           - 1000 workbench + 1000 oat + 500 search detections + 500 audit logs
           - no last run
           - max_fetch = 1000

        When:
           - running fetch-events through the main flow

        Then:
           - make sure last run is correct
           - make sure 3000 logs were sent

        """
        from TrendMicroVisionOneEventCollector import main

        start_freeze_time('2023-01-01T15:00:00Z')

        mocker.patch.object(demisto, 'params', return_value={"max_fetch": 1000})
        mocker.patch.object(demisto, 'command', return_value='fetch-events')
        mocker.patch.object(demisto, 'getLastRun', return_value={})
        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(
                num_of_workbench_logs=1500,
                num_of_oat_logs=1500,
                num_of_search_detection_logs=500,
                num_of_audit_logs=500,
                last_workbench_time="2023-01-01T14:00:00Z",
                last_audit_log_time="2023-01-01T14:00:00Z"
            )
        )

        set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun')
        send_events_to_xsiam_mocker = mocker.patch('TrendMicroVisionOneEventCollector.send_events_to_xsiam')
        main()

        assert set_last_run_mocker.call_args.args[0] == {
            'workbench_start_time': '2023-01-01T14:16:40Z',
            'found_workbench_logs': [1000],
            'oat_detection_start_time': '2023-01-01T14:59:59Z',
            'dedup_found_oat_logs': [1000],
            'pagination_found_oat_logs': [1000],
            'oat_detection_next_link': 'https://api.xdr.trendmicro.com/v3.0/oat/detections?top=1000&fetchedAmountOfEvents=1000',
            'search_detection_start_time': '2023-01-01T14:59:59Z', 'dedup_found_search_detection_logs': [500],
            'pagination_found_search_detection_logs': [], 'search_detection_next_link': '',
            'audit_start_time': '2023-01-01T14:08:20Z',
            'found_audit_logs': ['77b363584231085e7909d48e0e103a07b6c10127e00da6e4739f07248eee7682']
        }

        assert send_events_to_xsiam_mocker.call_count == 1
        # 1000 workbench + 1000 oat + 500 search detections + 500 audit logs
        assert len(send_events_to_xsiam_mocker.call_args.kwargs['events']) == 3000

    def test_get_workbench_logs_no_last_run(self, mocker, client: Client):
        """
        Given:
         - no last run
         - limit = 500
         - 1000 workbench events

        When:
         - running get_workbench_logs function

        Then:
         - make sure only 500 events are returned
         - make sure latest workbench event is saved in the workbench_logs_time without adding 1 second to it.
         - make sure in the cache we will have event with 500 id as its the event that happened in the last second.
        """
        from TrendMicroVisionOneEventCollector import get_workbench_logs
        start_freeze_time('2023-01-01T15:00:00Z')

        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(num_of_workbench_logs=1000)
        )

        workbench_logs, updated_last_run = get_workbench_logs(
            client=client, first_fetch='1 month ago', last_run={}, limit=500
        )

        assert len(workbench_logs) == 500
        assert updated_last_run == {
            LastRunLogsStartTimeFields.WORKBENCH.value: '2023-01-01T15:07:20Z', 'found_workbench_logs': [500]
        }
        assert workbench_logs[-1]['_time'] == '2023-01-01T15:07:20Z'

    def test_get_workbench_logs_with_last_run(self, mocker, client: Client):
        """
        Given:
         - last_run={'workbench_logs_time': '2023-01-01T14:00:00Z', 'found_workbench_logs': [1, 2, 3, 4, 5, 6, 7, 8]}
         - limit = 500
         - 200 workbench events

        When:
         - running get_workbench_logs function

        Then:
         - make sure only 192 events are returned as there are 8 events in cache from last run
         - make sure latest workbench event is saved in the workbench_logs_time without adding 1 second to it.
        """
        from TrendMicroVisionOneEventCollector import get_workbench_logs
        start_freeze_time('2023-01-01T15:00:00Z')

        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(
                num_of_workbench_logs=200, last_workbench_time='2023-01-01T14:00:00Z'
            )
        )

        workbench_logs, updated_last_run = get_workbench_logs(
            client=client,
            first_fetch='1 month ago',
            last_run={LastRunLogsStartTimeFields.WORKBENCH.value: '2023-01-01T14:00:00Z',
                      'found_workbench_logs': [1, 2, 3, 4, 5, 6, 7, 8]},
            limit=500
        )

        assert len(workbench_logs) == 192
        assert updated_last_run == {
            LastRunLogsStartTimeFields.WORKBENCH.value: '2023-01-01T14:03:20Z', 'found_workbench_logs': [200]}
        assert workbench_logs[-1]['_time'] == '2023-01-01T14:03:20Z'

    def test_get_observed_attack_techniques_logs_no_last_run(self, mocker, client: Client):
        """
        Given:
         - no last run
         - limit = 500
         - 1000 oat events

        When:
         - running get_observed_attack_techniques_logs function

        Then:
         - make sure only 500 events are returned
         - make sure latest observed attack technique event is saved in the oat_detection_logs_time without adding 1 second to it.
        """
        from TrendMicroVisionOneEventCollector import get_observed_attack_techniques_logs
        start_freeze_time('2023-01-01T15:00:00Z')

        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(num_of_oat_logs=1000)
        )

        observed_attack_techniques_logs, updated_last_run = get_observed_attack_techniques_logs(
            client=client,
            first_fetch='1 month ago',
            last_run={},
            limit=500
        )

        assert len(observed_attack_techniques_logs) == 500
        assert updated_last_run == {
            'oat_detection_start_time': '2023-01-01T14:59:59Z',
            'dedup_found_oat_logs': [1000],
            'pagination_found_oat_logs': [],
            'oat_detection_next_link': ''
        }

    def test_get_observed_attack_techniques_logs_with_last_run(self, mocker, client: Client):
        """
        Given:
         - last_run={
                'oat_detection_start_time': '2023-01-01T14:00:00Z',
                'dedup_found_oat_logs': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                'pagination_found_oat_logs': [],
                'oat_detection_next_link': f'{BASE_URL}/v3.0{UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value}'
                                           f'?top=1000&fetchedAmountOfEvents=100'
            }
         - limit = 500
         - 300 oat events

        When:
         - running get_observed_attack_techniques_logs function

        Then:
         - make sure only 185 events are returned
         - make sure latest observed attack technique event is saved in the oat_detection_logs_time without adding 1 second to it.
        """
        from TrendMicroVisionOneEventCollector import get_observed_attack_techniques_logs
        start_freeze_time('2023-01-01T15:00:00Z')

        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(num_of_oat_logs=300, last_oat_time='2023-01-01T14:00:00Z')
        )

        observed_attack_techniques_logs, updated_last_run = get_observed_attack_techniques_logs(
            client=client,
            first_fetch='1 month ago',
            last_run={
                'oat_detection_start_time': '2023-01-01T14:00:00Z',
                'dedup_found_oat_logs': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                'pagination_found_oat_logs': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                'oat_detection_next_link': f'{BASE_URL}/v3.0{UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value}'
                                           f'?top=1000&fetchedAmountOfEvents=100'
            },
            limit=500
        )

        assert len(observed_attack_techniques_logs) == 185
        assert updated_last_run == {
            'oat_detection_start_time': '2023-01-01T14:00:00Z',
            'dedup_found_oat_logs': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            'pagination_found_oat_logs': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            'oat_detection_next_link': ''
        }

    def test_get_search_detection_logs_no_last_run(self, mocker, client: Client):
        """
        Given:
         - no last run
         - limit = 500
         - 1000 search detection events

        When:
         - running get_search_detection_logs function

        Then:
         - make sure only 500 events are returned
         - make sure latest observed attack technique event is saved in
           the search_detection_logs_time without adding 1 second to it.
        """
        from TrendMicroVisionOneEventCollector import get_search_detection_logs
        start_freeze_time('2023-01-01T15:00:00Z')

        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(num_of_search_detection_logs=1000)
        )

        search_detection_logs, updated_last_run = get_search_detection_logs(
            client=client,
            first_fetch='1 month ago',
            last_run={},
            limit=500
        )

        assert len(search_detection_logs) == 500
        assert updated_last_run == {
            'search_detection_start_time': '2023-01-01T14:59:59Z',
            'dedup_found_search_detection_logs': [500],
            'pagination_found_search_detection_logs': [500],
            'search_detection_next_link': 'https://api.xdr.trendmicro.com/v3.0/search/detections?top=500'
                                          '&fetchedAmountOfEvents=500'
        }

    def test_get_search_detection_logs_with_last_run(self, mocker, client: Client):
        """
        Given:
         - last_run = {
                'search_detection_start_time': '2023-01-01T14:00:00Z',
                'dedup_found_search_detection_logs': [1, 2, 3, 4, 5, 6, 7],
                'pagination_found_search_detection_logs': [],
                'search_detection_next_link': 'https://api.xdr.trendmicro.com/v3.0/search/detections?top=200'
                                              '&fetchedAmountOfEvents=500'
            }
         - limit = 500
         - 200 detection events

        When:
         - running get_search_detection_logs function

        Then:
         - make sure only 193 events are returned
         - make sure latest search detection log event time is saved in
           the search_detection_logs_time without adding 1 second to it.
        """
        from TrendMicroVisionOneEventCollector import get_search_detection_logs
        start_freeze_time('2023-01-01T15:00:00Z')

        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(
                num_of_search_detection_logs=700, last_search_detection_logs='2023-01-01T14:00:00Z'
            )
        )

        search_detection_logs, updated_last_run = get_search_detection_logs(
            client=client,
            first_fetch='1 month ago',
            last_run={
                'search_detection_start_time': '2023-01-01T14:00:00Z',
                'dedup_found_search_detection_logs': [1, 2, 3, 4, 5, 6, 7],
                'pagination_found_search_detection_logs': [1, 2, 3, 4, 5, 6, 7],
                'search_detection_next_link': 'https://api.xdr.trendmicro.com/v3.0/search/detections?top=200'
                                              '&fetchedAmountOfEvents=500'
            },
            limit=500
        )

        assert len(search_detection_logs) == 193
        assert updated_last_run == {
            'search_detection_start_time': '2023-01-01T14:00:00Z',
            'dedup_found_search_detection_logs': [1, 2, 3, 4, 5, 6, 7],
            'pagination_found_search_detection_logs': [1, 2, 3, 4, 5, 6, 7],
            'search_detection_next_link': ''
        }

    def test_get_audit_logs_no_last_run(self, mocker, client: Client):
        """
        Given:
         - no last run
         - limit = 500
         - 200 audit logs

        When:
         - running get_audit_logs function

        Then:
         - make sure only 500 events are returned
         - make sure in the cache we will have event with hash of the 500 id as its the event that happened in the last second.
        """
        from TrendMicroVisionOneEventCollector import get_audit_logs
        start_freeze_time('2023-01-01T15:00:00Z')

        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(num_of_audit_logs=1000, last_audit_log_time='2023-01-01T14:00:00Z')
        )

        audit_logs, updated_last_run = get_audit_logs(
            client=client,
            first_fetch='1 month ago',
            last_run={},
            limit=500
        )

        assert len(audit_logs) == 500
        assert updated_last_run == {
            LastRunLogsStartTimeFields.AUDIT.value: '2023-01-01T14:08:20Z',
            'found_audit_logs': ['77b363584231085e7909d48e0e103a07b6c10127e00da6e4739f07248eee7682']
        }

    def test_get_audit_logs_with_last_run(self, mocker, client: Client):
        """
        Given:
         - last_run={'audit_logs_time': '2023-01-01T14:00:00Z'}
         - limit = 500
         - 200 audit logs

        When:
         - running get_audit_logs function

        Then:
         - make sure only 200 events are returned
         - make sure in the cache we will have event with hash of the 200 id as its the event that happened in the last second.
        """
        from TrendMicroVisionOneEventCollector import get_audit_logs
        start_freeze_time('2023-01-01T15:00:00Z')

        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(num_of_audit_logs=200, last_audit_log_time='2023-01-01T14:00:00Z')
        )

        audit_logs, updated_last_run = get_audit_logs(
            client=client,
            first_fetch='1 month ago',
            last_run={LastRunLogsStartTimeFields.AUDIT.value: '2023-01-01T14:00:00Z'},
            limit=500
        )

        assert len(audit_logs) == 200
        assert updated_last_run == {
            LastRunLogsStartTimeFields.AUDIT.value: '2023-01-01T14:03:20Z',
            'found_audit_logs': ['4410bac4975e15bc234ee627129e46665744349bb59830968a2e4769fe0afc0e']
        }


@pytest.mark.parametrize(
    "last_run_time, first_fetch, log_type_time_field_name, start_time, expected_start_and_end_date_times",
    [
        (
            None,
            '3 years',
            LastRunLogsStartTimeFields.WORKBENCH.value,
            '2023-01-01T15:20:45Z',
            ('2020-01-01T15:20:45Z', '2023-01-01T15:20:45Z')
        ),
        (
            None,
            '3 years',
            LastRunLogsStartTimeFields.AUDIT.value,
            '2023-01-01T15:20:45Z',
            ('2022-07-05T15:20:45Z', '2023-01-01T15:20:45Z')
        ),
        (
            None,
            '3 years ago',
            LastRunLogsStartTimeFields.OBSERVED_ATTACK_TECHNIQUES.value,
            '2023-01-01T15:20:45Z',
            ('2020-01-01T15:20:45Z', '2020-12-31T15:20:45Z')
        ),
        (
            None,
            '1 month ago',
            LastRunLogsStartTimeFields.OBSERVED_ATTACK_TECHNIQUES.value,
            '2023-01-01T15:20:45Z',
            ('2022-12-01T15:20:45Z', '2023-01-01T15:20:45Z')
        ),
        (
            '2023-01-01T15:00:00Z',
            '1 month ago',
            LastRunLogsStartTimeFields.SEARCH_DETECTIONS.value,
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
    expected_start_and_end_date_times: tuple[str, str],
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
        - Case C: make sure the start time is 3 years ago and the time is 1 day after.
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
                {
                    "Id": 1,
                    "Time": "2023-01-01T15:19:46Z",
                    "Type": "Workbench"
                },
                {
                    "Id": 1,
                    "Time": "2023-01-01T15:20:44Z",
                    "Type": "Observed Attack Technique"
                },
                {
                    "Id": 1,
                    "Time": "2023-01-01T15:20:44Z",
                    "Type": "Search Detection"
                },
                {
                    "Id": 1,
                    "Time": "2023-01-01T15:19:46Z",
                    "Type": "Audit"
                }
            ]
        ),
        (
            {'from_time': '2023-01-01T15:00:45Z', 'to_time': '2023-01-01T15:20:45Z', 'log_type': LogTypes.AUDIT.value},
            [{'Id': 1, 'Time': '2023-01-01T15:19:46Z', 'Type': 'Audit'}]
        ),
        (
            {
                'from_time': '2023-01-01T15:00:45Z',
                'to_time': '2023-01-01T15:20:45Z',
                'log_type': LogTypes.OBSERVED_ATTACK_TECHNIQUES.value
            },
            [{'Id': 1, 'Time': '2023-01-01T15:20:44Z', 'Type': 'Observed Attack Technique'}]
        ),
        (
            {
                'from_time': '2023-01-01T15:00:45Z',
                'to_time': '2023-01-01T15:20:45Z',
                'log_type': LogTypes.SEARCH_DETECTIONS.value
            },
            [{'Id': 1, 'Time': '2023-01-01T15:20:44Z', 'Type': 'Search Detection'}]
        ),
        (
            {
                'from_time': '2023-01-01T15:00:45Z',
                'to_time': '2023-01-01T15:20:45Z',
                'log_type': LogTypes.WORKBENCH.value
            },
            [{'Id': 1, 'Time': '2023-01-01T15:19:46Z', 'Type': 'Workbench'}]
        )
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
    assert "events for log_types=" in return_results_mocker.call_args.args[0].readable_output

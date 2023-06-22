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

    return {
        'items': logs,
        'nextLink': f'{BASE_URL}/v3.0{url_suffix}?top={top}&fetchedAmountOfEvents={fetched_amount_of_events}'
    }


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

    @pytest.mark.parametrize(
        "last_run, integration_params, expected_updated_last_run, datetime_string_freeze_time, "
        "num_of_workbench_logs, num_of_oat_logs, num_of_search_detection_logs, num_of_audit_logs, "
        "num_of_expected_events",
        [
            (
                {},
                {'max_fetch': 100, 'first_fetch': '1 month ago'},
                {
                    'audit_logs_time': '2023-01-01T14:59:49Z',
                    'oat_detection_logs_time': '2023-01-01T14:59:59Z',
                    'search_detection_logs_time': '2023-01-01T14:59:59Z',
                    'workbench_logs_time': '2023-01-01T14:59:50Z',
                    'found_audit_logs': ['269308b9e721fbc755e03ce501642697db992274e035496577fcef470e3ea860'],
                    'found_oat_logs': [50],
                    'found_search_detection_logs': [50],
                    'found_workbench_logs': [50],
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
                    'audit_logs_time': '2023-01-01T14:59:58Z',
                    'oat_detection_logs_time': '2023-01-01T14:59:59Z',
                    'search_detection_logs_time': '2023-01-01T14:59:59Z',
                    'workbench_logs_time': '2023-01-01T14:59:59Z',
                    'found_audit_logs': ['8268fed996476cb055174e5b5c27fad5281c2fd7ee81cf9e9539a3a53a7ddbbe'],
                    'found_oat_logs': [1, 2, 3],
                    'found_search_detection_logs': [1, 2],
                    'found_workbench_logs': [1],
                },
                {'max_fetch': 100},
                {
                    'audit_logs_time': '2023-01-01T15:00:47Z',
                    'oat_detection_logs_time': '2023-01-01T15:00:59Z',
                    'search_detection_logs_time': '2023-01-01T15:00:59Z',
                    'workbench_logs_time': '2023-01-01T15:00:49Z',
                    'found_audit_logs': ['bb5e99823e4c65cfe33692829d55a7b2df3795a0243ed4a6cc8383a04027b9a7'],
                    'found_oat_logs': [50],
                    'found_search_detection_logs': [50],
                    'found_workbench_logs': [50],
                },
                '2023-01-01T15:01:00Z',
                50,
                50,
                50,
                50,
                49 + 47 + 48 + 49
            ),
            (
                {
                    'audit_logs_time': '2023-01-01T15:00:58Z',
                    'oat_detection_logs_time': '2023-01-01T15:00:56Z',
                    'search_detection_logs_time': '2023-01-01T15:00:57Z',
                    'workbench_logs_time': '2023-01-01T15:00:58Z',
                    'found_audit_logs': [],
                    'found_oat_logs': [1, 2, 3, 4],
                    'found_search_detection_logs': [1, 2, 3],
                    'found_workbench_logs': [1, 2],
                },
                {'max_fetch': 20},
                {
                    'audit_logs_time': '2023-01-01T15:01:17Z',
                    'oat_detection_logs_time': '2023-01-01T15:01:59Z',
                    'search_detection_logs_time': '2023-01-01T15:01:19Z',
                    'workbench_logs_time': '2023-01-01T15:01:02Z',
                    'found_audit_logs': ['da4bdff56581a841c69eb8e9fddd558e7ff25edf9f213f333db2d25fdca432d6'],
                    'found_oat_logs': [9],
                    'found_search_detection_logs': [20],
                    'found_workbench_logs': [4],
                },
                '2023-01-01T15:02:00Z',
                4,
                9,
                81,
                55,
                2 + 5 + 17 + 20
            ),
            (
                {
                    'audit_logs_time': '2023-01-01T15:01:17Z',
                    'oat_detection_logs_time': '2023-01-01T15:01:59Z',
                    'search_detection_logs_time': '2023-01-01T15:01:19Z',
                    'workbench_logs_time': '2023-01-01T15:01:02Z',
                    'found_audit_logs': [],
                    'found_oat_logs': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                    'found_search_detection_logs': [1, 2, 3],
                    'found_workbench_logs': [1, 2, 3, 4],
                },
                {'max_fetch': 1000},
                {
                    'audit_logs_time': '2023-01-01T15:15:55Z',
                    'oat_detection_logs_time': '2023-01-01T15:19:59Z',
                    'search_detection_logs_time': '2023-01-01T15:19:59Z',
                    'workbench_logs_time': '2023-01-01T15:17:46Z',
                    'found_audit_logs': ['83197a6e76a6cbf0da30bcb3e3a8a63ed1f0319c8b7d856c7f3f5f6b444ef0d9'],
                    'found_oat_logs': [62],
                    'found_search_detection_logs': [102],
                    'found_workbench_logs': [1004],
                },
                '2023-01-01T15:20:00Z',
                1400,
                62,
                102,
                879,
                1000 + 52 + 99 + 879
            ),
            (
                {
                    'audit_logs_time': '2023-01-01T15:01:00Z',
                    'oat_detection_logs_time': '2023-01-01T15:01:00Z',
                    'search_detection_logs_time': '2023-01-01T15:01:00Z',
                    'workbench_logs_time': '2023-01-01T15:01:00Z',
                    'found_audit_logs': [],
                    'found_oat_logs': [1],
                    'found_search_detection_logs': [1, 2, 3, 4],
                    'found_workbench_logs': [1],
                },
                {'max_fetch': 1000},
                {
                    'audit_logs_time': '2023-01-01T15:01:13Z',
                    'oat_detection_logs_time': '2023-01-01T15:03:45Z',
                    'search_detection_logs_time': '2023-01-01T15:03:44Z',
                    'workbench_logs_time': '2023-01-01T15:03:45Z',
                    'found_audit_logs': ['d6294890ed71d3399f2a5ab568738be6fe1fd5dca7d8dbcbf480d1095c7f3bb5'],
                    'found_oat_logs': [],
                    'found_search_detection_logs': [50],
                    'found_workbench_logs': [],
                },
                '2023-01-01T15:03:45Z',
                0,
                0,
                50,
                14,
                14 + 46
            )
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
            - make sure the audit log last time is the last log without -1 second to it.
            - make sure the expected_events_length is correct according to the limit of number of events from each type
              + caching of the events from last run

        """
        from TrendMicroVisionOneEventCollector import main

        start_freeze_time(datetime_string_freeze_time)
        workbench_last_fetch_time = last_run.get(LastRunLogsTimeFields.WORKBENCH.value)
        oat_last_fetch_time = last_run.get(LastRunLogsTimeFields.OBSERVED_ATTACK_TECHNIQUES.value)
        search_detection_last_fetch_time = last_run.get(LastRunLogsTimeFields.SEARCH_DETECTIONS.value)
        audit_log_last_fetch_time = last_run.get(LastRunLogsTimeFields.AUDIT.value)

        mocker.patch.object(demisto, 'params', return_value=integration_params)
        mocker.patch.object(demisto, 'command', return_value='fetch-events')
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run)
        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(
                last_workbench_time=workbench_last_fetch_time,
                last_oat_time=oat_last_fetch_time,
                last_search_detection_logs=search_detection_last_fetch_time,
                last_audit_log_time=audit_log_last_fetch_time,
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
        assert updated_last_run == {'workbench_logs_time': '2023-01-01T15:07:20Z', 'found_workbench_logs': [500]}
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
            last_run={'workbench_logs_time': '2023-01-01T14:00:00Z', 'found_workbench_logs': [1, 2, 3, 4, 5, 6, 7, 8]},
            limit=500
        )

        assert len(workbench_logs) == 192
        assert updated_last_run == {'workbench_logs_time': '2023-01-01T14:03:20Z', 'found_workbench_logs': [200]}
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
         - make sure in the cache we will have event with 500 id as its the event that happened in the last second.
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
            limit=500,
            date_range_for_oat_and_search_logs=365
        )

        assert len(observed_attack_techniques_logs) == 500
        assert updated_last_run == {'oat_detection_logs_time': '2023-01-01T14:51:39Z', 'found_oat_logs': [500]}
        assert observed_attack_techniques_logs[-1]['_time'] == '2023-01-01T14:51:39Z'

    def test_get_observed_attack_techniques_logs_with_last_run(self, mocker, client: Client):
        """
        Given:
         - last_run={
                'oat_detection_logs_time': '2023-01-01T14:00:00Z',
                'found_oat_logs': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            }
         - limit = 500
         - 200 oat events

        When:
         - running get_observed_attack_techniques_logs function

        Then:
         - make sure only 185 events are returned
         - make sure latest observed attack technique event is saved in the oat_detection_logs_time without adding 1 second to it.
         - make sure in the cache we will have event with 500 id as its the event that happened in the last second.
        """
        from TrendMicroVisionOneEventCollector import get_observed_attack_techniques_logs
        start_freeze_time('2023-01-01T15:00:00Z')

        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(num_of_oat_logs=200, last_oat_time='2023-01-01T14:00:00Z')
        )

        observed_attack_techniques_logs, updated_last_run = get_observed_attack_techniques_logs(
            client=client,
            first_fetch='1 month ago',
            last_run={
                'oat_detection_logs_time': '2023-01-01T14:00:00Z',
                'found_oat_logs': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            },
            limit=500,
            date_range_for_oat_and_search_logs=365
        )

        assert len(observed_attack_techniques_logs) == 185
        assert updated_last_run == {'oat_detection_logs_time': '2023-01-01T14:59:59Z', 'found_oat_logs': [200]}
        assert observed_attack_techniques_logs[-1]['_time'] == '2023-01-01T14:59:59Z'

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
         - make sure in the cache we will have event with 500 id as its the event that happened in the last second.
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
            limit=500,
            date_range_for_oat_and_search_logs=365
        )

        assert len(search_detection_logs) == 500
        assert updated_last_run == {'search_detection_logs_time': '2023-01-01T14:43:19Z', 'found_search_detection_logs': [500]}
        assert search_detection_logs[-1]['_time'] == '2023-01-01T14:43:19Z'

    def test_get_search_detection_logs_with_last_run(self, mocker, client: Client):
        """
        Given:
         - {'search_detection_logs_time': '2023-01-01T14:43:19Z', 'found_search_detection_logs': [1, 2, 3, 4, 5, 6, 7]}
         - limit = 500
         - 200 detection events

        When:
         - running get_search_detection_logs function

        Then:
         - make sure only 193 events are returned
         - make sure latest search detection log event time is saved in
           the search_detection_logs_time without adding 1 second to it.
         - make sure in the cache we will have event with 200 id as its the event that happened in the last second.
        """
        from TrendMicroVisionOneEventCollector import get_search_detection_logs
        start_freeze_time('2023-01-01T15:00:00Z')

        mocker.patch.object(
            BaseClient,
            '_http_request',
            side_effect=_http_request_side_effect_decorator(
                num_of_search_detection_logs=200, last_search_detection_logs='2023-01-01T14:00:00Z'
            )
        )

        search_detection_logs, updated_last_run = get_search_detection_logs(
            client=client,
            first_fetch='1 month ago',
            last_run={'search_detection_logs_time': '2023-01-01T14:43:19Z', 'found_search_detection_logs': [1, 2, 3, 4, 5, 6, 7]},
            limit=500,
            date_range_for_oat_and_search_logs=365
        )

        assert len(search_detection_logs) == 193
        assert updated_last_run == {'search_detection_logs_time': '2023-01-01T14:59:59Z', 'found_search_detection_logs': [200]}
        assert search_detection_logs[-1]['_time'] == '2023-01-01T14:59:59Z'


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
            ('2020-01-01T15:20:45Z', '2020-01-02T15:20:45Z')
        ),
        (
            None,
            '1 month ago',
            LastRunLogsTimeFields.OBSERVED_ATTACK_TECHNIQUES.value,
            '2023-01-01T15:20:45Z',
            ('2022-12-01T15:20:45Z', '2022-12-02T15:20:45Z')
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

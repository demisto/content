import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import pytest
import freezegun
import pytz
from urllib.parse import parse_qs, urlparse
from TrendMicroVisionOneEventCollector import DATE_FORMAT, Client, DEFAULT_MAX_LIMIT


FREEZE_DATETIME = '2023-01-01T15:00:00Z'
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
            ).strftime(DATE_FORMAT) if created_time_field != 'eventTime' else (
                datetime.now(tz=pytz.utc) - timedelta(seconds=i)
            ).timestamp()
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


@freezegun.freeze_time(FREEZE_DATETIME)
def test_fetch_events(mocker, client: Client):
    first_fetch = '2 years ago'
    from TrendMicroVisionOneEventCollector import fetch_events
    mocker.patch.object(client, '_http_request', side_effect=_http_request_side_effect_decorator(14))
    fetch_events(client, first_fetch)
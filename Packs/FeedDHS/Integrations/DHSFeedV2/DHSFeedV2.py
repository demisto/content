import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from pytz import utc
from taxii2client.common import _ensure_datetime_to_string

from TAXII2ApiModule import *  # noqa: E402

''' CONSTANTS '''

COMPLEX_OBSERVATION_MODE_SKIP = 'Skip indicators with more than a single observation'
MAX_FETCH_INTERVAL = '48 hours'
DEFAULT_FETCH_INTERVAL = '24 hours'
DEFAULT_LIMIT_PER_REQUEST = 1000  # DHS default limit

''' HELPER FUNCTIONS '''


def get_datetime(given_interval: Union[str, datetime]) -> datetime:
    """
    Receives an interval and returns the corresponding datetime.
    """
    if isinstance(given_interval, datetime):
        return given_interval
    date = dateparser.parse(given_interval, date_formats=[TAXII_TIME_FORMAT])
    if not date:
        raise DemistoException('Given time interval is not in a valid format.')
    return date.replace(tzinfo=utc)  # type: ignore[union-attr]


def get_limited_interval(given_interval: Union[str, datetime],
                         fetch_interval: Optional[Union[str, datetime]] = MAX_FETCH_INTERVAL) -> datetime:
    """
    Returns the closer time between the two time intervals given.
    """
    given_interval: datetime = get_datetime(given_interval)
    fetch_interval: datetime = get_datetime(fetch_interval or MAX_FETCH_INTERVAL)
    return max(given_interval, fetch_interval)  # later time is bigger


def fetch_one_collection(client: Taxii2FeedClient, limit: int, initial_interval: datetime,
                         last_run_ctx: Optional[dict] = None):
    demisto.debug(f'Fetching collection {client.collection_to_fetch.id=}')
    last_fetch_time = last_run_ctx.get(client.collection_to_fetch.id) if last_run_ctx else None
    # initial_interval gets here limited so no need to check limitation with default value
    added_after: datetime = get_limited_interval(initial_interval, last_fetch_time)

    indicators = client.build_iterator(limit, added_after=added_after)

    if last_run_ctx is not None:  # in case we got {}, we want to set it because we are in fetch incident run
        last_run_ctx[client.collection_to_fetch.id] = _ensure_datetime_to_string(client.last_fetched_indicator__modified
                                                                                 if client.last_fetched_indicator__modified
                                                                                 else added_after)

    return indicators, last_run_ctx


def fetch_all_collections(client: Taxii2FeedClient, limit: int, initial_interval: datetime, last_run_ctx: Optional[dict] = None):
    indicators: list = []
    for collection in client.collections:  # type: ignore[attr-defined]
        client.collection_to_fetch = collection
        fetched_iocs, last_run_ctx = fetch_one_collection(client, limit, initial_interval, last_run_ctx)
        indicators.extend(fetched_iocs)

        if limit >= 0:
            limit -= len(fetched_iocs)
            if limit <= 0:
                break

    return indicators, last_run_ctx


''' COMMAND FUNCTIONS '''


def command_test_module(client: Taxii2FeedClient, initial_interval: str):
    if get_datetime(MAX_FETCH_INTERVAL) > get_datetime(initial_interval):
        return 'Due to DHS API limitations, "First Fetch Time" is limited to 48 hours.'

    try:
        client.initialise()
        if client.collections:
            get_indicators_command(client, {'limit': '1', 'added_after': get_limited_interval('6 hours', initial_interval)})
        else:
            return 'Could not connect to server'
    except requests.exceptions.ConnectTimeout:
        return 'Connection Timeout Error - potential reasons might be that the \'Discovery Service URL\' parameter' \
               ' is incorrect or that the server is not accessible from your host.'
    except requests.exceptions.SSLError:
        return 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
               ' the instance configuration. If this doesn\'t work, verify that your certificate and key are valid  and matching.'
    except requests.exceptions.ProxyError:
        return 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
               ' selected, try clearing the checkbox.'
    except requests.exceptions.ConnectionError:
        return 'Verify that the server URL parameter is correct and that you have access to the server from your host.' \
               ' Run the test again.'
    except requests.HTTPError:
        return 'HTTP error - check your certificate and key, and that you are trying to reach a valid URL and API root.' \
               ' Wait and run the test again.'

    return 'ok'


def fetch_indicators_command(client: Taxii2FeedClient, limit: int, last_run_ctx: dict,
                             initial_interval: str = DEFAULT_FETCH_INTERVAL) -> tuple[list, dict]:
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param limit: upper limit of indicators to fetch
    :param last_run_ctx: last run dict with {collection_id: last_run_time string}
    :param initial_interval: initial interval in human readable format
    :return: indicators in cortex TIM format, updated last_run_ctx
    """
    initial_interval: datetime = get_limited_interval(get_datetime(initial_interval or DEFAULT_FETCH_INTERVAL))

    if client.collection_to_fetch:
        indicators, last_run_ctx = fetch_one_collection(client, limit, initial_interval, last_run_ctx)  # type: ignore[arg-type]
    else:
        indicators, last_run_ctx = fetch_all_collections(client, limit, initial_interval, last_run_ctx)  # type: ignore[arg-type]

    return indicators, last_run_ctx


def get_indicators_command(client: Taxii2FeedClient, args: Dict[str, Any]) \
        -> Union[CommandResults, Dict[str, List[Optional[str]]]]:
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param args: Dict that holds
        raw: When set to 'true' will return only rawJSON
        limit: upper limit of indicators to fetch
        added_after: added after time string in parse_date_range format
    :return: indicators in cortex TIM format
    """
    limit = arg_to_number(args.get('limit')) or 10
    raw = argToBoolean(args.get('raw', 'false'))
    max_fetch_datetime = get_datetime(MAX_FETCH_INTERVAL)
    added_after: datetime = get_datetime(args.get('added_after', DEFAULT_FETCH_INTERVAL))
    if max_fetch_datetime > added_after:
        raise DemistoException('Due to DHS API limitations, "added_after" is limited to 48 hours.')

    if client.collection_to_fetch:
        indicators = client.build_iterator(limit, added_after=added_after)
    else:
        indicators, _ = fetch_all_collections(client, limit, added_after)  # type: ignore[arg-type]

    if raw:
        return {'indicators': [x.get('rawJSON') for x in indicators]}

    return CommandResults(
        readable_output=f'Found {len(indicators)} results added after {_ensure_datetime_to_string(added_after)} UTC:\n'
                        + tableToMarkdown(name='DHS Indicators', t=indicators, headers=['value', 'type'], removeNull=True),
        outputs_prefix='DHS.Indicators',
        outputs_key_field='value',
        outputs=indicators,
        raw_response=indicators,
    )


def get_collections_command(client: Taxii2FeedClient) -> CommandResults:
    """
    Get the available collections in the DHS server
    """
    collections = []
    for collection in client.collections:  # type: ignore[attr-defined]
        collections.append({'Name': collection.title, 'ID': collection.id})
    return CommandResults(
        readable_output=tableToMarkdown('DHS Server Collections', t=collections, headers=['Name', 'ID']),
        outputs_prefix='DHS.Collections',
        outputs_key_field='ID',
        outputs=collections,
    )


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    params = demisto.params()
    url = params.get('url', 'https://ais2.cisa.dhs.gov/taxii2/')
    key = params.get('key', {}).get('password')
    certificate = params.get('certificate')
    verify_certificate = not params.get('insecure', False)
    proxies = handle_proxy()

    collection_to_fetch = params.get('collection_to_fetch')
    skip_complex_mode = params.get('observation_operator_mode') == COMPLEX_OBSERVATION_MODE_SKIP
    feed_tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color', '')
    objects_to_fetch = params.get('objects_to_fetch', [])

    initial_interval = params.get('initial_interval', DEFAULT_FETCH_INTERVAL)
    limit = arg_to_number(params.get('limit')) or -1
    limit_per_request = arg_to_number(params.get('limit_per_request')) or DEFAULT_LIMIT_PER_REQUEST
    default_api_root = params.get('default_api_root', 'public')

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Taxii2FeedClient(
            url=url,
            collection_to_fetch=collection_to_fetch,
            proxies=proxies,
            verify=verify_certificate,
            objects_to_fetch=objects_to_fetch,
            skip_complex_mode=skip_complex_mode,
            tags=feed_tags,
            limit_per_request=limit_per_request,
            tlp_color=tlp_color,
            certificate=certificate,
            key=key,
            default_api_root=default_api_root
        )

        start_time = time.time()
        if command == 'test-module':
            return_results(command_test_module(client, initial_interval))

        elif command == 'fetch-indicators':
            client.initialise()
            last_run_indicators = demisto.getLastRun()
            indicators, last_run_indicators = fetch_indicators_command(client, limit, last_run_indicators, initial_interval)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

            demisto.setLastRun(last_run_indicators)

        elif command == 'dhs-get-indicators':
            client.initialise()
            return_results(get_indicators_command(client, demisto.args()))

        elif command == 'dhs-get-collections':
            client.initialise()
            return_results(get_collections_command(client))

        else:
            raise NotImplementedError(f'{command} command is not implemented.')

        demisto.debug(f'Running {command} took {round(time.time() - start_time)}sec')

    except Exception as error:
        error_msg = str(error)
        if isinstance(error, requests.exceptions.SSLError):
            error_msg = 'Encountered an HTTPS certificate error. This error can be ignored by enabling ' \
                        '"Trust any certificate (not secure)" in the instance configuration.'
        elif isinstance(error, requests.HTTPError):
            error_msg = 'Encountered an HTTP error. Please check your certificate and key, and that you are trying to reach a ' \
                        'valid URL and API root. If this occurs when the test works, increase the "Max STIX Objects Per Poll" ' \
                        'in the instance configuration, reduce the "Max Indicators Per Fetch" in the instance configuration or ' \
                        'reduce the "limit" in the command argument.'
        return_error(error_msg, error)


''' ENTRY POINT '''

if __name__ in ('__main__', 'builtins'):
    main()

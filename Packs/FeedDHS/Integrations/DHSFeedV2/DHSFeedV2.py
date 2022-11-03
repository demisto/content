from taxii2client.common import _ensure_datetime_to_string

import demistomock as demisto
from CommonServerPython import *
from TAXII2ApiModule import *  # noqa: E402

''' CONSTANTS '''

COMPLEX_OBSERVATION_MODE_SKIP = 'Skip indicators with more than a single observation'


''' COMMAND FUNCTIONS '''


def command_test_module(client: Taxii2FeedClient):
    if client.collections:
        return 'ok'
    return 'Could not connect to server'


def fetch_indicators_command(client: Taxii2FeedClient, limit: int, last_run_ctx: dict, initial_interval: str = '24 hours') \
        -> Tuple[list, dict]:
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param limit: upper limit of indicators to fetch
    :param last_run_ctx: last run dict with {collection_id: last_run_time string}
    :param initial_interval: initial interval in human readable format
    :return: indicators in cortex TIM format, updated last_run_ctx
    """
    initial_interval = dateparser.parse(initial_interval or '24 hours', date_formats=[TAXII_TIME_FORMAT])

    if client.collection_to_fetch:
        indicators, last_run_ctx = fetch_one_collection(client, limit, initial_interval, last_run_ctx)  # type: ignore[arg-type]
    else:
        indicators, last_run_ctx = fetch_all_collections(client, limit, initial_interval, last_run_ctx)  # type: ignore[arg-type]

    return indicators, last_run_ctx


def fetch_one_collection(client: Taxii2FeedClient, limit: int, initial_interval: Union[str, datetime],
                         last_run_ctx: Optional[dict] = None):
    demisto.debug('in fetch_one_collection')
    last_fetch_time = last_run_ctx.get(client.collection_to_fetch.id) if last_run_ctx else None
    added_after = last_fetch_time or initial_interval

    indicators = client.build_iterator(limit, added_after=added_after, recover_http_errors=True)
    if last_run_ctx is not None:  # in case we got {}, we want to set it because we are in fetch incident run
        last_run_ctx[client.collection_to_fetch.id] = _ensure_datetime_to_string(client.last_fetched_indicator__modified
                                                                                 if client.last_fetched_indicator__modified
                                                                                 else added_after)

    return indicators, last_run_ctx


def fetch_all_collections(client: Taxii2FeedClient, limit: int, initial_interval: Union[str, datetime],
                          last_run_ctx: Optional[dict] = None):
    indicators: list = []
    demisto.debug('in fetch_all_collections')
    for collection in client.collections:  # type: ignore[attr-defined]
        client.collection_to_fetch = collection
        fetched_iocs, last_run_ctx = fetch_one_collection(client, limit, initial_interval, last_run_ctx)
        indicators.extend(fetched_iocs)

        if limit >= 0:
            limit -= len(fetched_iocs)
            if limit <= 0:
                break
        demisto.debug(f'{limit=}')

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
    added_after = dateparser.parse(args.get('added_after', '20 days'), date_formats=[TAXII_TIME_FORMAT])
    raw = argToBoolean(args.get('raw', 'false'))

    if client.collection_to_fetch:
        indicators = client.build_iterator(limit, added_after=added_after, recover_http_errors=True)
    else:
        indicators, _ = fetch_all_collections(client, limit, added_after)  # type: ignore[arg-type]

    if raw:
        return {'indicators': [x.get('rawJSON') for x in indicators]}

    return CommandResults(
        readable_output=f'Found {len(indicators)} results:\n' + tableToMarkdown(name='DHS Indicators', t=indicators,
                                                                                headers=['value', 'type'], removeNull=True),
        outputs_prefix='DHS.Indicators',
        outputs_key_field='value',
        outputs=indicators,
        raw_response=indicators,
    )


def get_collections_command(client: Taxii2FeedClient) -> CommandResults:
    """
    Get the available collections in the DHS server
    """
    collections = list()
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
    skip_complex_mode = COMPLEX_OBSERVATION_MODE_SKIP == params.get('observation_operator_mode')
    feed_tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color', '')

    initial_interval = params.get('initial_interval', '24 hours')
    limit = arg_to_number(params.get('limit')) or -1
    limit_per_request = arg_to_number(params.get('limit_per_request')) or DFLT_LIMIT_PER_REQUEST
    objects_types = ['indicator']
    objects_to_fetch = argToList(params.get('objects_to_fetch') or objects_types)
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
        client.initialise()

        if command == 'test-module':
            return_results(command_test_module(client))

        elif command == 'fetch-indicators':
            last_run_indicators = demisto.getLastRun()
            indicators, last_run_indicators = fetch_indicators_command(client, limit, last_run_indicators, initial_interval)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

            demisto.setLastRun(last_run_indicators)

        elif command == 'dhs-get-indicators':
            return_results(get_indicators_command(client, demisto.args()))

        elif command == 'dhs-get-collections':
            return_results(get_collections_command(client))

        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as error:
        error_msg = str(error)
        if isinstance(error, requests.exceptions.SSLError):
            error_msg = 'Encountered an HTTPS certificate error. This error can be ignored by enabling ' \
                        '"Trust any certificate (not secure)" in the instance configuration.'
        elif isinstance(error, requests.HTTPError):
            error_msg = 'Encountered an HTTP error. Please check your certificate and key, and that you are trying to reach a ' \
                        'valid URL and API root. If this occurs when the test works, change the "limit" in the instance ' \
                        'configuration or command argument.'
        return_error(error_msg, error)


''' ENTRY POINT '''

if __name__ in ('__main__', 'builtins'):
    main()

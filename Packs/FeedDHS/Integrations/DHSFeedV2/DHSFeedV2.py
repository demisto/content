import demistomock as demisto
from CommonServerPython import *
from TAXII2ApiModule import *  # noqa: E402

''' CONSTANTS '''

COMPLEX_OBSERVATION_MODE_SKIP = 'Skip indicators with more than a single observation'

''' HELPER FUNCTIONS '''


def assert_incremental_feed_params(fetch_full_feed: bool, is_incremental_feed: bool):
    if fetch_full_feed == is_incremental_feed:
        toggle_value = 'enabled' if fetch_full_feed else 'disabled'
        raise DemistoException(f"'Full Feed Fetch' cannot be {toggle_value} when 'Incremental Feed' is {toggle_value}.")


''' COMMAND FUNCTIONS '''


def command_test_module(client: Taxii2FeedClient, limit: int, fetch_full_feed: bool):
    if client.collections:
        if fetch_full_feed:
            if limit and limit != -1:
                return 'Configuration Error - Max Indicators Per Fetch is disabled when Full Feed Fetch is enabled'
        return 'ok'
    else:
        return 'Could not connect to server'


def fetch_indicators_command(client: Taxii2FeedClient, limit: int, last_run_ctx: dict, initial_interval: str = '24 hours',
                             fetch_full_feed: bool = False) -> Tuple[list, dict]:
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param limit: upper limit of indicators to fetch
    :param last_run_ctx: last run dict with {collection_id: last_run_time string}
    :param initial_interval: initial interval in human readable format
    :param fetch_full_feed: when set to true, will ignore last run, and try to fetch the entire feed
    :return: indicators in cortex TIM format
    """
    initial_interval = dateparser.parse(initial_interval, date_formats=[TAXII_TIME_FORMAT])

    if client.collection_to_fetch:
        indicators, last_run_ctx = fetch_one_collection(client, limit, initial_interval, last_run_ctx, fetch_full_feed)
    else:
        indicators, last_run_ctx = fetch_all_collections(client, limit, initial_interval, last_run_ctx, fetch_full_feed)

    return indicators, last_run_ctx


def fetch_one_collection(client: Taxii2FeedClient, limit: int, initial_interval: Union[str, datetime],
                         last_run_ctx: Optional[dict] = None, fetch_full_feed: bool = False):
    last_fetch_time = last_run_ctx.get(client.collection_to_fetch.id) if last_run_ctx else None
    added_after = get_added_after(fetch_full_feed, initial_interval, last_fetch_time)

    indicators = client.build_iterator(limit, added_after=added_after)
    if last_run_ctx:
        last_run_ctx[client.collection_to_fetch.id] = (client.last_fetched_indicator__modified
                                                       if client.last_fetched_indicator__modified
                                                       else added_after)

    return indicators, last_run_ctx


def fetch_all_collections(client: Taxii2FeedClient, limit: int, initial_interval: Union[str, datetime],
                          last_run_ctx: Optional[dict] = None, fetch_full_feed: bool = False):
    indicators: list = []
    for collection in client.collections:  # type: ignore[attr-defined]
        client.collection_to_fetch = collection
        fetched_iocs, last_run_ctx = fetch_one_collection(client, limit, initial_interval, last_run_ctx, fetch_full_feed)
        indicators.extend(fetched_iocs)

        if limit >= 0:
            limit -= len(fetched_iocs)
            if limit <= 0:
                break

    return indicators, last_run_ctx


def get_added_after(fetch_full_feed: bool, initial_interval: Union[str, datetime], last_fetch_time: str = None):
    if fetch_full_feed:
        return initial_interval

    return last_fetch_time or initial_interval


def get_indicators_command(client: Taxii2FeedClient, raw: str = 'false', limit: str = '10', added_after: str = '20 days') \
        -> Union[CommandResults, Dict[str, List[Optional[str]]]]:
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param raw: When set to 'true' will return only rawJSON
    :param limit: upper limit of indicators to fetch
    :param (Optional) added_after: added after time string in parse_date_range format
    :return: indicators in cortex TIM format
    """
    limit = arg_to_number(limit) or 10
    added_after = dateparser.parse(added_after, date_formats=[TAXII_TIME_FORMAT])
    raw = argToBoolean(raw)

    if client.collection_to_fetch:
        indicators = client.build_iterator(limit, added_after=added_after)
    else:
        indicators, _ = fetch_all_collections(client, limit, added_after)

    if raw:
        return {'indicators': [x.get('rawJSON') for x in indicators]}

    return CommandResults(
        readable_output=f'Found {len(indicators)} results:\n' + tableToMarkdown(name='DHS indicators', t=indicators,
                                                                                headers=['value', 'type'], removeNull=True),
        outputs_prefix='DHS.Indicators',
        outputs_key_field='value',
        outputs=indicators,
        raw_response=indicators
    )


def get_collections_command(client: Taxii2FeedClient) -> CommandResults:
    """
    Get the available collections in the DHS server
    """
    collections = list()
    for collection in client.collections:  # type: ignore[attr-defined]
        collections.append({'Name': collection.title, 'ID': collection.id})
    return CommandResults(
        outputs_prefix='DHS.Collections',
        outputs_key_field='ID',
        outputs=collections,
        readable_output=tableToMarkdown('DHS Server Collections:', collections))


''' MAIN FUNCTION '''


def main():
    params = demisto.params()
    args = demisto.args()

    url = params.get('url', 'https://ais2.cisa.dhs.gov/taxii2/')
    key = params.get('key')
    certificate = params.get('certificate')
    verify_certificate = not params.get('insecure', False)
    proxies = handle_proxy()

    collection_to_fetch = params.get('collection_to_fetch')
    skip_complex_mode = COMPLEX_OBSERVATION_MODE_SKIP == params.get('observation_operator_mode')
    feed_tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color', '')

    initial_interval = params.get('initial_interval', '24 hours')
    fetch_full_feed = params.get('fetch_full_feed') or False
    is_incremental_feed = params.get('feedIncremental') or False
    limit = arg_to_number(params.get('limit')) or -1
    limit_per_request = arg_to_number(params.get('limit_per_request')) or DFLT_LIMIT_PER_REQUEST
    objects_types = ['report', 'indicator', 'malware', 'campaign', 'attack-pattern',
                     'course-of-action', 'intrusion-set', 'tool', 'threat-actor', 'infrastructure']
    objects_to_fetch = argToList(params.get('objects_to_fetch') or objects_types)
    default_api_root = params.get('default_api_root', 'public')

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        assert_incremental_feed_params(fetch_full_feed, is_incremental_feed)
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
            default_api_root=default_api_root,
        )
        client.initialise()

        if command == 'test-module':
            return_results(command_test_module(client, limit, fetch_full_feed))

        elif command == 'fetch-indicators':
            if fetch_full_feed:
                limit = -1

            last_run_indicators = get_feed_last_run()
            indicators, last_run_indicators = fetch_indicators_command(client, limit, last_run_indicators, initial_interval,
                                                                       fetch_full_feed)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

            set_feed_last_run(last_run_indicators)

        elif command == 'dhs-get-indicators':
            return_results(get_indicators_command(client, **args))

        elif command == 'dhs-get-collections':
            return_results(get_collections_command(client))

        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as error:
        if isinstance(error, requests.exceptions.SSLError):
            return_error('Encountered an HTTPS certificate error. This error can be ignored by enabling '
                         '"Trust any certificate (not secure)" in the instance configuration.', error)
        if isinstance(error, requests.HTTPError):
            return_error('Encountered an HTTP error. Please check your certificate and key, and that you are trying to reach a '
                         'valid URL and API root. If this occurs when the test works, change the "limit" in the instance '
                         'configuration or command argument.', error)
        return_error(str(error), error)


''' ENTRY POINT '''

if __name__ in ('__main__', 'builtins'):
    main()

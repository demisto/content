from typing import Text, Iterable

from TAXII2ApiModule import *  # noqa: E402

''' CONSTANTS '''

COMPLEX_OBSERVATION_MODE_SKIP = "Skip indicators with more than a single observation"

''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''


def command_test_module(client: Taxii2FeedClient, first_fetch: str):
    if client.collections:
        get_first_fetch(first_fetch)
        return 'ok'
    else:
        return 'Could not connect to server'


def fetch_indicators_command(client: Taxii2FeedClient, last_run_ctx: Dict,
                             initial_interval: str = '24 hours') -> Tuple[list, dict]:
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param last_run_ctx: last run dict with {collection_id: last_run_time string}
    :param initial_interval: initial interval in parse_date_range format
    :return: indicators in cortex TIM format
    """
    if initial_interval:
        initial_interval = get_first_fetch(initial_interval)

    if client.collection_to_fetch:
        indicators, last_run_ctx = fetch_one_collection(client, initial_interval, last_run_ctx)
    else:
        indicators, last_run_ctx = fetch_all_collections(client, initial_interval, last_run_ctx)

    return indicators, last_run_ctx


def fetch_one_collection(client: Taxii2FeedClient, initial_interval: str, last_run_ctx: Dict):
    last_fetch_time = last_run_ctx.get(client.collection_to_fetch.id)
    added_after = last_fetch_time or initial_interval

    indicators = client.build_iterator(added_after=added_after)
    last_run_ctx[client.collection_to_fetch.id] = (
        client.last_fetched_indicator__modified
        if client.last_fetched_indicator__modified
        else added_after
    )
    return indicators, last_run_ctx


def fetch_all_collections(client: Taxii2FeedClient, initial_interval: str, last_run_ctx: Dict):
    if client.collections is None:
        raise DemistoException(ERR_NO_COLL)
    indicators: list = []
    for collection in client.collections:
        client.collection_to_fetch = collection
        added_after = last_run_ctx.get(collection.id) or initial_interval
        fetched_iocs = client.build_iterator(added_after=added_after)
        indicators.extend(fetched_iocs)
        last_run_ctx[collection.id] = client.last_fetched_indicator__modified
    return indicators, last_run_ctx


def get_indicators_command(client: Taxii2FeedClient, limit: int = 20, added_after: str = '20 days'):
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param limit: upper limit of indicators to fetch
    :param (Optional) added_after: added after time string in parse_date_range format
    :return: indicators in cortex TIM format
    """
    if added_after:
        added_after, _ = parse_date_range(added_after, date_format=TAXII_TIME_FORMAT)

    if client.collection_to_fetch is None:
        # fetch all collections
        if client.collections is None:
            raise DemistoException(ERR_NO_COLL)
        indicators: list = []
        for collection in client.collections:
            client.collection_to_fetch = collection
            fetched_iocs = client.build_iterator(limit, added_after=added_after)
            indicators.extend(fetched_iocs)
            if limit >= 0:
                limit -= len(fetched_iocs)
                if limit <= 0:
                    break

    else:
        indicators = client.build_iterator(limit, added_after=added_after)

    if not indicators:
        return CommandResults(readable_output='No results')

    return CommandResults(
        readable_output=f"Found {len(indicators)} results:\n" + tableToMarkdown(name='DHS indicators',
                                                                                t=indicators, removeNull=True),
        outputs_prefix='DHS',
        outputs=indicators,
        raw_response=indicators
    )


def get_first_fetch(first_fetch_string: str) -> str:
    try:
        first_fetch_date = dateparser.parse(first_fetch_string, settings={'TIMEZONE': 'UTC'})
        assert first_fetch_date is not None, f'could not parse {first_fetch_string}'
        return first_fetch_date.strftime(TAXII_TIME_FORMAT_NO_MS)
    except ValueError:
        raise DemistoException('first_fetch is not in the correct format (e.g. <number> <time unit>).')


''' MAIN FUNCTION '''


def main():
    params = demisto.params()
    args = demisto.args()

    url = params.get('url', 'https://ais2.cisa.dhs.gov/taxii2/')  # todo check what happens when there is no / at the end
    key = params.get('key')
    certificate = params.get('certificate')
    verify_certificate = not params.get('insecure', False)
    proxies = handle_proxy()

    collection_to_fetch = params.get('collection_to_fetch')
    skip_complex_mode = COMPLEX_OBSERVATION_MODE_SKIP == params.get('observation_operator_mode')
    feed_tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color', '')  # todo add

    initial_interval = params.get('initial_interval')
    fetch_full_feed = params.get('fetch_full_feed') or False
    is_incremental_feed = params.get('feedIncremental') or False
    limit = arg_to_number(params.get('limit') or -1)
    limit_per_request = try_parse_integer(params.get('limit_per_request'))  # todo add
    objects_types = ['report', 'indicator', 'malware', 'campaign', 'attack-pattern',
                     'course-of-action', 'intrusion-set', 'tool', 'threat-actor', 'infrastructure']
    objects_to_fetch = argToList(params.get('objects_to_fetch') or objects_types)
    default_api_root = params.get('default_api_root', 'public')  # todo check if authorized?

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
            default_api_root=default_api_root,
        )
        client.initialise()

        command = demisto.command()
        demisto.info(f"Command being called is {command}")

        if command == 'fetch-indicators':
            last_run_indicators = get_feed_last_run()
            indicators, last_run_indicators = fetch_indicators_command(client,
                                                                       last_run_ctx=last_run_indicators,
                                                                       initial_interval=params.get('first_fetch', '24 hours'))
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

            set_feed_last_run(last_run_indicators)

        elif command == 'dhs-get-indicators':
            limit: int = arg_to_number(args.get('limit', 20))  # type: ignore
            command_results = get_indicators_command(client, limit=limit)
            return_results(command_results)

        elif command == 'test-module':
            return_results(command_test_module(client, params.get('first_fetch', '')))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as error:
        return_error(str(error), error)


''' ENTRY POINT '''

if __name__ in ('__main__', 'builtins'):
    main()

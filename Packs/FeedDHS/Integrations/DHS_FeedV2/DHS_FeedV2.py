from typing import Text, Iterable

from TAXII2ApiModule import *  # noqa: E402


def fix_rsa_data(rsa_data: str, count: int) -> str:
    rsa_data = rsa_data.strip().split(' ')
    return '{}\n{}\n{}\n'.format(
        ' '.join(rsa_data[:count]),
        '\n'.join(rsa_data[count:-count]),
        ' '.join(rsa_data[-count:])
    )


def safe_data_get(data: Dict, keys: Union[Iterable[Text], Text], prefix: str = '',
                  default: Optional[Any] = None):
    keys = [keys] if isinstance(keys, Text) else keys
    if prefix:
        keys = map(lambda x: ':'.join([prefix, x]), keys)
    temp_data = data
    try:
        for key in keys:
            if key not in temp_data:
                raise AttributeError
            temp_data = temp_data[key]
        return temp_data
    except AttributeError:
        return default


def header_transform(header: str) -> str:
    return 'reported by' if header == 'reportedby' else header


def indicator_to_context(indicator: Dict) -> Dict:
    reported_by = safe_data_get(indicator, ['fields', 'reportedby'], default='')
    context_indicator = {
        'value': indicator.get('value', ''),
        'tlp': safe_data_get(indicator, ['fields', 'trafficlightprotocol'], default=''),
        'type': indicator.get('type', '')
    }
    if reported_by:
        context_indicator['reportedby'] = reported_by
    return context_indicator


def command_test_module(client: Taxii2FeedClient, first_fetch: str):
    if client.collections:
        get_first_fetch(first_fetch)
        return 'ok'
    else:
        return 'Could not connect to server'


def fetch_indicators_command(client: Taxii2FeedClient, last_run_ctx, tlp_color: Optional[str] = None,
                             initial_interval: str = '24 hours') -> Tuple[list, dict]:
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param last_run_ctx: last run dict with {collection_id: last_run_time string}
    :param (Optional) tlp_color: Traffic Light Protocol Color to filter by
    :param initial_interval: initial interval in parse_date_range format
    :return: indicators in cortex TIM format
    """
    if initial_interval:
        initial_interval = get_first_fetch(initial_interval)

    last_fetch_time = last_run_ctx.get(client.collection_to_fetch.id) if client.collection_to_fetch else None

    if client.collection_to_fetch is None:
        indicators, last_run_ctx = fetch_all_collections(client, initial_interval, last_run_ctx)
    else:
        indicators, last_run_ctx = fetch_one_collection(client, initial_interval, last_fetch_time, last_run_ctx)

    if tlp_color:
        indicators = filter_indicators_by_tlp_color(indicators, tlp_color)

    return indicators, last_run_ctx


def fetch_one_collection(client, initial_interval, last_fetch_time, last_run_ctx):
    added_after = last_fetch_time or initial_interval
    indicators = client.build_iterator(added_after=added_after)
    last_run_ctx[client.collection_to_fetch.id] = (
        client.last_fetched_indicator__modified
        if client.last_fetched_indicator__modified
        else added_after
    )
    return indicators, last_run_ctx


def fetch_all_collections(client, initial_interval, last_run_ctx):
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


def get_indicators_results(indicators):
    entry_context = list(map(indicator_to_context, indicators))
    human_readable = tableToMarkdown(name='DHS indicators', t=entry_context,
                                     removeNull=True, headerTransform=header_transform)
    return CommandResults(
        readable_output=f"Found {len(indicators)} results:\n" + human_readable,
        outputs_prefix='DHS',
        outputs=entry_context,
        raw_response=indicators
    )


def get_indicators_command(client: Taxii2FeedClient, limit: int = 20, added_after='20 days', tlp_color: Optional[str] = None):
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param limit: upper limit of indicators to fetch
    :param (Optional) added_after: added after time string in parse_date_range format
    :param (Optional) tlp_color: Traffic Light Protocol Color to filter by
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

    if tlp_color:
        indicators = filter_indicators_by_tlp_color(indicators, tlp_color)

    if not indicators:
        return CommandResults(readable_output='No results')

    # return get_indicators_results(indicators) # todo check if done in load_stix_objects_from_envelope
    return CommandResults(
        readable_output=f"Found {len(indicators)} results:\n" +
                        tableToMarkdown(name='DHS indicators', t=indicators, removeNull=True),
        outputs_prefix='DHS',
        outputs=indicators,
        raw_response=indicators
    )


def filter_indicators_by_tlp_color(indicators, tlp_color):
    # todo check if indicators need to be filtered by tlp_color, or tlp_color needs to be added to indicators
    return [indicator for indicator in indicators if indicators["fields"].get('trafficlightprotocol') == tlp_color]


def get_first_fetch(first_fetch_string: str) -> str:
    try:
        first_fetch_date = dateparser.parse(first_fetch_string, settings={'TIMEZONE': 'UTC'})
        assert first_fetch_date is not None, f'could not parse {first_fetch_string}'
        return first_fetch_date.strftime(TAXII_TIME_FORMAT_NO_MS)
    except ValueError:
        raise DemistoException('first_fetch is not in the correct format (e.g. <number> <time unit>).')


def main():
    params = demisto.params()
    key = fix_rsa_data(params.get('key', {}).get('password'), 4)
    crt = params.get('crt', '')
    collection = params.get('collection')
    tags = argToList(params['tags']) if params.get('tags') else None
    base_url = params.get('base_url', 'https://ais2.cisa.dhs.gov')
    verify = argToBoolean(params.get('insecure'))
    tlp_color = params.get('tlp_color')
    proxies = handle_proxy()

    client = Taxii2FeedClient(url=base_url,
                              collection_to_fetch=collection,
                              proxies=proxies,
                              verify=verify,
                              objects_to_fetch=[],  # todo add
                              # field_map=None,  # todo needed?
                              tags=tags,
                              certificate=crt,
                              key=key)
    client.initialise()

    command = demisto.command()
    try:
        if command == 'fetch-indicators':
            last_run_indicators = get_feed_last_run()
            indicators, last_run_indicators = fetch_indicators_command(client,
                                                                       last_run_ctx=last_run_indicators,
                                                                       tlp_color=tlp_color,
                                                                       initial_interval=params.get('first_fetch', '24 hours'))
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

            set_feed_last_run(last_run_indicators)

        elif command == 'dhs-get-indicators':
            args = demisto.args()
            limit = arg_to_number(args.get('limit', 20))
            command_results = get_indicators_command(client, limit=limit, tlp_color=tlp_color)
            return_results(command_results)

        elif command == 'test-module':
            return_results(command_test_module(client, params.get('first_fetch', '')))
        else:
            raise DemistoException('not implemented.')

    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', 'builtins'):
    main()

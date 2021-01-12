from typing import Dict, List

import demistomock as demisto
from CommonServerPython import *
from JSONFeedApiModule import *  # noqa: E402

SEARCH_PARAMS = {
    'from': 'from',
    'until': 'until',
    'actor': 'actor'
}
FEED_URL = 'https://api.intel471.com/v1/actors?'
MAPPING = {
    'handles': 'stixaliases',
    'lastUpdated': 'updateddate',
    'activeFrom': 'activefrom',
    'activeUntil': 'activeuntil',
    'links_forumTotalCount': 'intel471forumtotalcount',
    'links_forumPostTotalCount': 'intel471forumposttotalcount',
    'links_reportTotalCount': 'intel471reporttotalcount',
    'links_instantMessageTotalCount': 'intel471instantmessagetotalcount',
}


def _create_url(**kwargs):
    """
    This function gets parameters and adding the relevant to a url string
    """
    url_suffix = ""
    if 'actor' not in kwargs:
        kwargs['actor'] = '*'

    for param in kwargs:
        if param in SEARCH_PARAMS:
            url_suffix += f"&{SEARCH_PARAMS.get(param)}={kwargs.get(param)}"
    return FEED_URL + url_suffix.strip('&')


def custom_build_iterator(client: Client, feed: Dict, limit: int = 0, **kwargs) -> List:
    """
    This function replace the build iterator function in JsonFeedApiModule in order to enable paging specific to api.
    Paginf is done using
    """

    url = feed.get('url', client.url)
    fetch_time = feed.get('fetch_time')
    start_date, end_date = parse_date_range(fetch_time, utc=True, to_timestamp=True)
    integration_context = get_integration_context()
    last_fetch = integration_context.get(f"{feed.get('indicator_type')}_fetch_time")

    # sorting and count are used for paging purposes
    params = {'lastUpdatedFrom': last_fetch if last_fetch else start_date, 'sort': 'earliest', 'count': '100'}
    result: List[Dict] = []
    should_continue = True
    total_count = 0

    while should_continue:
        r = requests.get(
            url=url,
            verify=client.verify,
            auth=client.auth,
            cert=client.cert,
            headers=client.headers,
            params=params,
            **kwargs
        )
        try:
            r.raise_for_status()
            data = r.json()
            current_result = jmespath.search(expression=feed.get('extractor'), data=data)
            if current_result:
                if not total_count:
                    total_count = limit if limit else data.get('actorTotalCount')
                result = result + current_result
                params['from'] = result[-1].get('activeFrom')

            # gets next page reference and handles paging.
            should_continue = total_count > len(result)

        except ValueError as VE:
            raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {VE}')

    set_integration_context({f"{feed.get('indicator_type')}_fetch_time": str(end_date)})
    return result


def custom_handle_indicator(client: Client, item: Dict, feed_config: Dict, service_name: str,
                            indicator_type: str, indicator_field: str, use_prefix_flat: bool,
                            feedTags: list, auto_detect: bool,
                            mapping_function: Callable) -> List[dict]:
    """
    This function adds indicators to indicator lists after specific manipulation.
    :param client: Client (from JsonFeedApiModule
    :param item: Dict describing a specific indicator
    :param feed_config: Dict describing the feed configuration
    :param service_name: name of service
    :param indicator_type: str. Type of the indicator
    :param indicator_field: str. Field name in item which indicator value is taken from
    :param use_prefix_flat: bool. Whether attribute of item should be flattened.
    :param feedTags: list of tags.
    :param auto_detect: bool. Whether to use auto detect. Not in used in customized indicator handler,
    :param indicator_list: list of indicators to add indicator created from item to.
    :param mapping_function: Callable function to match json fields to demisto fields.
    """
    indicator_list = []
    mapping = feed_config.get('mapping')
    indicator_value = item.get(indicator_field)
    current_indicator_type = determine_indicator_type(indicator_type, auto_detect, indicator_value)

    if not current_indicator_type:
        return []

    indicator: dict = {
        'type': current_indicator_type,
        'fields': {
            'tags': feedTags,
        }
    }

    if client.tlp_color:
        indicator['fields']['trafficlightprotocol'] = client.tlp_color

    attributes: dict = {'source_name': service_name, 'type': current_indicator_type}
    attributes.update(extract_all_fields_from_indicator(item, indicator_field,
                                                        flat_with_prefix=use_prefix_flat))
    attributes['handles'] = []

    for forum_item in attributes.get(indicator_field, []):
        value = f"{forum_item.get('actorHandle', '')} ({forum_item.get('name', '')})"
        indicator['value'] = forum_item.get('actorHandle', '')
        attributes['handles'].append(value)

        if mapping:
            mapping_function(mapping, indicator, attributes)
        indicator['rawJSON'] = item

        indicator_list.append(indicator)
    return indicator_list


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}
    url = _create_url(**params)
    params['url'] = url
    params['indicator_type'] = 'Threat Actor'
    params['feed_name_to_config'] = {
        'actors': {
            'extractor': 'actors[*]',
            'indicator_type': 'STIX Threat Actor',
            'indicator': 'links_forums',
            'mapping': MAPPING,
            'flat_json_with_prefix': True,
            'custom_build_iterator': custom_build_iterator,
            'fetch_time': params.get('fetch_time', '7 days'),
            'handle_indicator_function': custom_handle_indicator
        },
    }
    feed_main(params, 'Intel471 Actor Feed', 'intel471-actors')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

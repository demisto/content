from typing import Dict, Union
from CommonServerPython import *
from JSONFeedApiModule import *  # noqa: E402


def custom_build_iterator(client: Client, feed: Dict, limit, **kwargs) -> List:
    if not limit:
        limit = 50000
    params: dict = feed.get('filters', {})
    current_indicator_type = feed.get('indicator_type')
    integration_context = get_integration_context()
    page_number = integration_context.get(f'{current_indicator_type}_page', 1)

    more_indicators = True
    params['page_size'] = 200
    result: list = []
    while more_indicators:
        params['page'] = page_number
        r = requests.get(
            url=feed.get('url', client.url),
            verify=client.verify,
            auth=client.auth,
            cert=client.cert,
            headers=client.headers,
            params=params,
            **kwargs
        )

        demisto.debug(f"initiating API call with url: {r.url}")
        try:
            r.raise_for_status()
            data = r.json()
            result.extend(jmespath.search(expression=feed.get('extractor'), data=data))
            more_indicators = data.get('more')
            page_number += 1
            if not more_indicators:
                set_integration_context({f'{current_indicator_type}_page': 1})
            if len(result) >= limit:
                set_integration_context({f'{current_indicator_type}_page': page_number})  # When reach the limit for
                # one fetching, save next page number in order to start from him at the next fetch
                break

        except ValueError as VE:
            raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {VE}')
        except TypeError as TE:
            raise TypeError(f'Error massage: {TE}\n\n Try To check extractor value')
    demisto.debug(f"Received in total {len(result)} results from api call")
    return result


def create_fetch_configuration(indicators_type: list, filters: dict, params: dict) -> Dict[str, dict]:
    mapping_by_indicator_type = {
        'IP': {
            'last_seen_as': 'stixmalwaretypes',
            'threat_types': 'stixprimarymotivation',
            'malware_family': 'malwarefamily',
            'severity': 'sourceoriginalseverity'},
        'Domain': {
            'last_seen_as': 'stixmalwaretypes',
            'threat_types': 'stixprimarymotivation',
            'malware_family': 'malwarefamily',
            'severity': 'sourceoriginalseverity'},
        'URL': {
            'last_seen_as': 'stixmalwaretypes',
            'threat_types': 'stixprimarymotivation',
            'malware_family': 'malwarefamily',
            'severity': 'sourceoriginalseverity'}
    }

    url_by_type = {"IP": 'https://api.intelgraph.idefense.com/rest/threatindicator/v0/ip',
                   "Domain": 'https://api.intelgraph.idefense.com/rest/threatindicator/v0/domain',
                   "URL": 'https://api.intelgraph.idefense.com/rest/threatindicator/v0/url'}

    common_conf = {'extractor': 'results',
                   'indicator': 'display_text',
                   'insecure': params.get('insecure', False),
                   'build_iterator_paging': custom_build_iterator,
                   'filters': filters}

    indicators_configuration = {}

    for ind in indicators_type:
        indicators_configuration[ind] = dict(common_conf)
        indicators_configuration[ind].update({'url': url_by_type[ind]})
        indicators_configuration[ind].update({'indicator_type': ind})
        indicators_configuration[ind].update({'mapping': mapping_by_indicator_type[ind]})

    return indicators_configuration


def build_feed_filters(params: dict) -> Dict[str, Optional[Union[str, list]]]:
    filters = {'severity.from': params.get('severity'),
               'threat_types.values': params.get('threat_type'),
               'confidence.from': params.get('confidence_from'),
               'malware_family.values': params.get('malware_family', '').split(',')
               if params.get('malware_family') else None}

    return {k: v for k, v in filters.items() if v is not None}


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}

    filters: Dict[str, Optional[Union[str, list]]] = build_feed_filters(params)
    indicators_type: List[str] = params.get('indicator_type', ['IP', 'Domain', 'URL'])

    params['feed_name_to_config'] = create_fetch_configuration(indicators_type, filters, params)

    params['headers'] = {"Content-Type": "application/json",
                         'auth-token': params.get('api_token')}

    feed_main(params, 'iDefense Feed', 'idefense')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

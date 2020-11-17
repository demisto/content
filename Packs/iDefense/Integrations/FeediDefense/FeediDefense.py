import demistomock as demisto
from CommonServerPython import *
# from Packs.ApiModules.Scripts.JSONFeedApiModule.JSONFeedApiModule import *

from JSONFeedApiModule import *  # noqa: E402


def build_iterator(client: Client, feed: Dict, **kwargs) -> List:
    params = feed.get('filters')
    more_indicators = True
    page_number = 1
    result = []
    while more_indicators and page_number != 4:  # TODO: Don't forget to remove second condition
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

        try:
            r.raise_for_status()
            data = r.json()
            result = result + jmespath.search(expression=feed.get('extractor'), data=data)
            more_indicators = data.get('more')
            page_number += 1

        except ValueError as VE:
            raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {VE}')

    return result


def create_fetch_configuration(indicators_type, filters, params):
    mapping_by_indicator_type = {
        'IP': {
            'display_text': 'ipaddress',  # instance field: cliname
            'threat_types': 'ThreatTypes.threattypes',
            # 'threat_types': 'threattypes',
            'last_published': 'published',
            'severity': 'sourceoriginalseverity'},
        'Domain': {
            # 'display_text': 'ipaddress',  # instance field: cliname
            'threat_types': 'threattypes',
            'last_published': 'published',
            'severity': 'sourceoriginalseverity'},
        'URL': {
            # 'display_text': 'ipaddress',  # instance field: cliname
            'threat_types': 'threattypes',
            'last_published': 'published',
            'severity': 'sourceoriginalseverity'}
    }

    url_by_type = {"IP": 'https://api.intelgraph.idefense.com/rest/threatindicator/v0/ip',
            "Domain": 'https://api.intelgraph.idefense.com/rest/threatindicator/v0/domain',
            "URL": 'https://api.intelgraph.idefense.com/rest/threatindicator/v0/url'}

    common_conf = {'extractor': 'results',
                   'indicator': 'display_text',
                   'insecure': params.get('insecure', False),
                   'build_iterator_paging': build_iterator,
                   'filters': filters}

    indicators_configuration = {}

    for ind in indicators_type:
        indicators_configuration[ind] = dict(common_conf)
        indicators_configuration[ind].update({'url': url_by_type[ind]})
        indicators_configuration[ind].update({'indicator_type': ind})
        indicators_configuration[ind].update({'mapping': mapping_by_indicator_type[ind]})

    return indicators_configuration


def build_feed_filters(params: dict):
    filters = {'severity.from': params.get('severity'),
               'severity.to': params.get('severity'),
               'threat_types.values': params.get('threat_type'),
               'confidence.from': params.get('confidence_from'),
               'confidence.to': params.get('confidence_to'),
               'malware_family.values': params.get('malware_family').split(',')
               if params.get('malware_family') is not None else None}

    return {k: v for k, v in filters.items() if v is not None}


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}

    filters: dict = build_feed_filters(params)
    indicators_type: list = params.get('indicator_type', ['IP', 'Domain', 'URL'])
    demisto.debug(f"tal indicators type {indicators_type}")

    params['feed_name_to_config'] = create_fetch_configuration(indicators_type, filters, params)

    params['headers'] = {
                "Content-Type": "application/json",
                'auth-token':  params.get('api_token')}

    # if not params.get('auto_detect_type'):
    #     if not params.get('indicator_type'):
    #         return_error('Indicator Type cannot be empty when Auto Detect Indicator Type is unchecked')
    #     params['feed_name_to_config'].get('IP')['indicator_type'] = params.get('indicator_type')
    #     # params['feed_name_to_config'].get(params.get('url'))['indicator_type'] = params.get('indicator_type')

    feed_main(params, 'iDefense Feed', 'idefense')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

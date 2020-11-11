import demistomock as demisto
from CommonServerPython import *
from Packs.ApiModules.Scripts.JSONFeedApiModule.JSONFeedApiModule import *

# from JSONFeedApiModule import *  # noqa: E402


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


def build_feed_filters(params: dict):
    filters = {'severity.from': params.get('severity'),
               'severity.to': params.get('severity'),
               'threat_types.values': params.get('threat_type'),
               'confidence.from': params.get('confidence_from'),
               'confidence.to': params.get('confidence_to'),
               'malware_family.values': params.get('malware_family').split(',')
               if params.get('malware_family') is not None else None}

    return {k: v for k, v in filters.items() if v is not None}


def test_module(client, params) -> str:  # type: ignore  # pylint: disable=function-redefined

    client.build_iterator()

    return 'ok'


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}

    filters: dict = build_feed_filters(params)
    indicator_type: list = params.get('indicator_type')

    params['feed_name_to_config'] = {
       'IP': {
            'url': f'https://api.intelgraph.idefense.com/rest/threatindicator/v0/ip',
            'extractor': 'results',
            'indicator': 'display_text',
            'indicator_type': FeedIndicatorType.IP,
            'insecure': params.get('insecure'),
            'build_iterator_paging': build_iterator,
            'filters': filters,
            'mapping': {
               'display_text': 'ipaddress',  # instance field: cliname
               'threat_types': 'threattypes',
               'last_published': 'published',
               'severity': 'sourceoriginalseverity'}
       },
       # 'Domain': {
       #     'url': 'https://api.intelgraph.idefense.com/rest/threatindicator/v0/domain',
       #     'extractor': 'results',
       #     'indicator_type': FeedIndicatorType.Domain
       # }
    }
    params['headers'] = {
                "Content-Type": "application/json",
                'auth-token':  params.get('api_token')}

    if not params.get('auto_detect_type'):
        if not params.get('indicator_type'):
            return_error('Indicator Type cannot be empty when Auto Detect Indicator Type is unchecked')
        params['feed_name_to_config'].get('IP')['indicator_type'] = params.get('indicator_type')
        # params['feed_name_to_config'].get(params.get('url'))['indicator_type'] = params.get('indicator_type')

    feed_main(params, 'iDefense Feed', 'idefense')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

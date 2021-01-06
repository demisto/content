from typing import Dict, Union
from CommonServerPython import *
from JSONFeedApiModule import *  # noqa: E402


def custom_build_iterator(client: Client, feed: Dict, limit, **kwargs) -> List:
    """
    Implement the http_request with API that works with pagination and filtering. Uses the integration context to
    save last fetch time to each indicator type
    Args:
        client: Client manage all http requests
        feed: dictionary holds all data needed to the specific service (Services- IP, Domain, URL)
        limit: maximum number of indicators to fetch

    Returns:
        list of indicators returned from api. Each indicator is represented in dictionary
    """
    fetch_time = demisto.params().get('fetch_time', '14 days')
    params: dict = feed.get('filters', {})
    current_indicator_type = feed.get('indicator_type', '')
    start_date, end_date = parse_date_range(fetch_time, utc=True)
    integration_context = get_integration_context()
    last_fetch = integration_context.get(f'{current_indicator_type}_fetch_time')
    if last_fetch:
        start_date = last_fetch
    page_number = 1
    params['end_date'] = end_date
    params['start_date'] = start_date
    params['page_size'] = 200

    if not limit:
        limit = 20000  # This limit was added to make sure we do not hit a timeout on the fetch
        integration_context[f'{current_indicator_type}_fetch_time'] = str(params['end_date'])
        set_integration_context(integration_context)

    more_indicators = True
    result: list = []

    while more_indicators:
        params['page'] = page_number
        demisto.debug(f"Initiating API call to iDefense with url: {feed.get('url', client.url)} ,with parameters: "
                      f"{params} and page number: {page_number} ")
        try:

            r = requests.get(
                url=feed.get('url', client.url),
                verify=client.verify,
                auth=client.auth,
                cert=client.cert,
                headers=client.headers,
                params=params,
                **kwargs
            )

            r.raise_for_status()
            data = r.json()
            if data.get('total_size'):
                result.extend(jmespath.search(expression=feed.get('extractor'), data=data))
            more_indicators = data.get('more')
            page_number += 1
            if len(result) >= limit:
                break

        except ValueError as VE:
            raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {VE}')
        except TypeError as TE:
            raise TypeError(f'Error massage: {TE}\n\n Try To check extractor value')
        except ConnectionError as exception:
            # Get originating Exception in Exception chain
            error_class = str(exception.__class__)
            err_type = f"""<{error_class[error_class.find("'") + 1: error_class.rfind("'")]}>"""
            err_msg = 'Verify that the server URL parameter' \
                      ' is correct and that you have access to the server from your host.' \
                      '\nError Type: {}\nError Number: [{}]\nMessage: {}\n' \
                .format(err_type, exception.errno, exception.strerror)
            raise DemistoException(err_msg, exception)

    demisto.debug(f"Received in total {len(result)} indicators from iDefense Feed")
    return result


def create_fetch_configuration(indicators_type: list, filters: dict, params: dict) -> Dict[str, dict]:
    mapping_by_indicator_type = {
        'IP': {
            'last_seen_as': 'malwaretypes',
            'threat_types': 'primarymotivation',
            'malware_family': 'malwarefamily',
            'severity': 'sourceoriginalseverity'},
        'Domain': {
            'last_seen_as': 'malwaretypes',
            'threat_types': 'primarymotivation',
            'malware_family': 'malwarefamily',
            'severity': 'sourceoriginalseverity'},
        'URL': {
            'last_seen_as': 'malwaretypes',
            'threat_types': 'primarymotivation',
            'malware_family': 'malwarefamily',
            'severity': 'sourceoriginalseverity'}
    }

    url_by_type = {"IP": 'https://api.intelgraph.idefense.com/rest/threatindicator/v0/ip',
                   "Domain": 'https://api.intelgraph.idefense.com/rest/threatindicator/v0/domain',
                   "URL": 'https://api.intelgraph.idefense.com/rest/threatindicator/v0/url'}

    common_conf = {'extractor': 'results',
                   'indicator': 'display_text',
                   'insecure': params.get('insecure', False),
                   'custom_build_iterator': custom_build_iterator,
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
    indicators_type: list = argToList(params.get('indicator_type', []))
    params['feed_name_to_config'] = create_fetch_configuration(indicators_type, filters, params)

    params['headers'] = {"Content-Type": "application/json",
                         'auth-token': params.get('api_token')}

    feed_main(params, 'iDefense Feed', 'idefense')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

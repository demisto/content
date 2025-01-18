from typing import Any
from collections.abc import Callable

import uuid
import urllib3

from CommonServerPython import *

# disable insecure warnings
urllib3.disable_warnings()
INTEGRATION_NAME = 'Office 365'
GERMANY = 'Germany'
ALL_REGIONS_LIST = ['Worldwide', 'China', 'USGovDoD', 'USGovGCCHigh']
ALL_CATEGORY_LIST = ['Optimize', 'Allow', 'Default']


def build_region_or_category_list(param_list: list, all_config_list: list, allow_germany: bool = False) -> list:
    """Builds the region or category list for the feed.
    If the param_list includes 'All',
    it will add all the items from the 'all_config_list' to the list, and remove the string all.

    Args:
        allow_germany: In some cases, Germany endpoints can throw a 400 error, by default we exclude Germany from All
        param_list: list of regions or categories provided by integration configuration
        all_config_list: list of all the regions or categories, to be added if All is chosen

    Returns:
        list of regions or categories
    """
    if allow_germany:
        param_list.append(GERMANY)
    if 'All' in param_list:
        param_list.remove('All')
        return list(set(param_list + all_config_list))
    return param_list


def build_urls_dict(regions_list: list, services_list: list, unique_id) -> list[dict[str, Any]]:
    """Builds a URL dictionary with the relevant data for each service

    Args:
        regions_list: list of regions
        services_list: list of services
        unique_id: unique uuid

    Returns:
        URLs services list
    """
    urls_list = []
    for region in regions_list:
        for service in services_list:
            if service == 'All':
                url = f'https://endpoints.office.com/endpoints/{region}?ClientRequestId={unique_id}'
            else:
                url = f'https://endpoints.office.com/endpoints/{region}?ServiceAreas={service}' \
                      f'&ClientRequestId={unique_id}'
            urls_list.append({
                'Region': region,
                'Service': service,
                'FeedURL': url
            })
    return urls_list


class Client:
    """
    Client to use in the Office 365 Feed integration. Overrides BaseClient.
    Office 365 IP address and URL web service announcement:
    https://docs.microsoft.com/en-us/office365/enterprise/managing-office-365-endpoints?redirectSourcePath=%252fen-us%252farticle%252fmanaging-office-365-endpoints-99cab9d4-ef59-4207-9f2b-3728eb46bf9a#webservice
    https://techcommunity.microsoft.com/t5/Office-365-Blog/Announcing-Office-365-endpoint-categories-and-Office-365-IP/ba-p/177638
    """

    def __init__(self, urls_list: list, category_list: list, insecure: bool = False, tags: list | None = None,
                 tlp_color: str | None = None):
        """
        Implements class for Office 365 feeds.
        :param urls_list: List of url, regions and service of each service.
        :param insecure: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        :param tlp_color: Traffic Light Protocol color.
        """
        self._urls_list: list[dict] = urls_list
        self._verify: bool = insecure
        self.tags = [] if tags is None else tags
        self.tlp_color = tlp_color
        self._proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
        self.category_list = category_list

    def build_iterator(self) -> list:
        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """
        result = []
        for feed_obj in self._urls_list:
            feed_url = feed_obj.get('FeedURL', '')
            region = feed_obj.get('Region')
            service = feed_obj.get('Service')
            try:
                response = requests.get(
                    url=feed_url,
                    verify=self._verify,
                    proxies=self._proxies,
                )
                response.raise_for_status()
                data = response.json()
                # filter empty entries and category param, add metadata
                indicators = [i for i in data if ('ips' in i or 'urls' in i)
                              and i.get('category') in self.category_list]
                for i in indicators:  # add relevant fields of services
                    i.update({
                        'Region': region,
                        'Service': service,
                        'FeedURL': feed_url
                    })
                result.extend(indicators)
            except requests.exceptions.SSLError as err:
                demisto.debug(str(err))
                raise Exception(f'Connection error in the API call to {INTEGRATION_NAME}.\n'
                                f'Check your not secure parameter.\n\n{err}')
            except requests.ConnectionError as err:
                demisto.debug(str(err))
                raise Exception(f'Connection error in the API call to {INTEGRATION_NAME}.\n'
                                f'Check your Server URL parameter.\n\n{err}')
            except requests.exceptions.HTTPError as err:
                demisto.debug(f'Got an error from {feed_url} while fetching indicators {(str(err))} ')
                if err.response.status_code == 503:
                    raise Exception(f'The service located at {feed_url} is unavailable while fetching '
                                    f'indicators {(str(err))} ')
                elif err.response.status_code == 400 and region == GERMANY:
                    raise Exception('The service returned a 400 status code, this could possibly be due to the Germany'
                                    ' endpoint being unavailable. Please exclude Germany from All using the parameter'
                                    ' Allow Germany.')
                else:
                    raise Exception(f'HTTP error in the API call to {INTEGRATION_NAME}.\n\n{err}')
            except ValueError as err:
                demisto.debug(str(err))
                raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {err}')
        return result

    @staticmethod
    def check_indicator_type(indicator):
        """Checks the indicator type.
           The indicator type can be classified as one of the following values: CIDR, IPv6CIDR, IP, IPv6 or Domain.

        Args:
            indicator: indicator value

        Returns:
            The type of the indicator
        """
        is_ip_indicator = FeedIndicatorType.ip_to_indicator_type(indicator)
        if is_ip_indicator:
            return is_ip_indicator
        elif '*' in indicator:
            return FeedIndicatorType.DomainGlob
        # domain
        else:
            return FeedIndicatorType.Domain


def test_module(client: Client, *_) -> tuple[str, dict[Any, Any], dict[Any, Any]]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.build_iterator()
    return 'ok', {}, {}


def fetch_indicators(client: Client, indicator_type_lower: str, limit: int = -1, enrichment_excluded: bool = False) -> list[dict]:
    """Retrieves indicators from the feed

    Args:
        client: Client object with request
        indicator_type_lower: indicator type
        limit: limit the results

    Returns:
        Indicators.
    """
    iterator = client.build_iterator()
    # filter indicator_type specific entries
    if indicator_type_lower != 'both':
        iterator = [i for i in iterator if indicator_type_lower in i]
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    for item in iterator:
        if indicator_type_lower == 'both':
            values = item.get('ips', []) + item.get('urls', [])
        else:
            values = item.get(indicator_type_lower)
        if values:
            for value in values:
                type_ = Client.check_indicator_type(value)
                raw_data = {
                    'value': value,
                    'type': type_,
                }
                for key, val in item.items():
                    if key not in ['ips', 'urls']:
                        raw_data.update({key: val})

                indicator_mapping_fields = {
                    "port": argToList(item.get('tcpPorts', '')),
                    "service": item.get('serviceArea', '')
                }

                if item.get('expressRoute'):
                    indicator_mapping_fields["office365expressroute"] = item.get('expressRoute')
                if item.get('category'):
                    indicator_mapping_fields["office365category"] = item.get('category')
                if item.get('required'):
                    indicator_mapping_fields["office365required"] = item.get('required')
                if item.get('notes'):
                    indicator_mapping_fields["description"] = item.get('notes')
                indicator_mapping_fields['tags'] = client.tags
                if client.tlp_color:
                    indicator_mapping_fields['trafficlightprotocol'] = client.tlp_color

                indicator_obj = {
                    'value': value,
                    'type': type_,
                    'rawJSON': raw_data,
                    'fields': indicator_mapping_fields,
                }

                if enrichment_excluded:
                    indicator_obj['enrichmentExcluded'] = enrichment_excluded

                indicators.append(indicator_obj)

    return indicators


def get_indicators_command(client: Client,
                           args: dict[str, str],
                           enrichment_excluded: bool = False) -> tuple[str, dict[Any, Any], dict[Any, Any]]:
    """Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """
    indicator_type = str(args.get('indicator_type'))
    indicator_type_lower = indicator_type.lower()
    limit = int(demisto.args().get('limit')) if 'limit' in demisto.args() else 10
    indicators = fetch_indicators(client, indicator_type_lower, limit, enrichment_excluded)
    human_readable = tableToMarkdown('Indicators from Office 365 Feed:', indicators,
                                     headers=['value', 'type'], removeNull=True)

    return human_readable, {}, {'raw_response': indicators}


def fetch_indicators_command(client: Client, enrichment_excluded: bool = False) -> list[dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: Client object with request

    Returns:
        Indicators.
    """
    indicators = fetch_indicators(client, 'both', enrichment_excluded=enrichment_excluded)
    return indicators


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    unique_id = str(uuid.uuid4())
    regions_list = build_region_or_category_list(argToList(params.get('regions')), ALL_REGIONS_LIST,
                                                 allow_germany=params.get('allow_germany'))
    services_list = argToList(params.get('services'))
    category_list = build_region_or_category_list(argToList(params.get('category', ['All'])), ALL_CATEGORY_LIST)
    urls_list = build_urls_dict(regions_list, services_list, unique_id)
    use_ssl = not params.get('insecure', False)
    tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')
    enrichment_excluded = demisto.params().get('enrichmentExcluded', False)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(urls_list, category_list, use_ssl, tags, tlp_color)
        commands: dict[str, Callable[[Client, dict[str, str]], tuple[str, dict[Any, Any], dict[Any, Any]]]] = {
            'test-module': test_module,
            'office365-get-indicators': get_indicators_command
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, enrichment_excluded)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as err:
        err_msg = f'Error in {INTEGRATION_NAME} Integration. [{err}]'
        return_error(err_msg)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

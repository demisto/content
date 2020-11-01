from typing import Dict, List, Tuple, Any, Callable, Optional

import uuid
import urllib3

from CommonServerPython import *

# disable insecure warnings
urllib3.disable_warnings()
INTEGRATION_NAME = 'Office 365'


def build_urls_dict(regions_list: list, services_list: list, unique_id) -> List[Dict[str, Any]]:
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

    def __init__(self, urls_list: list, insecure: bool = False, tags: Optional[list] = None,
                 tlp_color: Optional[str] = None):
        """
        Implements class for Office 365 feeds.
        :param urls_list: List of url, regions and service of each service.
        :param insecure: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        :param tlp_color: Traffic Light Protocol color.
        """
        self._urls_list: List[dict] = urls_list
        self._verify: bool = insecure
        self.tags = [] if tags is None else tags
        self.tlp_color = tlp_color
        self._proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)

    def build_iterator(self) -> List:
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
                indicators = [i for i in data if 'ips' in i or 'urls' in i]  # filter empty entries and add metadata]
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
                demisto.debug(str(err))
                raise Exception(f'Connection error in the API call to {INTEGRATION_NAME}.\n')
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


def test_module(client: Client, *_) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.build_iterator()
    return 'ok', {}, {}


def fetch_indicators(client: Client, indicator_type_lower: str, limit: int = -1) -> List[Dict]:
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
    if not indicator_type_lower == 'both':
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

                indicators.append({
                    'value': value,
                    'type': type_,
                    'rawJSON': raw_data,
                    'fields': indicator_mapping_fields
                })

    return indicators


def get_indicators_command(client: Client, args: Dict[str, str]) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
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
    indicators = fetch_indicators(client, indicator_type_lower, limit)
    human_readable = tableToMarkdown('Indicators from Office 365 Feed:', indicators,
                                     headers=['value', 'type'], removeNull=True)

    return human_readable, {}, {'raw_response': indicators}


def fetch_indicators_command(client: Client) -> List[Dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: Client object with request

    Returns:
        Indicators.
    """
    indicators = fetch_indicators(client, 'both')
    return indicators


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    unique_id = str(uuid.uuid4())
    regions_list = argToList(params.get('regions'))
    services_list = argToList(params.get('services'))
    urls_list = build_urls_dict(regions_list, services_list, unique_id)
    use_ssl = not params.get('insecure', False)
    tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(urls_list, use_ssl, tags, tlp_color)
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
            'test-module': test_module,
            'office365-get-indicators': get_indicators_command
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as err:
        err_msg = f'Error in {INTEGRATION_NAME} Integration. [{err}]'
        return_error(err_msg)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

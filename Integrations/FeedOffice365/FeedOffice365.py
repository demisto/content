import ipaddress
from typing import Dict, List, Tuple, Any, Callable

import uuid
import urllib3

from CommonServerPython import *

# disable insecure warnings
urllib3.disable_warnings()
INTEGRATION_NAME = 'Office365'


def build_urls_dict(regions_list: list, services_list: list, unique_id) -> List[Dict[str, Any]]:
    """Builds a URL dictionary with the relevant data for each Sub feed

    Args:
        regions_list: list of regions
        services_list: list of services
        unique_id: unique uuid

    Returns:
        URLs sub feeds list
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


def check_indicator_type(indicator):
    """Checks the indicator type

    Args:
        indicator: IP

    Returns:
        The IP type per the indicators defined in Demisto
    """
    if '/' in indicator:  # check for network
        try:
            ip_ = ipaddress.ip_network(indicator)
        except Exception:
            return 'URL'
        if ip_.version == 4:
            return 'CIDR'
        if ip_.version == 6:
            return 'IPv6CIDR'
        demisto.debug(f'Office365 feed indicator type unknown: {str(indicator)}')
        return None
    try:
        ip_ = ipaddress.ip_address(indicator)
    except Exception:
        return 'URL'
    if ip_.version == 4:
        return 'IPv4'
    if ip_.version == 6:
        return 'IPv6'
    demisto.debug(f'Office365 feed indicator type unknown: {str(indicator)}')
    return None


class Client(BaseClient):
    """
    Client to use in the Office365 Feed integration. Overrides BaseClient.
    Office 365 IP address and URL web service announcement:
    https://docs.microsoft.com/en-us/office365/enterprise/managing-office-365-endpoints?redirectSourcePath=%252fen-us%252farticle%252fmanaging-office-365-endpoints-99cab9d4-ef59-4207-9f2b-3728eb46bf9a#webservice
    https://techcommunity.microsoft.com/t5/Office-365-Blog/Announcing-Office-365-endpoint-categories-and-Office-365-IP/ba-p/177638
    """

    def __init__(self, urls_list: list, indicator: str, insecure: bool = False, proxy: bool = False):
        """
        Implements class for Office365 feeds.
        :param urls_list: List of url, regions and service of each sub feed.
        :param indicator: the JSON attribute to use as indicator. Can be ips or urls. Default: ips
        :param insecure: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        :param proxy: boolean, if *false* feed HTTPS server certificate will not use proxies. Default: *false*
        """
        super().__init__(base_url=urls_list, verify=insecure, proxy=proxy)
        self.indicator = indicator

    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """
        result = []
        for feed_obj in self._base_url:
            feed_url = feed_obj.get('FeedURL')
            region = feed_obj.get('Region')
            service = feed_obj.get('Service')
            try:
                response = requests.get(
                    url=feed_url,
                    verify=self._verify
                )
                response.raise_for_status()
                data = response.json()
                indicators = [i for i in data if 'ips' in i or 'urls' in i]  # filter empty entries and add metadata]
                for i in indicators:  # add relevant fields of sub feeds
                    i.update({
                        "Region": region,
                        "Service": service,
                        "FeedURL": feed_url
                    })
                result.extend(indicators)
            except requests.exceptions.SSLError as err:
                demisto.debug(str(err))
                raise Exception(f'Connection error in the API call to Office365.\n'
                                f'Check your not secure parameter.\n\n{err}')
            except requests.ConnectionError as err:
                demisto.debug(str(err))
                raise Exception(f'Connection error in the API call to Office365.\n'
                                f'Check your Server URL parameter.\n\n{err}')
            except requests.exceptions.HTTPError as err:
                demisto.debug(str(err))
                raise Exception(f'Error issuing the request call to Office365.\n\n{err}')
            except ValueError as err:
                demisto.debug(str(err))
                raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {err}')
        return result


def test_module(client: Client, *_) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.build_iterator()
    return 'ok', {}, {}


def get_indicators_command(client: Client, args: Dict[str, str]) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
    """Retrieves indicators from the feed to the war-room.

    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """
    indicator_type = str(args.get('indicator_type'))
    iterator = client.build_iterator()
    indicator_type_lower = indicator_type.lower()
    indicators = []
    raw_response = []

    # filter indicator_type specific entries
    iterator = [i for i in iterator if indicator_type_lower in i or indicator_type_lower == 'both']
    limit = int(demisto.args().get('limit')) if 'limit' in demisto.args() else 10
    iterator = iterator[:limit]

    for item in iterator:
        if indicator_type_lower == 'both':
            values = item.get('ips') if 'ips' in iterator else item.get('urls')
        else:
            values = item.get(indicator_type_lower)
        if values:
            for value in values:
                type_ = check_indicator_type(value)
                indicators.append({
                    "Value": value,
                    "Type": type_,
                    'rawJSON': {"Value": value, "Type": type_}
                })
                raw_data = {
                    'value': value,
                    'type': type_
                }
                for k, v in item.items():
                    if k not in ['ips', 'urls']:
                        raw_data.update({k: v})
                raw_response.append(raw_data)
    human_readable = tableToMarkdown('Indicators from Office 365 Feed:', indicators,
                                     headers=['Value', 'Type'], removeNull=True)

    return human_readable, {f'{INTEGRATION_NAME}.Indicator': indicators}, {'raw_response': raw_response}


def fetch_indicators_command(client: Client, *_) -> List[Dict]:
    """Fetches indicators from the feed to the indicators tab.

    Args:
        client: Client object with request

    Returns:
        Indicators.
    """
    indicator_type = client.indicator
    indicator_type_lower = indicator_type.lower()
    iterator = client.build_iterator()
    indicators = []
    for item in iterator:
        if indicator_type_lower == 'both':
            values = item.get('ips') if 'ips' in iterator else item.get('urls')
        else:
            values = item.get(indicator_type_lower)
        if values:
            for value in values:
                type_ = check_indicator_type(value)
                raw_data = {
                    'value': value,
                    'type': type_,
                }
                for k, v in item.items():
                    if k not in ['ips', 'urls']:
                        raw_data.update({k: v})
                indicators.append({
                    "value": value,
                    "type": type_,
                    "rawJSON": raw_data,
                })
    return indicators


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    unique_id = str(uuid.uuid4())
    regions_list = argToList(demisto.params().get('regions'))
    services_list = argToList(demisto.params().get('services'))
    urls_list = build_urls_dict(regions_list, services_list, unique_id)
    indicator = demisto.params().get('indicator')
    insecure = demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy')

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(urls_list, indicator, insecure, proxy)
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
            'test-module': test_module,
            'get-indicators': get_indicators_command
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

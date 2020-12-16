import re
import urllib3
from typing import Dict, List, Tuple, Optional

from CommonServerPython import *

# disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = 'Azure'
AZUREJSON_URL = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519'  # disable-secrets-detection

ERROR_TYPE_TO_MESSAGE = {
    requests.ConnectionError: F'Connection error in the API call to {INTEGRATION_NAME}.\n',
    requests.exceptions.SSLError: F'Connection error in the API call to {INTEGRATION_NAME}.\n'
                                  F'Check your \'Trust any certificate\' parameter.\n\n',
    requests.exceptions.HTTPError: F'Error issuing the request call to {INTEGRATION_NAME}.\n\n',
}


class Client(BaseClient):
    """Client to use in the Azure Feed integration. Overrides BaseClient.

    Args:
        regions_list (list): List of regions to filter.
        services_list (list): List of services to filter.
        insecure (bool): False if feed HTTPS server certificate should be verified, True otherwise.
        proxy (bool): False if feed HTTPS server certificate will not use proxies, True otherwise.
    """

    def __init__(self, regions_list: list, services_list: list, polling_timeout: int = 20, insecure: bool = False,
                 proxy: bool = False):
        super().__init__(base_url=AZUREJSON_URL, verify=not insecure, proxy=proxy)
        self.regions_list = regions_list
        self.services_list = services_list
        self._polling_timeout = polling_timeout

    @staticmethod
    def build_ip_indicator(azure_ip_address, **indicator_metadata) -> Dict:
        """Creates an IP data dict.

        Args:
            azure_ip_address (str): IP extracted from Azure.
            **indicator_metadata (dict): Additional information related to the IP.

        Returns:
            Dict. IP data object.
        """
        if re.match(ipv4cidrRegex, azure_ip_address):
            type_ = FeedIndicatorType.CIDR

        elif re.match(ipv4Regex, azure_ip_address):
            type_ = FeedIndicatorType.IP

        elif re.match(ipv6cidrRegex, azure_ip_address):
            type_ = FeedIndicatorType.IPv6CIDR

        elif re.match(ipv6Regex, azure_ip_address):
            type_ = FeedIndicatorType.IPv6

        else:
            LOG(F'{INTEGRATION_NAME} - Unknown IP version: {azure_ip_address}')
            return {}

        ip_object = {
            'value': azure_ip_address,
            'type': type_,
        }
        ip_object.update(indicator_metadata)

        return ip_object

    def get_azure_download_link(self):
        """Extracts the download link for the file from the Azure url.

        Returns:
            str. The download link.
        """
        azure_url_response = self._http_request(
            method='GET',
            full_url=self._base_url,
            url_suffix='',
            stream=False,
            timeout=self._polling_timeout,
            resp_type='text'
        )

        download_link_search_regex = re.search(r'downloadData={.+(https://(.)+\.json)\",', azure_url_response)
        download_link = download_link_search_regex.group(1) if download_link_search_regex else None

        if download_link is None:
            raise RuntimeError(F'{INTEGRATION_NAME} - Download link not found')

        demisto.debug(F'download link: {download_link}')

        return download_link

    def get_download_file_content_values(self, download_link: str) -> Dict:
        """Create a request to receive file content from link.

        Args:
            download_link (str): Link to the desired Azure file.

        Returns:
            Dict. Content of values section in the Azure downloaded file.
        """
        file_download_response = self._http_request(
            method='GET',
            full_url=download_link,
            url_suffix='',
            stream=True,
            timeout=self._polling_timeout
        )

        return file_download_response.get('values')

    @staticmethod
    def extract_metadata_of_indicators_group(indicators_group_data: Dict) -> Dict:
        """Extracts metadata of an indicators group.

        Args:
            indicators_group_data (Dict): Indicator's group object from the Azure downloaded file.

        Returns:
            Dict. Indicators group metadata.
        """
        indicator_metadata = dict()

        indicator_metadata['id'] = indicators_group_data.get('id')
        indicator_metadata['name'] = indicators_group_data.get('name')
        indicator_properties = indicators_group_data.get('properties')

        if not indicator_properties:
            LOG(F'{INTEGRATION_NAME} - no properties for indicators group {indicator_metadata["name"]}')
            return {}

        indicator_metadata['region'] = indicator_properties.get('region')
        indicator_metadata['platform'] = indicator_properties.get('platform')
        indicator_metadata['system_service'] = indicator_properties.get('systemService')
        indicator_metadata['address_prefixes'] = indicator_properties.get('addressPrefixes', [])

        return indicator_metadata

    @staticmethod
    def filter_and_aggregate_values(address_list: List) -> List:
        """For each indicator value from the given list we aggregate the all the different keys found.

        Args:
            address_list (List): list of indicator objects containing objects with duplicate values.

        Returns:
            List. List of filtered indicator objects (no indicator value appear twice) and aggregated data
        """
        indicator_objects: dict = {}
        for item_to_search in address_list:
            current_value = item_to_search.get('value')
            ind_obj = indicator_objects.get(current_value)
            if ind_obj:
                indicator_objects[current_value].update(item_to_search)
            else:
                indicator_objects[current_value] = item_to_search

        return [value for value in indicator_objects.values()]

    def extract_indicators_from_values_dict(self, values_from_file: Dict) -> List:
        """Builds a list of all IP indicators in the input dict.

        Args:
            values_from_file (Dict): The values object from the Azure downloaded file.

        Returns:
            list. All indicators that match the filtering options.
        """
        results = []

        if values_from_file is None:
            LOG(F'{INTEGRATION_NAME} - No values in JSON response')
            return []

        for indicators_group in values_from_file:
            demisto.debug(F'{INTEGRATION_NAME} - Extracting value: {indicators_group.get("id")}')

            indicator_metadata = self.extract_metadata_of_indicators_group(indicators_group)
            if not indicator_metadata:
                continue

            is_region_not_in_filter = 'All' not in self.regions_list and \
                                      indicator_metadata['region'] not in self.regions_list
            is_service_not_in_filter = 'All' not in self.services_list and \
                                       indicator_metadata['system_service'] not in self.services_list

            if is_region_not_in_filter or is_service_not_in_filter:
                continue

            for address in indicator_metadata['address_prefixes']:
                results.append(
                    self.build_ip_indicator(address,
                                            azure_name=indicator_metadata['name'],
                                            azure_id=indicator_metadata['id'],
                                            azure_region=indicator_metadata['region'],
                                            azure_platform=indicator_metadata['platform'],
                                            azure_system_service=indicator_metadata['system_service'])
                )
        return self.filter_and_aggregate_values(results)

    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """
        try:
            download_link = self.get_azure_download_link()
            values_from_file = self.get_download_file_content_values(download_link)
            results = self.extract_indicators_from_values_dict(values_from_file)

            return results

        except (requests.exceptions.SSLError, requests.ConnectionError, requests.exceptions.HTTPError) as err:
            demisto.debug(str(err))
            raise Exception(ERROR_TYPE_TO_MESSAGE[err.__class__] + str(err))

        except RuntimeError as err:
            demisto.debug(str(err))
            raise RuntimeError('Could not fetch download link from Azure')

        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {err}')


def test_module(client: Client) -> Tuple[str, Dict, Dict]:
    """Test the ability to fetch Azure file.
    Args:
        client: Client object.
    Returns:
        str. ok for success, relevant error string otherwise.
    """
    try:
        if 'All' in client.regions_list and len(client.regions_list) >= 2:
            err_msg = 'ConfigurationError: You may not select additional regions if you selected \'All\''
            return_error(err_msg)

        if 'All' in client.services_list and len(client.services_list) >= 2:
            err_msg = 'ConfigurationError: You may not select additional services if you selected \'All\''
            return_error(err_msg)

        download_link = client.get_azure_download_link()
        client.get_download_file_content_values(download_link)

    except (requests.exceptions.SSLError, requests.ConnectionError, requests.exceptions.HTTPError) as err:
        demisto.debug(str(err))
        raise Exception(ERROR_TYPE_TO_MESSAGE[err.__class__] + str(err))

    return 'ok', {}, {}


def get_indicators_command(client: Client, feedTags: list, tlp_color: Optional[str]) -> Tuple[str, Dict, Dict]:
    """Retrieves indicators from the feed to the war-room.

    Args:
        client (Client): Client object configured according to instance arguments.
        feedTags (list): The indicator tags.
        tlp_color (str): Traffic Light Protocol color

    Returns:
        Tuple of:
            str. Information to be printed to war room.
            Dict. The raw data of the indicators.
    """
    limit = int(demisto.args().get('limit')) if 'limit' in demisto.args() else 10
    indicators, raw_response = fetch_indicators_command(client, feedTags, tlp_color, limit)

    human_readable = tableToMarkdown('Indicators from Azure Feed:', indicators,
                                     headers=['value', 'type'], removeNull=True)

    return human_readable, {}, {'raw_response': raw_response}


def fetch_indicators_command(client: Client, feedTags: list, tlp_color: Optional[str], limit: int = -1) \
        -> Tuple[List[Dict], List]:
    """Fetches indicators from the feed to the indicators tab.
    Args:
        client (Client): Client object configured according to instance arguments.
        limit (int): Maximum number of indicators to return.
        feedTags (list): Indicator tags
        tlp_color (str): Traffic Light Protocol color
    Returns:
        Tuple of:
            str. Information to be printed to war room.
            Dict. Data to be entered to context.
            Dict. The raw data of the indicators.
    """
    iterator = client.build_iterator()
    indicators = []
    raw_response = []

    if limit != -1:
        iterator = iterator[:limit]

    for indicator in iterator:
        indicator_obj = {
            'value': indicator['value'],
            'type': indicator['type'],
            'fields': {
                'region': indicator.get('azure_region'),
                'service': indicator.get('azure_system_service'),
                'tags': feedTags,
            },
            'rawJSON': indicator
        }

        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color

        indicators.append(indicator_obj)
        raw_response.append(indicator)

    return indicators, raw_response


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    regions_list = argToList(demisto.params().get('regions'))
    if not regions_list:
        regions_list = ['All']

    services_list = argToList(demisto.params().get('services'))
    if not services_list:
        services_list = ['All']

    feedTags = argToList(demisto.params().get('feedTags'))
    tlp_color = demisto.params().get('tlp_color')

    polling_arg = demisto.params().get('polling_timeout', '')
    polling_timeout = int(polling_arg) if polling_arg.isdigit() else 20
    insecure = demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    command = demisto.command()
    try:
        client = Client(regions_list, services_list, polling_timeout, insecure, proxy)
        if command == 'test-module':
            return_outputs(*test_module(client))
        elif command == 'azure-get-indicators':
            if feedTags:
                feedTags['tags'] = feedTags
            return_outputs(*get_indicators_command(client, feedTags, tlp_color))
        elif command == 'fetch-indicators':
            indicators, _ = fetch_indicators_command(client, feedTags, tlp_color)
            for single_batch in batch(indicators, batch_size=2000):
                demisto.createIndicators(single_batch)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception:
        raise


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

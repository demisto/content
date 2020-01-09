import re
import urllib3
import ipaddress
import requests
from typing import Dict, List, Tuple

from CommonServerPython import *

# disable insecure warnings
urllib3.disable_warnings()

REGIONS_XPATH = '/AzurePublicIpAddresses/Region'
AZUREJSON_URL = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519'

INTEGRATION_NAME = 'Azure'

ERROR_TYPE_TO_MESSAGE = {
    requests.exceptions.SSLError: F'Connection error in the API call to {INTEGRATION_NAME}.\n'
                                    F'Check your not secure parameter.\n\n',
    requests.ConnectionError: F'Connection error in the API call to {INTEGRATION_NAME}.\n'
                                F'Check your Server URL parameter.\n\n',
    requests.exceptions.HTTPError: F'Error issuing the request call to {INTEGRATION_NAME}.\n\n',
}


class Client(BaseClient):
    """Client to use in the Azure Feed integration. Overrides BaseClient.

    Args:
        insecure (bool): False if feed HTTPS server certificate is verified, True otherwise.
        proxy (bool):False if feed HTTPS server certificate will not use proxies, True otherwise.
    """

    def __init__(self, regions_list: list, services_list: list, polling_timeout: int, insecure: bool,
                 proxy: bool):
        super().__init__(base_url=AZUREJSON_URL, verify=insecure, proxy=proxy)
        self.regions_list = regions_list
        self.services_list = services_list
        self._polling_timeout = polling_timeout

    @staticmethod
    def build_ip_indicator(azure_address_prefix, **keywords) -> Dict:
        """Creates an IP data dict.

        Args:
            azure_address_prefix (str): IP extracted from Azure.
            **keywords (dict): Additional information related to the IP.

        Returns:
            Dict. IP data object.
        """
        try:
            address_type = ipaddress.ip_network(azure_address_prefix)
        except Exception:
            LOG(F'{INTEGRATION_NAME} - Invalid ip range: {azure_address_prefix}')
            return {}

        if address_type.version == 4:
            type_ = 'IPv4'
        elif address_type.version == 6:
            type_ = 'IPv6'
        else:
            LOG.error(F'{INTEGRATION_NAME} - Unknown IP version: {address_type.version}')
            return {}

        ip_object = {
            'value': azure_address_prefix,
            'type': type_,
        }
        ip_object.update(keywords)

        return ip_object

    def get_azure_download_link(self):
        """Extracts the download link for the file from the Azure url.

        Returns:
            str. The download link.
        """
        azure_url_response = requests.get(
            url=self._base_url,
            stream=False,
            verify=self._verify,
            timeout=self._polling_timeout
        )

        azure_url_response.raise_for_status()
        download_link = re.search(r'(https://.+\.json)\",', azure_url_response.text).group(1)

        return download_link

    def get_download_file_content_values(self, download_link: str) -> Dict:
        """Create a request to receive file content from link.

        Args:
            download_link (str): Link to the desired Azure file.

        Returns:
            Dict. Content of values section in the Azure downloaded file.
        """
        if download_link is None:
            raise RuntimeError(F'{INTEGRATION_NAME} - failoverLink not found')
        LOG(F'download link: {download_link}')

        file_download_response = requests.get(
            url=download_link,
            stream=True,
            verify=self._verify,
            timeout=self._polling_timeout
        )

        file_download_response.raise_for_status()
        file_download_response_json = file_download_response.json()  # type: Dict

        return file_download_response_json.get('values', None)

    @staticmethod
    def extract_metadata_of_indicators_group(indicators_group_data: Dict) -> Dict:
        """Extracts metadata of an indicators group.

        Args:
            indicators_group_data (Dict): Indicator's group object from the Azure downloaded file.

        Returns:
            Dict. Indicators group metadata.
        """
        indicator_metadata = dict()

        indicator_metadata['id'] = indicators_group_data.get('id', None)
        indicator_metadata['name'] = indicators_group_data.get('name', None)
        indicator_properties = indicators_group_data.get('properties', None)

        if indicator_properties is None:
            LOG.error(F'{INTEGRATION_NAME} - no properties for indicators group {indicator_metadata["name"]}')
            return {}

        indicator_metadata['region'] = indicator_properties.get('region', None)
        indicator_metadata['platform'] = indicator_properties.get('platform', None)
        indicator_metadata['system_service'] = indicator_properties.get('systemService', None)
        indicator_metadata['address_prefixes'] = indicator_properties.get('addressPrefixes', [])

        return indicator_metadata

    def extract_indicators_from_values_dict(self, values_from_file: Dict) -> List:
        """Builds a list of all IP indicators in the input dict.

        Args:
            values_from_file (Dict): The values object from the Azure downloaded file.

        Returns:
            list. All indicators that match the filtering options.
        """
        results = []

        if values_from_file is None:
            LOG.error(F'{INTEGRATION_NAME} - No values in JSON response')
            return []

        for indicators_group in values_from_file:
            LOG(F'{INTEGRATION_NAME} - Extracting value: {indicators_group.get("id", None)}')

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

        return results

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

        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {err}')

        except RuntimeError as err:
            demisto.debug(str(err))
            raise Exception(err)


def test_module(client: Client) -> Tuple[str, Dict, Dict]:
    """Test the ability to fetch Azure file.
    Args:
        client: Client object.
    Returns:
        str. ok for success, relevant error string otherwise.
    """
    try:
        download_link = client.get_azure_download_link()
        client.get_download_file_content_values(download_link)

    except (requests.exceptions.SSLError, requests.ConnectionError, requests.exceptions.HTTPError) as err:
        demisto.debug(str(err))
        raise Exception(ERROR_TYPE_TO_MESSAGE[err.__class__] + str(err))

    return 'ok', {}, {}


def get_indicators_command(client: Client) -> Tuple[str, Dict, Dict]:
    """Retrieves indicators from the feed to the war-room.

    Args:
        client (Client): Client object configured according to instance arguments.

    Returns:
        Tuple of:
            str. Information to be printed to war room.
            Dict. Data to be entered to context.
            Dict. The raw data of the indicators.
    """
    limit = int(demisto.args().get('limit')) if 'limit' in demisto.args() else 10

    indicators, raw_response = fetch_indicators(client, limit)

    human_readable = tableToMarkdown('Indicators from Azure Feed:', indicators,
                                     headers=['Value', 'Type'], removeNull=True)

    return human_readable, {f'{INTEGRATION_NAME}.Indicator(val.value && val.value === obj.value': indicators}, {
        'raw_response': raw_response}


def fetch_indicators(client: Client, limit: int = -1) -> Tuple[List[Dict], List]:
    """Fetches indicators from the feed to the indicators tab.
    Args:
        client (Client): Client object configured according to instance arguments.
        limit (int): Maximum number of indicators to return.
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
        raw_data = {
            'Value': indicator['value'],
            'Type': 'ip',
            'Azure_group_name': indicator['azure_name'],
            'Azure_group_id': indicator['azure_id'],
            'Azure_region': indicator['azure_region'],
            'Azure_platform': indicator['azure_platform'],
            'Azure_system_service': indicator['azure_system_service']
        }

        indicators.append({
            "Value": indicator['value'],
            "Type": 'ip',
            'rawJSON': {"Value": indicator['value'], "Type": 'ip'}
        })

        raw_response.append(raw_data)

    return indicators, raw_response


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    regions_list = argToList(demisto.params().get('regions', ''))
    services_list = argToList(demisto.params().get('services', ''))
    polling_arg = demisto.params().get('polling_timeout', '')
    polling_timeout = int(polling_arg) if polling_arg.isdigit() else 20
    insecure = demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy') == 'true'

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(regions_list, services_list, polling_timeout, insecure, proxy)

        commands = {
            'test-module': test_module,
            'get-indicators': get_indicators_command
        }

        if command in commands:
            return_outputs(*commands[command](client))

        # elif command == 'fetch-indicators':
        #     indicators, _ = fetch_indicators(client)
        #
        #     for single_batch in batch(indicators, batch_size=1500):
        #         demisto.createIndicators(single_batch)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as err:
        err_msg = f'Error in {INTEGRATION_NAME} Integration. [{err}]'
        return_error(err_msg)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

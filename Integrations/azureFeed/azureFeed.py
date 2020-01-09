import bs4
import netaddr
import urllib3
import requests
from typing import Dict, List, Tuple, Any, Callable

from CommonServerPython import *

REGIONS_XPATH = '/AzurePublicIpAddresses/Region'
AZUREJSON_URL = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519'

# disable insecure warnings
urllib3.disable_warnings()
INTEGRATION_NAME = 'Azure'

ERROR_TYPE_TO_MESSAGE = {
    'requests.exceptions.SSLError': f'Connection error in the API call to {INTEGRATION_NAME}.\n'
                                    f'Check your not secure parameter.\n\n',
    'requests.ConnectionError': f'Connection error in the API call to {INTEGRATION_NAME}.\n'
                                f'Check your Server URL parameter.\n\n',
    'requests.exceptions.HTTPError': f'Error issuing the request call to {INTEGRATION_NAME}.\n\n',
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
            address_type = netaddr.IPNetwork(azure_address_prefix)
        except Exception:
            LOG.exception(F'{INTEGRATION_NAME} - Invalid ip range: {azure_address_prefix}')
            return {}

        if address_type.version == 4:
            type_ = 'IPv4'
        elif address_type.version == 6:
            type_ = 'IPv6'
        else:
            LOG.error(F'{INTEGRATION_NAME} - Unknown IP version: {address_type.version}')
            return {}

        ip_object = {
            'indicator': azure_address_prefix,
            'type': type_,
            'confidence': 100,
            'sources': [INTEGRATION_NAME]
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
        response_html_tree = bs4.BeautifulSoup(azure_url_response.content, "lxml")

        return response_html_tree.find('a', class_='failoverLink')

    def get_download_file_content_values(self, download_link):
        """Create a request to receive file content from link.

        Args:
            download_link (str): Link to the desired Azure file.

        Returns:
            Dict. Content of values section in the Azure downloaded file.
        """
        if download_link is None:
            raise RuntimeError(F'{INTEGRATION_NAME} - failoverLink not found')
        LOG.debug(F'download link: {download_link["href"]}')

        file_download_response = requests.get(
            url=download_link["href"],
            stream=True,
            verify=self._verify,
            timeout=self._polling_timeout
        )

        file_download_response.raise_for_status()
        file_download_response_json = file_download_response.json()  # type: Dict

        return file_download_response_json.get('values', None)

    @staticmethod
    def extract_metadata_of_indicators_group(indicators_group_data):
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
            return None

        indicator_metadata['region'] = indicator_properties.get('region', None)
        indicator_metadata['platform'] = indicator_properties.get('platform', None)
        indicator_metadata['system_service'] = indicator_properties.get('systemService', None)
        indicator_metadata['address_prefixes'] = indicator_properties.get('addressPrefixes', [])

        return indicator_metadata

    def extract_indicators_from_values_dict(self, values_from_file):
        """Builds a list of all IP indicators in the input dict.

        Args:
            values_from_file (Dict): The values object from the Azure downloaded file.

        Returns:

        """
        results = []

        if values_from_file is None:
            LOG.error(F'{INTEGRATION_NAME} - No values in JSON response')
            return []

        for indicators_group in values_from_file:
            LOG.debug(F'{INTEGRATION_NAME} - Extracting value: {indicators_group.get("id", None)}')

            indicator_metadata = self.extract_metadata_of_indicators_group(indicators_group)
            if not indicator_metadata:
                continue

            if indicator_metadata['region'] not in self.regions_list or \
                    indicator_metadata['system_service'] not in self.services_list:
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

        except requests.exceptions as err:
            demisto.debug(str(err))
            raise Exception(ERROR_TYPE_TO_MESSAGE[err.__class__] + err)

        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {err}')

        except RuntimeError as err:
            demisto.debug(str(err))
            raise Exception(err)


def test_module(client: Client, *_) -> str:
    """Test the ability to fetch Azure file.
    Args:
        client: Client object.
    Returns:
        str. ok for success, relevant error string otherwise.
    """
    try:
        download_link = client.get_azure_download_link()
        client.get_download_file_content_values(download_link)

    except requests.exceptions as err:
        return ERROR_TYPE_TO_MESSAGE[err.__class__]

    return 'ok'


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
        values = item.get(indicator_type_lower)
        raw_data = {'type': indicator_type[:-1]}
        if values:
            for value in values:
                raw_data['value'] = value
                indicators.append({
                    "Value": value,
                    "Type": indicator_type[:-1],
                    'rawJSON': {"Value": value, "Type": indicator_type[:-1]}
                })
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
        values = item.get(indicator_type_lower)
        raw_data = {'type': indicator_type[:-1]}
        if values:
            for value in values:
                raw_data['value'] = value
                indicators.append({
                    "value": value,
                    "type": indicator_type[:-1],
                    "rawJSON": raw_data,
                })
    return indicators


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
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
            'test-module': test_module,
            'get-indicators': get_indicators_command
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))

        # elif command == 'fetch-indicators':
        #     indicators = fetch_indicators_command(client)
        #     for batch1 in batch(indicators, batch_size=2000):
        #         demisto.createIndicators(batch)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as err:
        err_msg = f'Error in {INTEGRATION_NAME} Integration. [{err}]'
        return_error(err_msg)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

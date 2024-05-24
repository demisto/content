import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any, Tuple, List

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DEFAULT_FEED_TAGS = {'XPANSE'}
DEFAULT_ASSET_SEARCH_LIMIT = 5000
DEFAULT_IPRANGE_SEARCH_LIMIT = 1000
''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, feed_tags: List[str], tlp_color: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.feed_tags = feed_tags
        self.tlp_color = tlp_color
        self.verify = verify
        self.proxy = proxy

    def list_asset_internet_exposure_request(self, search_params: list[dict], search_from: int = 0,
                                             search_to: int = DEFAULT_ASSET_SEARCH_LIMIT) -> dict[str, Any]:
        """Get a list of all your internet exposure assets using the '/assets/get_assets_internet_exposure/' endpoint.

        Args:
            search_params (list): list of search parameters to add to the API call body.
            search_from (int): Starting search index.
            search_to (int): Ending search index.

        Returns:
            dict: dict containing list of internet exposure assets.
        """
        data = {"request_data": {"filters": search_params, "search_to": int(search_to), "search_from": int(search_from)}}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/assets/get_assets_internet_exposure/', json_data=data)

        return response


    def list_external_ip_address_range_request(self) -> dict[str, Any]:
        """Get a list of all your internet exposure IP ranges using the '/assets/get_external_ip_address_ranges/' endpoint.

        Returns:
            dict: dict containing list of external ip address ranges.
        """
        data = {"request_data": {"search_to": DEFAULT_IPRANGE_SEARCH_LIMIT}}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/assets/get_external_ip_address_ranges/', json_data=data)

        return response


''' COMMAND FUNCTIONS '''


def test_module(client: Client):  # pragma: no cover
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    client.get_indicators()
    return_results('ok')


def map_indicator_fields(raw_indicator: Dict[str, Any]) -> Dict[str, Any]:
    command_keys = ['Command', 'Description', 'Usecase', 'Category', 'Privileges', 'MitreID', 'OperatingSystem', 'MitreName']

    mapped_commands = []
    mapped_detections = []
    mapped_paths = []
    commands = raw_indicator.get('Commands', [])
    detections = raw_indicator.get('Detection', [])
    paths = raw_indicator.get('Full_Path', [])
    if commands:
        for command in commands:
            mapped_commands.append({lolbas_field.lower(): command.get(lolbas_field) for lolbas_field in command_keys})
    if detections:
        for detection in detections:
            if detection_keys := list(detection.keys()):
                mapped_detections.append({'type': detection_keys[0], 'content': detection.get(detection_keys[0])})
    if paths:
        for path in paths:
            mapped_paths.append({'path': path.get('Path')})

    return {
        'Commands': mapped_commands,
        'Detections': mapped_detections,
        'Paths': mapped_paths,
        'description': raw_indicator.get('Description')
    }


def build_indicators(client: Client, raw_indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Builds indicators JSON data in XSOAR expected format from the raw response.
    """
    demisto.debug(f'Creating {len(raw_indicators)} indicators.')
    indicators: List[Dict[str, Any]] = []

    for raw_indicator in raw_indicators:
        indicator: Dict[str, Any] = {
            'type': ThreatIntel.ObjectsNames.TOOL,
            'value': raw_indicator.get('Name'),
            'fields': map_indicator_fields(raw_indicator),
            'rawJSON': raw_indicator,
        }
        if tlp_color := client.tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color
        if feed_tags := client.feed_tags:
            indicator['fields']['tags'] = feed_tags
        indicators.append(indicator)
    return indicators


def fetch_indicators(client: Client, limit: int = None) -> \
        List[Dict[str, Any]] | Tuple[List[Dict[str, Any]], str]:
    """
        Fetch indicators from Xpanse API and create indicators in XSOAR.
    """
    # Start here, need to make sure we just pass back list of indicators (asset or range)
    # Also need to think about only searching for assets we care about now (ipv4 range and asset=cert/ip/domain)
    asset_response = client.list_asset_internet_exposure_request()
    range_response = client.list_external_ip_address_range_request() 
    indicators = build_indicators(client, asset_response + range_response)
    if limit:
        return indicators[:limit], response
    return indicators, response


''' MAIN FUNCTION '''


def get_indicators(client, limit):
    """
    Get indicators from Xpanse API, mainly for debug.
    """
    hr_list = []
    output_list = []

    if limit and limit <= 0:
        raise ValueError('Limit must be a positive number.')
    indicators, raw_res = fetch_indicators(client, limit)
    indicators = indicators[:limit] if isinstance(indicators, List) \
        else [indicators] if indicators else []
    for record in indicators:
        hr = {'Name': record.get('value'), 'Description': record.get('fields', {}).get('description')}
        hr_list.append(hr)
        output_list.append({'Type': record.get('type'),
                            'Commands': record.get('fields', {}).get('Commands'),
                            'Detections': record.get('fields', {}).get('Detections'),
                            'Paths': record.get('fields', {}).get('Paths')} | hr)
    return CommandResults(outputs=output_list, outputs_prefix='ASM.Indicators', raw_response=raw_res,
                          readable_output=tableToMarkdown("Xpanse indicators", hr_list, headers=['Name', 'Description']),
                          outputs_key_field='Name')


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    base_url = params.get('base_url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    # Append default tags.
    feed_tags = list(set(argToList(params.get('feedTags', []))) | DEFAULT_FEED_TAGS)
    tlp_color = params.get('tlp_color', '')
    command = demisto.command()

    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            feed_tags=feed_tags,
            tlp_color=tlp_color,
        )

        if command == 'test-module':
            test_module(client)
        elif command == 'fetch-indicators':
            indicators, _ = fetch_indicators(client)
            for iter_ in batch(indicators, batch_size=2000):
                try:
                    demisto.createIndicators(iter_)
                except Exception:
                    # find problematic indicator
                    for indicator in iter_:
                        try:
                            demisto.createIndicators([indicator])
                        except Exception as err:
                            demisto.debug(f'createIndicators Error: failed to create the following indicator:'
                                          f' {indicator}\n {err}')
                    raise
        elif command == 'xpanse-get-indicators':
            limit = arg_to_number(demisto.args().get('limit', None))
            return_results(get_indicators(client, limit))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

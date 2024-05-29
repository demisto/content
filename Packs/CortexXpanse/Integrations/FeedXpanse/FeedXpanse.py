import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any, Tuple, List, Iterable
from ipaddress import IPv4Address, AddressValueError, summarize_address_range

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DEFAULT_FEED_TAGS = {'XPANSE'}
# DEFAULT_ASSET_SEARCH_LIMIT = 5000
# DEFAULT_IPRANGE_SEARCH_LIMIT = 1000
DEFAULT_ASSET_SEARCH_LIMIT = 5000
DEFAULT_IPRANGE_SEARCH_LIMIT = 1000
V1_URL_SUFFIX = "/public_api/v1"

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, feed_tags: List[str], tlp_color: str, headers: Dict):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)
        self.feed_tags = feed_tags
        self.tlp_color = tlp_color
        self.verify = verify
        self.proxy = proxy
        self.headers= headers

    # TODO Paging from V1, add later
    def _paginate(self, method: str, url_suffix: str, params: Optional[Dict[str, Any]]) -> Iterable[Any]:
        next_url: Optional[str] = None

        while True:
            result = self._http_request(
                method=method,
                url_suffix=url_suffix,
                full_url=next_url,
                params=params,
                raise_on_status=True,
                timeout=30
            )

            data = result.get('data', [])
            if data is not None:
                yield from data

            pagination = result.get('pagination', None)
            if pagination is None:
                break
            next_url = pagination.get('next', None)
            if next_url is None:
                break

            params = None

    def list_asset_internet_exposure_request(self, search_params: list[dict] = [], search_from: int = 0,
                                             search_to: int = DEFAULT_ASSET_SEARCH_LIMIT) -> dict[str, Any]:
        """Get a list of all your internet exposure assets using the '/assets/get_assets_internet_exposure/' endpoint.

        Args:
            search_params (list): list of search parameters to add to the API call body.
            search_from (int): Starting search index.
            search_to (int): Ending search index.

        Returns:
            dict: dict containing list of internet exposure assets.
        """
        data = {"request_data": {"filters": search_params, "search_to": int(search_to), "search_from": int(search_from), "use_page_token": True}}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/assets/get_assets_internet_exposure/', json_data=data)

        return response


    def list_external_ip_address_range_request(self, search_params: list[dict] = []) -> dict[str, Any]:
        """Get a list of all your internet exposure IP ranges using the '/assets/get_external_ip_address_ranges/' endpoint.

        Returns:
            dict: dict containing list of external ip address ranges.
        """
        data = {"request_data": {"filters": search_params, "search_to": DEFAULT_IPRANGE_SEARCH_LIMIT, "use_page_token": True}}

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
    client.list_asset_internet_exposure_request()
    return_results('ok')


def create_x509_certificate_grids(self, string_object: Optional[str]) -> list:
        """
        Creates a grid field related to the subject and issuer field of the x509 certificate object.

        Args:
            string_object (Optional[str]): A str in format of C=ZA, ST=Western Cape, L=Cape Town, O=Thawte.

        Returns:
            list: The return value. A list of dict [{"title": "C", "data": "ZA"}].
        """
        result_grid_list = []
        if string_object:
            key_value_pairs = string_object.split(', ')
            for pair in key_value_pairs:
                result_grid = {}
                key, value = pair.split('=', 1)
                result_grid['title'] = key
                result_grid['data'] = value
                result_grid_list.append(result_grid)
        return result_grid_list


def map_indicator_fields(raw_indicator: Dict[str, Any], asset_type: str) -> Dict[str, Any]:
    indicator_fields = {"internal": True}
    if asset_type == 'Domain':
        return indicator_fields
    if asset_type == 'Certificate':
        if cert_details := raw_indicator.get("certificate_details"):
            if signatureAlgorithm := cert_details.get("signatureAlgorithm"):
                indicator_fields['signaturealgorithm'] = signatureAlgorithm
            if serialNumber := cert_details.get("serialNumber"):
                indicator_fields['serialnumber'] = serialNumber
            if validNotAfter := cert_details.get("validNotAfter"):
                indicator_fields['validitynotafter'] = timestamp_to_datestring(validNotAfter)
            if validNotBefore := cert_details.get("validNotBefore"):
                indicator_fields['validitynotbefore'] = timestamp_to_datestring(validNotBefore)
            if issuer := cert_details.get("issuer"):
                indicator_fields['issuer'] = create_x509_certificate_grids(issuer)
            if subject := cert_details.get("subject"):
                indicator_fields['subject'] = create_x509_certificate_grids(subject)
    else:
        return indicator_fields


def map_indicator_type(asset_type: str) -> str:
    asset_types_mapping = {
        'UNASSOCIATED_RESPONSIVE_IP': 'IP',
        "DOMAIN": 'Domain',
        "CERTIFICATE": "X509 Certificate",
        'CIDR': 'CIDR'
    }
    try:
        return asset_types_mapping[asset_type]
    except:
        return "None"


def build_asset_indicators(client: Client, raw_indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Builds indicators JSON data in XSOAR expected format from the raw response.
    """
    demisto.debug(f'Creating {len(raw_indicators)} asset indicators.')
    indicators: List[Dict[str, Any]] = []
    for raw_indicator in raw_indicators:
        # Need to skip IPv6 responsive or not found type
        if raw_indicator.get("ipv6s") or ((indicator_type := map_indicator_type(raw_indicator.get("asset_type", 'None'))) == 'None'):
            continue
        name = raw_indicator.get('name')
        demisto.debug(f'JW_log {indicator_type} --- {name}')
        # DomainGlob is a wildcard domain
        indicator: Dict[str, Any] = {
            'value': name,
            'type': 'DomainGlob' if '*' in name and indicator_type == 'Domain' else indicator_type,
            'fields': map_indicator_fields(raw_indicator, indicator_type),
            'rawJSON': raw_indicator
        }
        if tlp_color := client.tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color
        if feed_tags := client.feed_tags:
            indicator['fields']['tags'] = feed_tags
        indicators.append(indicator)
    return indicators


def build_range_indicators(client: Client, raw_indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Builds indicators JSON data in XSOAR expected format from the raw response.
    """
    demisto.debug(f'Creating {len(raw_indicators)} range indicators.')
    indicators: List[Dict[str, Any]] = []
    for raw_indicator in raw_indicators:
        start_address = raw_indicator.get('first_ip', None)
        end_address = raw_indicator.get('last_ip', None)
        if start_address is None or end_address is None:
            continue
        try:
            start_address = IPv4Address(start_address)
            end_address = IPv4Address(end_address)
        except AddressValueError:
            continue
        for cidr in summarize_address_range(start_address, end_address):
            indicator: Dict[str, Any] = {
                'type': 'CIDR',
                'value': str(cidr),
                'fields': {"internal": True},
                'rawJSON': raw_indicator,
            }
            if tlp_color := client.tlp_color:
                indicator['fields']['trafficlightprotocol'] = tlp_color
            if feed_tags := client.feed_tags:
                indicator['fields']['tags'] = feed_tags
            indicators.append(indicator)
    return indicators


def fetch_indicators(client: Client, limit: int = None, asset_type: str = 'all') -> \
        List[Dict[str, Any]] | Tuple[List[Dict[str, Any]], str]:
    """
        Fetch indicators from Xpanse API and create indicators in XSOAR.
    """
    asset_list, range_response, asset_response = [], [], []
    if asset_type == 'all':
        asset_list = ["CERTIFICATE","DOMAIN","UNASSOCIATED_RESPONSIVE_IP"]
    if 'domain' in asset_type:
        asset_list.append("DOMAIN")
    if 'certificate' in asset_type:
        asset_list.append("CERTIFICATE")
    if 'ipv4' in asset_type:
        asset_list.append("UNASSOCIATED_RESPONSIVE_IP")
    # TODO, might move the .get from these to underlying _pagination function
    asset_response = (client.list_asset_internet_exposure_request(search_params=[{"field": "type", "operator": "in", "value": asset_list}])).get("reply", {}).get("assets_internet_exposure", [])
    # Only doing IPv4 at this time
    if asset_type == 'all' or 'ipv4_range' in asset_type:
        range_response = (client.list_external_ip_address_range_request(search_params=[{"field": "Ipaddress_version", "operator": "eq", "value":4}])).get("reply", {}).get("external_ip_address_ranges", [])
    
    assset_indicators = build_asset_indicators(client, asset_response)
    range_indicators = build_range_indicators(client, range_response)
    
    full_response = asset_response + range_response
    all_indicators = assset_indicators + range_indicators
    if limit:
        return all_indicators[:limit], full_response
    return all_indicators, full_response


''' MAIN FUNCTION '''

#Todo, figure out this logic
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
                          readable_output=tableToMarkdown("Xpanse indicators", hr_list, headers=['Name', 'Type']),
                          outputs_key_field='Name')


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    base_url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    # Append default tags.
    feed_tags = list(set(argToList(params.get('feedTags', []))) | DEFAULT_FEED_TAGS)
    tlp_color = params.get('tlp_color', '')
    creds = params.get('credentials', {})
    api = creds.get('password', '')
    add_sensitive_log_strs(api)
    auth_id = creds.get('identifier', '')
    headers = {
        'Authorization': f'{api}',
        'x-xdr-auth-id': f'{auth_id}',
        'Content-Type': 'application/json'
    }
    command = demisto.command()

    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            feed_tags=feed_tags,
            tlp_color=tlp_color,
            headers=headers
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

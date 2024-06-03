import demistomock as demisto # noqa: F401
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import urllib3
from typing import Dict, Any, Tuple, List

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DEFAULT_FEED_TAGS = {'XPANSE'}
DEFAULT_ASSET_SEARCH_LIMIT = 5000
# DEFAULT_ASSET_SEARCH_LIMIT = 1000
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


    def list_asset_internet_exposure_request(self, search_params: list[dict] = [], search_from: int = 0,
                                             search_to: int = DEFAULT_ASSET_SEARCH_LIMIT, use_paging: bool = True) -> dict[str, Any]:
        """Get a list of all your internet exposure assets using the '/assets/get_assets_internet_exposure/' endpoint.

        Args:
            search_params (list): list of search parameters to add to the API call body.
            search_from (int): Starting search index.
            search_to (int): Ending search index.

        Returns:
            dict: dict containing list of internet exposure assets.
        """
        body = {"request_data": {"filters": search_params, "search_to": int(search_to), "search_from": int(search_from), "use_page_token": True}}
        full_response = []
        while True:
            result = self._http_request(
                method='POST',
                url_suffix=f'{V1_URL_SUFFIX}/assets/get_assets_internet_exposure/',
                json_data=body
            )

            data = result.get('reply', {}).get('assets_internet_exposure')
            if data:
                full_response.extend(data)
            if not use_paging:
                break
            pagination = result.get('reply', {}).get("next_page_token")
            if pagination is None:
                break
            body["request_data"]["next_page_token"] = pagination
        
        return full_response


''' HELPER FUNCTIONS '''


def create_x509_certificate_grids(string_object: Optional[str]) -> list:
    """
    Creates a grid field related to the subject and issuer field of the x509 certificate object.

    Args:
        string_object (Optional[str]): A str in format of C=ZA,ST=Western Cape,L=Cape Town,O=Thawte.

    Returns:
        list: The return value. A list of dict [{"title": "C", "data": "ZA"}].
    """
    result_grid_list = []
    if string_object:
        # TODO sometimes there is something like `, Inc.`, not sure how to account for that
        key_value_pairs = string_object.split(',')
        for pair in key_value_pairs:
            result_grid = {}
            if '=' in pair:
                key, value = pair.split('=', 1)
                result_grid['title'] = key
                result_grid['data'] = value
                result_grid_list.append(result_grid)
    return result_grid_list


def map_indicator_fields(raw_indicator: Dict[str, Any], asset_type: str) -> Dict[str, Any]:
    description = raw_indicator.get('name') + " indicator of asset type " + asset_type + " from Cortex Xpanse"
    indicator_fields = {"internal": True, "description": description}
    if asset_type == 'Domain':
        if domain_details := raw_indicator.get("domain_details"):
            fields_mapping = {
                "creationDate": "creationdate",
                "registryExpiryDate": "expirationdate",
            }
            
            for key, mapped_key in fields_mapping.items():
                if detail_value := domain_details.get(key): 
                    indicator_fields[mapped_key] = timestamp_to_datestring(detail_value)
    
    elif asset_type == 'X509 Certificate':
        if cert_details := raw_indicator.get("certificate_details"):
            fields_mapping = {
                "signatureAlgorithm": ("signaturealgorithm", None),
                "serialNumber": ("serialnumber", None),
                "validNotAfter": ("validitynotafter", timestamp_to_datestring),
                "validNotBefore": ("validitynotbefore", timestamp_to_datestring),
                "issuer": ("issuer", create_x509_certificate_grids),
                "subject": ("subject", create_x509_certificate_grids),
            }

            for key, (mapped_key, processing_func) in fields_mapping.items():
                if detail_value := cert_details.get(key):
                    # Apply processing function if one is defined
                    if processing_func:
                        indicator_fields[mapped_key] = processing_func(detail_value)
                    else:
                        indicator_fields[mapped_key] = detail_value
    return indicator_fields


def map_indicator_type(asset_type: str) -> str:
    asset_types_mapping = {
        'UNASSOCIATED_RESPONSIVE_IP': 'IP',
        "DOMAIN": 'Domain',
        "CERTIFICATE": "X509 Certificate",
        'CIDR': 'CIDR'
    }
    return asset_types_mapping.get(asset_type, "None")


def build_asset_indicators(client: Client, raw_indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Builds indicators JSON data in XSOAR expected format from the raw response.
    """
    demisto.debug(f'Creating {len(raw_indicators)} asset indicators.')
    indicators: List[Dict[str, Any]] = []

    for raw_indicator in raw_indicators:
        asset_type = raw_indicator.get("asset_type", 'None')
        indicator_type = map_indicator_type(asset_type)

        # Skip IPv6 responsive or not found type
        if raw_indicator.get("ipv6s") or indicator_type == 'None':
            continue

        name = raw_indicator.get('name')
        indicator_type = 'DomainGlob' if '*' in name and indicator_type == 'Domain' else indicator_type
        fields = map_indicator_fields(raw_indicator, indicator_type)

        # Add TLP color and feed tags if they exist
        if client.tlp_color:
            fields['trafficlightprotocol'] = client.tlp_color
        if client.feed_tags:
            fields['tags'] = client.feed_tags

        indicator = {
            'value': name,
            'type': indicator_type,
            'fields': fields,
            'rawJSON': raw_indicator
        }

        indicators.append(indicator)

    return indicators


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
    client.list_asset_internet_exposure_request(search_to=1, use_paging=False)
    return_results('ok')

def fetch_indicators(client: Client, limit: int = None, asset_type: str = 'all'):
#       -> \ List[Dict[str, Any]] | List[Dict]:
    """
        Fetch indicators from Xpanse API and create indicators in XSOAR.
    """
    asset_list, asset_response = [], []
    if asset_type == 'all':
        asset_list = ["CERTIFICATE","DOMAIN","UNASSOCIATED_RESPONSIVE_IP"]
    if 'domain' in asset_type:
        asset_list.append("DOMAIN")
    if 'certificate' in asset_type:
        asset_list.append("CERTIFICATE")
    if 'ipv4' in asset_type:
        asset_list.append("UNASSOCIATED_RESPONSIVE_IP")
    if limit:
        asset_response = client.list_asset_internet_exposure_request(search_params=[{"field": "type", "operator": "in", "value": asset_list}], search_to=limit, use_paging=False)
    else:
        asset_response = client.list_asset_internet_exposure_request(search_params=[{"field": "type", "operator": "in", "value": asset_list}])
    
    assset_indicators = build_asset_indicators(client, asset_response)
    
    if limit:
        return assset_indicators[:limit], asset_response
    return assset_indicators, asset_response


''' MAIN FUNCTION '''


def get_indicators(client, args: Dict[str, Any]):
    """
    Get indicators from Xpanse API, mainly for debug.
    """
    hr_list = []
    output_list = []

    asset_type = ''
    if argToBoolean(args.get('ip', 'yes')):
        asset_type += 'ipv4'
    if argToBoolean(args.get('domain', 'yes')):
        asset_type += 'domain'
    if argToBoolean(args.get('certificate', 'yes')):
        asset_type += 'certificate'
    
    limit = arg_to_number(args.get('limit', None))

    if limit and limit <= 0:
        raise ValueError('Limit must be a positive number.')
    if asset_type == '':
        raise ValueError('need to specify at least one asset type')
    indicators, raw_res = fetch_indicators(client, limit, asset_type)

    indicators = indicators[:limit] if isinstance(indicators, List) \
        else [indicators] if indicators else []
    for record in indicators:
        hr = {'Name': record.get('value'), 'Type': record.get('type')}
        hr_list.append(hr)
        output_list.append({'Type': record.get('type'),
                            'Name': record.get('value')})
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
            #limit = arg_to_number(demisto.args().get('limit', None))
            return_results(get_indicators(client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

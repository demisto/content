from typing import Any, Callable, Dict, List, Tuple, Optional

import urllib3

import demistomock as demisto
from CommonServerPython import *

# disable insecure warnings
urllib3.disable_warnings()
INTEGRATION_NAME = 'Prisma Access'


class Client(BaseClient):
    """
    Client to use in the Prisma Access Feed integration. Overrides BaseClient.
    Prisma Access V2 API: https://api.gpcloudservice.com/getPrismaAccessIP/v2
    https://docs.paloaltonetworks.com/prisma/prisma-access/prisma-access-panorama-admin/prisma-access-overview/retrieve-ip-addresses-for-prisma-access
    """

    def __init__(self, clientConfigs: list, api_key: str, insecure: bool = False, proxy: bool = False,
                 tags: Optional[list] = [], tlp_color: Optional[str] = None):
        """
        Implements class for Prisma Access feed.
        :param clientConfigs: config data
        :param insecure: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        :param proxy: boolean, if *false* feed HTTPS server certificate will not use proxies. Default: *false*
        :param tlp_color: Traffic Light Protocol color.
        """
        self._apiKey = api_key
        self.tags = [] if tags is None else tags
        self.tlp_color = tlp_color
        super().__init__(base_url=clientConfigs, verify=not insecure, proxy=proxy)

    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """
        result = []
        for feed_obj in self._base_url:
            feed_url = feed_obj.get('FeedURL')
            postData = feed_obj.get('feedParams',
                                    {"serviceType": 'all',
                                     "addrType": 'all',
                                     "location": 'all'})

            try:
                response = requests.post(
                    url=feed_url,
                    verify=self._verify,
                    headers={
                        'header-api-key': self._apiKey
                    },
                    data=json.dumps(postData)
                )
                response.raise_for_status()
                responseData = response.json()
                prismaStatus = responseData.get('status', '')
                if 'success' == prismaStatus:
                    zones = responseData.get('result', [])
                    for z in zones:
                        zoneName = z.get('zone', '')
                        addresses = z.get('addresses', [])
                        for addr in addresses:
                            indicator = {
                                "zone": zoneName,
                                "value": addr,
                                "FeedURL": feed_url
                            }
                            if postData['serviceType'] != 'all':
                                indicator['serviceType'] = postData['serviceType']
                            if postData['addrType'] != 'all':
                                indicator['addrType'] = postData['addrType']
                            result.append(indicator)
                else:
                    demisto.debug(str(prismaStatus))
                    raise Exception(f'Non-success status returned from call to {INTEGRATION_NAME}.\n'
                                    f'Raw response: ' + json.dumps(responseData, indent=2))
            except requests.exceptions.SSLError as err:
                demisto.debug(str(err))
                raise Exception(f'SSL error in the API call to {INTEGRATION_NAME}.\n'
                                f'Check your not secure parameter.\n\n{err}')
            except requests.ConnectionError as err:
                demisto.debug(str(err))
                raise Exception(f'Connection error in the API call to {INTEGRATION_NAME}.\n'
                                f'Check your Server URL parameter.\n\n{err}')
            except requests.exceptions.HTTPError as err:
                demisto.debug(str(err))
                raise Exception(f'HTTP error in the API call to {INTEGRATION_NAME}:\n\n' + str(err))
            except ValueError as err:
                demisto.debug(str(err))
                raise ValueError(f'Could not parse returned data to Json. \n\nError message: {err}')
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


def fetch_indicators(client: Client, limit: int = -1) -> List[Dict]:
    """Retrieves indicators from the feed

    Args:
        client: Client object with request
        limit: limit the results

    Returns:
        Indicators.
    """
    iterator = client.build_iterator()
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    for item in iterator:
        value = item.get('value')
        raw_data = {
            "value": value,
            "serviceType": item.get('serviceType', ''),
            "addrType": item.get('addrType', ''),
            "zone": item.get('zone', '')
        }
        indicator_mapping_fields = {}
        indicator_mapping_fields['geocountry'] = item.get('zone', '')
        indicator_mapping_fields["description"] = 'IP from Prisma Access Egress API'
        indicator_mapping_fields['tags'] = client.tags
        if client.tlp_color:
            indicator_mapping_fields['trafficlightprotocol'] = client.tlp_color

        indicators.append({
            "value": value,
            "type": FeedIndicatorType.IP,
            "rawJSON": raw_data,
            "fields": indicator_mapping_fields,
            "zone": item.get('zone', '')
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
    limit = int(demisto.args().get('limit')) if 'limit' in demisto.args() else 0
    indicators = fetch_indicators(client, limit)
    human_readable = tableToMarkdown('Prisma Access Egress IPs:', indicators,
                                     headers=['zone', 'value'], removeNull=True)

    outputs = {
        'PrismaAccess.Egress.IP':
            [
                {
                    'Address': ip.get('value', ''),
                    'Zone': ip.get('zone', '')
                } for ip in indicators
            ]
    }

    retIndicators = {'raw_response': indicators}

    return human_readable, outputs, retIndicators


def fetch_indicators_command(client: Client) -> List[Dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: Client object with request

    Returns:
        Indicators.
    """
    indicators = fetch_indicators(client)
    return indicators


def main():
    PRISMA_ACCESS_EGRESS_V2_URI = 'getPrismaAccessIP/v2'
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    param_api_key = params.get('api_key') or (params.get('credentials') or {}).get('password')
    if not param_api_key:
        raise Exception('API Key must be provided.')
    insecure = params.get('insecure', False)
    proxy = params.get('proxy')
    tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')
    baseURL = params.get('URL')
    if baseURL[-1] != '/':
        baseURL += '/'
    feedURL = baseURL + PRISMA_ACCESS_EGRESS_V2_URI

    feedParams = {
        "serviceType": demisto.params().get('serviceType', 'all'),
        "addrType": demisto.params().get('addrType', 'all'),
        "location": demisto.params().get('location', 'all')
    }
    clientConfigs = [{'FeedURL': feedURL,
                      'feedParams': feedParams}]
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(clientConfigs, param_api_key, insecure, proxy, tags, tlp_color)
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
            'test-module': test_module,
            'prisma-access-get-indicators': get_indicators_command
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

import copy
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# IMPORTS
from datetime import datetime
import requests
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

XSOHR_TYPES_TO_CROWDSTRIKE = {
    'user-account': "username",
    'domain': "domain",
    'email-address': "email_address",
    'file-md5': "hash_md5",
    'file-sha256': "hash_sha256",
    'ipv4-addr': "ip_address",
    'ipv6-addr': "ip_address",
    'registry-key-value': "registry",
    'url': "url"
}
CROWDSTRIKE_TO_XSOHR_TYPES = {
    'username': 'User-Account',
    'domain': 'Domain',
    'email-address': 'Email_Address',
    'hash_md5': 'File-MD5',
    'hash_sha256': 'File-SHA256',
    'registry': 'Registry-Key-Value',
    'url': 'URL'
}


class Client(BaseClient):

    def __init__(self, client_id, client_secret, base_url, verify, proxy):
        self._client_id = client_id
        self._client_secret = client_secret
        self._verify_certificate = verify
        self._base_url = base_url
        super().__init__(base_url=base_url, verify=self._verify_certificate,
                         ok_codes=tuple(), proxy=proxy)
        self._token = self._get_access_token()
        self._headers = {'Authorization': 'Bearer ' + self._token}

    def http_request(self, method, url_suffix=None, full_url=None, headers=None, params=None, data=None,
                     timeout=10, auth=None) -> dict:

        return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                     params=params, data=data, timeout=timeout, auth=auth)

    def _get_access_token(self) -> str:
        body = {
            'client_id': self._client_id,
            'client_secret': self._client_secret
        }
        token_res = self.http_request(method='POST', url_suffix='/oauth2/token', data=body,
                                      auth=(self._client_id, self._client_secret))
        return token_res.get('access_token')

    def get_indicators(self, type: list = None, malicious_confidence: str = '', filter: str = '', q: str = '',
                       limit: int = 100, offset: int = 0, include_deleted=False,
                       get_indicators_command=False) -> Dict[str, Any]:
        if type:
            type_fql = build_type_fql(type)
            filter = f'{type_fql}+{filter}' if filter else type_fql

        if malicious_confidence:
            malicious_confidence_fql = f"malicious_confidence:'{malicious_confidence}'"
            filter = f"{malicious_confidence_fql}+{filter}" if filter else malicious_confidence_fql

        if not get_indicators_command:
            if last_run := get_last_run():
                filter = f'{last_run}+{filter}' if filter else last_run
                set_last_run()

        params = assign_params(include_deleted=include_deleted, limit=limit, offset=offset, q=q, filter=filter)

        response = self.http_request(method='GET', params=params, headers=self._headers,
                                     url_suffix='intel/combined/indicators/v1')
        return response


def build_type_fql(types_list: list) -> str:
    """Builds an indicator type query for the query"""

    if 'ALL' in types_list:
        # Replaces "ALL" for all types supported on XSOAR.
        crowdstrike_types = ['username', 'domain', 'email_address', 'hash_md5', 'hash_sha256', 'ip_address',
                             'registry', 'url']
        crowdstrike_types = [f"type:'{type}'" for type in crowdstrike_types]

    else:
        crowdstrike_types = [f"type:'{XSOHR_TYPES_TO_CROWDSTRIKE.get(type.lower(), type)}'" for type in types_list]

    result = ','.join(crowdstrike_types)
    return result


def set_last_run():
    current_time = datetime.now()
    current_timestamp = datetime.timestamp(current_time)
    timestamp = str(int(current_timestamp))
    demisto.setLastRun({'last_modified_time': timestamp})


def get_last_run() -> str:
    if last_run := demisto.getLastRun().get('last_modified_time'):
        params = f'last_updated:>{last_run}'
        set_last_run()
    else:
        params = ''
        set_last_run()
    return params


def fetch_indicators(client: Client, tlp_color, include_deleted, type, malicious_confidence, filter, q, feed_tags):
    """ fetch indicators from the Crowdstrike Intel

    Args:
        client: Client object
        tlp_color (str): Traffic Light Protocol color.
        include_deleted (bool): include deleted indicators. (send just as parameter)
        type (list): type indicator.
        malicious_confidence(str): medium, low, high
        filter (str): indicators filter.
        q (str): generic phrase match
        feed_tags (list): tags to assign fetched indicators

    Returns:
        list of indicators(list)
    """
    raw_response = client.get_indicators(type=type, malicious_confidence=malicious_confidence, filter=filter, q=q,
                                         include_deleted=include_deleted, get_indicators_command=True)
    parsed_indicators = []
    indicator = {}
    for resource in raw_response['resources']:
        indicator = {
            'type': CROWDSTRIKE_TO_XSOHR_TYPES.get(resource.get('type'), resource.get('type')),
            'value': resource.get('indicator'),
            'rawJSON': resource,
            'fields': {
                'tags': [label.get('name') for label in indicator.get('labels')]
            }
        }
        if feed_tags:
            indicator['fields']['tags'] = feed_tags
        if tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color
        parsed_indicators.append(indicator)

    return parsed_indicators


def crowdstrike_indicators_list_command(client: Client, args: dict) -> CommandResults:
    """ Gets indicator from Crowdstrike Intel to readable output

    Args:
        client: Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    include_deleted = argToBoolean(args.get('include_deleted', False))
    type = argToList(args.get('type'))
    malicious_confidence = args.get('malicious_confidence')
    filter = args.get('filter')
    q = args.get('generic_phrase_match')
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 50))

    raw_response = client.get_indicators(type=type, malicious_confidence=malicious_confidence, filter=filter, q=q,
                                         limit=limit, offset=offset, include_deleted=include_deleted,
                                         get_indicators_command=True)
    indicators_list = raw_response.get('resources')
    if outputs := copy.deepcopy(indicators_list):
        for indicator in outputs:
            indicator['published_date'] = timestamp_to_datestring(indicator['published_date'])
            indicator['last_updated'] = timestamp_to_datestring(indicator['last_updated'])
            indicator['value'] = indicator['indicator']
            indicator['labels'] = [label.get('name') for label in indicator.get('labels')]
            del indicator['indicator']
            del indicator['relations']
            del indicator['_marker']

        readable_output = tableToMarkdown(name='Indicators from CrowdStrike Falcon Intel', t=outputs,
                                          headers=["type", "value", "id"], headerTransform=pascalToSpace)

        return CommandResults(
            outputs=outputs,
            outputs_prefix='CrowdStrikeFalconIntel.Indicators',
            outputs_key_field='id',
            readable_output=readable_output,
            raw_response=raw_response
        )
    else:
        return CommandResults(
            readable_output='No Indicators.',
            raw_response=raw_response
        )


def test_module(client: Client, args: dict) -> str:
    try:
        client.get_indicators(limit=1)
    except Exception:
        raise Exception("Could not fetch CrowdStrike Indicator Feed\n"
                        "\nCheck your API key and your connection to CrowdStrike.")
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')
    proxy = params.get('proxy', False)
    verify_certificate = not demisto.params().get('insecure', False)
    feed_tags = argToList(params.get('feedTags'))
    base_url = "https://api.crowdstrike.com/"
    tlp_color = params.get('tlp_color')
    include_deleted = argToBoolean(params.get('include_deleted', False))
    type = argToList(params.get('type'))
    malicious_confidence = params.get('malicious_confidence')
    filter = params.get('filter')
    q = params.get('q')
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, args)
            return_results(result)

        elif command == 'fetch-indicators':
            indicators = fetch_indicators(client=client, tlp_color=tlp_color, include_deleted=include_deleted,
                                          type=type, malicious_confidence=malicious_confidence,
                                          filter=filter, q=q, feed_tags=feed_tags)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

        elif command == 'crowdstrike-indicators-list':
            return_results(crowdstrike_indicators_list_command(client, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

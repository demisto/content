import copy
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# IMPORTS
from datetime import datetime
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

XSOAR_TYPES_TO_CROWDSTRIKE = {
    'account': "username",
    'domain': "domain",
    'email': "email_address",
    'file md5': "hash_md5",
    'file sha-256': "hash_sha256",
    'ip': "ip_address",
    'registry key': "registry",
    'url': "url"
}
CROWDSTRIKE_TO_XSOAR_TYPES = {
    'username': 'Account',
    'domain': 'Domain',
    'email_address': 'Email',
    'hash_md5': 'File MD5',
    'hash_sha256': 'File SHA-256',
    'registry': 'Registry Key',
    'url': 'URL',
    "ip_address": 'IP'
}


class Client(BaseClient):

    def __init__(self, client_id, client_secret, base_url, include_deleted, type, limit, tlp_color=None,
                 malicious_confidence=None, filter=None, generic_phrase=None, verify=True, proxy=False):
        self._client_id = client_id
        self._client_secret = client_secret
        super().__init__(
            base_url=base_url,
            verify=verify,
            ok_codes=tuple(),
            proxy=proxy
        )
        self._token = self._get_access_token()
        self._headers = {'Authorization': 'Bearer ' + self._token}
        self.type = type
        self.malicious_confidence = malicious_confidence
        self.filter = filter
        self.generic_phrase = generic_phrase
        self.include_deleted = include_deleted
        self.tlp_color = tlp_color
        self.limit = limit

    def http_request(self, method, url_suffix=None, full_url=None, headers=None, params=None, data=None,
                     timeout=10, auth=None) -> dict:

        return super()._http_request(
            method=method,
            url_suffix=url_suffix,
            full_url=full_url,
            headers=headers,
            params=params,
            data=data,
            timeout=timeout,
            auth=auth,
            error_handler=self.handle_error_response
        )

    def _get_access_token(self):
        body = {
            'client_id': self._client_id,
            'client_secret': self._client_secret
        }
        token_res = self.http_request(
            method='POST',
            url_suffix='/oauth2/token',
            data=body
        )
        return token_res.get('access_token')

    def get_indicators(self, params):
        response = self.http_request(
            method='GET',
            params=params,
            headers=self._headers,
            url_suffix='intel/combined/indicators/v1'
        )
        return response

    def fetch_indicators(self, limit: Optional[int], type: list = None, malicious_confidence='', filter='', q='',
                         offset: Optional[int] = 0, include_deleted=False,
                         fetch_command=False, tlp_color=None) -> list:
        """ Get indicators from CrowdStrike API

        Args:
            limit(int): number of indicators to return
            type: indicators type requested by customer
            malicious_confidence: indicator malicious confidence requested by customer
            filter: fql filter
            q: generic phrase match
            offset: indicators offset
            include_deleted: whether include deleted indicators or not
            fetch_command: In order not to update last_run time if it is not fetch command
            tlp_color: traffic light protocol

        Returns:
            (list): parsed indicators
        """
        if type:
            type_fql = self.build_type_fql(type)
            filter = f'{type_fql}+{filter}' if filter else type_fql

        if malicious_confidence:
            malicious_confidence_fql = f"malicious_confidence:'{malicious_confidence}'"
            filter = f"{filter}+{malicious_confidence_fql}" if filter else malicious_confidence_fql

        if fetch_command:
            if last_run := self.get_last_run():
                filter = f'{filter}+{last_run}' if filter else last_run

        demisto.info(f' filter {filter}')
        params = assign_params(include_deleted=include_deleted,
                               limit=limit,
                               offset=offset, q=q,
                               filter=filter,
                               sort='last_updated|asc')

        response = self.get_indicators(params=params)

        timestamp = self.set_last_run()

        # need to fetch all indicators after the limit
        if pagination := response.get('meta', {}).get('pagination'):
            pagination_offset = pagination.get('offset', 0)
            pagination_limit = pagination.get('limit')
            total = pagination.get('total', 0)
            if pagination_offset + pagination_limit < total:
                timestamp = response.get('resources', [])[-1].get('last_updated')

        if response.get('meta', {}).get('pagination', {}).get('total', 0) and fetch_command:
            demisto.setIntegrationContext({'last_modified_time': timestamp})
            demisto.info(f'set last_run: {timestamp}')

        indicators = self.create_indicators_from_response(response, tlp_color)
        return indicators

    @staticmethod
    def set_last_run():
        """
        Returns: Current timestamp
        """
        current_time = datetime.now()
        current_timestamp = datetime.timestamp(current_time)
        timestamp = str(int(current_timestamp))
        return timestamp

    @staticmethod
    def get_last_run() -> str:
        """ Gets last run time in timestamp

        Returns:
            last run in timestamp, or '' if no last run
        """
        if last_run := demisto.getIntegrationContext().get('last_modified_time'):
            demisto.info(f'get last_run: {last_run}')
            params = f'last_updated:>={last_run}'
        else:
            params = ''
        return params

    @staticmethod
    def create_indicators_from_response(raw_response, tlp_color=None) -> list:
        """ Builds indicators from API raw response

            Args:
                raw_response: response from crowdstrike API
                tlp_color: tlp color chosen by customer

            Returns:
                (list): list of indicators
            """

        parsed_indicators: list = []
        indicator: dict = {}
        for resource in raw_response['resources']:
            indicator = {
                'type': CROWDSTRIKE_TO_XSOAR_TYPES.get(resource.get('type'), resource.get('type')),
                'value': resource.get('indicator'),
                'rawJSON': resource,
                'fields': {'actor': resource.get('actors'),
                           'reports': resource.get('reports'),
                           'malwarefamily': resource.get('malware_families'),
                           'stixkillchainphases': resource.get('kill_chains'),
                           'ipaddress': resource.get('ip_address_types'),
                           'domainname': resource.get('domain_types'),
                           'targets': resource.get('targets'),
                           'threattypes': resource.get('threat_types'),
                           'vulnerabilities': resource.get('vulnerabilities'),
                           'maliciousconfidence': resource.get('malicious_confidence'),
                           'updateddate': resource.get('last_updated'),
                           'creationdate': resource.get('published_date'),
                           'tags': [label.get('name') for label in resource.get('labels')]  # type: ignore
                           }
            }
            if tlp_color:
                indicator['fields']['trafficlightprotocol'] = tlp_color
            parsed_indicators.append(indicator)

        return parsed_indicators

    @staticmethod
    def build_type_fql(types_list: list) -> str:
        """ Builds an indicator type query for the filter parameter

        Args:
            types_list(list): indicator types that was chosen by user

        Returns:
            (str): FQL query containing the relevant indicator types we want to fetch from Crowdstrike
        """

        if 'ALL' in types_list:
            # Replaces "ALL" for all types supported on XSOAR.
            crowdstrike_types = [f"type:'{type}'" for type in CROWDSTRIKE_TO_XSOAR_TYPES.keys()]
        else:
            crowdstrike_types = [f"type:'{XSOAR_TYPES_TO_CROWDSTRIKE.get(type.lower())}'" for type in types_list if
                                 type.lower() in XSOAR_TYPES_TO_CROWDSTRIKE]

        result = ','.join(crowdstrike_types)
        return result

    @staticmethod
    def handle_error_response(res) -> None:
        """
        Handle error response and display user specific error message based on status code.

        Args:
            res: response from API.

        Returns:
            raise DemistoException based on status code.
        """
        errors = []
        try:
            error_entry = res.json()
            errors = error_entry['errors']
        except Exception:  # ignoring json parsing errors
            pass

        # error_message = next((item for item in errors if item['code'] == res.status_code)).get('message')
        errors_array = [item.get('message') for item in errors if item['code'] == res.status_code]
        error_message = '\n'.join(errors_array)

        if error_message:
            raise DemistoException(f'Error in API call [{res.status_code}] - {res.reason}. {error_message}')
        else:
            raise DemistoException(f'Error in API call [{res.status_code}] - {res.reason}. {res.text}')


def fetch_indicators_command(client: Client):
    """ fetch indicators from the Crowdstrike Intel

    Args:
        client: Client object

    Returns:
        list of indicators(list)
    """
    parsed_indicators = client.fetch_indicators(
        type=client.type,
        malicious_confidence=client.malicious_confidence,
        filter=client.filter, q=client.generic_phrase,
        include_deleted=client.include_deleted,
        fetch_command=True,
        tlp_color=client.tlp_color,
        limit=client.limit
    )
    # we submit the indicators in batches
    for b in batch(parsed_indicators, batch_size=2000):
        demisto.createIndicators(b)
    return parsed_indicators


def crowdstrike_indicators_list_command(client: Client, args: dict) -> CommandResults:
    """ Gets indicator from Crowdstrike Intel to readable output

    Args:
        client: Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """

    offset = arg_to_number(args.get('offset', 0))
    limit = arg_to_number(args.get('limit', 50))
    parsed_indicators = client.fetch_indicators(
        type=client.type,
        malicious_confidence=client.malicious_confidence,
        filter=client.filter, q=client.generic_phrase,
        include_deleted=client.include_deleted,
        tlp_color=client.tlp_color,
        limit=limit,
        offset=offset,
        fetch_command=False
    )
    if outputs := copy.deepcopy(parsed_indicators):
        for indicator in outputs:
            indicator['id'] = indicator.get('rawJSON', {}).get('id')

        readable_output = tableToMarkdown(name='Indicators from CrowdStrike Falcon Intel', t=outputs,
                                          headers=["type", "value", "id"], headerTransform=pascalToSpace)

        return CommandResults(
            outputs=outputs,
            outputs_prefix='CrowdStrikeFalconIntel.Indicators',
            outputs_key_field='id',
            readable_output=readable_output,
            raw_response=parsed_indicators
        )
    else:
        return CommandResults(
            readable_output='No Indicators.'
        )


def test_module(client: Client, args: dict) -> str:
    try:
        client.fetch_indicators(limit=1, fetch_command=False)
    except Exception:
        raise Exception("Could not fetch CrowdStrike Indicator Feed\n"
                        "\nCheck your API key and your connection to CrowdStrike.")
    return 'ok'


def reset_last_run():
    """
    Reset the last run from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')
    proxy = params.get('proxy', False)
    verify_certificate = not demisto.params().get('insecure', False)
    base_url = params.get('base_url')
    tlp_color = params.get('tlp_color')
    include_deleted = argToBoolean(params.get('include_deleted', False))
    type = argToList(params.get('type'), 'ALL')
    malicious_confidence = params.get('malicious_confidence')
    filter = params.get('filter')
    generic_phrase = params.get('generic_phrase')
    max_fetch = arg_to_number(params.get('max_indicator_to_fetch')) if params.get('max_indicator_to_fetch') else 100
    args = demisto.args()

    try:
        command = demisto.command()
        demisto.info(f'Command being called is {demisto.command()}')

        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            tlp_color=tlp_color,
            include_deleted=include_deleted,
            type=type,
            malicious_confidence=malicious_confidence,
            filter=filter,
            generic_phrase=generic_phrase,
            limit=max_fetch
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, args)
            return_results(result)

        elif command == 'fetch-indicators':
            fetch_indicators_command(client=client)

        elif command == 'crowdstrike-indicators-list':
            return_results(crowdstrike_indicators_list_command(client, args))

        elif command == "crowdstrike-reset-fetch-indicators":
            return_results(reset_last_run())

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

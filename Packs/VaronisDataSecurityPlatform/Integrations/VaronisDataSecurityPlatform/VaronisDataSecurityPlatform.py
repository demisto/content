"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any
from requests_ntlm import HttpNtlmAuth

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

THREAT_MODEL_ENUM_ID = 5821
ALERT_STATUSES = { 'Open': 1, 'Under Investigation': 2, 'Closed': 3 }
STATUSES_TO_RETRY = [304, 405]
ALERT_COLUMNS = [
        'Alert.ID',
        'Alert.Rule.Name',
        'Alert.Time',
        'Alert.Rule.Severity.Name',
        'Alert.Rule.Category.Name',
        'Alert.Location.CountryName',
        'Alert.Location.SubdivisionName',
        'Alert.Status.Name',
        'Alert.CloseReason.Name',
        'Alert.Location.BlacklistedLocation',
        'Alert.Location.AbnormalLocation',
        'Alert.EventsCount',
        'Alert.User.Name',
        'Alert.User.SamAccountName',
        'Alert.User.AccountType.Name',
        'Alert.User.IsFlagged',
        'Alert.Data.IsFlagged',
        'Alert.Data.IsSensitive',
        'Alert.Filer.Platform.Name',
        'Alert.Asset.Path',
        'Alert.Filer.Name',
        'Alert.Device.HostName',
        'Alert.Device.IsMaliciousExternalIP',
        'Alert.Device.ExternalIPThreatTypesName'
    ]

''' CLIENT CLASS '''


class Client(BaseClient):

    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """
    def baseintegration_dummy(self, url: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """
        
        return {'dummy': url}
        
    def varonis_authenticate(self, username: str, password: str) -> Dict[str, Any]:
        ntlm = HttpNtlmAuth(username, password)
        response = self._http_request('POST', '/auth/win', auth=ntlm, data='grant_type=client_credentials')
        token = response['access_token']
        token_type = response['token_type']
        self._expires_in = response['expires_in']
        self._headers = {
            'Authorization': f'{token_type} {token}'
        }
        return response

    def varonis_get_enum(self, enum_id: int) -> Dict[str, Any]:
        respose = self._http_request('GET', f'/api/entitymodel/enum/{enum_id}')
        return respose

    def varonis_search_alerts(self, query: Dict[str, Any]) -> Dict[str, Any]:
        response = self._http_request('POST', f'/api/search/v2/search', json_data=query)
        return response

    def varonis_get_alerts(self, search_location: str, url_query: str, retries=0) -> Dict[str, Any]:
        response = self._http_request('GET', 
            f'/api/search/{search_location}?{url_query}', 
            retries=retries,
            status_list_to_retry=STATUSES_TO_RETRY
        )
        return response
    

''' HELPER FUNCTIONS '''
class QueryBuilder(object):
    def __init__(self, select_columns: 'list[str]', client: Client):
        self._filters = []
        self._columns = select_columns
        self._client = client
        self._url_query = ''

    def create_threat_model_filter(self, threats: 'list[str]'):
        rule_enum = self._client.varonis_get_enum(THREAT_MODEL_ENUM_ID)
        filter = {
            'path': 'Alert.Rule.ID',
            'operator': 'In',
            'values': []
        }

        for t in threats:
            rule = next(x for x in rule_enum if x['ruleName'] == t)
            threat_object = {
              'Alert.Rule.ID': rule['ruleID'],
              'displayValue': rule['ruleName']
            }
            filter['values'].append(threat_object)
        self._filters.append(filter)

    def create_time_interval_filter(self, start: datetime, end: datetime):
        filter = {
            'path': 'Alert.Time',
            'operator': 'Between',
            'values': [
                {
                    'Alert.Time': start.isoformat(),
                    'displayValue': start.isoformat(),
                    'Alert.Time0': end.isoformat()
                }
            ]
        }
        self._filters.append(filter)

    def create_alert_status_filter(self, statuses: 'list[str]'):
        status_enum = ALERT_STATUSES
        filter = {
            'path': 'Alert.Status.ID',
            'operator': 'In',
            'values': []
        }

        for status_name in statuses:
            status_id = status_enum[status_name]
            status_object = {
                'Alert.Status.ID': status_id,
                'displayValue': status_name
            }
            filter['values'].append(status_object)
        self._filters.append(filter)

    def build(self):
        query = dict()
        query['rows'] = { 'columns' : self._columns }
        query['query'] = { 
            'entityName': 'Alert', 
            'requestParams': { 'searchSource': 1, 'searchSourceName': 'Alert'}, # todo
            'filter': { 'filterOperator': 0, 'filters': self._filters }
        }
        return query

def get_query_range(count: int):
    return f'from=0&to={count-1}'

def get_search_result_path(search_response: 'list[Any]') -> str:
    return next(x['location'] for x in search_response if x['dataType'] == 'rows')

def get_alerts(client: Client, statuses: 'list[str]', threats: 'list[str]', start: datetime, end: datetime):
    builder = QueryBuilder(ALERT_COLUMNS, client)

    if statuses and any(statuses):
        builder.create_alert_status_filter(statuses)
    if threats and any(threats):    
        builder.create_threat_model_filter(threats)
    if start and end:
        builder.create_time_interval_filter(start, end)

    query = builder.build()
    print(json.dumps(query))
    response = client.varonis_search_alerts(query)
    location = get_search_result_path(response)
    print(location)
    range = get_query_range(10)
    search_result = client.varonis_get_alerts(location, range, 10)
    return search_result

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message

def varonis_get_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO: make sure you properly handle authentication
    username = demisto.params().get('credentials', {}).get('username')
    password = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/DatAdvantage')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. 'Authorization': {api key})
        headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        client.varonis_authenticate(username, password)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'varonis-get-alerts':
            return_results(varonis_get_alerts_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

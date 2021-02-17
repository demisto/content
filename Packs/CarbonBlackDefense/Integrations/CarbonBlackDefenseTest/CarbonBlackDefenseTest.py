import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """
    def __init__(self, base_url, verify, proxies, api_secret_key, api_key, organization_key):
        self.base_url = base_url
        self.verify = verify
        self.proxies = proxies
        self.api_secret_key = api_secret_key
        self.api_key = api_key
        self.organization_key = organization_key
        self.headers = {'X-Auth-Token': f'{self.api_secret_key}/{self.api_key}',
                        'Content-Type': 'application/json'}
        super(Client, self).__init__(base_url, verify, proxies)

    def get_alerts(self):
        res = self._http_request(method='POST',
                                 url_suffix=f'appservices/v6/orgs/{self.organization_key}/alerts/_search',
                                 headers=self.headers,
                                 json_data={})
        return res

    def get_alert_by_id(self, alert_id):
        res = self._http_request(method='GET',
                                 url_suffix=f'appservices/v6/orgs/{self.organization_key}/alerts/{alert_id}',
                                 headers=self.headers)
        return res


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
        client.get_alerts()
        message = 'ok'
    except DemistoException as e:
        # if 'Forbidden' in str(e) or 'Authorization' in str(e):
        #     message = 'Authorization Error: make sure API Key is correctly set'
        # else:
        raise e
    return message

def get_alert_details_command(client, args):
    alert_id = args.get('alertId')
    res = client.get_alert_by_id(alert_id)

    headers = ['id', 'category', 'device_id', 'device_name', 'device_username', 'create_time', 'ioc_hit', 'policy_name', 'process_name', 'type', 'severity']
    readable_output = tableToMarkdown('Carbon Black Defense Get Alert Details',
                                      res,
                                      headers,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.GetAlertDetails',
        outputs_key_field='id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """


    params = demisto.params()
    # get the service API url
    base_url = params.get('url')
    api_key = params.get('api_key')
    api_secret_key = params.get('api_secret_key')
    organization_key = params.get('organization_key')

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxies=proxy,
            api_secret_key=api_secret_key,
            api_key=api_key,
            organization_key=organization_key)

        commands = {
            'cbd-get-alert-details': get_alert_details_command
        }
        command = demisto.command()

        if command == 'test-module':
            demisto.results(test_module(client))
        elif command in commands:
            command_results = commands[command](client, demisto.args())
            return_results(command_results)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

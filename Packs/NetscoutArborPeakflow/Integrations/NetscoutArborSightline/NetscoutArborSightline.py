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
API_VERSION = 'v7'
IMPORTANCE_DICTIONARY = {
    'Low': 1,
    'Medium': 2,
    'High': 3
}
ONGOING_DICTIONARY = {
    'Ongoing': 'true',
    'Not Ongoing': 'false',
}

''' CLIENT CLASS '''


class NetscoutClient(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    OPERATOR_NAME_DICTIONARY = {
        'importance': 'importance_operator',
        'start_time': 'start_time_operator',
        'stop_time': 'stop_time_operator',
    }



    def __init__(self, base_url, verify, ok_codes, headers, proxy, alert_class=None, alert_type=None,
                 classification=None, importance=None, importance_operator=None, ongoing=None):
        self.alert_class = alert_class
        self.alert_type = alert_type
        self.classification = classification
        self.importance = importance
        self.importance_operator = importance_operator
        self.ongoing = ongoing

        super().__init__(base_url=base_url, verify=verify, ok_codes=ok_codes, headers=headers, proxy=proxy)

    @staticmethod
    def build_data_attribute_filter(self, **kwargs):
        param_list = []
        operator_names = self.OPERATOR_NAME_DICTIONARY.values()
        for key, val in kwargs.items():
            if key not in operator_names:
                operator = '='
                if operator_name := self.OPERATOR_NAME_DICTIONARY.get(key):
                    operator = kwargs.get(operator_name, '=')
                param_list += f'/data/attributes/{key + operator + val}'

        return ' AND '.join(param_list)

    mckibbenc: master
    def get_alerts(self, **kwargs):
        filter_value = self.build_data_attribute_filter(kwargs)

        self._http_request(
            method=
        )

        # incidents

    def fetch_incidents(self):
        self.get_alerts(
            alert_class=self.alert_class,
            alert_type=self.alert_type,
            classification=self.classification,
            importance=self.importance,
            importance_operator=self.importance_operator,
            ongoing=self.ongoing,
        )

    ''' HELPER FUNCTIONS '''

    # TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

    ''' COMMAND FUNCTIONS '''


def test_module(client: NetscoutClient) -> str:
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
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


# def fetch_incidents_command(client: NetscoutClient):
#     client.


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    api_token = params.get('api_token')
    base_url = urljoin(params['url'], 'api/sp', API_VERSION)
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    alert_class = params.get('alert_class')
    alert_type = params.get('alert_type')
    classification = params.get('classification')
    importance = IMPORTANCE_DICTIONARY.get(params.get('importance'))
    importance_operator = params.get('importance_operator', '=')
    ongoing = ONGOING_DICTIONARY.get(params.get('ongoing'))

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        headers: Dict = {
            'X-Arbux-APIToken': api_token
        }

        client = NetscoutClient(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            alert_class=alert_class,
            alert_type=alert_type,
            classification=classification,
            importance=importance,
            importance_operator=importance_operator,
            ongoing=ongoing
        )

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

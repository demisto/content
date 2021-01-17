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

ALERTS_DICTIONARY = {
    'alert_class': {
        'key': 'alert_class',
        'operator': '=',
        'value': ''
    },
    'alert_type': {
        'key': 'alert_type',
        'operator': '=',
        'value': ''
    },
    'classification': {
        'key': 'classification',
        'operator': '=',
        'value': ''
    },
    'importance': {
        'key': 'importance',
        'operator': '=',
        'value': ''
    },
    'importance_operator': {
        'key': 'importance_operator',
        'operator': '=',
        'value': ''
    },
    'ongoing': {
        'key': 'ongoing',
        'operator': '=',
        'value': ''
    }
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

    def __init__(self, base_url, verify, ok_codes, headers, proxy, alert_class, alert_type, classification, importance,
                 importance_operator, ongoing):
        self.alert_class = alert_class
        self.alert_type = alert_type
        self.classification = classification
        self.importance = importance
        self.importance_operator = importance_operator
        self.ongoing = ongoing

        super().__init__(base_url=base_url, verify=verify, ok_codes=ok_codes, headers=headers, proxy=proxy)

    @staticmethod
    def build_url_attribute_filters(**kwargs):
        param_list = [f'/data/attributes/{key}{operator}{val}' for key, val in kwargs.items()]
        return ' AND '.join(param_list)

    def get_alerts(self, alert_class: str, alert_type: str, classification: str, importance: int,
                   importance_operator: str, ongoing: str):
        self._http_request()

        incidents

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

def fetch_incidents_command(client: NetscoutClient):
    client.

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

bgp, cloudsignal, data, dos, smart, system_error, system_event, tms, traffic

autoclassify_restart, bgp_down, bgp_hijack, bgp_instability, bgp_trap, blob_thresh, cloud_mit_request, cloudsignal_fault, collector_down, collector_start, config_change, device_system_error, dns_baseline, dos, dos_host_detection, dos_mo_profiled, dos_profiled_network, dos_profiled_router, fingerprint_thresh, flexible_license_error, flow_down, flow_missing, gre_down, hw_failure, smart_thresh, interface_usage, nucleus_fault, routing_failover, routing_interface_failover, service_thresh, smart_thresh, snmp_down, spcomm_failure, tms_fault, traffic_auto_mitigation,

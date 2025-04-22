from CommonServerPython import *

''' IMPORTS '''

import json
import requests

# Disable insecure warnings
import urllib3
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

SECRET = demisto.params().get('secret')
BASE_URL = 'https://connect.signl4.com/webhook/{}'.format(SECRET)

''' HELPER FUNCTIONS '''


def http_request(method, params=None, data=None):
    result = requests.request(
        method,
        BASE_URL,
        verify=False,
        params=params,
        data=data
    )
    if result.status_code not in {200, 201}:
        return_error('Error in API call to SIGNL4 integration [%d] - %s' % (result.status_code, result.reason))

    return result.json()


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    result = send_signl4_alert()
    if 'eventId' in result:
        demisto.results("ok")
    else:
        error_code = result['error_code']
        description = result['description']
        demisto.results(f'{error_code} {description}')


def send_signl4_alert():
    """
    Sent HTTP post request
    """
    payload = {
        "Title": demisto.args().get('title'),
        "Message": demisto.args().get('message'),
        "X-S4-ExternalID": demisto.args().get('s4_external_id'),
        "X-S4-Status": "new",
        "X-S4-Service": demisto.args().get('s4_service'),
        "X-S4-Location": demisto.args().get('s4_location'),
        "X-S4-AlertingScenario": demisto.args().get('s4_alerting_scenario'),
        "X-S4-Filtering": demisto.args().get('s4_filtering'),
        "X-S4-SourceSystem": "CortexXSOAR"
    }

    return http_request("POST", data=json.dumps(payload))

def close_signl4_alert():
    """
    Sent HTTP post request
    """

    payload = {
        "X-S4-ExternalID": demisto.args().get('s4_external_id'),
        "X-S4-Status": "resolved",
        "X-S4-SourceSystem": "CortexXSOAR"
    }

    return http_request("POST", data=json.dumps(payload))


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    if not SECRET:
        raise DemistoException('Team or integration secret must be provided.')
    LOG(f'SECRET is {demisto.command()}')

    try:
        # Remove proxy if not set to true in params
        handle_proxy()

        if demisto.command() == 'test-module':
            test_module()
        elif demisto.command() == 'signl4_alert':
            send_signl4_alert()
        elif demisto.command() == 'signl4_close':
            close_signl4_alert()

    except Exception as ex:
        return_error(str(ex))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

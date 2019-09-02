import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from json.decoder import JSONDecodeError

import json
import traceback
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# Headers to be sent in requests
HEADERS = {
    'Authorization': 'Token ' + TOKEN,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None):
    url = SERVER + url_suffix
    LOG(f'attackiq is attempting {method} request sent to {url} with params:\n{json.dumps(params, indent=4)}')
    res = requests.request(
        method,
        url,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )
    # Handle error responses gracefully
    if res.status_code not in {200, 201}:
        return_error(f'Error in API call to Example Integration [{res.status_code}] - {res.reason}')
    # TODO: Add graceful handling of various expected issues (Such as wrong URL and wrong creds)
    try:
        return res.json()
    except JSONDecodeError:
        return_error('Response contained no valid body. See logs for more information.',
                     error=f'attackiq response body:\n{res.content}')


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    http_request('GET', '/v1/assessments')
    return 'ok'


''' COMMANDS MANAGER / SWITCH PANEL '''


def activate_assement_command():
    """ Implements attackiq-activate-assessment command
    Returns: Result of command
    """
    pass


def get_assessment_execution_status_command():
    """ Implements attackiq-get-assessment-execution-status command
    Returns: Result of command
    """
    pass


def get_test_execution_status_command():
    """ Implements attackiq-get-test-execution-status command
    Returns: Result of command
    """
    pass


def get_test_results_command():
    """ Implements attackiq-get-test-results command
    Returns: Result of command
    """
    pass


def list_assessments_command():
    """ Implements attackiq-list-assessments command
    Returns: Result of command
    """
    pass


def list_tests_by_assessment_command():
    """ Implements attackiq-list-tests-by-assessment command
    Returns: Result of command
    """
    pass


def run_all_tests_in_assessment_command():
    """ Implements attackiq-run-all-tests-in-assessment
    Returns: Result of command"""
    pass


def main():
    handle_proxy()
    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        if command == 'test-module':
            demisto.results(test_module())
        elif command == 'attackiq-activate-assessment':
            demisto.results(activate_assement_command())
        elif command == 'attackiq-get-assessment-execution-status':
            demisto.results(get_assessment_execution_status_command())
        elif command == 'attackiq-get-test-execution-status':
            demisto.results(get_test_execution_status_command())
        elif command == 'attackiq-get-test-results':
            demisto.results(get_test_results_command())
        elif command == 'attackiq-list-assessments':
            demisto.results(list_assessments_command())
        elif command == 'attackiq-list-tests-by-assessment':
            demisto.results(list_tests_by_assessment_command())
        elif command == 'attackiq-run-all-tests-in-assessment':
            demisto.results(run_all_tests_in_assessment_command())
        else:
            return_error(f'Command {command} is not supported.')
    except Exception as e:
        message = f'Unexpected error: {str(e)}, traceback: {traceback.format_exc()}'
        return_error(message)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

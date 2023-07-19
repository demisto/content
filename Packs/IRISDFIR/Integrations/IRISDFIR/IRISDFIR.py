import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import traceback
import requests
import urllib3
import os

# disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS '''

verify_cert = not demisto.params().get('insecure', False)
proxies = handle_proxy()


class DFIRIrisAPI:
    def __init__(self, api_endpoint, api_key):
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.headers = {'Authorization': f'Bearer {self.api_key}',
                        'User-Agent': 'Defined'
                        }

    def get_last_case_id(self):

        response = requests.get(f'{self.api_endpoint}/manage/cases/list',
                                headers=self.headers, verify=verify_cert, proxies=proxies)

        if response.status_code == 200:
            cases = response.json()
            if cases:
                list = []
                counter = 0
                for last_case in cases['data']:
                    list.append(last_case['case_id'])
                    counter += 1

                return cases['data'][list.index(max(list))]
            else:
                return "No cases found."
        else:
            return (f"Request failed with status code {response.status_code}.")

    def get_all_cases(self):

        response = requests.get(f'{self.api_endpoint}/manage/cases/list',
                                headers=self.headers, verify=verify_cert, proxies=proxies)

        if response.status_code == 200:
            cases = response.json()
            if cases:
                return cases['data']
            else:
                return "No cases found."
        else:
            return f"Request failed with status code {response.status_code}."


''' COMMAND FUNCTIONS '''


def test_module(dfir_iris):
    try:

        headers = {'Authorization': f'Bearer {dfir_iris.api_key}',
                   'User-Agent': 'Defined'
                   }

        response = requests.get(f'{dfir_iris.api_endpoint}/manage/cases/list',
                                headers=headers, verify=verify_cert, proxies=proxies)

        if response.status_code == 200:
            return 'ok'
        else:
            if response.status_code == 401:
                return 'Authorization Error: make sure API Key is correctly set'
            else:
                return f'Not able to connect to {dfir_iris.api_endpoint}'

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e


def process_incidents(results_str, args: Dict[str, Any]) -> CommandResults:

    return CommandResults(
        outputs_prefix='IRIS',
        outputs_key_field='',
        outputs=results_str,
    )


''' MAIN FUNCTION '''


def main():
    """ COMMANDS MANAGER / SWITCH PANEL """
    params = demisto.params()
    command = demisto.command()

    demisto.info(f'Command being called is {command}')
    try:
        # initialized Authentication client
        api_key = params.get('api_key', {}).get('password', '')
        api_endpoint = params.get('host')
        #  ignore proxy
        os.environ['NO_PROXY'] = api_endpoint.split("https://")[1]
        dfir_iris = DFIRIrisAPI(api_endpoint, api_key)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(dfir_iris)
            return_results(result)
        elif command == 'iris-get-last-case-id':
            results_str = dfir_iris.get_last_case_id()
        elif command == 'iris-get-all-cases':
            results_str = dfir_iris.get_all_cases()
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

        return return_results(process_incidents(results_str, demisto.args()))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to process incidents. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

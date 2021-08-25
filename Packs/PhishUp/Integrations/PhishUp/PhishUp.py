import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from requests.exceptions import Timeout

''' IMPORTS '''

import json
import urllib3
import requests
# import dateparser
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def test_module():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    api_url = demisto.params().get('api-url')
    if not api_url.endswith("/"):
        api_url += "/api/auth"
    else:
        api_url += "api/auth"

    token_service_request_body = {
        'username': username,
        'password': password
    }

    try:
        response = requests.post(api_url, json.dumps(token_service_request_body),
                                 headers={'Content-Type': 'application/json'})
        if response.status_code == 200 and "token" in response.json():
            return "ok"
        else:
            return "Error"

    except Exception as e:
        return f"An error ocured... {e}"


def return_response(outputs_prefix, outputs, raw_response, readable_output):
    command_result = CommandResults(
        outputs_prefix=outputs_prefix,
        outputs=outputs,
        raw_response=raw_response,
        # outputs_key_field='Result',
        readable_output=readable_output
    )
    return_results(command_result)


def phishup_scan_urls(args, token):
    input_urls_raw = args.get('Urls')
    api_url = demisto.params().get('api-url')
    if not api_url.endswith("/"):
        api_url += "/counterfeit-service/api/computeMultiDomain"
    else:
        api_url += "counterfeit-service/api/computeMultiDomain"

    if "[" in input_urls_raw:
        input_urls = json.loads(input_urls_raw)
    elif "," in input_urls_raw and "[" not in input_urls_raw:
        if ", " in input_urls_raw:
            input_urls = input_urls_raw.split(", ")
        elif "," in input_urls_raw:
            input_urls = input_urls_raw.split(",")
    else:
        input_urls = [input_urls_raw]

    bulk_url_request_body = {
        'hosts': input_urls
    }

    try:
        response = requests.post(api_url,
                                 json.dumps(bulk_url_request_body),
                                 headers={'Content-Type': 'application/json',
                                          'x-auth-token': token}, timeout=60)

        if response.status_code == 200:
            phish_result = 'Clean'
            for result in response.json()['counterfeitApiResultModel']:
                if result['predicitPhishResult'].upper() == 'PHISH':
                    phish_result = 'Phish'
                    break
                elif result['predicitPhishResult'].upper() == 'MALICIOUS':
                    phish_result = 'Phish'
                    break

            result = phish_result
            return_response(outputs_prefix='PhishUp.Result',
                            outputs=phish_result,
                            raw_response=response.json(),
                            readable_output=f"{phish_result} - Raw Response: {response.json()}")
        else:
            return_response(outputs_prefix='PhishUp.Result',
                            outputs='Error',
                            raw_response={"Error": f"{response.status_code}"},
                            readable_output='Error')

    except Timeout:
        return_response(outputs_prefix='PhishUp.Result',
                        outputs='Error',
                        raw_response={"Error": "Timeout"},
                        readable_output='Timeout Error')


def get_access_token():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    api_url = demisto.params().get('api-url')
    if not api_url.endswith("/"):
        api_url += "/api/auth"
    else:
        api_url += "api/auth"

    token_service_request_body = {
        'username': username,
        'password': password
    }

    try:
        response = requests.post(api_url, json.dumps(token_service_request_body),
                                 headers={'Content-Type': 'application/json'})
        authentication_token = response.json()['token']
        if response.status_code == 200:
            return authentication_token
        else:
            return "Error"
    except Exception as e:
        return f"An error ocured... {e} {response.json()}"


def get_chosen_phishup_action():
    action = demisto.params().get("action")

    demisto.log(action)
    return_response(outputs_prefix='PhishUp.Action',
                    outputs=action,
                    raw_response={"PhishUp.Action": action},
                    readable_output=f"{action}")


def main():
    # verify_certificate = not demisto.params().get('insecure', False)
    # proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            demisto.results(test_module())

        elif demisto.command() == "phishup-check-urls":
            demisto.results(phishup_scan_urls(demisto.args(), get_access_token()))
        elif demisto.command() == "phishup-get-chosen-action":
            demisto.results(get_chosen_phishup_action())

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

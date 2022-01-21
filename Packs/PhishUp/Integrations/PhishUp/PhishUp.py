import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
# import dateparser


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    def investigate_url_http_request(self, apikey, target_url):
        """
        initiates a http request to target investigate url
        """
        data = self._http_request(
            method='POST',
            url_suffix='/sherlock/investigate?apikey=' + apikey,
            json_data={"Url": target_url},
            timeout=40
        )
        return data

    def investigate_bulk_url_http_request(self, apikey, target_url_list):
        """
        initiates a http request to bulk target investigate url
        """
        demisto.log(f"""WTF DUDE APİKEY: {apikey}, URLS: {target_url_list}""")
        data = self._http_request(
            method='POST',
            url_suffix="/sherlock/bulk?apikey=" + apikey,
            json_data={"Urls": target_url_list},
            timeout=40
        )
        return data

    def check_api_key_test_module_http_request(self, apikey):
        """
        initiates a http request to validateapikey endpoint for test-module
        """
        data = self._http_request(
            method='POST',
            url_suffix="/sherlock/ValidateApiKey?apikey=" + apikey,
            timeout=20
        )
        return data


def investigate_url_command(client: Client, args, apikey):
    result = client.investigate_url_http_request(apikey, args.get("Url"))

    if result != "Error" and "Url" in result:
        return CommandResults(
            readable_output=f"PhishUp Result: {result}",
            outputs={
                "Result": result["PhishUpStatus"],
                "Score": result["PhishUpScore"]
            },
            raw_response=result
        )
    else:
        raise Exception(f"PhishUp Response Error")


def investigate_bulk_url_command(client: Client, args, apikey):
    if isinstance(args.get("Urls"), str):
        if "[" in args.get("Urls"):
            urls = json.loads(args.get("Urls"))

        else:
            urls = [args.get("Urls")]
    elif isinstance(args.get("Urls"), list):
        urls = args.get("Urls")

    if len(urls) == 0:
        raise Exception("Empty Urls List")

    # for getting unique Urls
    urls = list(set(urls))

    demisto.log(f"""apikey: {apikey}""")

    result = client.investigate_bulk_url_http_request(apikey, urls)

    if "Results" in result and result["Results"] is not None:
        any_phish = "Clean"
        for r in result["Results"]:
            if r["PhishUpStatus"] == "Phish":
                any_phish = "Phish"
                break

        return CommandResults(
            readable_output=result,
            outputs={
                "PhishUp.AverageResult": any_phish,
                "PhishUp.Results": result["Results"]
            },
            raw_response=result
        )
    else:
        raise Exception("PhishUp Response Error")


def get_chosen_phishup_action_command(params):
    return CommandResults(
        readable_output=f"""Chosen Action: {params.get("phishup-playbook-action")}""",
        outputs={
            "PhishUp.Action": params.get("phishup-playbook-action"),
        },
        raw_response=params.get("phishup-playbook-action")
    )


def test_module(client, apikey):
    result = client.check_api_key_test_module_http_request(apikey)
    if result["Status"] == "Success":
        return 'ok'
    else:
        return result["Status"]


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API url
    base_url = "https://apiv2.phishup.co"

    apikey = demisto.params().get('credentials').get('password')

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, apikey)
            demisto.results(result)

        elif demisto.command() == 'phishup-investigate-url':
            return_results(investigate_url_command(client, demisto.args(), apikey))
        elif demisto.command() == 'phishup-investigate-bulk-url':
            return_results(investigate_bulk_url_command(client, demisto.args(), apikey))
        elif demisto.command() == 'phishup-get-chosen-action':
            return_results(get_chosen_phishup_action_command(demisto.params()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

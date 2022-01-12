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
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def investigate_url_http_request(self, apikey, target_url):
        """
        initiates a http request to a test url
        """
        try:
            data = self._http_request(
                method='POST',
                url_suffix='/sherlock/investigate?apikey=' + apikey,
                json_data={"Url": target_url},
                timeout=20
            )
            return data
        except Exception as e:
            demisto.log(f"""http request error: {e}""")
            return "Error"

    def investigate_bulk_url_http_request(self, apikey, target_url_list):
        """
        initiates a http request to a test url
        """

        try:
            data = self._http_request(
                method='POST',
                url_suffix="/sherlock/bulk?apikey=" + apikey,
                json_data={"Urls": target_url_list},
                timeout=20
            )
            return data
        except Exception as e:
            demisto.log(f"""http request error: {e}""")
            return "Error"

    def check_api_key_test_module_http_request(self, apikey):
        try:
            data = self._http_request(
                method='POST',
                url_suffix="/sherlock/ValidateApiKey?apikey=" + apikey,
                timeout=20
            )
            return data
        except Exception as e:
            demisto.log(f"""http request error: {e}""")
            return "Error"

    def list_incidents(self):
        """
        returns dummy incident data, just for the example.
        """
        return [
            {
                'incident_id': 1,
                'description': 'Hello incident 1',
                'created_time': datetime.utcnow().strftime(DATE_FORMAT)
            },
            {
                'incident_id': 2,
                'description': 'Hello incident 2',
                'created_time': datetime.utcnow().strftime(DATE_FORMAT)
            }
        ]


def investigate_url_command(client: Client, args, params):
    result = client.investigate_url_http_request(params.get("apikey"), args.get("Url"))

    if result != "Error" and "Url" in result:
        return (
            f"PhishUp Result: {result}",  # readable_output,
            {
                "Result": result["PhishUpStatus"],
                "Score": result["PhishUpScore"]
            },  # outputs,
            result  # raw response - the original response
        )
    else:
        return (
            "An error occurred...",  # readable_output,
            {
                "Result": "Error",
                "Score": "Error"
            },  # outputs,
            "Error"  # raw response - the original response
        )


def investigate_bulk_url_command(client: Client, args, params):
    if isinstance(args.get("Urls"), str):
        if "[" in args.get("Urls"):
            try:
                urls = json.loads(args.get("Urls"))
            except Exception as e:
                return (
                    "String List Parsing Error",  # readable_output,
                    {
                        "PhishUp.AverageResult": "Error",
                        "PhishUp.Results": "Error"
                    },  # outputs,
                    f"String List Parsing Error {e} "  # raw response - the original response
                )
        else:
            urls = [args.get("Urls")]
    else:
        urls = list(set(args.get("Urls")))

    if len(urls) == 0:
        return (
            "Empty Urls List",  # readable_output,
            {
                "PhishUp.AverageResult": "Error",
                "PhishUp.Results": "Error"
            },
            "Empty Urls List"  # raw response - the original response
        )

    result = client.investigate_bulk_url_http_request(params.get("apikey"), urls)

    if result != "Error" and "Results" in result and result["Results"] is not None:
        any_phish = "Clean"
        for r in result["Results"]:
            if r["PhishUpStatus"] == "Phish":
                any_phish = "Phish"
                break

        return (
            result,  # readable_output,
            {
                "PhishUp.AverageResult": any_phish,
                "PhishUp.Results": result["Results"]
            },  # outputs,
            result  # raw response - the original response
        )
    else:
        return (
            "An error occurred...",  # readable_output,
            {
                "PhishUp.AverageResult": "Error",
                "PhishUp.Results": "Error"
            },  # outputs,
            "Error"  # raw response - the original response
        )


def get_chosen_phishup_action_command(params):
    return (
        f"""Chosen Action: {params.get("phishup-playbook-action")}""",  # readable_output,
        {
            "PhishUp.Action": params.get("phishup-playbook-action"),
        },  # outputs,
        params.get("phishup-playbook-action")  # raw response - the original response
    )


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    result = client.check_api_key_test_module_http_request(demisto.params().get("apikey"))
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

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'phishup-investigate-url':
            return_outputs(*investigate_url_command(client, demisto.args(), demisto.params()))
        elif demisto.command() == 'phishup-investigate-bulk-url':
            return_outputs(*investigate_bulk_url_command(client, demisto.args(), demisto.params()))
        elif demisto.command() == 'phishup-get-chosen-action':
            return_outputs(*get_chosen_phishup_action_command(demisto.params()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

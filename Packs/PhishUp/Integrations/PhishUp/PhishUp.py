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

    urls = argToList(args.get("Url"))
    if len(urls) == 0:
        raise ValueError('Empty URLs list')

    command_results: List[CommandResults] = []

    for url in urls:
        phishup_result = client.investigate_url_http_request(apikey, url)

        score = 0
        if "Url" in phishup_result:
            if phishup_result["PhishUpStatus"] == "Phish":
                score = Common.DBotScore.BAD
            elif phishup_result["PhishUpStatus"] == "Clean":
                score = Common.DBotScore.GOOD
        else:
            raise Exception("PhishUp Response Error")

        dbot_score = Common.DBotScore(
            indicator=url,
            integration_name="PhishUp",
            indicator_type=DBotScoreType.URL,
            score=score
        )

        url_standard_context = Common.URL(
            url=url,
            dbot_score=dbot_score
        )

        readable_output = tableToMarkdown("URL", phishup_result)

        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix="PhishUp.URLs",
            outputs_key_field='URLs',
            outputs={
                "Result": phishup_result["PhishUpStatus"],
                "Score": phishup_result["PhishUpScore"]
            },
            indicator=url_standard_context,
            raw_response=phishup_result
        ))
    return command_results


def evaluate_phishup_response_command(args):
    phishup_result = "Clean"
    for response in args.get("URLs"):
        if response["Result"] == "Phish":
            phishup_result = "Phish"

    return CommandResults(
        readable_output=f"""PhishUp Result Evaluation: {phishup_result}""",
        outputs={
            "PhishUp.Evaluation": phishup_result,
        },
        raw_response=phishup_result
    )


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
        elif demisto.command() == 'phishup-evaluate-response':
            return_results(evaluate_phishup_response_command(demisto.args()))
        elif demisto.command() == 'phishup-get-chosen-action':
            return_results(get_chosen_phishup_action_command(demisto.params()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

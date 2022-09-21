import traceback
from typing import Any, Dict, List, Union

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

SAFEBROWSE_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

CLIENT_INFO = {
    "clientId": "XSOAR",
    "clientVersion": "0.1a"
}

TEST_THREAT_INFO = {
    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
    "platformTypes": ["WINDOWS"],
    "threatEntryTypes": ["URL"],
    "threatEntries": [
        {"url": "http://www.example.com"},
    ]

}

''' CLIENT CLASS '''


class Client(BaseClient):

    def get_lookup_reputation(self, threatinfo: Dict, apikey: str) -> Dict[str, Any]:

        params = {
            "key": apikey
        }

        postdata = {
            "client": CLIENT_INFO,
            "threatInfo": threatinfo
        }

        return self._http_request(
            method='POST',
            params=params,
            json_data=postdata

        )


''' COMMAND FUNCTIONS '''


def test_module(client: Client, apikey: str) -> str:

    try:
        client.get_lookup_reputation(TEST_THREAT_INFO, apikey)

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def url_reputation_command(client: Client, params: Dict, args: Dict[str, Any], apikey: str) -> Union[List[CommandResults], str]:

    urls = argToList(args.get('url'))
    if len(urls) == 0:
        raise ValueError('URL(s) not specified')

    threatEntries = []
    for url in urls:
        threatEntries.append({"url": f"{url}"})

    threatTypes = argToList(params.get('threatTypes'))
    platformTypes = argToList(params.get('platformTypes'))
    threatEntryTypes = argToList(params.get('threatEntryTypes'))

    threatinfo = {
        "threatTypes": threatTypes,
        "platformTypes": platformTypes,
        "threatEntryTypes": threatEntryTypes,
        "threatEntries": threatEntries

    }

    feedReliability = params.get('feedReliability')

    command_results: List[CommandResults] = []

    url_data = client.get_lookup_reputation(threatinfo, apikey)

    indicators = None

    if 'matches' in url_data:
        for match in url_data['matches']:

            dbot_score = Common.DBotScore(
                indicator=match['threat']['url'],
                indicator_type=match['threatEntryType'].lower(),
                integration_name="GoogleSafeBrowsing",
                score=Common.DBotScore.BAD,
                reliability=feedReliability

            )

            url = Common.URL(
                url=match['threat']['url'],
                dbot_score=dbot_score
            )

            indicators = url

            readable_output = tableToMarkdown('URL', url_data['matches'])

            command_results.append(CommandResults(
                readable_output=readable_output,
                outputs_prefix='GoogleSafeBrowsing.URL',
                outputs=url_data['matches'],
                outputs_key_field='threat.url',
                indicator=indicators

            ))

        return command_results

    return "Not Found"


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = SAFEBROWSE_URL

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    headers = {
        "Content-Type": "application/json"
    }

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, api_key)
            return_results(result)

        elif demisto.command() == 'url':
            results = url_reputation_command(client, demisto.params(), demisto.args(), api_key)
            return_results(results)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

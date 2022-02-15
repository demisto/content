import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

TYPES = {
    'threatTypes': ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
    'platformTypes': ["ANY_PLATFORM", "WINDOWS", "LINUX", "ALL_PLATFORMS", "OSX", "CHROME", "IOS", "ANDROID"]
}

INTEGRATION_NAME = 'GoogleSafeBrowsing'
URL_OUTPUT_PREFIX = 'GoogleSafeBrowsing.URL'


class Client(BaseClient):
    def __init__(self, proxy: bool, verify: bool, reliability: str, base_url: str, params: dict):
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        super().__init__(proxy=proxy, verify=verify, base_url=base_url, headers=headers)

        self.base_url = base_url
        self.client_body = {
            'clientId': params.get('client_id'),
            'clientVersion': params.get('client_version'),
        }

        if DBotScoreReliability.is_valid_type(reliability):
            self.reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
        else:
            raise Exception("Google Safe Browsing v2 error: "
                            "Please provide a valid value for the Source Reliability parameter.")

    def build_request_body(self, client_body: Dict, list_url: List) -> Dict:
        """ build the request body according to the client body and the urls.

        Args:
            client_body: client body to add it in the request body
            list_url: The urls list
        Returns:
            (dict) The request body, in the right format.
        """
        list_urls = []
        for url in list_url:
            list_urls.append({"url": url})

        body: Dict = {
            "client": client_body,
            "threatInfo": {
                "threatTypes": TYPES.get('threatTypes'),
                "platformTypes": TYPES.get('platformTypes'),
                "threatEntryTypes": ["URL"],
                "threatEntries": list_urls
            }
        }
        return body

    def url_request(self, client_body, list_url) -> Dict:
        """ send the url request.

        Args:
            client_body: client body to add it in the request body
            list_url: The urls list
        Returns:
            (dict) The response from the request.
        """
        body = self.build_request_body(client_body, list_url)
        result = self._http_request(
            method='POST',
            json_data=body,
            full_url=self.base_url)
        return result


def test_module(client: Client) -> str:
    """
    Performs basic get request to get sample URL details.
    """
    try:
        # testing a known malicious URL to check if we get matches
        test_url = "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/"
        res = client.url_request(client.client_body, [test_url])
        if res.get('matches'):  # matches - There is a match for the URL we were looking for
            message = 'ok'
        else:
            message = 'Error querying Google Safe Browsing. Expected matching respons, but received none'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: please make sure the API Key is set correctly.'
        else:
            raise e
    return message


def handle_errors(result: Dict) -> None:
    """
    Handle errors, raise Exception when there is errors in the response.
    """

    status_code = result.get('StatusCode', 0)
    result_body = result.get('Body')

    if result_body == '' and status_code == 204:
        raise Exception('No content received. Possible API rate limit reached.')

    if 200 < status_code < 299:
        raise Exception(f'Failed to perform request, request status code: {status_code}.')

    if result_body == '':
        raise Exception('No content received. Maybe you tried a private API?.')

    if result.get('error'):
        error_massage = result.get('error', {}).get('message')
        error_code = result.get('error', {}).get('code')
        raise Exception(f'Failed accessing Google Safe Browsing APIs. Error: {error_massage}. Error code: {error_code}')


def arrange_results_to_urls(results: List, url_list: List) -> Dict:
    """ Arrange and filter the URLs results according to the URLs list that we asked information on.
    Args:
        results: the API response.
        url_list: The URLs list that we asked information on.
    Returns:
        (dict) The results according the urls.
    """
    urls_results: Dict[str, list] = {}
    for url in url_list:
        urls_results[url] = []

    for result in results:
        url = result.get('threat', {}).get('url')
        urls_results[url].append(result)

    return urls_results


def url_command(client: Client, args: Dict[str, Any]) -> Union[List[CommandResults], CommandResults]:
    """
    url command: Returns URL details for a list of URL
    """

    url = argToList(args.get('url'))

    result = client.url_request(client.client_body, url)

    if not result:
        dbot_score = Common.DBotScore(
            indicator=url,
            indicator_type=DBotScoreType.URL,
            integration_name=INTEGRATION_NAME,
            score=0,
            reliability=client.reliability
        )
        url_standard_context = Common.URL(
            url=url,
            dbot_score=dbot_score
        )
        return CommandResults(
            readable_output=f'No information was found for url {url}',
            outputs_prefix=URL_OUTPUT_PREFIX,
            outputs_key_field='IndicatorValue',
            outputs=result,
            indicator=url_standard_context
        )

    if result.get('StatusCode'):
        if result.get('StatusCode') == 204:
            ScheduledCommand.raise_error_if_not_supported()
            scheduled_command = ScheduledCommand(
                command='url',
                next_run_in_seconds=5,
                args=args,
                timeout_in_seconds=600)
            return CommandResults(scheduled_command=scheduled_command, rate_limited=True, )
        else:
            handle_errors(result)

    urls_data = arrange_results_to_urls(result.get('matches'), url)  # type: ignore

    url_data_list = []
    for url_key, url_data in urls_data.items():
        if url_data:
            dbot_score = Common.DBotScore(
                indicator=url_key,
                indicator_type=DBotScoreType.URL,
                integration_name=INTEGRATION_NAME,
                score=3,
                reliability=client.reliability
            )
            url_standard_context = Common.URL(
                url=url_key,
                dbot_score=dbot_score
            )
            url_data_list.append(CommandResults(
                readable_output=tableToMarkdown(f'Google Safe Browsing APIs - URL Query: {url_key}', url_data),
                outputs_prefix=URL_OUTPUT_PREFIX,
                outputs_key_field='IndicatorValue',
                outputs=url_data,
                indicator=url_standard_context
            ))
        else:
            dbot_score = Common.DBotScore(
                indicator=url_key,
                indicator_type=DBotScoreType.URL,
                integration_name=INTEGRATION_NAME,
                score=0,
                reliability=client.reliability
            )
            url_standard_context = Common.URL(
                url=url_key,
                dbot_score=dbot_score
            )
            url_data_list.append(CommandResults(
                readable_output=f'No matches for URL {url_key}',
                outputs_prefix=URL_OUTPUT_PREFIX,
                outputs_key_field='IndicatorValue',
                outputs=result,
                indicator=url_standard_context
            ))

    return url_data_list


def build_base_url(params: Dict) -> str:
    api_key = params.get('api_key')
    base_url = params.get('url', '')

    if not base_url.endswith('/'):
        base_url += '/'

    return f"{base_url}?key={api_key}"


def main() -> None:
    params = demisto.params()

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    base_url = build_base_url(params)

    reliability = params.get('integrationReliability')
    reliability = reliability if reliability else DBotScoreReliability.B

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            params=params,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            reliability=reliability)

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'url':
            return_results(url_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

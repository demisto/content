import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

TYPES = {
    'threatTypes': ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
    'platformTypes': ["ANY_PLATFORM", "WINDOWS", "LINUX", "ALL_PLATFORMS", "OSX", "CHROME", "IOS", "ANDROID"]
}


class Client(BaseClient):
    def url_request(self, body: Dict, full_url):
        result = self._http_request(
            method='POST',
            json_data=body,
            full_url=full_url)
        return result


def test_module(client: Client, client_body: Dict, full_url) -> str:
    try:
        # testing a known malicious URL to check if we get matches var
        test_url = "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/"
        body = build_request_body(client_body, test_url)
        res = client.url_request(body, full_url)
        if res.get('matches'):
            message = 'ok'
        else:
            message = 'Error querying Google Safe Browsing. Expected matching respons, but received none'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def build_request_body(client_body, list_url):
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


def handle_errors(result):
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


def arrange_results_to_urls(results, url_list):
    urls_results: Dict[str, list] = {}
    for url in url_list:
        urls_results[url] = []

    for result in results:
        url = result.get('threat', {}).get('url')
        urls_results[url].append(result)

    return urls_results


def url_command(client: Client, args: Dict[str, Any], client_body, reliability, full_url) -> CommandResults:

    url = argToList(args.get('url'))

    request_body = build_request_body(client_body, url)

    result = client.url_request(request_body, full_url)

    if result.get('StatusCode'):
        handle_errors(result)

    if not result:
        handle_errors(result)

    urls_data = arrange_results_to_urls(result.get('matches'), url)

    url_data_list = []
    for url_key, url_data in urls_data.items():
        if url_data:
            dbot_score = Common.DBotScore(
                indicator=url_key,
                indicator_type=DBotScoreType.URL,
                integration_name='GoogleSafeBrowsingV2',
                score=3,
                reliability=reliability
            )
            url_standard_context = Common.URL(
                url=url_key,
                dbot_score=dbot_score
            )
            url_data_list.append(CommandResults(
                readable_output=tableToMarkdown(f'Google Safe Browsing APIs - URL Query: {url_key}', url_data),
                outputs_prefix='GoogleSafeBrowsingV2.URL',
                outputs_key_field='IndicatorValue',
                outputs=url_data,
                indicator=url_standard_context
            ))
        else:
            dbot_score = Common.DBotScore(
                indicator=url_key,
                indicator_type=DBotScoreType.URL,
                integration_name='GoogleSafeBrowsingV2',
                score=0,
                reliability=reliability
            )
            url_standard_context = Common.URL(
                url=url_key,
                dbot_score=dbot_score
            )
            url_data_list.append(CommandResults(
                readable_output=f'No matches for URL {url_key}',
                outputs_prefix='GoogleSafeBrowsingV2.URL',
                outputs_key_field='IndicatorValue',
                outputs=result,
                indicator=url_standard_context
            ))

    return url_data_list  # type: ignore


def main() -> None:
    api_key = demisto.params().get('api_key')

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    base_url = demisto.params().get('url')
    if not base_url.endswith('/'):
        base_url += '/'

    base_url = f"{base_url}?key={api_key}"

    reliability = demisto.params().get('integrationReliability')
    reliability = reliability if reliability else DBotScoreReliability.B

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        raise Exception("Please provide a valid value for the Source Reliability parameter.")

    client_body = {
        'clientId': demisto.params().get('client_id'),
        'clientVersion': demisto.params().get('client_version'),
    }

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_module(client, client_body, full_url=base_url)
            return_results(result)

        elif demisto.command() == 'url':
            return_results(url_command(client, demisto.args(), client_body, reliability, full_url=base_url))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

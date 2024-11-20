import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
import traceback
import datetime
from typing import Callable, Dict, cast

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''
# used for dbot_score
INTEGRATION_NAME = 'Palo Alto Networks PAN-DB'
# used for relationships
INTEGRATION_BRAND = 'Palo Alto Networks PAN-DB'
INTEGRATION_ENTRY_CONTEXT = "PANDB"

# dont break on these error codes and catch them in code
VALID_STATUS_CODES = (200, 400, 401, 403, 405, 429)

ERROR_DICT = {
    '400': 'Bad Request. Got Invalid JSON',
    '401': 'Unauthorized access. An issue occurred during authentication. This can indicate an incorrect key, ID, or other invalid authentication parameters.',
    '403': 'Unauthorized denied, You do not have the required license type or permission to run this API.',
    '405': 'Unsupported Method. The API query as configured is not supported by the target resource. Ensure you are using POST for all calls.',
    '429': 'Too Many Requests. The user has exceeded the maximum number of requests within a 24 hour period.',
    '500': 'Internal server error. A unified status for API communication type errors.'
}

''' CLIENT CLASS '''


class Client(BaseClient):

    def get_url(self, args: dict = None):
        """
         Executes URL enrichment against PAN-DB API.
         Args:
             client (Client): client.
             args (Dict[str, str]): the arguments for the command.
         Returns:
             dict: the results to return into Demisto's context.
        """

        url_suffix = 'url'
        # print(json.dumps(args, indent=4, sort_keys=True))
        # demisto.info('running request with url=%s' % args.url)
        _response = self._http_request(
            'POST',
            url_suffix=url_suffix,
            json_data=args,
            resp_type='response',
            ok_codes=VALID_STATUS_CODES
        )

        # added response error code checking
        if _response.status_code < 200 or _response.status_code >= 300:
            if str(_response.status_code) in ERROR_DICT:

                response = _response.json()
                # print(response)

                response['error_code'] = _response.status_code
                response['error_reason'] = ERROR_DICT[str(_response.status_code)]

                '''
                return_results({
                    'Type': entryTypes["note"],
                    'Contents': f'API Error Message is: {response.get("message")}',
                    'ContentsFormat': formats['text']
                })
                '''

                return response

        else:
            # print(_response.headers)

            response = _response.json()

            '''
            {
                'server': 'openresty/1.25.3.1',
                'date': 'Sat,18 May 2024 00: 36: 58 GMT',
                'content-type': 'application/json; charset=UTF-8',
                'content-length': '265',
                'content-security-policy': "default-src 'none'",
                'strict-transport-security': 'max-age=7776000',
                'vary': 'Origin',
                'x-content-type-options': 'nosniff',
                'x-ratelimit-burst': '10000',
                'x-ratelimit-period': '86400',
                'x-ratelimit-rate': '10000',
                'x-ratelimit-remaining': '9999',
                'x-ratelimit-resetafter': '8',
                'x-ratelimit-retryafter': '0',
                'via': '1.1 google'
            }
            '''
            quota_limit_remaining = int(_response.headers.get('x-ratelimit-remaining', 99))
            quota_limit_total = int(_response.headers.get('x-ratelimit-rate', 99))
            # quota_limit_reset_after = int(_response.headers.get('x-ratelimit-resetafter', 60))
            # limit_action = _response.headers.get('X-Quota-Limit-Total', 'search')
            quota_limit_reset = int(_response.headers.get('x-ratelimit-period', 99))

            # append the api values to the returned json
            response['quota_limit_remaining'] = quota_limit_remaining
            response['quota_limit_total'] = quota_limit_total
            response['quota_limit_reset'] = quota_limit_reset

            quota_limit_reset_mins = quota_limit_reset / 60

            if quota_limit_remaining < 10:
                return_warning('Your available rate limit remaining is {} and is about to be exhausted. '
                               'The rate limit will reset at {}'.format(str(quota_limit_remaining),
                                                                        quota_limit_reset_date))

            return response


''' HELPER FUNCTIONS '''


def risk_category_explain(category: str):
    """translate a category to a dbot score. For more information:
    https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000Cm5hCAC
    Args:
        category: the URL category from URLFiltering
    Returns:
        dbot score.
    """

    RISK_CAT_DICT = {
        'high-risk': '''High-risk sites include:
Sites previously confirmed to be malware, phishing, or C2 sites. These sites will remain in this category for at least 30 days.
Unknown domains are classified as high-risk until PAN-DB completes site analysis and categorization.
Sites that are associated with confirmed malicious activity. For example, a page might be high-risk if there are malicious hosts on the same domain, even if the page itself does not contain malicious content.
Bulletproof ISP-hosted sites.
Domains classified as DDNS due to the presence of an active dynamic DNS configuration.
Sites hosted on IPs from ASNs that are known to allow malicious content.
Default and Recommended Policy Action: Alert
''',
        'medium-risk': '''Medium-risk sites include:
All cloud storage sites (with the URL category online-storage-and-backup).
Sites previously confirmed to be malware, phishing, or C2 sites that have displayed only benign activity for at least 30 days. These sites will remain in this category for an additional 60 days.
Unknown IP addresses are categorized as medium-risk until PAN-DB completes site analysis and categorization.
Default and Recommended Policy Action: Alert
''',
        'low-risk': '''Sites that are not medium or high risk are considered low risk. These sites have displayed benign activity for a minimum of 90 days.
Default and Recommended Policy Action: Allow
''',
        'newly-registered-domain': '''Identifies sites that have been registered within the last 32 days. New domains are frequently used as tools in malicious campaigns.
Default Policy Action: Alert
Recommended Policy Action: Block
''',
    }

    markdown = ''
    if category in RISK_CAT_DICT:
        # risk_cat_desc = RISK_CAT_DICT.get(category)

        table = {
            'Risk Category': category,
            'Description': RISK_CAT_DICT.get(category)
        }

        markdown = tableToMarkdown(f'URL Filtering Risk Category Details:\n', table, removeNull=True)

    return markdown


def pretty_context(response_data: list):
    """remove empty category entries in list for context entry
    Args:
        raw categories from API with blank entries
    Returns:
        Categories with blank entries removed
    """

    # categories_raw = response_data[0]['categories']
    categories_raw = response_data[0].get('categories')
    str_list = list(filter(None, categories_raw))

    response_data[0]['categories'] = str_list

    return response_data


def calculate_dbot_score(category: str, additional_suspicious: list, additional_malicious: list):
    """translate a category to a dbot score. For more information:
    https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000Cm5hCAC
    Args:
        category: the URL category from URLFiltering
    Returns:
        dbot score.
    """

    predefined_malicious = PREDEFINED_MALICIOUS
    predefined_suspicious = PREDEFINED_SUSPICIOUS
    suspicious_categories = list((set(additional_suspicious)).union(set(predefined_suspicious)))
    malicious_categories = list((set(additional_malicious)).union(set(predefined_malicious)))

    malicious_categories = [element.lower() for element in malicious_categories]
    malicious_categories
    suspicious_categories = [element.lower() for element in suspicious_categories]
    suspicious_categories

    # rewriting with constants
    if category in malicious_categories:
        # dbot_score = 3
        dbot_score = Common.DBotScore.BAD
    elif category in suspicious_categories:
        # dbot_score = 2
        dbot_score = Common.DBotScore.SUSPICIOUS
    elif category == 'unknown':
        # dbot_score = 0
        dbot_score = Common.DBotScore.NONE
    else:
        # dbot_score = 1
        dbot_score = Common.DBotScore.GOOD

    return dbot_score


def indicator_to_context(indicator) -> dict[str, str]:
    """
    Returning an indicator structure with the following fields:
    * ID: The cve ID.
    * CVSS: The cve score scale/
    * Published: The date the cve was published.
    * Modified: The date the cve was modified.
    * Description: the cve's description

    Args:
        indicator: The indocator response from API
    Returns:
        The indicator structure.
    """
    cvss = cve.get('cvss')
    return {
        'ID': cve.get('id', ''),
        'CVSS': cvss or 'N\\A',
        'Published': cve.get('Published', '').rstrip('Z'),
        'Modified': cve.get('Modified', '').rstrip('Z'),
        'Description': cve.get('summary', '')
    }


def clean_up_blanks(data: list, category: str):
    """
    Returning an indicator structure without blank fields

    Args:
        data: The indicator response from API
        category: where in the response structure to search and replace blanks
    Returns:
        The indicator structure cleaned up
    """
    if category == 'categories':
        category_list = list(filter(None, data[0].get(category)))
        response_trimmed = '\n'.join(category_list)
    elif category == 'evidences':
        response_trimmed = data[0].get(category)
    else:
        # histories
        response_trimmed = data[0].get(category)

    return response_trimmed


''' COMMAND FUNCTIONS '''

''' Test module '''


def test_command(client: Client, arg_url: str):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    query_list = {}
    # list of image_details
    query_list["urls"] = []
    # query for getting object
    query_list["urls"].append(arg_url)
    query_list["get_evidence"] = False
    query_list["get_history"] = False

    response = client.get_url(query_list)
    response_data = response.get('success')

    if response_data:
        return_results('ok')
    else:
        print(json.dumps(response_data, indent=4, sort_keys=True))


def get_category_command(client: Client, args: dict) -> list[CommandResults] | CommandResults:
    """translate a category to a dbot score. For more information:
    https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000Cm5hCAC
    Args:
        category: the URL category from URLFiltering
    Returns:
        dbot score.
    """

    table = {}
    metrics_write = False
    execution_metrics = ExecutionMetrics()
    # command_results: list = []
    command_results: list[CommandResults] = []

    if args.get('url') or args.get('domain') or args.get('ip'):
        try:
            # get the values to search for
            query_value = ''
            if args.get('url'):
                query_value = args.get('url')
            elif args.get('domain'):
                query_value = args.get('domain')
            else:
                query_value = args.get('ip')

            query_list = {}
            # list of image_details
            query_list["urls"] = []
            # query for getting object
            # print(query_value)
            query_list["urls"].append(query_value)
            query_list["get_evidence"] = RETURN_EVIDENCE
            query_list["get_history"] = RETURN_HISTORY

            response = client.get_url(query_list)
            if response.get("message"):
                # handling errors in the API
                # print(response.get("message"))

                execution_metrics.general_error += 1

                if response.get("message") == 'found URL longer than 1023':
                    url_len = len(args.get('url'))

                # create the table based on the response
                table = {
                    'URL': args.get('url'),
                    'Error': response.get("message"),
                    'Error_Code': response.get("error_code"),
                    'Error_Reason': response.get("error_reason"),
                    'URL_Length': url_len
                }
                indicator_output = []
                indicator_output.append({
                    'Tags': 'invalid_panos_long',
                    'IndicatorValue': args.get('url')
                })

                markdown = tableToMarkdown(f'PAN-DB Results for: {args.get("url")}\n', table, removeNull=True)

                command_results = CommandResults(
                    outputs_prefix=f'{INTEGRATION_ENTRY_CONTEXT}.URL',
                    outputs_key_field='IndicatorValue',
                    outputs=table,
                    readable_output=markdown,
                    raw_response=response
                )
                return_results(command_results)

            else:

                # print(json.dumps(response, indent=4, sort_keys=True))
                response_data = response.get('data')
                # append the api values to the returned json

                quota_limit_total = int(response.get('quota_limit_total', 99))
                quota_limit_remaining = int(response.get('quota_limit_remaining', 99))
                quota_limit_reset = int(response.get('quota_limit_reset', 99))
                # quota_limit_reset_date = datetime.fromtimestamp(quota_limit_reset, tz=timezone.utc)
                quota_limit_reset_date = datetime.timedelta(seconds=quota_limit_reset)

                execution_metrics.success += 1

                histories_trimmed = clean_up_blanks(response_data, 'histories')
                # histories_trimmed = response_data[0].get('histories')

                evidences_trimmed = clean_up_blanks(response_data, 'evidences')
                # evidences_trimmed = response_data[0].get('evidences')

                # get the categories and strip out any blank entries
                category_list = list(filter(None, response_data[0].get('categories')))
                # categories_trimmed = '\n'.join(category_list)
                categories_trimmed = clean_up_blanks(response_data, 'categories')

                url = response_data[0].get('url')

                # if integration set to use PANDB to enrich URLs and domains to calculate dbot score
                max_dbot_score = 0
                dbot_score_category = ''
                risk_cat_md = ''
                object_tags = []
                indicator_output = []

                if USE_URL_FILTERING:

                    for category in category_list:
                        # print("Category: "+ category)
                        # returns list with 3 values [ dbotscore, malicious_cats, susp_cats ]
                        current_dbot_score = calculate_dbot_score(
                            category.lower(), ADDITIONAL_SUSPICIOUS, ADDITIONAL_MALICIOUS
                        )
                        # get the risk category description if it exists
                        risk_cat_md += risk_category_explain(category)
                        # print(risk_cat_md)

                        # print("Score "+ str(current_dbot_score))
                        if current_dbot_score > max_dbot_score:
                            max_dbot_score = current_dbot_score
                            dbot_score_category = category

                        # add the category to the list of tags to write for the indicator
                        object_tags.append(category)

                        # end score calculation

                    indicator_output.append({
                        'categories': object_tags,
                        'Tags': object_tags,
                        'IndicatorValue': url
                        # 'Verdict':
                    })

                    # which indicator type do we have to construct the DBot score
                    if args.get('url'):
                        # print('url_dbot')
                        dbot_score = Common.DBotScore(
                            indicator=url,
                            indicator_type=DBotScoreType.URL,
                            integration_name=INTEGRATION_NAME,
                            score=max_dbot_score,
                            reliability=RELIABILITY
                        )

                        common_obj = Common.URL(
                            url=url,
                            dbot_score=dbot_score,
                            category=dbot_score_category,
                            tags=object_tags
                        )

                    elif args.get('domain'):
                        # print('domain_dbot')
                        dbot_score = Common.DBotScore(
                            indicator=url,
                            indicator_type=DBotScoreType.DOMAIN,
                            integration_name=INTEGRATION_NAME,
                            score=max_dbot_score,
                            reliability=RELIABILITY
                        )

                        common_obj = Common.Domain(
                            domain=url,
                            dbot_score=dbot_score,
                            category=dbot_score_category,
                            tags=object_tags
                        )
                    else:
                        # print('ip_dbot')
                        dbot_score = Common.DBotScore(
                            indicator=url,
                            indicator_type=DBotScoreType.IP,
                            integration_name=INTEGRATION_NAME,
                            score=max_dbot_score,
                            reliability=RELIABILITY
                        )

                        common_obj = Common.IP(
                            ip=url,
                            dbot_score=dbot_score,
                            # category=dbot_score_category,
                            tags=object_tags
                        )

                    # create the table based on the response
                    table = {
                        'URL': url,
                        'Categories': categories_trimmed,
                        'Evidence': evidences_trimmed,
                        'History': histories_trimmed,
                        'Raw_Response': response_data[0],
                        'DBot_Score': max_dbot_score,
                        'API_Quota': str(quota_limit_remaining) + '/' + str(quota_limit_total) + ' resets in ' + str(quota_limit_reset_date)
                    }

                    markdown = tableToMarkdown(f'PAN-DB Results for: {url}\n', table, removeNull=True)

                    # append the markdown from a risk cateogry seen if exists
                    markdown = markdown + risk_cat_md

                    command_results = CommandResults(
                        outputs_prefix=f'{INTEGRATION_ENTRY_CONTEXT}.URL',
                        outputs_key_field='IndicatorValue',
                        outputs=indicator_output,
                        indicator=common_obj,
                        readable_output=markdown,
                        raw_response=response_data[0]
                        # indicators_timeline,
                        # ignore_auto_extract=False,
                        # mark_as_note=False,
                        # https://xsoar.pan.dev/docs/integrations/code-conventions#commandresults
                    )

                else:
                    # not using url filtering for enrichment (unselected)
                    # create the table based on the response
                    print("not using it for enrichment")
                    table = {
                        'URL': url,
                        'Categories': categories_trimmed,
                        'Evidence': evidence_trimmed_str,
                        'Raw_Response': response_data[0],
                        'API Quota': str(quota_limit_remaining) + '/' + str(quota_limit_total) + ' resets in ' + str(quota_limit_reset_date)
                    }

                    markdown = tableToMarkdown(f'PAN-DB Results for: {url}\n', table, removeNull=True)

                    command_results = CommandResults(
                        outputs_prefix=f'{INTEGRATION_ENTRY_CONTEXT}.URL',
                        outputs_key_field='IndicatorValue',
                        outputs=pretty_context(response_data),
                        readable_output=markdown
                    )

                if execution_metrics.is_supported():
                    if metrics_write:
                        command_results_list = [command_results]
                        _metric_results = execution_metrics.metrics
                        metric_results = cast(CommandResults, _metric_results)
                        command_results_list.append(metric_results)
                        return_results(command_results_list)
                    else:
                        return_results(command_results)
                else:
                    return_results(command_results)

        except Exception as err:
            return_error(f"PAN-DB API Query Error: {err}")


''' MAIN FUNCTION '''


def main() -> None:
    global API_KEY, USE_SSL, USE_URL_FILTERING, RETURN_EVIDENCE, RETURN_HISTORY, ADDITIONAL_MALICIOUS, ADDITIONAL_SUSPICIOUS, RELIABILITY, PREDEFINED_SUSPICIOUS, PREDEFINED_MALICIOUS
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('url')
    API_KEY = params.get('api_key')
    ADDITIONAL_MALICIOUS = argToList(params.get('additional_malicious'))
    ADDITIONAL_SUSPICIOUS = argToList(params.get('additional_suspicious'))
    PREDEFINED_SUSPICIOUS = argToList(params.get('predefined_suspicious'))
    PREDEFINED_MALICIOUS = argToList(params.get('predefined_malicious'))

    RELIABILITY = params.get('integrationReliability', DBotScoreReliability.B) or DBotScoreReliability.B
    USE_URL_FILTERING = params.get('use_url_filtering')
    RETURN_EVIDENCE = params.get('get_evidence')
    RETURN_HISTORY = params.get('get_history')
    PARAMS = demisto.params()
    # USE_SSL = not params.get('insecure', False)
    # USE_PROXY = demisto.params().get('proxy', False)

    exe_metrics = ExecutionMetrics()

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:

        commands: Dict[str, Callable] = {
            'pan-url-category-get': get_category_command,
            'url': get_category_command,
            'domain': get_category_command,
            'ip': get_category_command
        }

        headers: Dict = {
            'X-PANDB-API-KEY': API_KEY,
            'Content-Type': 'application/json'
        }

        client = Client(
            base_url=base_url,
            # verify=verify_certificate,
            headers=headers,
            # proxy=proxy
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_command(client, 'paloaltonetworks.com')
            return_results(result)

        elif command in commands:
            commands[command](client, args)  # type: ignore[operator]

        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

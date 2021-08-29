import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

PARAMS = demisto.params()
URL = PARAMS.get('server')
TOKEN = PARAMS.get('token')

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url, verify=True, proxy=False, ok_codes=(), headers=None, auth=None, params=None):
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth)
        self.params = params

    def get_url_report(self, url: str):
        """Retrieving the results of a previously uploaded url

        :type url: ``str``
        :param url: string to add in the dummy dict that is returned

        :return:
        :rtype:
        """
        suffix_url = '/get/report'
        self.params['url'] = url

        return self._http_request('POST', suffix_url, params=self.params)


''' HELPER FUNCTIONS '''


@logger
def wildfire_get_url_report(url: str) -> Tuple:
    """
    This functions is used for retrieving the results of a previously uploaded url.
    Args:
        url: The url of interest.

    Returns:
        A CommandResults object with the results of the request and the status of that upload (Pending/Success/NotFound).

    """

    get_report_uri = f"{URL}{URL_DICT['report']}"
    params = {'apikey': TOKEN, 'url': url}
    entry_context = {'URL': url}

    try:
        response = http_request(get_report_uri, 'POST', headers=DEFAULT_HEADERS, params=params, resp_type='json')
        report = response.get('result').get('report')

        if not report:
            entry_context['Status'] = 'Pending'
            human_readable = 'The sample is still being analyzed. Please wait to download the report.'

        else:
            entry_context['Status'] = 'Success'
            report = json.loads(report) if type(report) is not dict else report
            report.update(entry_context)
            sha256_of_file_in_url = get_sha256_of_file_from_report(report)
            human_readable_dict = {'SHA256': sha256_of_file_in_url, 'URL': url, 'Status': 'Success'}
            human_readable = tableToMarkdown(f'Wildfire URL report for {url}', t=human_readable_dict, removeNull=True)

    except NotFoundError:
        entry_context['Status'] = 'NotFound'
        human_readable = 'Report not found.'
        report = ''
    except Exception as e:
        entry_context['Status'] = ''
        human_readable = f'Error while requesting the report: {e}.'
        report = ''
        demisto.error(f'Error while requesting the given report. Error: {e}')

    finally:
        command_results = CommandResults(outputs_prefix='WildFire.Report', outputs_key_field='url',
                                         outputs=report, readable_output=human_readable, raw_response=report)
        return command_results, entry_context['Status']


@logger
def wildfire_get_file_report(file_hash: str, args: dict):
    get_report_uri = URL + URL_DICT["report"]
    params = {'apikey': TOKEN, 'format': 'xml', 'hash': file_hash}

    # necessarily one of them as passed the hash_args_handler
    sha256 = file_hash if sha256Regex.match(file_hash) else None
    md5 = file_hash if md5Regex.match(file_hash) else None
    entry_context = {key: value for key, value in (['MD5', md5], ['SHA256', sha256]) if value}

    try:
        json_res = http_request(get_report_uri, 'POST', headers=DEFAULT_HEADERS, params=params)
        reports = json_res.get('wildfire', {}).get('task_info', {}).get('report')
        file_info = json_res.get('wildfire').get('file_info')

        verbose = args.get('verbose', 'false').lower() == 'true'
        format_ = args.get('format', 'xml')

        if reports and file_info:
            human_readable, entry_context, indicator = create_file_report(file_hash,
                                                                          reports, file_info, format_, verbose)

        else:
            entry_context['Status'] = 'Pending'
            human_readable = 'The sample is still being analyzed. Please wait to download the report.'
            indicator = None

    except NotFoundError as exc:
        entry_context['Status'] = 'NotFound'
        human_readable = 'Report not found.'
        dbot_score_file = 0
        json_res = ''
        dbot_score_object = Common.DBotScore(
            indicator=file_hash,
            indicator_type=DBotScoreType.FILE,
            integration_name='WildFire',
            score=dbot_score_file,
            reliability=RELIABILITY)
        indicator = Common.File(dbot_score=dbot_score_object, md5=md5, sha256=sha256)
        demisto.error(f'Report not found. Error: {exc}')

    finally:
        try:
            command_results = CommandResults(outputs_prefix=WILDFIRE_REPORT_DT_FILE,
                                             outputs=remove_empty_elements(entry_context),
                                             readable_output=human_readable, indicator=indicator, raw_response=json_res)
            return command_results, entry_context['Status']
        except Exception:
            raise DemistoException('Error while trying to get the report from the API.')


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def wildfire_get_report_command(args):
    """
    Args:
        args: the command arguments from demisto.args(), including url or file hash (sha256 or md5) to query on

    Returns:
        A single or list of CommandResults, and the status of the reports of the url or file of interest.
        Note that the status is only used for the polling sequence, where the command will always receive a single
        file or url. Hence, when running this command via the polling sequence, the CommandResults list will contain a
        single item, and the status will represent that result's status.

    """
    command_results_list = []
    urls = argToList(args.get('url', ''))
    if 'sha256' in args:
        sha256 = args.get('sha256')
    elif 'hash' in args:
        sha256 = args.get('hash')
    else:
        sha256 = None
    md5 = args.get('md5')
    inputs = urls if urls else hash_args_handler(sha256, md5)

    for element in inputs:
        command_results, status = wildfire_get_url_report(element) if urls else wildfire_get_file_report(element, args)
        command_results_list.append(command_results)

    return command_results_list, status


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()

    # get the service API url
    base_url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:

        headers: Dict = {'Content-Type': 'application/x-www-form-urlencoded'}
        params: Dict = {'apikey': params.get('token')}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            params=params,
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'wildfire-report':
            return_results(wildfire_get_report_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

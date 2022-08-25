import typing

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from typing import Dict, Generator, Tuple
from jbxapi import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


class Client(JoeSandbox):
    def __init__(self, apikey, base_url, accept_tac, verify_ssl,
                 proxy, reliability):
        self.reliability = reliability
        super().__init__(apikey=apikey, apiurl=base_url, accept_tac=accept_tac, verify_ssl=verify_ssl, proxies=proxy)


''' HELPER FUNCTIONS '''


def pagination(args: Dict[str, str], results: Generator) -> List:
    """
         Helper function supporting pagination for results.

         Args:
            args: Dict(str, str): pagination arguments (page, page_size, limit).
            results (Generator): API results for pagination.

         Returns:
             List: The requests pages.
    """
    page = arg_to_number(args.get('page', None))
    page_size = arg_to_number(args.get('page_size', None))
    limit = arg_to_number(args.get('limit', 50))

    # pagination is available only if supplied page and page size.
    if (page and not page_size) or (page_size and not page):
        raise Exception("one of page or page_size arguments are missing")

    number_of_entries = page * page_size if page else limit
    try:
        all_pages = [next(results) for _ in range(0, number_of_entries)]
    except Exception:
        return []
    return all_pages[-page_size:] if page_size else all_pages


def build_analysis_hr(analysis: Dict[str, str]) -> Dict[str, str]:
    """
         Helper function supporting the building of the human-readable output.

         Args:
            analysis: Dict(str, str): Analysis result returned by the API.

         Returns:
             Dict[str, str]: The analysis human-readable entry.
    """
    file_name = analysis.get('filename')
    sha1 = analysis.get('sha1')
    sha256 = analysis.get('sha256')
    md5 = analysis.get('md5')
    tags = analysis.get('tags')
    hr_analysis = {
        'ID': analysis.get('webid'),
        'SampleName': file_name,
        'Status': analysis.get('status'),
        'Time': analysis.get('time'),
        'MD5': md5,
        'SHA1': sha1,
        'SHA256': sha256,
        'Systems': list(set([run.get('system') for run in analysis.get('runs')])),
        'Result': list(set([run.get('detection') for run in analysis.get('runs')])),
        'Tags': tags,
        'Errors': list(set([run.get('error') for run in analysis.get('runs')])),
        'Comments': analysis.get('comments'),
    }
    return hr_analysis


def build_file_object(client: Client, analysis: Dict[str, str]) -> Common.File:
    """
         Helper function supporting the building of the human-readable output.

         Args:
            client (Client): The client class.
            analysis: Dict(str, str): Analysis result returned by the API.

         Returns:
             Common.File: The file indicator class.
    """
    file_name = analysis.get('filename')
    sha1 = analysis.get('sha1')
    sha256 = analysis.get('sha256')
    md5 = analysis.get('md5')
    tags = analysis.get('tags')
    score, description = file_calculate_score(analysis.get('detection', ''))
    dbot_score = Common.DBotScore(
        indicator=file_name,
        integration_name='JoeSecurityV2',
        indicator_type=DBotScoreType.FILE,
        reliability=client.reliability,
        score=score,
        malicious_description=description
    )
    return Common.File(name=file_name, sha1=sha1, sha256=sha256, dbot_score=dbot_score, md5=md5, tags=tags)


def file_calculate_score(detection: str = '') -> Tuple[int, str]:
    # todo: change function descriptions (doc and returned value)
    """
         Calculate DBot Score for file.

         Args:
            -

         Returns:
             dbot_score,description (tuple): The DBot Score and the description associated with it.
     """
    if 'malicious' in detection:
        return Common.DBotScore.BAD, 'bad'
    elif 'suspicious' in detection:
        return Common.DBotScore.SUSPICIOUS, 'suspicious'
    elif 'clean' in detection:
        return Common.DBotScore.GOOD, 'clean'
    return Common.DBotScore.NONE, 'There is no result'


# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``JoeSandbox``
    :param JoeSandbox: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    if client.server_online():
        return 'ok'


def is_online(client: Client) -> CommandResults:
    """
         Check if the Joe Sandbox analysis back end is online or in maintenance mode.

         Args:
            client (JoeSandbox): The Joe Sandbox API Wrapper.

         Returns:
             result (CommandResults): The CommandResults object .
    """
    result = client.server_online()
    status = 'online' if result.get('online') else 'offline'
    return CommandResults(readable_output=f"Joe server is {status}")


def list_analysis(client: Client, args: Dict[str, str]) -> CommandResults:
    """
        List all analyses in descending order, starting with the most recent. The result may be sliced by page and page size or by limit. (default 50)

         Args:
            client (Client): The client class.
            args: Dict(str, str): commands arguments.

         Returns:
             result (CommandResults): The CommandResults object.
    """
    file_ls = []
    hr_analysis_ls = []
    headers = ['ID', 'SampleName', 'Status', 'Time', 'MD5', 'SHA1', 'SHA256', 'Systems', 'Result', 'Errors', 'Comments']

    filtered_pages = pagination(args, client.analysis_list_paged())
    analysis_result_ls = [client.analysis_info(webid=entry.get('webid')) for entry in filtered_pages]
    for analysis in analysis_result_ls:
        hr_analysis_ls.append(build_analysis_hr(analysis))
        file_ls.append(build_file_object(client, analysis))

    return CommandResults(outputs=analysis_result_ls, outputs_prefix='Joe.Analysis',
                          readable_output=tableToMarkdown('Analysis Result:', hr_analysis_ls, headers),
                          indicators=file_ls
                          )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    api_key = demisto.get(demisto.params(), 'credentials.password')
    base_url = demisto.params().get('url')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    reliability = demisto.params().get('Reliability')
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(apikey=api_key, base_url=base_url, accept_tac=True, verify_ssl=verify_certificate,
                        proxy=proxy, reliability=reliability)

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'joe-is-online':
            return_results(is_online(client))
        elif command == 'joe-list-analysis':
            return_results((list_analysis(client, args)))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

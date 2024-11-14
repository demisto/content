from copy import deepcopy
from collections.abc import Generator
import jbxapi
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import urllib3

urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
API_ERRORS = {1: 'Quota', 2: 'MissingParameterError', 3: 'InvalidParameterError', 4: 'InvalidApiKeyError',
              5: 'ServerOfflineError', 6: 'InternalServerError', 7: 'PermissionError', 8: 'UnknownEndpointError'}


class Client(jbxapi.JoeSandbox):
    def __init__(self, apikey: str = '', on_premise: bool = True, base_url: str = '', accept_tac: bool = True,
                 verify_ssl: bool = True, proxy: bool = False, create_relationships: bool = False,
                 reliability: str = DBotScoreReliability.C):
        proxies = {}
        self.reliability = reliability
        self.create_relationships = create_relationships
        self.on_premise = on_premise
        if not proxy:
            demisto.debug("Removing proxy environment variables.")
        else:
            demisto.debug("Handling proxy.")
        proxies = handle_proxy()
        super().__init__(apikey=apikey, apiurl=base_url, accept_tac=accept_tac, verify_ssl=verify_ssl, proxies=proxies)

    def analysis_info_list(self, web_ids: List[str]) -> List[Dict[str, Any]]:
        """
             A wrapper function supporting a list of webids to query.

             Args:
                web_ids: List(str): List of analysis webids to query.

             Returns:
                 result: List(Dict(str, any)): List of analysis info result.
        """
        return [self.analysis_info(webid=web_id) for web_id in web_ids]


''' HELPER FUNCTIONS '''


def update_metrics(exception: Exception, exe_metrics: ExecutionMetrics):
    """
        Helper function that supports the update of the execution metrics.

        Args:
            exception: Exception: The exception.
            exe_metrics: ExecutionMetrics: Execution metrics object.

        Returns:
            None
    """
    if isinstance(exception, jbxapi.ApiError):
        match API_ERRORS.get(exception.code):
            case 'Quota':
                exe_metrics.quota_error += 1
            case 'InvalidApiKeyError' | 'PermissionError':
                exe_metrics.auth_error += 1
            case 'ServerOfflineError' | 'InternalServerError':
                exe_metrics.connection_error += 1
            case _:
                exe_metrics.general_error += 1
    else:
        exe_metrics.general_error += 1


def paginate(args: Dict[str, Any], results: Generator) -> List:
    """
         Helper function supporting paginate for results.

         Args:
            args: Dict(str, any): paginate arguments (page, page_size, limit).
            results: (Generator): API results for paginate.

         Returns:
             result: List: The requests pages.
    """
    page: Optional[int] = arg_to_number(args.get('page', None))
    page_size: Optional[int] = arg_to_number(args.get('page_size', None))
    limit: Optional[int] = arg_to_number(args.get('limit', 50))

    # paginate is available only if supplied page and page size.
    if (page and not page_size) or (page_size and not page):
        raise DemistoException('Either `page` or `page_size` was not provided.')
    if page and page <= 0:
        raise ValueError("The 'page' argument value is not valid.")
    if page_size and page_size <= 0:
        raise ValueError("The 'page_size' argument value is not valid.")
    if limit and limit < 0:
        raise ValueError("The 'limit' argument value is not valid.")

    number_of_entries = page * page_size if (page and page_size) else limit if limit else 0
    if page and page_size:
        try:
            all_pages = [next(results) for _ in range(0, number_of_entries)]
            return all_pages[-page_size:]  # pylint: disable=E1130
        except StopIteration:
            return []
    return list(results)[:limit]


def build_analysis_hr(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
         Helper function that supports the building of the human-readable output.

         Args:
            analysis: Dict(str, any): Analysis result returned by the API.

         Returns:
             result: Dict(str, any): The analysis human-readable entry.
    """
    file_name = analysis.get('filename')
    sha1 = analysis.get('sha1')
    sha256 = analysis.get('sha256')
    md5 = analysis.get('md5')
    tags = analysis.get('tags')
    hr_analysis = {'Id': analysis.get('webid'), 'SampleName': file_name, 'Status': analysis.get('status'),
                   'Time': analysis.get('time'), 'MD5': md5, 'SHA1': sha1, 'SHA256': sha256,
                   'Systems': list({run.get('system') for run in analysis.get('runs', [])}),
                   'Result': list({run.get('detection') for run in analysis.get('runs', [])}), 'Tags': tags,
                   'Errors': list({run.get('error') for run in analysis.get('runs', [])}),
                   'Comments': analysis.get('comments'), }
    return hr_analysis


def build_search_hr(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
           Helper function that supports the building of the human-readable output for search command.

           Args:
              analysis: Dict(str, any): Analysis result returned by the API.

           Returns:
               result: Dict(str, any): The analysis human-readable entry.
      """
    file_name = analysis.get('filename')
    web_id = analysis.get('webid')
    sha1 = analysis.get('sha1')
    sha256 = analysis.get('sha256')
    md5 = analysis.get('md5')
    tags = analysis.get('tags')
    hr_analysis = {'Id': web_id, 'Name': file_name, 'MD5': md5, 'SHA1': sha1, 'SHA256': sha256, 'Tags': tags}
    return hr_analysis


def build_quota_hr(res: Dict[str, Any]) -> tuple[Dict[str, Any], List[str]]:
    """
         Helper function that supports the building of the human-readable output for quota command.

         Args:
            res: Dict(str, any): Quota result returned by the API.

         Returns:
             result: Tuple(Dict(str,Any), List(str)): The quota human-readable entry.
    """

    headers = ['Quota Type', 'Daily Quota Current', 'Daily Quota Limit', 'Daily Quote Remaining',
               'Monthly Quota Current', 'Monthly Quota Limit', 'Monthly Quota Remaining']
    hr = {'Quota Type': res.get('type'), 'Daily Quota Current': res.get('quota', {}).get('daily', {}).get('current', 0),
          'Daily Quota Limit': res.get('quota', {}).get('daily', {}).get('limit', 0),
          'Daily Quote Remaining': res.get('quota', {}).get('daily', {}).get('remaining', 0),
          'Monthly Quota Current': res.get('quota', {}).get('monthly', {}).get('current', 0),
          'Monthly Quota Limit': res.get('quota', {}).get('monthly', {}).get('limit', 0),
          'Monthly Quota Remaining': res.get('quota', {}).get('monthly', {}).get('remaining', 0)}
    return hr, headers


def build_submission_hr(res: Dict[str, Any], analyses: List[Dict[str, Any]]) -> tuple[Dict[str, Any], List[str]]:
    """
            Helper function that supports the building of the human-readable output for submission command.

         Args:
            res: Dict(str, any): Submission result returned by the API.
            analyses: List(Dict(str, any)): List of analysis result returned by the API.
         Returns:
             result: Tuple(Dict(str,Any), List(str)): The submission human-readable entry.
    """
    headers = ['Submission Id', 'Sample Name', 'Time', 'Status', 'Web Id', 'Encrypted', 'Analysis Id', 'Classification',
               'Threat Name', 'Score', 'Detection']
    hr = {'Submission Id': res.get('submission_id'), 'Sample Name': res.get('name'), 'Time': res.get('time'),
          'Status': res.get('status'), 'Web Id': analyses[0].get('webid'), 'Encrypted': analyses[0].get('encrypted'),
          'Analysis Id': analyses[0].get('analysisid'), 'Classification': analyses[0].get('classification'),
          'Threat Name': analyses[0].get('threatname'), 'Score': analyses[0].get('score'),
          'Detection': analyses[0].get('detection')}
    if res.get('analyses', [{}])[0].get('sha256'):
        headers.extend(['SHA256', 'MD5', 'SHA1', 'File Name'])
        hr.update({'SHA256': analyses[0].get('sha256'), 'MD5': analyses[0].get('md5'), 'SHA1': analyses[0].get('sha1'),
                   'File Name': analyses[0].get('filename')})
    else:
        headers.append('URL')
        hr.update({'URL': res.get('url')})
    return hr, headers


def build_reputation_hr(analysis: Dict[str, Any], command: str) -> Dict[str, Any]:
    """
          Helper function that supports the building of the human-readable output.

          Args:
             analysis: (Dict(str, any)): Analysis result returned by the API.
             command: (str): The command url or file.

          Returns:
              result: Dict(str, any): The analysis human-readable entry.
     """
    if command == 'file':
        file_name = analysis.get('filename')
        sha1 = analysis.get('sha1')
        sha256 = analysis.get('sha256')
        md5 = analysis.get('md5')
        tags = analysis.get('tags')
        hr_analysis = {'File Name': file_name, 'Sha1': sha1, 'Sha256': sha256, 'Md5': md5, 'Tags': tags}
        return hr_analysis
    return {'Url': analysis.get('filename')}


def build_relationships(threat_name: str, entity: str, entity_type: str) -> EntityRelationship:
    """
         Helper function that creates the relationships table.

         Args:
            threat_name (str): The malware from joe security.
            entity: (str): The main entity value.
            entity_type: Union(File, URL): The main entity type.

         Returns:
             result: List(EntityRelationship): The relationship entry.
    """
    return EntityRelationship(name=EntityRelationship.Relationships.INDICATOR_OF, entity_a=entity,
                              entity_a_type=entity_type, entity_b=threat_name, entity_b_type=FeedIndicatorType.Malware,
                              reverse_name=EntityRelationship.Relationships.INDICATED_BY)


def build_indicator_object(client: Client, analysis: Dict[str, Any], analyses: List[Dict[str, Any]],
                           is_reputation: bool = False) -> CommandResults:
    """
         Helper function that creates the Indicator object.

         Args:
            client (Client): The client class.
            analysis: Dict(str, any): Analysis result returned by the API.
            analyses: List(Dict(str, any)): List of analysis result returned by the API.
            is_reputation: (bool): If the command is reputation command.
         Returns:
             result: (CommandResults) The indicator object including its relationships
    """
    if analysis.get('sha256'):
        return build_file_object(client, analysis, analyses, is_reputation)
    return build_url_object(client, analysis, analyses, is_reputation)


def build_file_object(client: Client, analysis: Dict[str, Any], analyses: List[Dict[str, Any]],
                      is_reputation: bool) -> CommandResults:
    """
         Helper function that creates the File object.

         Args:
            client (Client): The client class.
            analysis: Dict(str, any): Analysis result returned by the API.
            analyses: List(Dict(str, any)): List of analysis result returned by the API.
            is_reputation (bool): Whether the command is reputation command.
         Returns:
             result: (CommandResults) The indicator object including its relationships
    """
    file_name = analysis.get('filename')
    sha1 = analysis.get('sha1')
    sha256 = analysis.get('sha256', '')
    md5 = analysis.get('md5')
    tags = analysis.get('tags')
    threat_name = analysis.get('threatname', '')
    relationships = []
    headers = ['File Name', 'Sha1', 'Sha256', 'Md5']
    hr = {'File Name': file_name, 'Sha1': sha1, 'Sha256': sha256, 'Md5': md5}
    score, description = max(
        [indicator_calculate_score(entry.get('detection', '')) for entry in analyses if entry.get('sha256') == sha256],
        key=lambda tup: tup[1])  # Find the max dbot score between all the analysis results.
    dbot_score = Common.DBotScore(indicator=sha256, integration_name='JoeSecurityV2',
                                  indicator_type=DBotScoreType.FILE,
                                  reliability=DBotScoreReliability.get_dbot_score_reliability_from_str(
                                      client.reliability), score=score, malicious_description=description)
    if client.create_relationships and threat_name and threat_name.lower() != 'unknown':
        relationships.append(build_relationships(threat_name, sha256, FeedIndicatorType.File))
    indicator = Common.File(name=file_name, sha1=sha1, sha256=sha256, dbot_score=dbot_score, md5=md5, tags=tags,
                            relationships=relationships)
    if is_reputation:
        return CommandResults(outputs=hr, indicator=indicator, relationships=relationships, outputs_prefix='Joe.File',
                              readable_output=tableToMarkdown('File Result:', hr, headers))
    return CommandResults(indicator=indicator, relationships=relationships,
                          readable_output=tableToMarkdown('File Result:', hr, headers))


def build_url_object(client: Client, analysis: Dict[str, Any], analyses: List[Dict[str, Any]],
                     is_reputation: bool) -> CommandResults:
    """
         Helper function that creates the URL object.

         Args:
            client (Client): The client class.
            analysis: Dict(str, any): Analysis result returned by the API.
            analyses: List(Dict(str, any)): Analysis results returned by the API.
            is_reputation (bool): Whether the command is reputation command.
         Returns:
             result: (CommandResults) The indicator object including its relationships
    """
    url = analysis.get('filename', '')
    threat_name = analysis.get('threatname', '')
    relationships = []

    score, description = max(
        [indicator_calculate_score(entry.get('detection', '')) for entry in analyses if entry.get('filename') == url],
        key=lambda tup: tup[1])  # Find the max dbot score between all the analysis results.
    dbot_score = Common.DBotScore(indicator=url, integration_name='JoeSecurityV2', indicator_type=DBotScoreType.URL,
                                  reliability=DBotScoreReliability.get_dbot_score_reliability_from_str(
                                      client.reliability), score=score, malicious_description=description)

    if client.create_relationships and threat_name and threat_name.lower() != 'unknown':
        relationships.append(build_relationships(threat_name, url, FeedIndicatorType.URL))
    indicator = Common.URL(url=url, dbot_score=dbot_score, relationships=relationships)
    if is_reputation:
        return CommandResults(outputs=url, indicator=indicator, relationships=relationships, outputs_prefix='Joe.URL',
                              readable_output=tableToMarkdown('Url Result:', {'Url': url}))
    return CommandResults(indicator=indicator, relationships=relationships,
                          readable_output=tableToMarkdown('Url Result:', {'Url': url}))


def indicator_calculate_score(detection: str = '') -> tuple[int, str]:
    """
         Calculate the DBot Score based on analysis detection.

         Args:
            detection (str): The analysis detection.

         Returns:
             dbot_score,description (tuple): The DBot Score and the description associated with it.
     """
    if 'malicious' in detection:
        return Common.DBotScore.BAD, 'This indicator is malicious'
    elif 'suspicious' in detection:
        return Common.DBotScore.SUSPICIOUS, ''
    elif 'clean' in detection:
        return Common.DBotScore.GOOD, ''
    return Common.DBotScore.NONE, ''


def build_search_command_result(analyses: List[Dict[str, Any]]) -> CommandResults:
    """
         Helper function that parses the search result object.

         Args:
            analyses: (List(Dict(str, any))): The analyses result returned by the API.
         Returns:
             result: (CommandResults) The parsed CommandResults object.
    """
    hr_headers = ['Id', 'Name', 'SHA256', 'SHA1', 'MD5', 'Tags']
    hr_analysis_ls = []
    for analysis in analyses:
        hr_analysis_ls.append(build_search_hr(analysis))

    return CommandResults(outputs=analyses,
                          readable_output=tableToMarkdown('Analysis Result:', hr_analysis_ls, hr_headers),
                          outputs_prefix='Joe.Analysis', outputs_key_field='Id')


def build_analysis_command_result(client: Client, analyses: List[Dict[str, Any]], full_display: bool)\
        -> List[CommandResults]:
    """
         Helper function that parses the analysis result object.

         Args:
            client (Client): The client class.
            analyses: (List(Dict(str, any))): The analyses result returned by the API.
            full_display (bool): Whether to display the full analysis result or not.
         Returns:
             result: List(CommandResults) The parsed CommandResults object.
    """
    hr_headers = ['Id', 'SampleName', 'Status', 'Time', 'MD5', 'SHA1', 'SHA256', 'Systems', 'Result', 'Errors',
                  'Comments']
    command_res_ls = []
    hr_analysis_ls = []
    for analysis in analyses:
        hr_analysis_ls.append(build_analysis_hr(analysis))
        if full_display:
            command_res = build_indicator_object(client, analysis, analyses)
            command_res_ls.append(command_res)
    command_res_ls.append(CommandResults(outputs=analyses,
                                         readable_output=tableToMarkdown('Analysis Result:', hr_analysis_ls,
                                                                         hr_headers), outputs_prefix='Joe.Analysis'))
    return command_res_ls


def build_reputiation_command_result(client: Client, analyses: List[Dict[str, Any]]) -> List[CommandResults]:
    """
         Helper function that parses the file or URL result object.

         Args:
            client (Client): The client class.
            analyses: (List[Dict(str, any)]): The analyses file or URL returned by the API.

         Returns:
             result: List(CommandResults): The parsed CommandResults object.
    """
    command_res_ls = []
    for analysis in analyses:
        command_res = build_indicator_object(client, analysis, analyses, is_reputation=True)
        command_res_ls.append(command_res)

    return command_res_ls


def build_submission_command_result(client: Client, res: Dict[str, Any], args: Dict[str, Any],
                                    exe_metrics: ExecutionMetrics, download_report: bool)\
        -> List[Union[CommandResults, Dict[str, Any]]]:
    """
        Helper function that parses the submission result object.

         Args:
            client (Client): The client class.
            res: (Dict(str, any)): The submission result returned by the API.
            args: (Dict(str, any)): The submission arguments.
            download_report: (bool): Indicates either to download the report.
            exe_metrics: (ExecutionMetrics): The execution metrics.

         Returns:
            result: (List[Union[CommandResults, Dict[str, Any]]]): A list of CommandResults objects or fileResult data.
    """
    command_results: List[Union[CommandResults, Dict[str, Any]]] = []
    report_type = args.get('report_type')
    full_display = argToBoolean(args.get('full_display', True))
    analyses = res.get('analyses', [])
    hr, headers = build_submission_hr(res, res.get('analyses', []))
    res_copy = deepcopy(res)

    if full_display:
        for analysis in analyses:
            command_res = build_indicator_object(client, analysis, analyses)
            web_id = analysis.get('webid')
            if download_report:
                report = download_report_command(client, {'type': report_type, 'webid': web_id})
                command_results.append(report)
            command_results.append(command_res)
    context_entry = {'Joe.Submission': res, 'Joe.Analysis': res.pop('analyses')}
    command_results.append(CommandResults(outputs=context_entry, outputs_key_field='submission_id',
                                          readable_output=tableToMarkdown('Submission Results:', hr, headers=headers),
                                          execution_metrics=exe_metrics.get_metric_list(), raw_response=res_copy))
    return command_results


def build_submission_params(args: Dict[str, Any], on_premise: bool) -> Dict[str, Any]:
    """
         Helper function that builds the submission parameters.

         Args:
            args: (Dict[str, Any]): The command arguments.
         Returns:
             result: (Dict[str, Any]): The submission parameters.
     """
    params = {'comments': args.get('comments', None), 'systems': argToList(args.get('systems')),
              'tags': argToList(args.get('tags')), 'internet-access': argToBoolean(args.get('internet_access', True)),
              'archive-no-unpack': argToBoolean(args.get('archive_no_unpack', False)),
              'ssl-inspection': argToBoolean(args.get('ssl_inspection', False)),
              'localized-internet-country': args.get('localized_internet_country'),
              'internet-simulation': argToBoolean(args.get('internet_simulation', False)),
              'hybrid-code-analysis': argToBoolean(args.get('hybrid_code_analysis', True)),
              'hybrid-decompilation': argToBoolean(args.get('hybrid_decompilation', False)),
              'vba-instrumentation': argToBoolean(args.get('vba_instrumentation', True)),
              'js-instrumentation': argToBoolean(args.get('js_instrumentation', True)),
              'java-jar-tracing': argToBoolean(args.get('java_jar_tracing', True)),
              'dotnet-tracing': argToBoolean(args.get('dotnet_tracing', True)),
              'amsi-unpacking': argToBoolean(args.get('amsi_unpacking', True)),
              'fast-mode': argToBoolean(args.get('fast_mode', False)),
              'secondary-results': argToBoolean(args.get('secondary_results', False)),
              'report-cache': argToBoolean(args.get('report_cache', False)),
              'command-line-argument': args.get('command_line_argument'),
              'live-interaction': argToBoolean(args.get('live_interaction', False)),
              'document-password': args.get('document_password'), 'archive-password': args.get('archive_password'),
              'start-as-normal-user': argToBoolean(args.get('start_as_normal_user', False)),
              'language-and-locale': args.get('language_and_locale'),
              'delete-after-days': arg_to_number(args.get('delete_after_days', 30)),
              'encrypt-with-password': args.get('encrypt_with_password'),
              'email-notification': argToBoolean(args.get('email_notification', False))}

    if on_premise:
        params.pop('delete-after-days', None)

    return params


def file_submission(client: Client, args: Dict[str, Any], params: Dict[str, Any], file: str,
                    exe_metrics: ExecutionMetrics) -> PollResult:
    """
        Helper function that submits a file to Joe Sandbox.

         Args:
            client (Client): The client class.
            args: (Dict[str, Any]): The command arguments.
            params: (Dict[str, Any]): The submission parameters.
            file: (str): The file to submit.
            exe_metrics

         Returns:
             result: (PollResult): The parsed PollResult object.
     """
    file_path = demisto.getFilePath(file)
    name = file_path['name']
    demisto.debug(f"Trying to upload file {name=} from entry= {file_path['path']}")

    with open(file_path['path'], 'rb') as f:
        file_to_send = (args.get('file_name') or name, f)
        res = client.submit_sample(sample=file_to_send, params=params, cookbook=args.get('cookbook'))
        exe_metrics.success += 1
        partial_res = CommandResults(
            readable_output=f'Waiting for submission "{res.get("submission_id")}" to finish...')
        return PollResult(
            response=CommandResults(outputs=res, outputs_prefix='Joe.Submission', outputs_key_field='submission_id'),
            args_for_next_run={'submission_id': res.get('submission_id'), **args}, continue_to_poll=True,
            partial_result=partial_res)


def url_submission(client: Client, args: Dict[str, Any], params: Dict[str, Any], url: str,
                   exe_metrics: ExecutionMetrics) -> PollResult:
    """
        Helper function that submits a URL to Joe Sandbox.

         Args:
            client (Client): The client class.
            args: (Dict[str, Any]): The command arguments.
            params: (Dict[str, Any]): The submission parameters.
            url: (str): The URL to submit.
            exe_metrics: (ExecutionMetrics): The execution metrics.
         Returns:
             result: (PollResult): The parsed PollResult object.
     """
    res = client.submit_url(url=url, params=params)
    exe_metrics.success += 1
    partial_res = CommandResults(readable_output=f'Waiting for submission "{res.get("submission_id")}" to finish...')
    return PollResult(
        response=CommandResults(outputs=res, outputs_prefix='Joe.Submission', outputs_key_field='submission_id'),
        args_for_next_run={'submission_id': res.get('submission_id'), **args}, continue_to_poll=True,
        partial_result=partial_res)


@polling_function(name=demisto.command(), timeout=arg_to_number(demisto.args().get('timeout', 1200)), interval=10,
                  requires_polling_arg=False)
def polling_submit_command(args: Dict[str, Any], client: Client, params: Dict[str, Any],
                           exe_metrics: ExecutionMetrics) -> PollResult:
    """
         Helper function that polls the analysis result.

         Args:
            args: (Dict[str, Any]): The command arguments.
            client (Client): The client class.
            params: (Dict[str, Any]): The submission parameters.
            exe_metrics: (ExecutionMetrics): The execution metrics.
         Returns:
             result: (Dict[str, Any]): The analysis result.
     """
    if submission_id := args.get('submission_id'):
        res = client.submission_info(submission_id=submission_id)
        status = res.get('status')
        if status == 'finished':
            command_results = build_submission_command_result(client, res, args, exe_metrics, True)
            return PollResult(command_results)
        return PollResult(
            response=None,
            partial_result=CommandResults(outputs=res,  # this is what the response will be in case job has finished
                                          outputs_prefix='Joe.Submission', outputs_key_field='submission_id',
                                          readable_output=f'Waiting for submission "{res.get("submission_id")}" to finish...'),
            continue_to_poll=True,
            args_for_next_run={'submission_id': args.get('submission_id'), **args})
    else:
        if file := args.get('entry_id'):
            return file_submission(client, args, params, file, exe_metrics)
        elif url := args.get('url'):
            return url_submission(client, args, params, url, exe_metrics)
        else:
            raise DemistoException('No file or URL was provided.')


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:     # pragma: no cover
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``JoeSandbox``
    :param JoeSandbox: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        demisto.debug(f"sending request with url: {client.apiurl + '/v2/server/online'}")
        client.server_online()
    except Exception as e:
        if isinstance(e, jbxapi.ApiError):
            match API_ERRORS.get(e.code):
                case 'InvalidApiKeyError':
                    return "Invalid Api Key"
                case 'PermissionError':
                    return "Permission Error"
                case 'ServerOfflineError' | 'InternalServerError':
                    return "Server error, please verify the Server URL or check if the server is offline"
        else:
            return f"Server error, please verify the server url or check if the server is online, exact error: {e}"
    return 'ok'


def is_online_command(client: Client) -> CommandResults:
    """
         Check if the Joe Sandbox analysis back end is online or in maintenance mode.

         Args:
            client: (Client) The client class.

         Returns:
             result: (CommandResults) The CommandResults object .
    """
    result = client.server_online()
    status = 'online' if result.get('online') else 'offline'
    return CommandResults(outputs_prefix='Joe.ServerStatus.Online', outputs=result.get('online'),
                          readable_output=f'Joe server is {status}')


def analysis_info_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, List[CommandResults]]:
    """
        Get information about a specific analysis.

         Args:
            client: (Client) The client class.
            args: (Dict(str, any)) The commands arguments.

         Returns:
             result: Union[CommandResults, List[CommandResults]] The CommandResults object.
    """
    try:
        res = client.analysis_info(webid=args.get('webid'))
        command_results = build_analysis_command_result(client, [res], argToBoolean(args.get('full_display')))
        if command_results:
            return command_results
    except jbxapi.InvalidParameterError:
        pass
    return CommandResults(readable_output='No Results were found.')


def list_analysis_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, List[CommandResults]]:
    """
        List all analyses in descending order, starting with the most recent.
        The result may be sliced by page and page size or by limit. (default 50)

         Args:
            client: (Client) The client class.
            args: (Dict(str, any)) The commands arguments.

         Returns:
             result: Union(CommandResults, List(CommandResults)): The CommandResults object.
    """

    filtered_pages = paginate(args, client.analysis_list_paged())
    analysis_result_ls = client.analysis_info_list(web_ids=[entry.get('webid') for entry in filtered_pages])
    command_results = build_analysis_command_result(client, analysis_result_ls, argToBoolean(args.get('full_display')))
    if command_results:
        return command_results
    return CommandResults(readable_output='No Results were found.')


def download_report_command(client: Client, args: Dict[str, Any]) -> Dict[str, Any]:
    """
        Download a resource belonging to a report. This can be the full report, dropped binaries, etc.

         Args:
            client: (Client): The client class.
            args: (Dict(str, any)): The commands arguments.

         Returns:
             result: (Dict(str, Any)): The fileResult object.
    """
    web_id = args.get('webid')
    report_type = args.get('type')

    result = client.analysis_download(webid=web_id, type=report_type)[1]
    return fileResult(f'{web_id}_report.{report_type}', result, EntryType.ENTRY_INFO_FILE)


def download_sample_command(client: Client, args: Dict[str, Any]) -> Dict[str, Any]:
    """
        Download a sample.

         Args:
            client: (Client): The client class.
            args: (Dict(str, any)): The commands arguments.

         Returns:
             result: (Dict(str, Any)): The fileResult object.
    """
    web_id = args.get('webid')

    result = client.analysis_download(webid=web_id, type='sample')[1]
    return fileResult(f'{web_id}.dontrun', result)


def search_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, List[CommandResults]]:
    """
        Search through all analyses.

         Args:
            client: (Client) The client class.
            args: (Dict(str, any)) The commands arguments.

         Returns:
             result: (CommandResults) The CommandResults object.
    """
    query = args.get('query')
    result = client.analysis_search(query=query)
    if result:
        return build_analysis_command_result(client, result, argToBoolean(args.get('full_display', False)))
    return CommandResults(readable_output='No Results were found.')


def file_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, List[CommandResults]]:
    """
        The file reputation command.

         Args:
            client: (Client) The client class.
            args: (Dict(str, any)) The commands arguments.

         Returns:
             result: (CommandResults) The CommandResults object.
    """
    analyses = []
    files = set(argToList(args.get('file', '')))

    for file in files:
        res = client.analysis_search(query=file)
        if res:
            analyses.append(res[0])
    if analyses:
        return build_reputiation_command_result(client, analyses)
    return CommandResults(readable_output='No Results were found.')


def url_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, List[CommandResults]]:
    """
        The url reputation command.

         Args:
            client: (Client) The client class.
            args: (Dict(str, any)) The commands arguments.

         Returns:
             result: (CommandResults) The CommandResults object.
    """
    analyses = []
    urls = set(argToList(args.get('url', '')))

    for url in urls:
        res = client.analysis_search(query=url)
        if res:
            analyses.append(res[0])
    if analyses:
        return build_reputiation_command_result(client, analyses)
    return CommandResults(readable_output='No Results were found.')


def list_lia_countries_command(client: Client) -> CommandResults:
    """
        Retrieve a list of localized internet anonymization countries.

         Args:
            client: (Client) The client class.

         Returns:
             result: (CommandResults) The CommandResults object.
    """

    res = client.server_lia_countries()
    if res:
        data = [country.get('name') for country in res]
        return CommandResults(outputs_prefix='Joe.LIACountry', outputs=data,
                              readable_output=tableToMarkdown('Results:', {'Name': data}))
    return CommandResults(readable_output='No Results were found.')


def list_lang_locales_command(client: Client) -> CommandResults:
    """
        Retrieve a list of available language and locale combinations.

         Args:
            client: (Client) The client class.

         Returns:
             result: (CommandResults) The CommandResults object.
    """

    res = client.server_languages_and_locales()
    if res:
        data = [lang.get('name') for lang in res]
        return CommandResults(outputs_prefix='Joe.LangLocale', outputs=data,
                              readable_output=tableToMarkdown('Results:', {'Name': data}))
    return CommandResults(readable_output='No Results were found.')


def get_account_quota_command(client: Client) -> CommandResults:
    """
        Retrieve the quota for the current account.

         Args:
            client: (Client) The client class.

         Returns:
             result: (CommandResults) The CommandResults object.
    """
    res = client.account_info()
    if res:
        hr, headers = build_quota_hr(res)
        return CommandResults(outputs_prefix='Joe.AccountQuota', outputs=res,
                              readable_output=tableToMarkdown('Results:', hr, headers=headers))
    return CommandResults(readable_output='No Results were found.')


def submission_info_command(client: Client, args: Dict[str, Any], exe_metrics: ExecutionMetrics)\
        -> List[Union[CommandResults, Dict[str, Any]]]:
    """
        Retrieve information about a submission.
         Args:
            client: (Client) The client class.
            args: (Dict(str, any)) The commands arguments.
            exe_metrics: (ExecutionMetrics) The execution metrics object.
         Returns:
             result: (CommandResults) The CommandResults object.
    """
    submission_ids = argToList(args.get('submission_ids'))
    command_results = []
    for submission_id in submission_ids:
        res = client.submission_info(submission_id=submission_id)
        if res:
            command_results.extend(build_submission_command_result(client, res, args, exe_metrics, False))
        else:
            command_results.append(
                CommandResults(readable_output=f'No Results were found for submission {submission_id}.'))
    return command_results


def submit_sample_command(client: Client, args: Dict[str, Any], exe_metrics: ExecutionMetrics) -> PollResult:
    """
        Upload a sample to Joe server.
         Args:
            client: (Client) The client class.
            args: (Dict(str, any)) The commands arguments.
            exe_metrics: (ExecutionMetrics) The execution metrics.
         Returns:
             result: (CommandResults) The CommandResults object.
    """
    params = build_submission_params(args, client.on_premise)
    try:
        return polling_submit_command(args, client, params, exe_metrics)
    except jbxapi.InvalidParameterError as e:
        if e.message == 'Unknown parameter delete-after-days.':
            raw = {"code": 3,
                   "message":
                       ('The parameter delete-after-days is only available in the cloud version.\n'
                        'Check the "On-Premise" option in the integration settings for on-premise setups to avoid this error')
                   }
            raise jbxapi.ApiError(raw)
        else:
            raise


def submit_url_command(client: Client, args: Dict[str, Any], exe_metrics: ExecutionMetrics) -> PollResult:
    """
        Upload a URL to Joe server.
         Args:
            client: (Client) The client class.
            args: (Dict(str, any)) The commands arguments.
            exe_metrics: (ExecutionMetrics) The execution metrics.
         Returns:
             result: (CommandResults) The CommandResults object.
    """
    params = build_submission_params(args, client.on_premise)
    params.update({'url-reputation': argToBoolean(args.get('url_reputation', False))})
    return polling_submit_command(args, client, params, exe_metrics)


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    api_key = demisto.get(demisto.params(), 'credentials.password')
    base_url = demisto.params().get('url')

    demisto.debug(f"base url before handling it: {base_url}")
    if 'api' not in base_url:
        base_url = urljoin(base_url, 'api/')
    demisto.debug(f"base url after handling it: {base_url}")

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    reliability = demisto.params().get('Reliability', DBotScoreReliability.C)
    create_relationships = demisto.params().get('create_relationships', False)
    on_premise = demisto.params().get('onprem', False)
    command = demisto.command()
    args = demisto.args()
    exe_metrics = ExecutionMetrics()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(apikey=api_key, on_premise=on_premise, base_url=base_url, accept_tac=True, verify_ssl=verify_certificate,
                        proxy=proxy, reliability=reliability, create_relationships=create_relationships)

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'joe-is-online':
            return_results(is_online_command(client))
        elif command == 'joe-analysis-info':
            return_results(analysis_info_command(client, args))
        elif command == 'joe-list-analysis':
            return_results(list_analysis_command(client, args))
        elif command == 'joe-download-report':
            demisto.results(download_report_command(client, args))
        elif command == 'joe-download-sample':
            demisto.results(download_sample_command(client, args))
        elif command == 'joe-search':
            return_results(search_command(client, args))
        elif command == 'file':
            return_results(file_command(client, args))
        elif command == 'url':
            return_results(url_command(client, args))
        elif command == 'joe-list–lia-countries':  # noqa: RUF001 (backwards compatibility)
            return_results(list_lia_countries_command(client))
        elif command == 'joe-list-lang-locales':
            return_results(list_lang_locales_command(client))
        elif command == 'joe-get-account-quota':
            return_results(get_account_quota_command(client))
        elif command == 'joe-submission-info':
            return_results(submission_info_command(client, args, exe_metrics))
        elif command == 'joe-submit-sample':
            return_results(submit_sample_command(client, args, exe_metrics))
        elif command == 'joe-submit-url':
            return_results(submit_url_command(client, args, exe_metrics))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        update_metrics(e, exe_metrics)
        return_results(CommandResults(execution_metrics=exe_metrics.get_metric_list()))
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

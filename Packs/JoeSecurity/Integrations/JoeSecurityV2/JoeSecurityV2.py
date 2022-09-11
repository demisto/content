from typing import Generator, Tuple

import jbxapi

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


class Client(jbxapi.JoeSandbox):
    def __init__(self, apikey: str = '', base_url: str = '', accept_tac: bool = True, verify_ssl: bool = True,
                 proxy: bool = False, create_relationships: bool = False, reliability: str = DBotScoreReliability.C):
        self.reliability = reliability
        self.create_relationships = create_relationships
        super().__init__(apikey=apikey, apiurl=base_url, accept_tac=accept_tac, verify_ssl=verify_ssl, proxies=proxy)

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
    limit: int = arg_to_number(args.get('limit', 50))

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
            return all_pages[-page_size:]
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
    hr_analysis = {'ID': analysis.get('webid'), 'SampleName': file_name, 'Status': analysis.get('status'),
                   'Time': analysis.get('time'), 'MD5': md5, 'SHA1': sha1, 'SHA256': sha256,
                   'Systems': list(set([run.get('system') for run in analysis.get('runs', [])])),
                   'Result': list(set([run.get('detection') for run in analysis.get('runs', [])])), 'Tags': tags,
                   'Errors': list(set([run.get('error') for run in analysis.get('runs', [])])),
                   'Comments': analysis.get('comments'), }
    return hr_analysis


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
    # todo: create and change entity_b_type to malware.
    return EntityRelationship(name=EntityRelationship.Relationships.INDICATOR_OF, entity_a=entity,
                              entity_a_type=entity_type, entity_b=threat_name, entity_b_type=FeedIndicatorType.File,
                              reverse_name=EntityRelationship.Relationships.INDICATED_BY)


def build_indicator_object(client: Client, analysis: Dict[str, Any]) -> Tuple[CommandResults, List[EntityRelationship]]:
    """
         Helper function that creates the Indicator object.

         Args:
            client (Client): The client class.
            analysis: Dict(str, any): Analysis result returned by the API.

         Returns:
             result: Tuple(Common.Indicator, Optional(EntityRelationship)) The indicator class.
    """
    if analysis.get('sha256'):
        return build_file_object(client, analysis)
    return build_url_object(client, analysis)


def build_file_object(client: Client, analysis: Dict[str, Any]) -> Tuple[CommandResults, List[EntityRelationship]]:
    """
         Helper function that creates the File object.

         Args:
            client (Client): The client class.
            analysis: Dict(str, any): Analysis result returned by the API.

         Returns:
             result: Tuple(CommandResults, EntityRelationship): Tuple of the File indicator class and the relationship entry.
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
    score, description = indicator_calculate_score(analysis.get('detection', ''))
    dbot_score = Common.DBotScore(indicator=file_name, integration_name='JoeSecurityV2',
                                  indicator_type=DBotScoreType.FILE,
                                  reliability=DBotScoreReliability.get_dbot_score_reliability_from_str(
                                      client.reliability), score=score, malicious_description=description)
    if client.create_relationships and not threat_name == 'Unknown':
        relationships.append(build_relationships(threat_name, sha256, FeedIndicatorType.File))
    indicator = Common.File(name=file_name, sha1=sha1, sha256=sha256, dbot_score=dbot_score, md5=md5, tags=tags,
                            relationships=relationships)
    return CommandResults(indicator=indicator, relationships=relationships,
                          readable_output=tableToMarkdown('File Result:', hr, headers)), relationships


def build_url_object(client: Client, analysis: Dict[str, Any]) -> Tuple[CommandResults, List[EntityRelationship]]:
    """
         Helper function that creates the URL object.

         Args:
            client (Client): The client class.
            analysis: Dict(str, any): Analysis result returned by the API.

         Returns:
             result: Tuple(URL, Optional(EntityRelationship)): Tuple of the URL indicator class and the relationship entry.
    """
    url = analysis.get('filename', '')
    threat_name = analysis.get('threatname', '')
    relationships = []

    score, description = indicator_calculate_score(analysis.get('detection', ''))
    dbot_score = Common.DBotScore(indicator=url, integration_name='JoeSecurityV2', indicator_type=DBotScoreType.URL,
                                  reliability=DBotScoreReliability.get_dbot_score_reliability_from_str(
                                      client.reliability), score=score, malicious_description=description)

    if client.create_relationships and not threat_name == 'Unknown':
        relationships.append(build_relationships(threat_name, url, FeedIndicatorType.URL))
    indicator = Common.URL(url=url, dbot_score=dbot_score, relationships=relationships)
    return CommandResults(indicator=indicator, relationships=relationships,
                          readable_output=tableToMarkdown('Url Result:', {'Url': url})), relationships


def indicator_calculate_score(detection: str = '') -> Tuple[int, str]:
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


def update_non_indicator_dict(entry, dict, indicator_type):
    """
         Helper function that parses the analysis result object.

         Args:
            client (Client): The client class.
            analyses: (List(Dict(str, any))): The analyses result returned by the API.
            reputation: (bool): Indicates either to add indicators and relationships.
         Returns:
             result: (CommandResults) The parsed CommandResults object.
    """
    if indicator_type not in dict.keys():
        dict[indicator_type] = entry
    elif not isinstance(dict.get(indicator_type), List) and entry != dict[indicator_type]:
        dict[indicator_type] = [dict.get(indicator_type), entry]
    elif isinstance(dict.get(indicator_type), List) and entry not in dict[indicator_type]:
        dict[indicator_type] = dict[indicator_type].append(entry)


def build_non_indicator_object(analysis: Dict[str, Any], non_indicator_dict: Dict[str, Any]):
    # todo: change the doc
    """
         Helper function that parses the analysis result object.

         Args:
            client (Client): The client class.
            analyses: (List(Dict(str, any))): The analyses result returned by the API.
            reputation: (bool): Indicates either to add indicators and relationships.
         Returns:
             result: (CommandResults) The parsed CommandResults object.
    """
    if analysis.get('sha256'):
        entry = {}
        file_fields = ['filename', 'sha1', 'sha256', 'md5', 'tags']
        for field in file_fields:
            entry[field.capitalize()] = analysis.get(field)
        update_non_indicator_dict(entry, non_indicator_dict, 'File')
    else:
        update_non_indicator_dict({'Data': analysis.get('filename')}, non_indicator_dict, 'URL')


# def build_search_command_result(client: Client, analyses: List[Dict[str, Any]]) -> List[CommandResults]:
#     """
#          Helper function that parses the analysis result object.
#
#          Args:
#             client (Client): The client class.
#             analyses: (List(Dict(str, any))): The analyses result returned by the API.
#          Returns:
#              result: (CommandResults) The parsed CommandResults object.
#     """
#     hr_headers = ['ID', 'SampleName', 'Status', 'Time', 'MD5', 'SHA1', 'SHA256', 'Systems', 'Result', 'Errors',
#                   'Comments']
#     command_res_ls = []
#     hr_analysis_ls = []
#     relationships = []
#     for analysis in analyses:
#         hr_analysis_ls.append(build_analysis_hr(analysis))
#         command_res, relationship = build_indicator_object(client, analysis)
#         command_res_ls.append(command_res)
#         if relationship:
#             relationships.append(relationship)
#     command_res_ls.append(CommandResults(outputs=analyses,
#                                          readable_output=tableToMarkdown('Analysis Result:', hr_analysis_ls,
#                                                                          hr_headers), outputs_prefix='Joe.Analysis',
#                                          relationships=relationships))
#     return command_res_ls


def build_analysis_command_result(client: Client, analyses: List[Dict[str, Any]]) -> List[CommandResults]:
    """
         Helper function that parses the analysis result object.

         Args:
            client (Client): The client class.
            analyses: (List(Dict(str, any))): The analyses result returned by the API.
         Returns:
             result: (CommandResults) The parsed CommandResults object.
    """
    hr_headers = ['ID', 'SampleName', 'Status', 'Time', 'MD5', 'SHA1', 'SHA256', 'Systems', 'Result', 'Errors',
                  'Comments']
    command_res_ls = []
    hr_analysis_ls = []
    relationships = []
    for analysis in analyses:
        hr_analysis_ls.append(build_analysis_hr(analysis))
        command_res, relationship = build_indicator_object(client, analysis)
        command_res_ls.append(command_res)
        if relationship:
            relationships.append(relationship)
    command_res_ls.append(CommandResults(outputs=analyses,
                                         readable_output=tableToMarkdown('Analysis Result:', hr_analysis_ls,
                                                                         hr_headers), outputs_prefix='Joe.Analysis',
                                         relationships=relationships))
    return command_res_ls


def build_reputiation_command_result(client: Client, analyses: List[Dict[str, Any]]) -> List[CommandResults]:
    """
         Helper function that parses the file or URL result object.

         Args:
            client (Client): The client class.
            analyses: (List[Dict(str, any)]): The analyses file or URL returned by the API.

         Returns:
             result: (CommandResults): The parsed CommandResults object.
    """
    command_res_ls = []
    for analysis in analyses:
        command_res, _ = build_indicator_object(client, analysis)
        command_res_ls.append(command_res)

    return command_res_ls


def filter_result(analyses: List[Dict[str, Any]], filter_by: str) -> List[Dict[str, Any]]:
    """
         Helper function that filters the duplication from the analyses.

         Args:
            analyses: (List[Dict[str, Any]): The files from Joe Security.
            filter_by: (str): The unique field from the analysis data, filename for urls and sha256 for files.
         Returns:
             result: (List[Dict[str, Any]]): The filtered analyses.
     """
    files = []
    existing_files = []
    analyses.reverse()  # In case of duplication, take the must updated run. (The last one)
    for analysis in analyses:
        # In the case of url command (filter by filename), ignore files if they were queried.
        if filter_by == 'filename' and analysis.get('sha256'):
            continue
        unique_field = analysis.get(filter_by)
        if unique_field and unique_field not in existing_files:
            existing_files.append(unique_field)
            files.append(analysis)
    return files


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

    client.server_online()
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


def list_analysis_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
        List all analyses in descending order, starting with the most recent.
        The result may be sliced by page and page size or by limit. (default 50)

         Args:
            client: (Client) The client class.
            args: (Dict(str, any)) The commands arguments.

         Returns:
             result: (CommandResults) The CommandResults object.
    """

    filtered_pages = paginate(args, client.analysis_list_paged())
    analysis_result_ls = client.analysis_info_list(web_ids=[entry.get('webid') for entry in filtered_pages])
    return build_analysis_command_result(client, analysis_result_ls)


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


def search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
        return build_analysis_command_result(client, result)[0]
    return CommandResults(readable_output='No Results were found.')


def file_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
        The file reputation command.

         Args:
            client: (Client) The client class.
            args: (Dict(str, any)) The commands arguments.

         Returns:
             result: (CommandResults) The CommandResults object.
    """
    analyses = []
    files = argToList(args.get('file', ''))

    for file in files:
        response = client.analysis_search(query=file)
        analyses.extend(response)

    return build_reputiation_command_result(client, filter_result(analyses, filter_by='sha256'))


def url_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
        The url reputation command.

         Args:
            client: (Client) The client class.
            args: (Dict(str, any)) The commands arguments.

         Returns:
             result: (CommandResults) The CommandResults object.
    """
    analyses = []
    urls = argToList(args.get('url', ''))

    for url in urls:
        response = client.analysis_search(query=url)
        analyses.extend(response)
    return build_reputiation_command_result(client, filter_result(analyses, filter_by='filename'))


def list_lia_countries(client: Client) -> CommandResults:
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


def lis_lang_locales(client: Client) -> CommandResults:
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


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    api_key = demisto.get(demisto.params(), 'credentials.password')
    base_url = demisto.params().get('url')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    reliability = demisto.params().get('Reliability', DBotScoreReliability.C)
    create_relationships = demisto.params().get('create_relationships', False)
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(apikey=api_key, base_url=base_url, accept_tac=True, verify_ssl=verify_certificate, proxy=proxy,
                        reliability=reliability, create_relationships=create_relationships)

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'joe-is-online':
            return_results(is_online_command(client))
        elif command == 'joe-list-analysis':
            return_results((list_analysis_command(client, args)))
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
        elif command == 'joe-list–lia-countries':
            return_results(list_lia_countries(client))
        elif command == 'joe-list-lang-locales':
            return_results(lis_lang_locales(client))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

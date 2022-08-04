from collections import defaultdict
from http import HTTPStatus
from typing import Callable
from typing import Dict
from typing import List
from typing import Tuple

from intezer_sdk import consts
from intezer_sdk.analysis import FileAnalysis
from intezer_sdk.analysis import UrlAnalysis
from intezer_sdk.api import IntezerApi
from intezer_sdk.errors import AnalysisIsAlreadyRunning
from intezer_sdk.errors import AnalysisIsStillRunning
from intezer_sdk.errors import FamilyNotFoundError
from intezer_sdk.errors import HashDoesNotExistError
from intezer_sdk.errors import InvalidApiKey
from intezer_sdk.errors import ServerError
from intezer_sdk.family import Family
from intezer_sdk.sub_analysis import SubAnalysis
from requests import HTTPError

from CommonServerPython import *

''' CONSTS '''
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

IS_AVAILABLE_URL = 'is-available'
REQUESTER = 'xsoar'

dbot_score_by_verdict = {
    'malicious': 3,
    'suspicious': 2,
    'trusted': 1,
    'neutral': 1,
    'no_threats': 1
}

''' HELPER FUNCTIONS '''


def _get_missing_file_result(file_hash: str) -> CommandResults:
    dbot = {
        'Vendor': 'Intezer',
        'Type': 'hash',
        'Indicator': file_hash,
        'Score': 0
    }

    return CommandResults(
        readable_output=f'The Hash {file_hash} was not found on Intezer genome database',
        outputs={
            outputPaths['dbotscore']: dbot
        }
    )


def _get_missing_url_result(url: str, ex: ServerError = None) -> CommandResults:
    dbot = {
        'Vendor': 'Intezer',
        'Type': 'Url',
        'Indicator': url,
        'Score': 0
    }

    return CommandResults(
        readable_output=f'The Url {url} was not found on Intezer. Error {ex}',
        outputs={
            outputPaths['dbotscore']: dbot
        }
    )


def _get_missing_analysis_result(analysis_id: str, sub_analysis_id: str = None) -> CommandResults:
    if not sub_analysis_id:
        output = f'The Analysis {analysis_id} was not found on Intezer Analyze'
    else:
        output = f'Could not find the analysis \'{analysis_id}\' or the sub analysis \'{sub_analysis_id}\''

    return CommandResults(
        readable_output=output
    )


def _get_missing_family_result(family_id: str) -> CommandResults:
    return CommandResults(
        readable_output=f'The Family {family_id} was not found on Intezer Analyze'
    )


def _get_analysis_running_result(analysis_id: str = None, response: requests.Response = None) -> CommandResults:
    if response:
        analysis_id = response.json()['result_url'].split('/')[2]

    context_json = {
        'ID': analysis_id,
        'Status': 'InProgress'
    }

    return CommandResults(
        outputs_prefix='Intezer.Analysis',
        outputs_key_field='ID',
        readable_output='Analysis is still in progress',
        outputs=context_json
    )


''' COMMANDS '''


def check_is_available(intezer_api: IntezerApi, args: dict) -> str:
    try:
        response = intezer_api.get_url_result(f'/{IS_AVAILABLE_URL}')
        return 'ok' if response else 'Empty response from intezer service'
    except InvalidApiKey as error:
        return f'Invalid API key received.\n{error}'
    except HTTPError as error:
        return f'Error occurred when reaching Intezer Analyze. Please check Analyze Base URL. \n{error}'
    except ConnectionError as error:
        return f'Error connecting to Analyze Base url.\n{error}'


def analyze_by_hash_command(intezer_api: IntezerApi, args: Dict[str, str]) -> CommandResults:
    file_hash = args.get('file_hash')

    if not file_hash:
        raise ValueError('Missing file hash')

    analysis = FileAnalysis(file_hash=file_hash, api=intezer_api)

    try:
        analysis.send(requester=REQUESTER)
        analysis_id = analysis.analysis_id

        context_json = {
            'ID': analysis.analysis_id,
            'Status': 'Created',
            'type': 'File'
        }

        return CommandResults(
            outputs_prefix='Intezer.Analysis',
            outputs_key_field='ID',
            outputs=context_json,
            readable_output='Analysis created successfully: {}'.format(analysis_id)
        )
    except HashDoesNotExistError:
        return _get_missing_file_result(file_hash)
    except AnalysisIsAlreadyRunning as error:
        return _get_analysis_running_result(response=error.response)


def analyze_url_command(intezer_api: IntezerApi, args: Dict[str, str]) -> CommandResults:
    url = args.get('url')

    if not url:
        raise ValueError('Missing url')

    analysis = UrlAnalysis(url=url, api=intezer_api)

    try:
        analysis.send(requester=REQUESTER)
        analysis_id = analysis.analysis_id

        context_json = {
            'ID': analysis.analysis_id,
            'Status': 'Created',
            'type': 'Url'
        }

        return CommandResults(
            outputs_prefix='Intezer.Analysis',
            outputs_key_field='ID',
            outputs=context_json,
            readable_output='Analysis created successfully: {}'.format(analysis_id)
        )
    except AnalysisIsAlreadyRunning as error:
        return _get_analysis_running_result(response=error.response)
    except ServerError as ex:
        return _get_missing_url_result(url, ex)


def get_latest_result_command(intezer_api: IntezerApi, args: Dict[str, str]) -> CommandResults:
    file_hash = args.get('file_hash')

    if not file_hash:
        raise ValueError('Missing file hash')

    latest_analysis = FileAnalysis.from_latest_hash_analysis(file_hash=file_hash, api=intezer_api, requester=REQUESTER)

    if not latest_analysis:
        return _get_missing_file_result(file_hash)

    file_metadata = latest_analysis.get_root_analysis().metadata
    return enrich_dbot_and_display_file_analysis_results(latest_analysis.result(), file_metadata)


def analyze_by_uploaded_file_command(intezer_api: IntezerApi, args: dict) -> CommandResults:
    file_id = args.get('file_entry_id')
    file_data = demisto.getFilePath(file_id)

    try:
        analysis = FileAnalysis(file_path=file_data['path'], api=intezer_api)
        analysis.send(requester=REQUESTER)

        context_json = {
            'ID': analysis.analysis_id,
            'Status': 'Created',
            'type': 'File'
        }

        return CommandResults(
            outputs_prefix='Intezer.Analysis',
            outputs_key_field='ID',
            outputs=context_json,
            readable_output='Analysis created successfully: {}'.format(analysis.analysis_id)
        )
    except AnalysisIsAlreadyRunning as error:
        return _get_analysis_running_result(response=error.response)


def check_analysis_status_and_get_results_command(intezer_api: IntezerApi, args: dict) -> List[CommandResults]:
    analysis_type = args.get('analysis_type', 'File')
    analysis_ids = argToList(args.get('analysis_id'))
    indicator_name = args.get('indicator_name')

    command_results = []
    file_metadata = {}

    for analysis_id in analysis_ids:
        try:
            if analysis_type == 'Endpoint':
                response = intezer_api.get_url_result(f'/endpoint-analyses/{analysis_id}')
                analysis_result = response.json()['result']
            elif analysis_type == 'Url':
                analysis = UrlAnalysis.from_analysis_id(analysis_id, api=intezer_api)
                if not analysis:
                    command_results.append(_get_missing_url_result(analysis_id))
                    continue
                else:
                    analysis_result = analysis.result()
            else:
                analysis = FileAnalysis.from_analysis_id(analysis_id, api=intezer_api)
                if not analysis:
                    command_results.append(_get_missing_analysis_result(analysis_id))
                    continue
                else:
                    analysis_result = analysis.result()
                    file_metadata = analysis.get_root_analysis().metadata

            if analysis_result and analysis_type == 'Endpoint':
                command_results.append(
                    enrich_dbot_and_display_endpoint_analysis_results(analysis_result, indicator_name))
            elif analysis_result and analysis_type == 'Url':
                command_results.append(
                    enrich_dbot_and_display_url_analysis_results(analysis_result, intezer_api))
            elif analysis_result:
                command_results.append(enrich_dbot_and_display_file_analysis_results(analysis_result, file_metadata))

        except HTTPError as http_error:
            if http_error.response.status_code == HTTPStatus.CONFLICT:
                command_results.append(_get_analysis_running_result(analysis_id=analysis_id))
            elif http_error.response.status_code == HTTPStatus.NOT_FOUND:
                command_results.append(_get_missing_analysis_result(analysis_id))
            else:
                raise http_error
        except AnalysisIsStillRunning:
            command_results.append(_get_analysis_running_result(analysis_id=analysis_id))

    return command_results


def get_analysis_sub_analyses_command(intezer_api: IntezerApi, args: dict) -> CommandResults:
    analysis_id = args.get('analysis_id')

    try:
        analysis = FileAnalysis.from_analysis_id(analysis_id, api=intezer_api)
        if not analysis:
            return _get_missing_analysis_result(analysis_id=str(analysis_id))
    except AnalysisIsStillRunning:
        return _get_analysis_running_result(analysis_id=str(analysis_id))

    sub_analyses: List[SubAnalysis] = analysis.get_sub_analyses()

    all_sub_analyses_ids = [sub.analysis_id for sub in sub_analyses]
    sub_analyses_table = tableToMarkdown('Sub Analyses', all_sub_analyses_ids, headers=['Analysis IDs'])

    context_json = {
        'ID': analysis.analysis_id,
        'SubAnalysesIDs': all_sub_analyses_ids
    }

    return CommandResults(
        outputs_prefix='Intezer.Analysis',
        outputs_key_field='ID',
        readable_output=sub_analyses_table,
        outputs=context_json,
        raw_response=all_sub_analyses_ids
    )


def get_analysis_code_reuse_command(intezer_api: IntezerApi, args: dict) -> CommandResults:
    analysis_id = args.get('analysis_id')
    sub_analysis_id = args.get('sub_analysis_id', 'root')

    try:
        sub_analysis: SubAnalysis = SubAnalysis(analysis_id=sub_analysis_id,
                                                composed_analysis_id=analysis_id,
                                                sha256='',
                                                source='',
                                                extraction_info=None,
                                                api=intezer_api)

        sub_analysis_code_reuse = sub_analysis.code_reuse
    except HTTPError as error:
        if error.response.status_code == HTTPStatus.NOT_FOUND:
            return _get_missing_analysis_result(analysis_id=str(analysis_id))
        elif error.response.status_code == HTTPStatus.CONFLICT:
            return _get_analysis_running_result(analysis_id=str(analysis_id))
        raise

    if not sub_analysis_code_reuse:
        return CommandResults(
            readable_output='No code reuse for this analysis'
        )

    families = sub_analysis_code_reuse.pop('families') if 'families' in sub_analysis_code_reuse else None

    readable_output = tableToMarkdown('Code Reuse', sub_analysis_code_reuse)

    if families:
        readable_output += '\nFamilies:\n'
        readable_output += '\n'.join(tableToMarkdown(family['family_name'], family) for family in families)

    is_root = sub_analysis_id == 'root'

    if is_root:
        context_json = {
            'Intezer.Analysis(obj.ID == val.ID)': {
                'ID': analysis_id,
                'CodeReuse': sub_analysis_code_reuse,
                'CodeReuseFamilies': families
            }
        }
    else:
        context_json = {
            'Intezer.Analysis(obj.RootAnalysis == val.ID).SubAnalyses(obj.ID == val.ID)': {
                'ID': sub_analysis_id,
                'RootAnalysis': analysis_id,
                'CodeReuse': sub_analysis_code_reuse,
                'CodeReuseFamilies': families
            }
        }

    return CommandResults(
        readable_output=readable_output,
        outputs=context_json,
        raw_response=sub_analysis.code_reuse
    )


def get_analysis_metadata_command(intezer_api: IntezerApi, args: dict) -> CommandResults:
    analysis_id = args.get('analysis_id')
    sub_analysis_id = args.get('sub_analysis_id', 'root')

    try:
        sub_analysis: SubAnalysis = SubAnalysis(analysis_id=sub_analysis_id,
                                                composed_analysis_id=analysis_id,
                                                sha256='',
                                                source='',
                                                extraction_info=None,
                                                api=intezer_api)

        sub_analysis_metadata = sub_analysis.metadata
    except HTTPError as error:
        if error.response.status_code == HTTPStatus.NOT_FOUND:
            return _get_missing_analysis_result(analysis_id=str(analysis_id))
        elif error.response.status_code == HTTPStatus.CONFLICT:
            return _get_analysis_running_result(analysis_id=str(analysis_id))
        raise
    metadata_table = tableToMarkdown('Analysis Metadata', sub_analysis_metadata)

    is_root = sub_analysis_id == 'root'

    if is_root:
        context_json = {
            'Intezer.Analysis(obj.ID == val.ID)': {
                'ID': analysis_id,
                'Metadata': sub_analysis_metadata
            }
        }
    else:
        context_json = {
            'Intezer.Analysis(obj.RootAnalysis == val.ID).SubAnalyses(obj.ID == val.ID)': {
                'ID': sub_analysis_id,
                'RootAnalysis': analysis_id,
                'Metadata': sub_analysis_metadata
            }
        }

    return CommandResults(
        readable_output=metadata_table,
        outputs=context_json,
        raw_response=sub_analysis_metadata
    )


def get_analysis_iocs_command(intezer_api: IntezerApi, args: dict) -> CommandResults:
    analysis_id = args.get('analysis_id')

    try:
        analysis = FileAnalysis.from_analysis_id(analysis_id, api=intezer_api)
    except HTTPError as error:
        if error.response.status_code == HTTPStatus.CONFLICT:
            return _get_analysis_running_result(analysis_id=str(analysis_id))
        raise

    if not analysis:
        return _get_missing_analysis_result(analysis_id=str(analysis_id))

    iocs = analysis.iocs
    readable_output = ''
    if iocs:
        if network_iocs := iocs.get('network'):
            readable_output += tableToMarkdown('Network IOCs', network_iocs)
        if files_iocs := iocs.get('files'):
            readable_output += tableToMarkdown('Files IOCs', files_iocs)
    else:
        readable_output = 'No IOCs found'

    context_json = {
        'Intezer.Analysis(obj.ID == val.ID)': {
            'ID': analysis_id,
            'IOCs': iocs
        }
    }

    return CommandResults(
        readable_output=readable_output,
        outputs=context_json,
        raw_response=iocs
    )


def get_family_info_command(intezer_api: IntezerApi, args: dict) -> CommandResults:
    family_id = args.get('family_id')
    family = Family(family_id, api=intezer_api)

    try:
        family.fetch_info()
    except FamilyNotFoundError:
        return _get_missing_family_result(str(family_id))

    output = {
        'ID': family_id,
        'Name': family.name,
        'Type': family.type
    }

    markdown = tableToMarkdown('Family Info', output)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Intezer.Family',
        outputs=output
    )


# region Enrich DBot

def enrich_dbot_and_display_file_analysis_results(intezer_result: dict, file_metadata: dict) -> CommandResults:
    verdict = intezer_result.get('verdict')
    sha256 = intezer_result.get('sha256')
    analysis_id = intezer_result.get('analysis_id')
    md5 = file_metadata.get('md5')
    sha1 = file_metadata.get('sha1')

    dbot_entry, file = _get_dbot_score_and_file_entries(intezer_result, file_metadata)

    if verdict == 'malicious':
        file['Malicious'] = {'Vendor': 'Intezer'}

    intezer_result['sha1'] = sha1
    intezer_result['md5'] = md5

    presentable_result = _file_analysis_presentable_code(intezer_result, sha256, verdict)

    return CommandResults(
        readable_output=presentable_result,
        raw_response=intezer_result,
        outputs={
            outputPaths['dbotscore']: dbot_entry,
            outputPaths['file']: file,
            'Intezer.Analysis(val.ID && val.ID == obj.ID)': {'ID': analysis_id, 'Status': 'Done'}
        }
    )


def _get_dbot_score_and_file_entries(file_analysis_result: dict, file_metadata: dict) -> Tuple[List[dict], dict]:
    verdict: str = file_analysis_result.get('verdict', '')
    sha256 = file_metadata.get('sha256')
    md5 = file_metadata.get('md5')
    sha1 = file_metadata.get('sha1')

    dbot = [
        {
            'Vendor': 'Intezer',
            'Type': 'file',
            'Indicator': sha256,
            'Score': dbot_score_by_verdict.get(verdict, 0)
        },
        {
            'Vendor': 'Intezer',
            'Type': 'file',
            'Indicator': sha1,
            'Score': dbot_score_by_verdict.get(verdict, 0)
        },
        {
            'Vendor': 'Intezer',
            'Type': 'file',
            'Indicator': md5,
            'Score': dbot_score_by_verdict.get(verdict, 0)
        }]
    file = {'SHA256': sha256, 'MD5': md5, 'SHA1': sha1, 'Metadata': file_analysis_result, 'ExistsInIntezer': True}

    return dbot, file


def _file_analysis_presentable_code(intezer_result: dict, sha256: str = None, verdict: str = None):
    if not sha256:
        sha256 = intezer_result['sha256']
    if not verdict:
        verdict = intezer_result['verdict']

    md = tableToMarkdown('Analysis Report', intezer_result, url_keys=['analysis_url'])
    presentable_result = '## Intezer File analysis result\n'
    presentable_result += f' SHA256: {sha256}\n'
    presentable_result += f' Verdict: **{verdict}** ({intezer_result["sub_verdict"]})\n'
    if 'family_name' in intezer_result:
        presentable_result += f'Family: **{intezer_result["family_name"]}**\n'
    presentable_result += f'[Analysis Link]({intezer_result["analysis_url"]})\n'
    presentable_result += md
    return presentable_result


def get_indicator_text(classification: str, indicators: dict) -> str:
    if classification in indicators:
        return f'{classification.capitalize()}: {", ".join(indicators[classification])}'
    return ''


def enrich_dbot_and_display_url_analysis_results(intezer_result, intezer_api):
    summary = intezer_result.pop('summary')
    _refine_gene_counts(summary)

    intezer_result.update(summary)
    verdict = summary['verdict_type']
    submitted_url = intezer_result['submitted_url']
    scanned_url = intezer_result['scanned_url']
    analysis_id = intezer_result['analysis_id']

    dbot = [{
        'Vendor': 'Intezer',
        'Type': 'Url',
        'Indicator': submitted_url,
        'Score': dbot_score_by_verdict.get(verdict, 0)
    }
    ]

    if scanned_url != submitted_url:
        dbot.append({
            'Vendor': 'Intezer',
            'Type': 'Url',
            'Indicator': scanned_url,
            'Score': dbot_score_by_verdict.get(verdict, 0)
        })

    url = {'URL': submitted_url, 'Metadata': intezer_result, 'ExistsInIntezer': True}

    if verdict == 'malicious':
        url['Malicious'] = {'Vendor': 'Intezer'}

    if 'redirect_chain' in intezer_result:
        redirect_chain = ' → '.join(f'{node["response_status"]}: {node["url"]}'
                                    for node in intezer_result['redirect_chain'])
        intezer_result['redirect_chain'] = redirect_chain

    if 'indicators' in intezer_result:
        indicators: Dict[str, List[str]] = defaultdict(list)
        for indicator in intezer_result['indicators']:
            indicators[indicator['classification']].append(indicator['text'])
        indicators_text = [
            get_indicator_text('malicious', indicators),
            get_indicator_text('suspicious', indicators),
            get_indicator_text('informative', indicators),
        ]

        intezer_result['indicators'] = '\n'.join(indicator_text for indicator_text in indicators_text if indicator_text)

    presentable_result = '## Intezer Url analysis result\n'
    presentable_result += f' Url: {submitted_url}\n'
    presentable_result += f' Verdict: **{verdict}** ({summary["verdict_name"]})\n'
    presentable_result += f'[Analysis Link]({intezer_result["analysis_url"]})\n'

    downloaded_file_presentable_result = ''
    file_entry: dict = {}
    if 'downloaded_file' in intezer_result:
        downloaded_file = intezer_result.pop('downloaded_file')
        presentable_result += f'Downloaded file SHA256: {downloaded_file["sha256"]}\n'
        presentable_result += f'Downloaded file Verdict: **{downloaded_file["analysis_summary"]["verdict_type"]}**\n'
        downloaded_file_analysis = FileAnalysis.from_analysis_id(downloaded_file['analysis_id'], intezer_api)
        download_file_result = downloaded_file_analysis.result()
        intezer_result['downloaded_file'] = download_file_result
        metadata = downloaded_file_analysis.get_root_analysis().metadata

        file_dbot_entry, file_entry = _get_dbot_score_and_file_entries(download_file_result, metadata)

        sha1 = metadata.get('sha1')
        md5 = metadata.get('md5')
        download_file_result['sha1'] = sha1
        download_file_result['md5'] = md5
        downloaded_file_presentable_result = _file_analysis_presentable_code(download_file_result)

        dbot.extend(file_dbot_entry)
        file_entry = {outputPaths['file']: file_entry}

    md = tableToMarkdown('Analysis Report', intezer_result, url_keys=['analysis_url'])
    presentable_result += md + downloaded_file_presentable_result

    return CommandResults(
        readable_output=presentable_result,
        raw_response=intezer_result,
        outputs={
            outputPaths['dbotscore']: dbot,
            outputPaths['url']: url,
            **file_entry,
            'Intezer.Analysis(val.ID && val.ID == obj.ID)': {'ID': analysis_id, 'Status': 'Done'}
        }
    )


def _refine_gene_counts(summary: dict):
    summary.pop('main_connection_gene_count', None)
    summary.pop('main_connection_gene_percentage', None)
    summary.pop('main_connection', None)
    summary.pop('main_connection_family_id', None)
    summary.pop('main_connection_software_type', None)
    summary.pop('main_connection_classification', None)


def enrich_dbot_and_display_endpoint_analysis_results(intezer_result, indicator_name=None) -> CommandResults:
    verdict = intezer_result['verdict']
    computer_name = intezer_result['computer_name']
    analysis_id = intezer_result['analysis_id']

    dbot = {
        'Vendor': 'Intezer',
        'Type': 'hostname',
        'Indicator': indicator_name if indicator_name else computer_name,
        'Score': dbot_score_by_verdict.get(verdict, 0)
    }

    endpoint = {'Metadata': intezer_result}

    presentable_result = '## Intezer Endpoint analysis result\n'
    presentable_result += f'Host Name: {computer_name}\n'
    presentable_result += f' Verdict: **{verdict}**\n'
    if intezer_result.get('families') is not None:
        presentable_result += f'Families: **{intezer_result["families"]}**\n'
    presentable_result += f' Scan Time: {intezer_result["scan_start_time"]}\n'
    presentable_result += f'[Analysis Link]({intezer_result["analysis_url"]})\n'

    return CommandResults(
        readable_output=presentable_result,
        raw_response=intezer_result,
        outputs={
            outputPaths['dbotscore']: dbot,
            'Endpoint': endpoint,
            'Intezer.Analysis(val.ID && val.ID == obj.ID)': {'ID': analysis_id, 'Status': 'Done'}
        }
    )


# endregion

''' EXECUTION CODE '''


def main():
    command = None

    try:
        handle_proxy()

        intezer_api_key = demisto.getParam('APIKey')
        intezer_base_url_param = demisto.getParam('AnalyzeBaseURL')
        use_ssl = not demisto.params().get('insecure', False)
        analyze_base_url = intezer_base_url_param or consts.BASE_URL

        intezer_api = IntezerApi(consts.API_VERSION, intezer_api_key, analyze_base_url, use_ssl)

        command_handlers: Dict[str, Callable[[IntezerApi, dict], Union[List[CommandResults], CommandResults, str]]] = {
            'test-module': check_is_available,
            'intezer-analyze-by-hash': analyze_by_hash_command,
            'intezer-analyze-by-file': analyze_by_uploaded_file_command,
            'intezer-analyze-url': analyze_url_command,
            'intezer-get-latest-report': get_latest_result_command,
            'intezer-get-analysis-result': check_analysis_status_and_get_results_command,
            'intezer-get-sub-analyses': get_analysis_sub_analyses_command,
            'intezer-get-analysis-code-reuse': get_analysis_code_reuse_command,
            'intezer-get-analysis-metadata': get_analysis_metadata_command,
            'intezer-get-analysis-iocs': get_analysis_iocs_command,
            'intezer-get-family-info': get_family_info_command
        }

        command = demisto.command()
        command_handler = command_handlers[command]
        command_results = command_handler(intezer_api, demisto.args())
        return_results(command_results)

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

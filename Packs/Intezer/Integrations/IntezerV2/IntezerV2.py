from http import HTTPStatus
from typing import Callable
from typing import Dict
from typing import List
from typing import Union

import demistomock as demisto
import requests
from CommonServerPython import *
from CommonServerUserPython import *
from intezer_sdk import consts
from intezer_sdk.analysis import Analysis
from intezer_sdk.analysis import get_analysis_by_id
from intezer_sdk.analysis import get_latest_analysis
from intezer_sdk.api import IntezerApi
from intezer_sdk.errors import AnalysisIsAlreadyRunning
from intezer_sdk.errors import AnalysisIsStillRunning
from intezer_sdk.errors import HashDoesNotExistError
from intezer_sdk.family import Family
from intezer_sdk.sub_analysis import SubAnalysis
from requests import HTTPError

''' CONSTS '''
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

IS_AVAILABLE_URL = 'is-available'
ERROR_PREFIX = 'Error from Intezer:'
ACCEPTABLE_HTTP_CODES = {200, 201, 202}

http_status_to_error_massage = {
    400: '400 Bad Request - Wrong or invalid parameters',
    401: '401 Unauthorized - Wrong or invalid api key',
    403: '403 Forbidden - The account is not allowed to preform this task',
    404: '404 Not Found - Analysis was not found',
    410: '410 Gone - Analysis no longer exists in the service',
    500: '500 Internal Server Error - Internal error',
    503: '503 Service Unavailable'
}

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


def _get_missing_analysis_result(analysis_id: str) -> CommandResults:
    return CommandResults(
        readable_output=f'The Analysis {analysis_id} was not found on Intezer Analyze'
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
    result = intezer_api.get_url_result(f'/{IS_AVAILABLE_URL}')
    return 'ok' if result else 'Failure'


def analyze_by_hash_command(intezer_api: IntezerApi, args: Dict[str, str]) -> CommandResults:
    file_hash = args.get('file_hash')

    if not file_hash:
        raise ValueError('Missing file hash')

    analysis = Analysis(file_hash=file_hash, api=intezer_api)

    try:
        analysis.send()
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


def get_latest_result_command(intezer_api: IntezerApi, args: Dict[str, str]) -> CommandResults:
    file_hash = args.get('file_hash')

    if not file_hash:
        raise ValueError('Missing file hash')

    latest_analysis = get_latest_analysis(file_hash=file_hash, api=intezer_api)

    if not latest_analysis:
        return _get_missing_file_result(file_hash)

    return enrich_dbot_and_display_file_analysis_results(latest_analysis.result())


def analyze_by_uploaded_file_command(intezer_api: IntezerApi, args: dict) -> CommandResults:
    file_id = args.get('file_entry_id')
    file_data = demisto.getFilePath(file_id)

    try:
        analysis = Analysis(file_path=file_data['path'], api=intezer_api)
        analysis.send()

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

    for analysis_id in analysis_ids:
        try:
            if analysis_type == 'Endpoint':
                response = intezer_api.get_url_result(f'/endpoint-analyses/{analysis_id}')
                analysis_result = response.json()['result']
            else:
                analysis = get_analysis_by_id(analysis_id, api=intezer_api)
                analysis_result = analysis.result()

            if analysis_result and analysis_type == 'Endpoint':
                command_results.append(
                    enrich_dbot_and_display_endpoint_analysis_results(analysis_result, indicator_name))
            else:
                command_results.append(enrich_dbot_and_display_file_analysis_results(analysis_result))

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

    analysis = get_analysis_by_id(analysis_id, api=intezer_api)
    sub_analyses: List[SubAnalysis] = analysis.get_sub_analyses()

    all_sub_analyses_ids = [sub.analysis_id for sub in sub_analyses]
    sub_analyses_table = tableToMarkdown('Sub Analyses', all_sub_analyses_ids, headers=['Analysis IDs'])

    context_json = {
        'ID': analysis.analysis_id,
        'SubAnalyses': all_sub_analyses_ids
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

    sub_analysis: SubAnalysis = SubAnalysis(analysis_id=sub_analysis_id,
                                            composed_analysis_id=analysis_id,
                                            sha256='',
                                            source='',
                                            api=intezer_api)

    sub_analysis_code_reuse = sub_analysis.code_reuse

    if not sub_analysis_code_reuse:
        return CommandResults(
            readable_output='No code reuse for this analysis'
        )

    families = sub_analysis_code_reuse.pop('families') if 'families' in sub_analysis_code_reuse else None

    readable_output = tableToMarkdown('Code Reuse', sub_analysis_code_reuse)

    if families:
        readable_output += '\nFamilies:\n'
        readable_output += '\n'.join(tableToMarkdown(family['family_name'], family) for family in families)

    context_json = {
        'ID': analysis_id if sub_analysis_id == 'root' else sub_analysis_id,
        'ComposedAnalysisID': analysis_id,
        'CodeReuse': sub_analysis_code_reuse,
        'CodeReuseFamilies': families
    }

    return CommandResults(
        outputs_prefix='Intezer.Analysis',
        outputs_key_field='ID',
        readable_output=readable_output,
        outputs=context_json,
        raw_response=sub_analysis.code_reuse
    )


def get_analysis_metadata_command(intezer_api: IntezerApi, args: dict) -> CommandResults:
    analysis_id = args.get('analysis_id')
    sub_analysis_id = args.get('sub_analysis_id', 'root')

    sub_analysis: SubAnalysis = SubAnalysis(analysis_id=sub_analysis_id,
                                            composed_analysis_id=analysis_id,
                                            sha256='',
                                            source='',
                                            api=intezer_api)

    sub_analysis_metadata = sub_analysis.metadata

    metadata_table = tableToMarkdown('Analysis Metadata', sub_analysis_metadata)

    context_json = {
        'ID': analysis_id if sub_analysis_id == 'root' else sub_analysis_id,
        'ComposedAnalysisID': analysis_id,
        'Metadata': sub_analysis_metadata
    }

    return CommandResults(
        outputs_prefix='Intezer.Analysis',
        outputs_key_field='ID',
        readable_output=metadata_table,
        outputs=context_json,
        raw_response=sub_analysis_metadata
    )


def get_family_info_command(intezer_api: IntezerApi, args: dict) -> CommandResults:
    family_id = args.get('family_id')
    family = Family(family_id, api=intezer_api)
    family.fetch_info()

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

def enrich_dbot_and_display_file_analysis_results(intezer_result):
    verdict = intezer_result.get('verdict')
    sha256 = intezer_result.get('sha256')
    analysis_id = intezer_result.get('analysis_id')

    dbot = {
        'Vendor': 'Intezer',
        'Type': 'hash',
        'Indicator': sha256,
        'Score': dbot_score_by_verdict.get(verdict, 0)
    }

    file = {'SHA256': sha256, 'Metadata': intezer_result, 'ExistsInIntezer': True}

    if verdict == 'malicious':
        file['Malicious'] = {'Vendor': 'Intezer'}

    md = tableToMarkdown('Analysis Report', intezer_result)

    presentable_result = '## Intezer File analysis result\n'
    presentable_result += f' SHA256: {sha256}\n'
    presentable_result += f' Verdict: **{verdict}** ({intezer_result["sub_verdict"]})\n'
    if 'family_name' in intezer_result:
        presentable_result += f'Family: **{intezer_result["family_name"]}**\n'
    presentable_result += f'[Analysis Link]({intezer_result["analysis_url"]})\n'
    presentable_result += md

    return CommandResults(
        readable_output=presentable_result,
        raw_response=intezer_result,
        outputs={
            outputPaths['dbotscore']: dbot,
            outputPaths['file']: file,
            'Intezer.Analysis(val.ID && val.ID == obj.ID)': {'ID': analysis_id, 'Status': 'Done'}
        }
    )


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
    try:
        handle_proxy()

        intezer_api_key = demisto.getParam('APIKey')
        intezer_base_url_param = demisto.getParam('AnalyzeBaseURL')
        analyze_base_url = intezer_base_url_param or consts.BASE_URL

        intezer_api = IntezerApi(consts.API_VERSION, intezer_api_key, analyze_base_url)

        command_handlers: Dict[str, Callable[[IntezerApi, dict], Union[CommandResults, str]]] = {
            'test-module': check_is_available,
            'intezer-analyze-by-hash': analyze_by_hash_command,
            'intezer-analyze-by-file': analyze_by_uploaded_file_command,
            'intezer-get-latest-report': get_latest_result_command,
            'intezer-get-analysis-result': check_analysis_status_and_get_results_command,
            'intezer-get-sub-analyses': get_analysis_sub_analyses_command,
            'intezer-get-analysis-code-reuse': get_analysis_code_reuse_command,
            'intezer-get-analysis-metadata': get_analysis_metadata_command,
            'intezer-get-family-info': get_family_info_command
        }

        command = demisto.command()
        command_handler = command_handlers[command]
        command_results = command_handler(intezer_api, demisto.args())
        return_results(command_results)

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


# python2 uses __builtin__ python3 uses builtins yo
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

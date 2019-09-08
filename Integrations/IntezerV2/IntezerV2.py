import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


''' IMPORTS '''

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

API_KEY = demisto.getParam('APIKey')
SERVER_URL = 'https://analyze.intezer.com/api'
API_VERSION = '/v2-0'
BASE_URL = SERVER_URL + API_VERSION
IS_AVAILABLE_URL = 'is-available'
ERROR_PREFIX = 'Error from Intezer:'
ACCEPTABLE_HTTP_CODES = {200, 201, 202}
USE_SSL = not demisto.params().get('insecure', False)

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


def handle_response(response, acceptable_http_status_codes):
    if response.status_code not in acceptable_http_status_codes:
        error_msg = http_status_to_error_massage.get(response.status_code, "Failed to perform request")
        return_error(f'{ERROR_PREFIX} {error_msg}')

    try:
        return response.json()
    except json.decoder.JSONDecodeError:
        # This error is unlikely to happen, as the return code should indicate of error beforehand
        return_error(f'Response returned with no data. This might be an issue with Intezer.\nPlease try again later\n'
                     f'Response content:\n{response.content}')


def get_session():
    response = requests.post(BASE_URL + '/get-access-token', json={'api_key': API_KEY}, verify=USE_SSL)
    response = handle_response(response, {200})
    session = requests.session()
    session.headers['Authorization'] = f'Bearer {response["result"]}'

    return session


''' COMMANDS '''


def check_is_available():
    url = f'{SERVER_URL}/{IS_AVAILABLE_URL}'
    result = SESSION.get(url, verify=USE_SSL)

    return 'ok' if result.json()['is_available'] else None


def analyze_by_hash_command():
    file_hash = demisto.getArg('file_hash')
    response = make_analyze_by_hash_request(file_hash)
    handle_analyze_by_hash_response(response, file_hash)


def make_analyze_by_hash_request(file_hash):
    data = {'hash': file_hash}
    return SESSION.post(BASE_URL + '/analyze-by-hash', json=data, verify=USE_SSL)


def handle_analyze_by_hash_response(response, file_hash):
    if response.status_code == 404:
        dbot = {
            'Vendor': 'Intezer',
            'Type': 'hash',
            'Indicator': file_hash,
            'Score': 0
        }
        hr = f'Hash {file_hash} does not exist on Intezer genome database'
        ec = {'DBotScore': dbot}
        return_outputs(hr, ec)
        return

    elif response.status_code == 400:
        return_error('File hash is not valid.\nIntezer file hash reputation supports only SHA-256, '
                     'SHA-1 and MD5 hash formats.\n')

    handle_analyze_response(response)


def analyze_by_uploaded_file_command():
    response = make_analyze_by_file_request(demisto.getArg('file_entry_id'))
    handle_analyze_response(response)


def make_analyze_by_file_request(file_id):
    file_data = demisto.getFilePath(file_id)
    with open(file_data['path'], 'rb') as file_to_upload:
        files = {'file': (file_data['name'], file_to_upload)}
        return SESSION.post(BASE_URL + '/analyze', files=files, verify=USE_SSL)


def handle_analyze_response(response):
    response = handle_response(response, ACCEPTABLE_HTTP_CODES)

    result_url = response['result_url']
    analysis_id = result_url.rsplit('/', 1)[-1]

    context_json = {'Intezer.Analysis(obj.ID === val.ID)': {'ID': analysis_id, 'Status': 'Created', 'type': 'File'}}

    return_outputs('Analysis created successfully', context_json, response)


def check_analysis_status_and_get_results_command():
    analysis_type = demisto.args().get('analysis_type', 'File')
    analysis_ids = argToList(demisto.args().get('analysis_id'))
    indicator_name = demisto.args().get('indicator_name')

    for analysis_id in analysis_ids:
        response = make_analysis_status_request(analysis_id, analysis_type)
        analysis_result = handle_analysis_result(response)

        if analysis_result and analysis_type == 'Endpoint':
            enrich_dbot_and_display_endpoint_analysis_results(analysis_result, indicator_name)
        elif analysis_result and analysis_type == 'File':
            enrich_dbot_and_display_file_analysis_results(analysis_result)


def make_analysis_status_request(analysis_id, analysis_type):
    analysis_endpoint = 'endpoint-analyses/' if analysis_type == 'Endpoint' else 'analyses/'
    result_url = f'{BASE_URL}/{analysis_endpoint}{analysis_id}'
    return SESSION.get(result_url, verify=USE_SSL)


def handle_analysis_result(response):
    json_response = handle_response(response, ACCEPTABLE_HTTP_CODES)

    if response.status_code != 200:
        result_url = json_response['result_url']
        analysis_id = result_url.rsplit('/', 1)[-1]

        context_json = {'Intezer.Analysis(val.ID === obj.ID)': {'ID': analysis_id,
                                                                'Status': 'InProgress'}}

        return_outputs('Analysis is still in progress', context_json)
        return

    return json_response['result']


def enrich_dbot_and_display_file_analysis_results(result):
    verdict = result.get('verdict')
    sha256 = result.get('sha256')
    analysis_id = result.get('analysis_id')

    dbot = {
        'Vendor': 'Intezer',
        'Type': 'hash',
        'Indicator': sha256,
        'Score': dbot_score_by_verdict.get(verdict, 0)
    }

    file = {'SHA256': sha256, 'Metadata': result, 'ExistsInIntezer': True}

    if verdict == 'malicious':
        file['Malicious'] = {'Vendor': 'Intezer'}

    presentable_result = '## Intezer File analysis result\n'
    presentable_result += f' SHA256: {sha256}\n'
    presentable_result += f' Verdict: **{verdict}** ({result["sub_verdict"]})\n'
    if 'family_name' in result:
        presentable_result += f'Family: **{result["family_name"]}**\n'
    presentable_result += f'[Analysis Link]({result["analysis_url"]})\n'

    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {
            outputPaths['dbotscore']: dbot,
            outputPaths['file']: file,
            'Intezer.Analysis(val.ID === obj.ID)': {'ID': analysis_id, 'Status': 'Done'}},
        'HumanReadable': presentable_result,
        'ContentsFormat': formats['json'],
        'Contents': result
    })


def enrich_dbot_and_display_endpoint_analysis_results(result, indicator_name=None):
    verdict = result['verdict']
    computer_name = result['computer_name']
    analysis_id = result['analysis_id']

    dbot = {
        'Vendor': 'Intezer',
        'Type': 'hostname',
        'Indicator': indicator_name if indicator_name else computer_name,
        'Score': dbot_score_by_verdict.get(verdict, 0)
    }

    endpoint = {'Metadata': result}

    presentable_result = '## Intezer Endpoint analysis result\n'
    presentable_result += f'Host Name: {computer_name}\n'
    presentable_result += f' Verdict: **{verdict}**\n'
    if result.get('families') is not None:
        presentable_result += f'Families: **{result["families"]}**\n'
    presentable_result += f' Scan Time: {result["scan_start_time"]}\n'
    presentable_result += f'[Analysis Link]({result["analysis_url"]})\n'
    ec = {
        'DBotScore': dbot,
        'Endpoint': endpoint,
        'Intezer.Analysis(val.ID === obj.ID)': {'ID': analysis_id, 'Status': 'Done'}
    }
    return_outputs(presentable_result, ec, result)


''' EXECUTION CODE '''


try:
    SESSION = get_session()
except Exception as e:
    return_error(str(e))


def main():
    try:
        handle_proxy()
        if demisto.command() == 'test-module':
            demisto.results(check_is_available())
        elif demisto.command() == 'intezer-analyze-by-hash':
            analyze_by_hash_command()
        elif demisto.command() == 'intezer-analyze-by-file':
            analyze_by_uploaded_file_command()
        elif demisto.command() == 'intezer-get-analysis-result':
            check_analysis_status_and_get_results_command()
    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

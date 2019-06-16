import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


''' IMPORTS '''

import requests

API_KEY = demisto.getParam('APIKey')
SERVER_URL = 'https://analyze.intezer.com/api'
API_VERSION = 'v2-0'
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
dbot_score_by_verdict = {'malicious': 3,
                         'suspicious': 2,
                         'trusted': 1,
                         'neutral': 1,
                         'no_threats': 1}

''' HELPER FUNCTIONS '''


def handle_response(response, acceptable_http_status_codes):
    if response.status_code not in acceptable_http_status_codes:
        return_error('{} {}'.format(ERROR_PREFIX, http_status_to_error_massage.get(response.status_code,
                                                                                   'Failed to perform request')))

    return response.json()


def get_session():
    response = requests.post(SERVER_URL + '/v2-0/get-access-token', json={'api_key': API_KEY})
    response = handle_response(response, {200})
    session = requests.session()
    session.headers['Authorization'] = 'Bearer {}'.format(response['result'])

    return session


''' COMMANDS '''


def check_is_available():
    session = get_session()
    url = '{}/{}'.format(SERVER_URL, IS_AVAILABLE_URL)
    result = session.get(url)

    return 'ok' if result.json()['is_available'] else None


def analyze_by_hash():
    file_hash = demisto.getArg('file_hash')
    response = make_analyze_by_hash_request(file_hash)
    handle_analyze_by_hash_response(response, file_hash)


def make_analyze_by_hash_request(file_hash):
    session = get_session()
    data = {'hash': file_hash}
    return session.post(SERVER_URL + '/v2-0/analyze-by-hash', json=data)


def handle_analyze_by_hash_response(response, file_hash):
    if response.status_code == 404:
        dbot = {
            'Vendor': 'Intezer',
            'Type': 'hash',
            'Indicator': file_hash,
            'Score': 0
        }

        demisto.results({
            'Type': entryTypes['note'],
            'EntryContext': {'DBotScore': [dbot]},
            'HumanReadable': 'Hash {} does not exist on Intezer genome database'.format(file_hash),
            'ContentsFormat': formats['json'],
            'Contents': ''
        })
        return

    elif response.status_code == 400:
        return_error('File hash is not valid.\nIntezer file hash reputation supports only sha256, '
                     'sha1 and md5 hash formats.\n')

    handle_analyze_response(response)


def analyze_by_uploaded_file():
    response = make_analyze_by_file_request(demisto.getArg('file_entry_id'))
    handle_analyze_response(response)


def make_analyze_by_file_request(file_id):
    session = get_session()
    file_data = demisto.getFilePath(file_id)
    with open(file_data['path'], 'rb') as file_to_upload:
        files = {'file': (file_data['name'], file_to_upload)}
        return session.post(SERVER_URL + '/v2-0/analyze', files=files)


def handle_analyze_response(response):
    response = handle_response(response, ACCEPTABLE_HTTP_CODES)

    result_url = response['result_url']
    analysis_id = result_url.rsplit('/', 1)[-1]

    context_json = {'Intezer.Analysis': {'ID': analysis_id, 'Status': 'Created', 'type':'File'}}

    return_outputs('Analysis created successfully', context_json, response)


def check_analysis_status_and_get_results():
    analysis_type = demisto.args().get('analysis_type', 'File')
    analysis_ids = argToList(demisto.getArg('analysis_id'))

    for analysis_id in analysis_ids:
        response = make_analysis_status_request(analysis_id, analysis_type)
        analysis_result = handle_analysis_result(response)

        if analysis_result and analysis_type == 'Endpoint':
            enrich_dbot_and_display_endpoint_analysis_results(analysis_result, demisto.getArg('indicator_name'))
        elif analysis_result and analysis_type == 'File':
            enrich_dbot_and_display_file_analysis_results(analysis_result)


def make_analysis_status_request(analysis_id, analysis_type):
    result_url = get_result_url(analysis_type, analysis_id)
    session = get_session()
    return session.get(result_url)


def get_result_url(analysis_type, analysis_id):
    result_url = '{}/{}/{}{}'.format(SERVER_URL, API_VERSION,
                                         'endpoint-analyses/' if analysis_type == 'Endpoint' else 'analyses/',
                                         analysis_id)

    return result_url


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
    verdict = result['verdict']
    sha256 = result['sha256']
    analysis_id = result['analysis_id']

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
    presentable_result += ' SHA256: {}\n'.format(sha256)
    presentable_result += ' Verdict: **{}** ({})\n'.format(verdict, result['sub_verdict'])
    if 'family_name' in result:
        presentable_result += 'Family: **{}**\n'.format(result['family_name'])
    presentable_result += '[Analysis Link]({})\n'.format(result['analysis_url'])

    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {outputPaths['dbotscore']: [dbot],
                         outputPaths['file']: [file],
                         'Intezer.Analysis(val.ID === obj.ID)': {'ID': analysis_id,
                                                                 'Status': 'Done'}},
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
        'Type': 'Hostname',
        'Indicator': indicator_name if indicator_name else computer_name,
        'Score': dbot_score_by_verdict.get(verdict, 0)
    }

    endpoint = {'Metadata': result}

    presentable_result = '## Intezer Endpoint analysis result\n'
    presentable_result += 'Host Name: {}\n'.format(computer_name)
    presentable_result += ' Verdict: **{}**\n'.format(verdict)
    if 'families' in result and result['families'] != None:
        presentable_result += 'Families: **{}**\n'.format(result['families'])
    presentable_result += ' Scan Time: {}\n'.format(result['scan_start_time'])
    presentable_result += '[Analysis Link]({})\n'.format(result['analysis_url'])

    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'DBotScore': [dbot], 'Endpoint': [endpoint],
                         'Intezer.Analysis(val.ID === obj.ID)': {'ID': analysis_id,
                                                                 'Status': 'Done'}},
        'HumanReadable': presentable_result,
        'ContentsFormat': formats['json'],
        'Contents': result
    })


''' EXECUTION CODE '''
try:
    if demisto.command() == 'test-module':
        demisto.results(check_is_available())
    elif demisto.command() == 'intezer-analyze-by-hash':
        analyze_by_hash()
    elif demisto.command() == 'intezer-analyze-by-file':
        analyze_by_uploaded_file()
    elif demisto.command() == 'intezer-get-analysis-result':
        check_analysis_status_and_get_results()


except Exception as e:
    LOG(e)
    LOG.print_log(False)
    return_error(e.message)

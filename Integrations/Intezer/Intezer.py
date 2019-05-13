import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import time

import requests

API_KEY = demisto.getParam('APIKey')
SERVER_URL = 'https://analyze.intezer.com/api'
API_VERSION = 'v2-0'
IS_AVAILABLE_URL = 'is-available'
ERROR_PREFIX = 'Error from Intezer:'
ACCEPTABLE_HTTP_CODES = {200, 201, 202}
USE_SSL = not demisto.params().get('insecure', False)

http_status_to_error_message = {
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
                         'no_threats': 1
                         }


def handle_response(response, acceptable_http_status_codes):
    if response.status_code not in acceptable_http_status_codes:
        raise Exception('{} {}'.format(ERROR_PREFIX, http_status_to_error_message.get(response.status_code,
                                                                                      'Failed to perform request')))

    return response.json()


def get_session():
    response = requests.post(SERVER_URL + '/v2-0/get-access-token', json={'api_key': API_KEY}, verify=USE_SSL)
    response = handle_response(response, {200})
    session = requests.session()
    session.headers['Authorization'] = 'Bearer {}'.format(response['result'])

    return session


def check_is_available():
    session = get_session()
    url = '{}/{}'.format(SERVER_URL, IS_AVAILABLE_URL)
    result = session.get(url)

    return 'ok' if result.json()['is_available'] else None


def _get_analysis_result(result_url=None, analysis_id=None, analysis_type='File', session=None, delay=5,
                         max_retries=60):
    result_url = _get_result_url(analysis_type, result_url, analysis_id)
    session = session or get_session()
    response = session.get(result_url, verify=USE_SSL)
    handle_response(response, ACCEPTABLE_HTTP_CODES)
    tries = 0
    max_retries = int(max_retries)
    while response.status_code != 200 and tries < max_retries:
        tries += 1
        time.sleep(float(delay))
        response = session.get(result_url, verify=USE_SSL)
        handle_response(response, ACCEPTABLE_HTTP_CODES)

    if response.status_code != 200:
        raise Exception('{} {}'.format(ERROR_PREFIX, 'Failed to analyze, Try to change maxRetries or delay arguments'))

    return response.json()['result']


def _get_result_url(analysis_type, result_url=None, analysis_id=None):
    if result_url:
        result_url = '{}/{}{}'.format(SERVER_URL, API_VERSION, result_url)
    else:
        result_url = '{}/{}/{}{}'.format(SERVER_URL, API_VERSION,
                                         'endpoint-analyses/' if analysis_type == 'Endpoint' else 'analyses/',
                                         analysis_id)

    return result_url


def analyze_by_hash(file_hash, delay, max_retries):
    session = get_session()
    data = {'hash': file_hash}
    response = session.post(SERVER_URL + '/v2-0/analyze-by-hash', json=data, verify=USE_SSL)
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
        hr = 'File hash is not valid. \nIntezer file hash reputation supports only sha256, sha1 and md5 hash formats.\n'
        demisto.results({
            'Type': entryTypes['note'],
            'HumanReadable': hr,
            'ContentsFormat': formats['json'],
            'Contents': ''
        })
        return

    response = handle_response(response, ACCEPTABLE_HTTP_CODES)

    analysis_result = _get_analysis_result(result_url=response['result_url'],
                                           session=session,
                                           delay=delay,
                                           max_retries=max_retries)
    enrich_dbot_and_display_file_analysis_results(analysis_result)


def get_analysis_result(analysis_id, analysis_type, delay, max_retries, indicator_name=None):
    result = _get_analysis_result(analysis_id=analysis_id,
                                  analysis_type=analysis_type,
                                  delay=delay,
                                  max_retries=max_retries)
    if analysis_type == 'Endpoint':
        enrich_dbot_and_display_endpoint_analysis_results(result, indicator_name)
    else:
        enrich_dbot_and_display_file_analysis_results(result)


def analyze_by_uploaded_file(file_id, delay, max_retries):
    session = get_session()
    file_data = demisto.getFilePath(file_id)
    with open(file_data['path'], 'rb') as file_to_upload:
        files = {'file': (file_data['name'], file_to_upload)}
        response = session.post(SERVER_URL + '/v2-0/analyze', files=files, verify=USE_SSL)

    response = handle_response(response, ACCEPTABLE_HTTP_CODES)
    analysis_result = _get_analysis_result(result_url=response['result_url'], session=session, delay=delay,
                                           max_retries=max_retries)
    enrich_dbot_and_display_file_analysis_results(analysis_result)


def enrich_dbot_and_display_file_analysis_results(result):
    verdict = result['verdict']
    sha256 = result['sha256']

    dbot = {
        'Vendor': 'Intezer',
        'Type': 'hash',
        'Indicator': sha256,
        'Score': dbot_score_by_verdict.get(verdict, 0)
    }

    file = {'SHA256':sha256, 'Metadata': result, 'ExistsInIntezer': True}

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
        'EntryContext': {outputPaths['dbotscore']: [dbot], outputPaths['file']: [file]},
        'HumanReadable': presentable_result,
        'ContentsFormat': formats['json'],
        'Contents': result
    })


def enrich_dbot_and_display_endpoint_analysis_results(result, indicator_name):
    verdict = result['verdict']
    computer_name = result['computer_name']

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
        'EntryContext': {'DBotScore': [dbot], 'Endpoint': [endpoint]},
        'HumanReadable': presentable_result,
        'ContentsFormat': formats['json'],
        'Contents': result
    })


''' EXECUTION CODE '''
try:
    handle_proxy()
    if demisto.command() == 'test-module':
        demisto.results(check_is_available())
    elif demisto.command() == 'file':
        analyze_by_hash(demisto.getArg('file'), demisto.getArg('delay'), demisto.getArg('maxRetries'))
    elif demisto.command() == 'intezer-upload':
        analyze_by_uploaded_file(demisto.getArg('fileEntryId'), demisto.getArg('delay'), demisto.getArg('maxRetries'))
    elif demisto.command() == 'intezer-get-analysis-result':
        get_analysis_result(demisto.getArg('analysisId'), demisto.getArg('analysisType'), demisto.getArg('delay'),
                            demisto.getArg('maxRetries'), demisto.getArg('indicatorName'))


except Exception as e:
    return_error(str(e))

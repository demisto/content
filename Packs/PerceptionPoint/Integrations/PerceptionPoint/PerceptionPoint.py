import demistomock as demisto
from CommonServerPython import *

''' IMPORTS'''
import requests
import json
from collections import defaultdict

''' INTEGRATION PARAMS '''
URL = 'http://api.perception-point.io/api/v1/{endpoint}'  # disable-secrets-detection
INCIDENTS_ENDPOINT = 'scans/incidents/'
RELEASE_ENDPOINT = 'quarantine/release/{id_}'

USER_PARAMS = demisto.params()
SECURED = not USER_PARAMS.get('insecure', False)
PP_TOKEN = USER_PARAMS.get('pp_token', None)
if PP_TOKEN is None:
    return_error('Perception Point token is mandatory. '
                 'Please enter your token or contact PerceptionPoint support for assistance')
try:
    API_MAX_LOOPS = int(USER_PARAMS.get('api_loops', 1))
except Exception:
    API_MAX_LOOPS = 1
HEADER = {'Authorization': f'Token {PP_TOKEN}'}

''' CONSTANTS '''
RELEASE = 'release'
LIST = 'list'
API_ACTIONS_DICT = {RELEASE: RELEASE_ENDPOINT,
                    LIST: INCIDENTS_ENDPOINT}
SPAM = 'SPM'
BLOCKED = 'BLK'
MALICIOUS = 'MAL'

API_CURSOR_ARG = '_cursor'

VERBOSE_VERDICT_PARAM = 'verbose_verdict[]'

FETCH_INCIDENTS_TYPE = [{'demisto_param': 'fetch_malicious',
                         'req_pname': VERBOSE_VERDICT_PARAM,
                         'req_pval': MALICIOUS},
                        {'demisto_param': 'fetch_blocked',
                         'req_pname': VERBOSE_VERDICT_PARAM,
                         'req_pval': BLOCKED},
                        {'demisto_param': 'fetch_spam',
                         'req_pname': VERBOSE_VERDICT_PARAM,
                         'req_pval': SPAM}]

''' HELPER FUNCTIONS '''


def build_fetch_incident_types(fetch_blocked, fetch_malicious, fetch_spam):
    fetch_type_dict = defaultdict(list)  # type: ignore
    fetch_select = {
        'fetch_blocked': fetch_blocked,
        'fetch_malicious': fetch_malicious,
        'fetch_spam': fetch_spam
    }
    for darg in FETCH_INCIDENTS_TYPE:
        darg_input = fetch_select.get(darg['demisto_param'])
        if darg_input:
            fetch_type_dict[darg['req_pname']].append(darg.get('req_pval', darg_input))
    return dict(fetch_type_dict)


def create_incident(record):
    record.pop('Attachment', None)
    record['RawJSON'] = json.dumps(record)
    return record


def collect_incidents(params):
    list_url = build_request_url(LIST)
    api_res = get_pp_api_result(list_url, params)
    num_of_results = api_res.get('count')
    incidents = []  # type: list
    api_loops = 0
    while num_of_results and api_loops < API_MAX_LOOPS:
        incidents += map(create_incident, api_res.get('results'))
        if api_res.get('next'):
            api_res = get_pp_api_result(api_res.get('next'), {})
            num_of_results = api_res.get('count')
        api_loops += 1
    return incidents


def report_incidents(incidents_list):
    demisto.incidents(incidents_list)


def get_pp_api_result(url, params):
    try:
        res = requests.get(url=url,
                           params=params,
                           headers=HEADER,
                           verify=SECURED)
        res.raise_for_status()
        try:
            res_content = res.json()
        except Exception:
            res_content = {}
        return res_content
    except requests.exceptions.HTTPError as err:
        if 400 <= res.status_code < 500:
            return_error('Invalid token')
        else:
            return_error(err)
    except Exception as err:
        return_error(err)


def build_request_url(api_action):
    return URL.format(endpoint=API_ACTIONS_DICT.get(api_action))


def command_fetch_incidents():
    try:
        fetch_blocked = USER_PARAMS.get('fetch_blocked')
        fetch_spam = USER_PARAMS.get('fetch_spam')
        fetch_malicious = USER_PARAMS.get('fetch_malicious')
        req_args = build_fetch_incident_types(fetch_blocked, fetch_malicious, fetch_spam)
        last_run_id = int(demisto.getLastRun().get('scan_id', 0))
        req_args[API_CURSOR_ARG] = last_run_id
        incidents_list = collect_incidents(req_args)
        report_incidents(incidents_list)
        if incidents_list:
            last_run_id = max(last_run_id, int(incidents_list[-1].get('Scan Id')))
            demisto.setLastRun({'scan_id': int(last_run_id)})
    except Exception as err:
        return_error(f'An error occurred while trying to fetch new incidents. '
                     f'Please contact PerceptionPoint support for more info. {err}')


def release_email_and_get_message(scan_id_to_release):
    try:
        release_url = build_request_url(RELEASE).format(id_=scan_id_to_release)
        _ = get_pp_api_result(release_url, {})
        return f'Email with id {scan_id_to_release} was released Successfully!'
    except Exception:
        raise


def command_release_email():
    try:
        scan_id_to_release = demisto.args().get('scan_id')
        entry = {
            'Type': entryTypes['note'],
            'ReadableContentsFormat': formats['markdown']
        }
        email_release_response = release_email_and_get_message(scan_id_to_release)
        entry.update({'Contents': email_release_response,
                      'ContentsFormat': formats['text'],
                      'EntryContext': {'PP.Released': scan_id_to_release}}
                     )
        demisto.results(entry)
    except Exception as err:
        return_error(f'An error occurred while trying to release email. '
                     f'Please contact PerceptionPoint support for more info\n. {err}')


def test_command():
    list_url = build_request_url(LIST)
    if get_pp_api_result(list_url, {}):
        demisto.results('ok')


''' COMMAND CLASSIFIER'''
try:
    handle_proxy()
    if demisto.command() == 'test-module':
        test_command()
    if demisto.command() == 'fetch-incidents':
        command_fetch_incidents()
    if demisto.command() == 'pp-release-email':
        command_release_email()
except Exception as e:
    LOG(str(e))
    message = f'Unexpected error: {e} \n'
    LOG(message)
    LOG.print_log()
    return_error(message)

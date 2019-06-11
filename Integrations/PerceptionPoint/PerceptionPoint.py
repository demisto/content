import demistomock as demisto
from CommonServerPython import *

''' IMPORTS'''
import requests
import json
import sys
import traceback
from collections import defaultdict

''' INTEGRATION PARAMS '''
URL = 'http://api.perception-point.io/api/v1/{endpoint}'
INCIDENTS_ENDPOINT = 'scans/incidents/'
RELEASE_ENDPOINT = 'quarantine/release/{id_}'

USER_PARAMS = demisto.params()
SECURED = not USER_PARAMS.get('insecure')
PP_TOKEN = demisto.params().pop('pp_token', None)
if PP_TOKEN is None:
    return_error('Perception Point token is mandatory. Please enter your token or cantact us at support@perception-point.io for assistance')
try:
    API_MAX_LOOPS = int(USER_PARAMS.pop('api_loops', 1))
except:
    API_MAX_LOOPS = 1
HEADER = {'Authorization': 'Token {}'.format(PP_TOKEN)}

''' CONSTANTS '''
RELEASE = 'release'
LIST = 'list'
API_ACTIONS_DICT = {RELEASE: RELEASE_ENDPOINT,
                    LIST: INCIDENTS_ENDPOINT}
SPAM = 'SPM'
BLOCKED = 'BLK'
MALICIOUS = 'MAL'

API_CURSOR_ARG = '_cursor'

FETCH_INCIDENTS_TYPE = [{'demisto_param': 'fetch_malicious',
                         'req_pname': 'verbose_verdict',
                         'req_pval': MALICIOUS},
                        {'demisto_param': 'fetch_blocked',
                         'req_pname': 'verbose_verdict',
                         'req_pval': BLOCKED},
                        {'demisto_param': 'fetch_spam',
                         'req_pname': 'verbose_verdict',
                         'req_pval': SPAM}]

''' HELPER FUNCTIONS '''


def build_fetch_incident_types(fetch_select):
    fetch_type_dict = defaultdict(list)
    for darg in FETCH_INCIDENTS_TYPE:
        darg_input = fetch_select.get(darg['demisto_param'])
        if darg_input:
            fetch_type_dict[darg['req_pname']].append(darg.get('req_pval', darg_input))
    for reqname, reqval in fetch_type_dict.iteritems():
        fetch_type_dict[reqname] = ','.join(reqval)
    return dict(fetch_type_dict)


def create_incident(record):
    record.pop('Attachment', None)
    record['RawJSON'] = json.dumps(record)
    return record


def collect_incidents(**kwargs):
    list_url = build_request_url(LIST)
    api_res = get_pp_api_result(url=list_url, **kwargs)
    num_of_results = api_res.get('count')
    incidents = []
    api_loops = 0
    while num_of_results and api_loops < API_MAX_LOOPS:
        incidents += map(create_incident, api_res.get('results'))
        if api_res.get('next'):
            api_res = get_pp_api_result(url=api_res.get('next'))
            num_of_results = api_res.get('count')
        api_loops += 1
    return incidents


def report_incidents(incidents_list):
    demisto.incidents(incidents_list)


def get_pp_api_result(url, **kwargs):
    try:
        res = requests.get(url=url,
                           params=kwargs,
                           headers=HEADER,
                           verify=SECURED)
        res.raise_for_status()
        try:
            res_content = res.json()
        except:
            res_content = {}
        return res_content
    except Exception as e:
        return_error(e.message)


def build_request_url(api_action):
    return URL.format(endpoint=API_ACTIONS_DICT.get(api_action))


def command_fetch_incidents():
    try:
        args_dict = demisto.args()
        args_dict.update(USER_PARAMS)
        req_args = build_fetch_incident_types(args_dict)
        last_run_id = int(demisto.getLastRun().get('scan_id', 0))
        req_args[API_CURSOR_ARG] = last_run_id
        incidents_list = collect_incidents(**req_args)
        report_incidents(incidents_list)
        if incidents_list:
            last_run_id = max(last_run_id, int(incidents_list[-1].get('Scan Id')))
            demisto.setLastRun({'scan_id': int(last_run_id)})
    except:
        return_error(
            'An error occurred while trying to fetch new incidents. Please contact us at support@perception-point.io')


def release_email_and_get_message(scan_id_to_release):
    try:
        release_url = build_request_url(RELEASE).format(id_=scan_id_to_release)
        _ = get_pp_api_result(url=release_url)
        return 'Email with id {} was released Successfully!'.format(scan_id_to_release)
    except:
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
    except Exception as e:
        return_error(
            'An error occurred while trying to release email. Please contact us at support@perception-point.io')


''' COMMAND CLASSIFIER'''
try:
    if demisto.command() == 'test-module':
        list_url = build_request_url(LIST)
        if get_pp_api_result(url=list_url):
            demisto.results('ok')
        sys.exit(0)
    if demisto.command() == 'fetch-incidents':
        command_fetch_incidents()
    if demisto.command() == 'pp-release-email':
        command_release_email()
except Exception as e:
    message = f'Unexpected error: {e}, traceback: {traceback.print_exc()}'
    LOG(message)
    LOG(str(e))
    LOG.print_log()
    return_error(message)

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

BASE_URL = demisto.params()['url']
API_KEY = demisto.params().get('token')
GOOD_DISP = argToList(demisto.params().get('good_disp'))
SUSP_DISP = argToList(demisto.params().get('susp_disp'))
BAD_DISP = argToList(demisto.params().get('bad_disp'))
USE_SSL = not demisto.params().get('insecure', False)

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

STATUS_SUFFIX = '/status'
CLEAN_STATUS = 'clean'
PENDING_STATUS = 'PENDING'
DONE_STATUS = 'DONE'

DEFAULT_GOOD_DISP = {
    'clean'
}

DEFAULT_SUSP_DISP = {
    'drug_spam',
    'gambling',
    'hacked_website',
    'streaming',
    'suspicious'
}

DEFAULT_BAD_DISP = {
    'cryptojacking',
    'phish',
    'likely_phish',
    'scam'
}

''' HELPER FUNCTIONS '''


def http_request(method, url, params=None, data=None):
    res = requests.request(
        method,
        url,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )

    if res.status_code not in {200}:
        return_error('Error in API call to CheckPhish [%d] - %s' % (res.status_code, res.reason))

    try:
        return res.json()

    except ValueError as err:
        return_error('Failed to parse response from service, received the following error:\n{}'.format(str(err)))


def unite_dispositions():
    for disp in GOOD_DISP:
        DEFAULT_GOOD_DISP.add(disp)

    for disp in SUSP_DISP:
        DEFAULT_SUSP_DISP.add(disp)

    for disp in BAD_DISP:
        DEFAULT_BAD_DISP.add(disp)


def get_dbot_score(disposition):
    if disposition in DEFAULT_BAD_DISP:
        return 3
    if disposition in DEFAULT_SUSP_DISP:
        return 2
    if disposition in DEFAULT_GOOD_DISP:
        return 1
    return 0


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    query = {
        'apiKey': API_KEY,
        'urlInfo': {'url': 'https://www.google.com'}
    }
    res = http_request('POST', BASE_URL, data=json.dumps(query))
    if res and 'message' not in res:
        return 'ok'

    return res['message']  # the message field contains the error message


def submit_to_checkphish(url):
    """ Submit a URL for analysis in CheckPhish

    Args:
        url(str): URL to be sent to CheckPhish for analysis

    Returns:
        (str). jobID retrieved from CheckPhish for the URL

    """
    if 'http' not in url:
        url = 'http://' + url

    if re.match(urlRegex, url):
        query = {
            'apiKey': API_KEY,
            'urlInfo': {'url': url},
            'scanType': 'full'
        }
        res = http_request('POST', BASE_URL, data=json.dumps(query))

        return res['jobID']

    else:
        return_error(url + ' is not a valid url')


def is_job_ready_checkphish(jobID):
    query = {
        'apiKey': API_KEY,
        'jobID': jobID
    }
    res = http_request('POST', BASE_URL + STATUS_SUFFIX, data=json.dumps(query))

    if res and res['status'] == DONE_STATUS:
        return True

    return False


def get_result_checkphish(jobID):
    query = {
        'apiKey': API_KEY,
        'jobID': jobID
    }
    res = http_request('POST', BASE_URL + STATUS_SUFFIX, data=json.dumps(query))

    if res and 'errorMessage' not in res:
        result = {
            'url': res['url'],
            'jobID': jobID,
            'status': res['status'],
            'disposition': res['disposition'],
            'brand': res['brand']
        }

        url_dict = {
            'Data': result['url']
        }

        if result['disposition'] != CLEAN_STATUS:
            url_dict['Malicious'] = {
                'Vendor': 'CheckPhish',
                'Description': 'Targets ' + result['brand']
            }

        dbot_score = {
            'Type': 'url',
            'Vendor': 'CheckPhish',
            'Indicator': result['url'],
            'Score': get_dbot_score(result['disposition'])
        }

        context = {
            'CheckPhish.' + outputPaths['url']: result,
            outputPaths['url']: url_dict,
            'DBotScore': dbot_score
        }

        human_readable = tableToMarkdown('CheckPhish reputation for ' + result['url'],
                                         result,
                                         ['url', 'disposition', 'brand', 'status', 'jobID'])

        return_outputs(human_readable, context, res)

    else:
        return_error('Error getting job status')


def checkphish_check_urls():
    urls = argToList(demisto.args().get('url'))
    job_ids = []

    for url in urls:
        submit = submit_to_checkphish(url)
        if submit:
            job_ids.append(submit)

    while len(job_ids):
        for job_id in job_ids[:]:
            if is_job_ready_checkphish(job_id):
                get_result_checkphish(job_id)
                job_ids.remove(job_id)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))
handle_proxy()
unite_dispositions()

try:
    if demisto.command() == 'test-module':
        demisto.results(test_module())

    elif demisto.command() == 'CheckPhish-check-urls':
        checkphish_check_urls()

# Log exceptions
except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise

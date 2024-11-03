import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''


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


def http_request(method, url, use_ssl, params=None, data=None):
    res = requests.request(
        method,
        url,
        verify=use_ssl,
        params=params,
        data=data,
        headers=HEADERS
    )

    if res.status_code not in {200}:
        return_error('Error in API call to CheckPhish [%d] - %s' % (res.status_code, res.reason))

    try:
        return res.json()

    except ValueError as err:
        return_error(f'Failed to parse response from service, received the following error:\n{str(err)}')


def unite_dispositions(good_disp, susp_disp, bad_disp):
    for disp in good_disp:
        DEFAULT_GOOD_DISP.add(disp)

    for disp in susp_disp:
        DEFAULT_SUSP_DISP.add(disp)

    for disp in bad_disp:
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


def test_module(**kwargs):
    query = {
        'apiKey': kwargs.get('api_key'),
        'urlInfo': {'url': 'https://www.google.com'}
    }
    res = http_request('POST', kwargs.get('base_url'), kwargs.get('use_ssl'), data=json.dumps(query))
    if res and 'errorMessage' not in res:
        return 'ok'

    return res['errorMessage']  # the errorMessage field contains the error message


def submit_to_checkphish(url, api_key, base_url, use_ssl):
    """ Submit a URL for analysis in CheckPhish

    Args:
        url(str): URL to be sent to CheckPhish for analysis
        api_key: api key for the authorization
        base_url: url for the API request
        use_ssl: for the http request

    Returns:
        (str). jobID retrieved from CheckPhish for the URL

    """
    if 'http' not in url:
        url = 'http://' + url

    if re.match(urlRegex, url):
        query = {
            'apiKey': api_key,
            'urlInfo': {'url': url},
            'scanType': 'full'
        }
        res = http_request('POST', base_url, use_ssl, data=json.dumps(query))
        if res.get('errorMessage'):
            raise ValueError(res.get('errorMessage'))

        return res['jobID']

    else:
        return_error(url + ' is not a valid url')


def is_job_ready_checkphish(jobID, api_key, base_url, use_ssl):
    query = {
        'apiKey': api_key,
        'jobID': jobID
    }
    res = http_request('POST', base_url + STATUS_SUFFIX, use_ssl, data=json.dumps(query))

    if res and res['status'] == DONE_STATUS:
        return True

    return False


def get_result_checkphish(jobID, api_key, base_url, use_ssl, reliability):
    query = {
        'apiKey': api_key,
        'jobID': jobID
    }
    res = http_request('POST', base_url + STATUS_SUFFIX, use_ssl, data=json.dumps(query))

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
            'Score': get_dbot_score(result['disposition']),
            'Reliability': reliability
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


def checkphish_check_urls(**kwargs):
    urls = argToList(demisto.args().get('url'))
    job_ids = []

    for url in urls:
        submit = submit_to_checkphish(url, kwargs.get('api_key'), kwargs.get('base_url'), kwargs.get('use_ssl'))
        if submit:
            job_ids.append(submit)

    while len(job_ids):
        for job_id in job_ids[:]:
            if is_job_ready_checkphish(job_id, kwargs.get('api_key'), kwargs.get('base_url'), kwargs.get('use_ssl')):
                get_result_checkphish(job_id, kwargs.get('api_key'), kwargs.get('base_url'), kwargs.get('use_ssl'),
                                      kwargs.get('reliability'))
                job_ids.remove(job_id)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))
handle_proxy()


def main():

    demisto_params = demisto.params()
    good_disp = argToList(demisto_params.get('good_disp'))
    susp_disp = argToList(demisto_params.get('susp_disp'))
    bad_disp = argToList(demisto_params.get('bad_disp'))
    api_key = demisto_params.get('credentials_api_token', {}).get('password') or demisto_params.get('token')
    if not api_key:
        raise DemistoException('API token must be provided.')
    unite_dispositions(good_disp, susp_disp, bad_disp)

    reliability = demisto_params.get('integrationReliability')
    reliability = reliability if reliability else DBotScoreReliability.B

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        raise Exception("Please provide a valid value for the Source Reliability parameter.")

    params = {
        'base_url': demisto_params['url'],
        'api_key': api_key,
        'use_ssl': not demisto_params.get('insecure', False),
        'reliability': reliability
    }

    try:
        if demisto.command() == 'test-module':
            demisto.results(test_module(**params))

        elif demisto.command() in ['CheckPhish-check-urls', 'url']:
            checkphish_check_urls(**params)

    # Log exceptions
    except Exception as e:
        LOG(str(e))
        LOG.print_log()
        raise


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

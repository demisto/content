import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import time
import shutil
import requests
from distutils.util import strtobool
# disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' GLOBAL VARS '''
BASE_URL = urljoin(demisto.params().get('url'), 'api/')
USE_SSL = not demisto.params().get('insecure', False)
MAX_POLLS = int(demisto.params().get('maxpolls', 300))
USE_PROXY = demisto.params().get('proxy', True)

nothing_to_analyze_message = 'We found nothing to analyze in your uploaded email' \
                             '(possibly all elements where whitelisted, check Input filtering in your Settings).'
nothing_to_analyze_output = {
    'Type': entryTypes['note'],
    'ContentsFormat': formats['markdown'],
    'Contents': 'We found nothing to analyze in your uploaded email',
    'HumanReadable': 'We found nothing to analyze in your uploaded email'
}


''' HELPER FUNCTIONS '''


def http_post(url_suffix, data=None, files=None, parse_json=True):
    data = {} if data is None else data

    LOG('running request with url=%s\n\tdata=%s\n\tfiles=%s' % (BASE_URL + url_suffix,
        data, files, ))
    data.setdefault('apikey', demisto.params()['api_key'])

    res = requests.post(BASE_URL + url_suffix, verify=USE_SSL, data=data, files=files)

    if res.status_code == 403:
        raise Exception('API Key is incorrect')

    if res.status_code != 200:
        error_msg = res.json()['errors'][0]['message']
        if error_msg == nothing_to_analyze_message:
            return 'nothing_to_analyze'

        LOG('result is: %s' % (res.json(), ))
        error_msg = res.json()['errors'][0]['message']
        raise Exception('Your request failed with the following error: %s.\n%s' % (res.reason, error_msg, ))

    if parse_json:
        return res.json()
    else:
        return res.content


def analysis_to_entry(title, info):
    if not isinstance(info, list):
        info = [info]

    context = []
    table = []
    dbot_scores = []
    for analysis in info:
        analysis_info = {
            'ID': analysis['webid'],  # for detonate generic polling
            'WebID': analysis['webid'],
            'SampleName': analysis['filename'],
            'Status': analysis['status'],
            'Comments': analysis['comments'],
            'Time': analysis['time'],
            'MD5': analysis['md5'],
            'SHA1': analysis['sha1'],
            'SHA256': analysis['sha256'],
            'Systems': list(set([run['system'] for run in analysis['runs']])),
            'Result': ', '.join([run['detection'] for run in analysis['runs']]),
            'Errors': [run['error'] for run in analysis['runs']],
        }

        analysis_context = dict(analysis_info)
        analysis_context['Runs'] = analysis['runs']

        analysis_table = dict(analysis_info)
        if not any(analysis_table['Errors']):
            analysis_table['Errors'] = None

        dbot_score = 0
        malicious = None
        if 'malicious' in analysis_info['Result']:
            dbot_score = 3
            malicious = {
                'Vendor': 'JoeSecurity',
                'Detections': ', '.join(set([run['detection'] for run in analysis['runs']])),
                'SHA1': analysis_info['SHA1'],
            }
        elif 'suspicious' in analysis_info['Result']:
            dbot_score = 2
        elif 'clean' in analysis_info['Result']:
            dbot_score = 1

        dbot_scores.append({
            'Vendor': 'JoeSecurity',
            'Indicator': analysis.get('MD5', analysis.get('filename')),
            'Type': 'file' if analysis_info['MD5'] else 'url',
            'Score': dbot_score,
            'Malicious': malicious,
        })
        context.append(analysis_context)
        table.append(analysis_table)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': context,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, table, removeNull=True),
        'EntryContext': {'Joe.Analysis(val.ID && val.ID == obj.ID)': createContext(context, removeNull=True),
                         'DBotScore': createContext(dbot_scores, removeNull=True), }
    }

    return entry


def poll_webid(web_id):
    result = {'data': {'status': 'pending'}}
    max_polls = MAX_POLLS

    while (max_polls >= 0) and result['data']['status'] != 'finished':
        if result['data']['status'] != 'pending':
            LOG('error while polling: result is %s' % (result, ))
        result = info_request(web_id)
        time.sleep(1)
        max_polls -= 1

    LOG('reached max_polls #%d' % (max_polls, ))
    if max_polls < 0:
        return analysis_to_entry('Polling timeout on Analysis #' + web_id, result['data'])
    else:
        return analysis_to_entry('Analysis #' + web_id, result['data'])


''' FUNCTIONS '''


def is_online():
    cmd_url = 'v2/server/online'
    res = http_post(cmd_url)
    return res['data']['online']


def list_analysis():
    cmd_url = 'v2/analysis/list'
    res = http_post(cmd_url)

    data = [info_request(web_id['webid'])['data'] for web_id in res['data']]
    return analysis_to_entry('All Analyses:', data)


def analysis_info():
    ids = demisto.args().get('webid')
    if type(ids) in STRING_TYPES:
        ids = ids.split(',')
    LOG('info: web_id = %s' % (ids, ))
    res = [info_request(webid)['data'] for webid in ids]
    return analysis_to_entry('Analyses:', res)


def info_request(web_id):
    cmd_url = 'v2/analysis/info'
    return http_post(cmd_url, data={'webid': web_id})


def search():
    cmd_url = 'v2/analysis/search'
    query = demisto.args().get('query')
    res = http_post(cmd_url, data={'q': query})
    if len(res['data']) == 0:
        return 'No Result was found.'

    data = [info_request(web_id['webid'])['data'] for web_id in res['data']]
    return analysis_to_entry('Analysis Search Results:', data)


def analyse_url():
    args = demisto.args()
    url = args.get('url')
    internet_access = bool(strtobool(args.get('internet-access', 'true')))
    comments = args.get('comments')
    systems = args.get('systems')

    should_wait = bool(strtobool(demisto.get(args, 'should_wait')))

    return analyse_url_request(url, should_wait, internet_access, comments, systems)


def analyse_url_request(url, should_wait, internet_access, comments='', systems=''):
    data = {
        'accept-tac': 1,
        'url': url,
        'internet-access': 1 if internet_access else 0,
    }
    if comments != '':
        data['comments'] = comments
    if systems != '':
        data['systems[]'] = [s.strip() for s in systems.split(',')]
    res = http_post('v2/analysis/submit', data=data)

    if 'errors' in res:
        LOG('Error! in command analyse_url: url=%s' % (url, ))
        LOG('got the following errors:\n' + '\n'.join(e['message'] for e in res['errors']))
        raise Exception('command failed to run.')

    if should_wait:
        return poll_webid(res['data']['webids'][0])

    web_id = res['data']['webids'][0]
    result = info_request(web_id)
    return analysis_to_entry('Analysis #%s' % (web_id, ), result['data'])


def analyse_sample():
    args = demisto.args()
    file_entry = args.get('file_id', '')
    if type(file_entry) in STRING_TYPES:
        file_entry = [f for f in file_entry.split(',') if f != '']
    sample_url = args.get('sample_url', '')
    if type(sample_url) in STRING_TYPES:
        sample_url = [f for f in sample_url.split(',') if f != '']
    internet_access = bool(strtobool(args.get('internet-access', 'true')))
    should_wait = bool(strtobool(demisto.get(args, 'should_wait')))
    comments = args.get('comments', '')
    systems = args.get('systems', '')

    if (len(file_entry) == 0 and len(sample_url) == 0) or ([] not in [file_entry, sample_url]):
        raise ValueError('You must specify one (and only one) of the following: sample_url, file_id.')

    LOG('analysing sample')
    if len(file_entry) != 0:
        return [analyse_sample_file_request(f, should_wait, internet_access, comments, systems) for f in file_entry]
    else:
        return [analyse_sample_url_request(s, should_wait, internet_access, comments, systems) for s in sample_url]


def analyse_sample_file_request(file_entry, should_wait, internet_access, comments='', systems=''):
    data = {
        'accept-tac': 1,
        'internet-access': 1 if internet_access else 0,
    }
    if comments != '':
        data['comments'] = comments
    if systems != '':
        data['systems[]'] = [s.strip() for s in systems.split(',')]  # type: ignore

    # removing backslashes from filename as the API does not like it
    # if given filename such as dir\file.xlsx - the sample will end with the name file.xlsx
    filename = demisto.getFilePath(file_entry)['name'].replace('\\', '/')

    with open(demisto.getFilePath(file_entry)['path'], 'rb') as f:
        res = http_post('v2/analysis/submit', data=data, files={'sample': (filename, f)})

    if res == 'nothing_to_analyze':
        return nothing_to_analyze_output

    if 'errors' in res:
        LOG('Error! in command sample file: file_entry=%s' % (file_entry, ))
        LOG('got the following errors:\n' + '\n'.join(e['message'] for e in res['errors']))
        raise Exception('command failed to run.')

    shutil.rmtree(demisto.getFilePath(file_entry)['name'], ignore_errors=True)

    if should_wait:
        return poll_webid(res['data']['webids'][0])

    web_id = res['data']['webids'][0]
    result = info_request(web_id)
    return analysis_to_entry('Analysis #%s' % (web_id, ), result['data'])


def analyse_sample_url_request(sample_url, should_wait, internet_access, comments, systems):
    data = {
        'accept-tac': 1,
        'sample-url': sample_url,
        'internet-access': 1 if internet_access else 0,
    }
    if comments != '':
        data['comments'] = comments
    if systems != '':
        data['systems[]'] = [s.strip() for s in systems.split(',')]

    res = http_post('v2/analysis/submit', data=data)

    if res == 'nothing_to_analyze':
        return nothing_to_analyze_output

    if 'errors' in res:
        LOG('Error! in command sample file: file url=%s' % (sample_url, ))
        LOG('got the following errors:\n' + '\n'.join(e['message'] for e in res['errors']))
        raise Exception('command failed to run.')

    if should_wait:
        return poll_webid(res['data']['webids'][0])

    web_id = res['data']['webids'][0]
    result = info_request(res['data']['webids'][0])
    return analysis_to_entry('Analysis #%s' % (web_id, ), result['data'])


def download_report():
    args = demisto.args()
    webid = args.get('webid')
    rsc_type = args.get('type')
    return download_request(webid, rsc_type)


def download_sample():
    args = demisto.args()
    webid = args.get('webid')
    rsc_type = 'sample'
    return download_request(webid, rsc_type)


def download_request(webid, rsc_type):
    res = http_post('v2/analysis/download', data={'webid': webid, 'type': rsc_type.lower()}, parse_json=False)

    info = info_request(webid)
    if rsc_type == 'sample':
        return fileResult('%s.dontrun' % (info.get('filename', webid), ), res)
    else:
        return fileResult('%s_report.%s' % (info.get('filename', webid), rsc_type, ), res, entryTypes['entryInfoFile'])


''' EXECUTION CODE '''
LOG('command is %s' % (demisto.command(), ))
try:
    handle_proxy()
    if demisto.command() in ['test-module', 'joe-is-online']:
        # This is the call made when pressing the integration test button.
        if is_online():
            demisto.results('ok')
        else:
            demisto.results('not online')
    elif demisto.command() == 'joe-list-analysis':
        demisto.results(list_analysis())
    elif demisto.command() == 'joe-analysis-info':
        demisto.results(analysis_info())
    elif demisto.command() == 'joe-analysis-submit-url':
        demisto.results(analyse_url())
    elif demisto.command() == 'joe-detonate-url':
        demisto.args()['should_wait'] = 'True'
        demisto.results(analyse_url())
    elif demisto.command() == 'joe-analysis-submit-sample':
        demisto.results(analyse_sample())
    elif demisto.command() == 'joe-detonate-file':
        demisto.args()['should_wait'] = 'True'
        demisto.results(analyse_sample())
    elif demisto.command() == 'joe-download-report':
        demisto.results(download_report())
    elif demisto.command() == 'joe-download-sample':
        demisto.results(download_sample())
    elif demisto.command() == 'joe-search':
        demisto.results(search())

except Exception as e:
    if demisto.params().get('verbose'):
        LOG(e.message)
        if demisto.command() != 'test-module':
            LOG.print_log()

    demisto.results({
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': 'error has occurred: %s' % (e.message, ),
    })

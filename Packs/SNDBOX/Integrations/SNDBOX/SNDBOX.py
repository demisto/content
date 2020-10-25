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
BASE_URL = 'https://api.sndbox.com/'
SAMPLE_URL = 'https://app.sndbox.com/sample/'
USE_SSL = not demisto.params().get('insecure', False)

''' HELPER FUNCTIONS '''


def http_cmd(url_suffix, data=None, files=None, parse_json=True):
    data = {} if data is None else data

    url_params = {}  # type:dict

    use_public_api = demisto.params().get('public_api_key', False)
    api_key = demisto.params().get('api_key', False)
    if not api_key and use_public_api:
        url_params.setdefault('apikey', demisto.params()['secret_public_api_key'])
    elif api_key:
        url_params.setdefault('apikey', api_key)

    LOG('running request with url=%s\n\tdata=%s\n\tfiles=%s' % (BASE_URL + url_suffix,
                                                                data, files,))

    res = {}  # type:dict
    if files:
        res = requests.post(BASE_URL + url_suffix,  # type:ignore
                            verify=USE_SSL,
                            params=url_params,
                            data=data,
                            files=files
                            )
    else:
        res = requests.get(BASE_URL + url_suffix,  # type:ignore
                           verify=USE_SSL,
                           params=url_params
                           )

    if res.status_code == 401:  # type:ignore
        raise Exception('API Key is incorrect')

    if res.status_code >= 400:  # type:ignore
        try:
            LOG('result is: %s' % (res.json(),))  # type:ignore
            error_msg = res.json()['errors'][0]['msg']  # type:ignore
            raise Exception('Your request failed with the following status code (%s) and error: %s.\n%s' %
                            (res.status_code, res.reason, error_msg,))  # type:ignore
        except ValueError:
            # in case the response is not parsed as JSON
            raise Exception('Your request failed with the following status code (%s) and error: %s.' %
                            (res.status_code, res.reason))  # type:ignore

    if parse_json:
        return res.json()  # type:ignore
    else:
        return res.content  # type:ignore


def extract_status(sndbox_status):
    s = sndbox_status['dynamic']['code'] + sndbox_status['static']['code']
    if s <= 1:
        return 'pending'
    elif s == 2:
        return 'finished'
    else:
        return 'error'


def extract_errors(sndbox_status):
    errors = []
    if 'message' in sndbox_status['static']:
        errors.append(sndbox_status['static']['message'])
    if 'message' in sndbox_status['dynamic']:
        errors.append(sndbox_status['dynamic']['message'])
    return errors


def analysis_to_entry(title, info):
    if not isinstance(info, list):
        info = [info]

    context = []
    table = []
    dbot_scores = []
    for analysis in info:
        malicious = analysis['score'] and analysis['score'] * 100 > 56
        status = extract_status(analysis['status'])
        result = ''
        if status == 'finished':
            result = 'malicious' if malicious else 'clean'

        analysis_info = {
            'ID': analysis['id'],  # for detonate generic polling
            'SampleName': analysis['name'],
            'Status': status,
            'Time': analysis['created_at'],
            'Link': SAMPLE_URL + analysis['id'],
            'MD5': analysis['md5'],
            'SHA1': analysis['sha1'],
            'SHA256': analysis['sha256'],
            'Score': analysis['score'],
            'Result': result,
            'Errors': extract_errors(analysis['status']),
        }

        analysis_context = dict(analysis_info)
        analysis_table = dict(analysis_info)
        if not any(analysis_table['Errors']):
            analysis_table['Errors'] = None

        dbot_score = 0

        if malicious:
            dbot_score = 3
            malicious = {
                'Vendor': 'SNDBOX',
                # 'Detections' : ['TODO'],
                'SHA1': analysis_info['SHA1'],
            }
        else:
            dbot_score = 1
            malicious = None

        dbot_scores.append({
            'Vendor': 'SNDBOX',
            'Indicator': analysis_info['SampleName'],
            'Type': 'file',
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
        'EntryContext': {'SNDBOX.Analysis(val.ID && val.ID == obj.ID)': createContext(context, removeNull=True),
                         'DBotScore':
                             createContext(dbot_scores, removeNull=True),
                         }
    }

    return entry


def poll_analysis_id(analysis_id):
    result = info_request(analysis_id)
    max_polls = MAX_POLLS / 10 if MAX_POLLS > 0 else MAX_POLLS  # type:ignore  # pylint: disable=E0602

    while (max_polls >= 0) and extract_status(result['status']) != 'finished':
        if extract_status(result['status']) != 'pending':
            LOG('error while polling: result is %s' % (result,))
        result = info_request(analysis_id)
        time.sleep(10)
        max_polls -= 1

    LOG('reached max_polls #%d' % (max_polls,))
    if max_polls < 0:
        return analysis_to_entry('Polling timeout on Analysis #' + analysis_id, result)
    else:
        return analysis_to_entry('Analysis #' + analysis_id, result)


''' FUNCTIONS '''


def is_online():
    cmd_url = ''
    res = http_cmd(cmd_url)
    return res['status'] == 'online'


def analysis_info():
    ids = demisto.args().get('analysis_id')
    if type(ids) in STRING_TYPES:
        ids = ids.split(',')
    LOG('info: analysis_id = %s' % (ids,))
    res = [info_request(analysis_id) for analysis_id in ids]
    return analysis_to_entry('Analyses:', res)


def info_request(analysis_id):
    cmd_url = '/developers/files/' + analysis_id
    return http_cmd(cmd_url)


def analyse_sample():
    args = demisto.args()
    file_entry = args.get('file_id', '')
    if type(file_entry) in STRING_TYPES:
        file_entry = [f for f in file_entry.split(',') if f != '']

    should_wait = bool(strtobool(demisto.get(args, 'should_wait')))

    if len(file_entry) == 0 or not file_entry:
        raise ValueError('You must specify: file_id.')

    LOG('analysing sample')
    return [analyse_sample_file_request(f, should_wait)
            for f in file_entry]


def analyse_sample_file_request(file_entry, should_wait):
    data = {}  # type:dict

    shutil.copy(demisto.getFilePath(file_entry)['path'],
                demisto.getFilePath(file_entry)['name'])

    with open(demisto.getFilePath(file_entry)['name'], 'rb') as f:
        res = http_cmd('/developers/files',
                       data=data,
                       files={'file': f})

        if 'errors' in res:
            LOG('Error! in command sample file: file_entry=%s' % (file_entry,))
            LOG('got the following errors:\n' + '\n'.join(e['msg'] for e in res['errors']))
            raise Exception('command failed to run.')

    shutil.rmtree(demisto.getFilePath(file_entry)['name'], ignore_errors=True)

    if should_wait:
        return poll_analysis_id(res['id'])

    analysis_id = res['id']
    result = info_request(analysis_id)
    return analysis_to_entry('Analysis #%s' % (analysis_id,), result)


def download_report():
    args = demisto.args()
    analysis_id = args.get('analysis_id')
    rsc_type = args.get('type')
    return download_request(analysis_id, rsc_type)


def download_sample():
    args = demisto.args()
    analysis_id = args.get('analysis_id')
    rsc_type = 'sample'
    return download_request(analysis_id, rsc_type)


def download_request(analysis_id, rsc_type):
    cmd_url = '/developers/files/' + analysis_id + '/' + rsc_type.lower()
    res = http_cmd(cmd_url, parse_json=False)

    info = info_request(analysis_id)
    if rsc_type == 'sample':
        return fileResult('%s.dontrun' % (info.get('filename', analysis_id),), res)
    else:
        rsc_type = rsc_type if rsc_type != 'json' else 'json.gz'
        return fileResult('%s_report.%s' % (info.get('filename', analysis_id), rsc_type,), res,
                          entryTypes['entryInfoFile'])


''' EXECUTION CODE '''
LOG('command is %s' % (demisto.command(),))
try:
    handle_proxy()
    if demisto.command() in ['test-module', 'sndbox-is-online']:
        # This is the call made when pressing the integration test button.
        if is_online():
            demisto.results('ok')
        else:
            demisto.results('not online')
    elif demisto.command() == 'sndbox-analysis-info':
        demisto.results(analysis_info())
    elif demisto.command() == 'sndbox-analysis-submit-sample':
        demisto.results(analyse_sample())
    elif demisto.command() == 'sndbox-download-report':
        demisto.results(download_report())
    elif demisto.command() == 'sndbox-download-sample':
        demisto.results(download_sample())

except Exception as e:
    if demisto.params().get('verbose'):
        LOG(str(e))
        if demisto.command() != 'test-module':
            LOG.print_log()
    return_error('An error has occurred in the SNDBOX integration: {err}'.format(err=str(e)))

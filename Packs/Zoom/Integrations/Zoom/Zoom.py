import shutil

import demistomock as demisto  # noqa: F401
import jwt
from CommonServerPython import *  # noqa: F401

if not demisto.getParam('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


def get_jwt(apiKey, apiSecret):
    """
    Encode the JWT token given the api ket and secret
    """
    tt = datetime.now()
    expire_time = int(tt.strftime('%s')) + 5000
    payload = {
        'iss': apiKey,
        'exp': expire_time
    }
    encoded = jwt.encode(payload, apiSecret, algorithm='HS256')
    return encoded


URL = 'https://api.zoom.us/v2/'
ACCESS_TOKEN = get_jwt(demisto.getParam('apiKey'), demisto.getParam('apiSecret'))
PARAMS = {'access_token': ACCESS_TOKEN}
HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}
USE_SSL = not demisto.params().get('insecure', False)


if demisto.command() == 'test-module':
    res = requests.get(URL + 'users', headers=HEADERS, params=PARAMS, verify=USE_SSL)
    if res.status_code == requests.codes.ok:
        demisto.results('ok')
    else:
        return_error('Error testing [%d] - %s' % (res.status_code, res.text))

elif demisto.command() == 'zoom-create-user':
    ut = demisto.getArg('user_type')
    user_type = 1  # Basic
    if ut == 'Pro':
        user_type = 2
    elif ut == 'Corporate':
        user_type = 3
    res = requests.post(URL + 'users', headers=HEADERS, params=PARAMS, verify=USE_SSL, json={
        'action': 'create',
        'user_info': {
            'email': demisto.getArg('email'),
            'type': user_type,
            'first_name': demisto.getArg('first_name'),
            'last_name': demisto.getArg('last_name')
        }
    })
    if res.status_code == 201:
        data = res.json()
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': data,
            'HumanReadable': 'User created successfully with ID %s' % data.get('id'),
            'EntryContext': {'Zoom.User': data}
        })
    else:
        return_error('User creation failed: [%d] - %s' % (res.status_code, res.text))

elif demisto.command() == 'zoom-list-users':
    params = {
        'access_token': ACCESS_TOKEN,
        'status': demisto.getArg('status'),
        'page_size': demisto.getArg('page-size'),
        'page_number': demisto.getArg('page-number')
    }
    res = requests.get(URL + 'users', headers=HEADERS, params=params, verify=USE_SSL)
    if res.status_code == requests.codes.ok:
        data = res.json()
        md = tableToMarkdown('Users', data.get('users'), ['id', 'first_name', 'last_name', 'email', 'type'])
        md += '\n' + tableToMarkdown('Metadata', [data], ['page_count', 'page_number', 'page_size', 'total_records'])
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': data,
            'HumanReadable': md,
            'EntryContext': {
                'Zoom.User': data.get('users'),
                'Zoom.Metadata': {
                    'Count': data.get('page_count'),
                    'Number': data.get('page_number'),
                    'Size': data.get('page_size'),
                    'Total': data.get('total_records')
                }
            }
        })
    else:
        return_error('User creation failed: [%d] - %s' % (res.status_code, res.text))

elif demisto.command() == 'zoom-delete-user':
    params = {
        'access_token': ACCESS_TOKEN,
        'action': demisto.getArg('action')
    }
    res = requests.delete(URL + 'users/' + demisto.getArg('user'), headers=HEADERS, params=params, verify=USE_SSL)
    if res.status_code == 204:
        demisto.results('User %s deleted successfully' % demisto.getArg('user'))
    else:
        return_error('User creation failed: [%d] - %s' % (res.status_code, res.text))

elif demisto.command() == 'zoom-create-meeting':
    auto_recording = "none"
    if (demisto.getArg('auto_record_meeting') == 'yes'):
        auto_recording = "cloud"
    params = {
        'type': 1,
        'topic': demisto.getArg('topic'),
        'settings': {
            'join_before_host': True,
            'auto_recording': auto_recording
        }
    }
    if (demisto.args()['type'] == 'Scheduled'):
        params.update({
            'type': 2,
            'start_time': demisto.getArg('start-time'),
            'timezone': demisto.getArg('timezone'),
        })
    res = requests.post(URL + "users/%s/meetings" % demisto.getArg('user'), headers=HEADERS, params=PARAMS, json=params,
                        verify=USE_SSL)
    if res.status_code == 201:
        data = res.json()
        md = 'Meeting created successfully.\nStart it [here](%s) and join [here](%s).' % (
            data.get('start_url'), data.get('join_url'))
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': data,
            'HumanReadable': md,
            'EntryContext': {'Zoom.Meeting': data}
        })
    else:
        return_error('Meeting creation failed: [%d] - %s' % (res.status_code, res.text))

elif demisto.command() == 'zoom-fetch-recording':
    meeting = demisto.getArg('meeting_id')
    res = requests.get(URL + 'meetings/%s/recordings' % meeting, headers=HEADERS, params=PARAMS, verify=USE_SSL)
    if res.status_code == requests.codes.ok:
        data = res.json()
        recording_files = data['recording_files']
        for file in recording_files:
            download_url = file['download_url']
            r = requests.get(download_url, stream=True)
            if r.status_code < 200 or r.status_code > 299:
                return_error('Unable to download recording for meeting %s: [%d] - %s' % (meeting, r.status_code, r.text))

            filename = 'recording_%s_%s.mp4' % (meeting, file['id'])
            with open(filename, 'wb') as f:
                r.raw.decode_content = True
                shutil.copyfileobj(r.raw, f)

            demisto.results(file_result_existing_file(filename))
            rf = requests.delete(URL + 'meetings/%s/recordings/%s' % (meeting, file['id']), headers=HEADERS,
                                 params=PARAMS, verify=USE_SSL)
            if rf.status_code == 204:
                demisto.results('File ' + filename + ' was moved to trash.')
            else:
                demisto.results('Failed to delete file ' + filename + '.')
    else:
        return_error('Download of recording failed: [%d] - %s' % (res.status_code, res.text))
else:
    return_error('Unrecognized command: ' + demisto.command())

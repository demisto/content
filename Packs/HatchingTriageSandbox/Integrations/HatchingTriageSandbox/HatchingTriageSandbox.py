################################################################################################

import json
import requests
import collections

requests.packages.urllib3.disable_warnings()

api_url = demisto.params().get('api_url')
api_key = demisto.params().get('api_key')
######################################File-Operation###############################################

def file_upload(entry_id):
    entry_id = demisto.getFilePath(entry_id)
    file_name = entry_id.get('name')
    file_path = entry_id.get('path')
    return file_path

################################################################################################

def hatching_triage_report(sample_id):

    URL = api_url + 'samples/' + sample_id + '/overview.json'

    AuthToken = 'Bearer ' + api_key
    headers = {
        'Authorization': AuthToken,

    }
    response = requests.get(URL, headers=headers)
    return response.json()



################################################################################################

def hatching_triage_submit(entry_id):

    file_path = file_upload(entry_id)

    URL = api_url + 'samples'
    AuthToken = 'Bearer ' + api_key
    headers = {
        'Authorization': AuthToken,

    }
    files = {
        'file': (file_path, open(file_path, 'rb')),
        '_json': (None, '{"kind":"file","interactive":false}'),

    }
    res = requests.post(URL, headers=headers, files=files)
    return res.json()


################################################################################################

LOG('command is %s' % (demisto.command(), ))
try:
    if demisto.command() == 'HatchingSubmitFile':
        entry_id = demisto.args().get('FileEntryID')
        response = hatching_triage_submit(entry_id)
        print(response)
    if demisto.command() == 'HatchingGetReport':
        sample_id = demisto.args().get('SampleID')
        response = hatching_triage_report(sample_id)
        print(response)
except Exception as e:
    demisto.debug('HaysFileUpload Debug')
    LOG.print_log()

################################################################################################

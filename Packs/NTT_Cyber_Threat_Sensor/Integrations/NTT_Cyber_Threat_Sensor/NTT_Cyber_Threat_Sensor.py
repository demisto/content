import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import base64
from datetime import datetime, timedelta, UTC
import requests
import dateutil.parser
import urllib3

# Local imports
from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

"""GLOBALS/PARAMS
"""

APIKEY = demisto.params().get('APIKEY')
SOARTOKEN = demisto.params().get('SOARTOKEN')
BASEURL = demisto.params().get('BASEURL', '').strip('/')
TENANT_ID = demisto.params().get('TENANT_ID')
DAYS_BACK = demisto.params().get('DAYS_BACK')
ITEMS_TO_FETCH = demisto.params().get('ITEMS_TO_FETCH')
USE_SSL = not demisto.params().get('insecure')

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'x-api-key': f'{APIKEY}',
    'x-soar-token': f'{SOARTOKEN}',
    'tenant-id': f'{TENANT_ID}'
}

"""HELPER FUNCTIONS
"""


@logger
def http_request(method, url_suffix, json_dict=None, params=None, headers=None, **kwargs):
    if not headers:
        headers = HEADERS

    # A wrapper for requests lib to send our requests and handle requests and responses better
    if json_dict:
        res = requests.request(
            method,
            BASEURL + url_suffix,
            verify=USE_SSL,
            params=params,
            headers=headers,
            json=json_dict,
            **kwargs
        )
    else:
        res = requests.request(
            method,
            BASEURL + url_suffix,
            verify=USE_SSL,
            params=params,
            headers=headers,
            **kwargs
        )

    # Handle error responses gracefully
    if res.status_code == 401:
        raise DemistoException('UnauthorizedError: please validate your credentials.')
    if res.status_code not in {200}:
        raise DemistoException(f'Error in API call [{res.status_code}] - {res.reason}')
    return res.json()


def download(url):
    """Send the request to API and return the JSON response
    """
    r = requests.request('GET', url)
    if r.status_code != requests.codes.ok:
        return_error(f'Error in API call to download {url} - {r.text}')
    return r


def item_to_incident(item):
    dt_string = item.get('last_updated', '')
    dz_string = dt_string.split('.')[0] + "Z"

    incident = {
        'Type': 'CTS Incident',
        'name': '{}'.format(item.get('name')),
        'occurred': dz_string,
        'shortdesc': item.get('shortdesc_md'),
        'shorttext': item.get('shortdesc'),
        'longdescmd': item.get('longdesc_md'),
        'eventid': item.get('sha'),
        'rawJSON': json.dumps(item),
        'CTS': {'DeviceName': item.get('devicephysical'),
                'Confidence': item.get('faereconfidence'),
                'Severity': item.get('faereseverity')}
    }
    return incident


def fetch_incidents():
    """Fetch incidents from the API
    """
    data = {}
    last_run = demisto.getLastRun()

    if last_run and 'timestamp' in last_run:
        data['after'] = last_run['timestamp']
        if 'offset' in last_run:
            data['offset'] = last_run['offset']
    else:
        last_run = {}
        last_run['timestamp'] = (datetime.now() - timedelta(days=int(DAYS_BACK))).isoformat()
        data['after'] = last_run['timestamp']

    data['limit'] = int(ITEMS_TO_FETCH)
    artifacts_meta = []
    results_meta = http_request('POST', '/artifacts/alerts', json_dict=data)
    if 'alerts' in results_meta:
        for result_meta in results_meta['alerts']:
            artifacts_meta.append(result_meta)
        if 'offset' in results_meta:
            last_run['offset'] = results_meta['offset']
        else:
            last_run.pop('offset', None)
            last_run['timestamp'] = datetime.now().isoformat()

    incidents = []
    for artifact_meta in artifacts_meta:
        demisto.debug('\nRequesting data for event: {}\n\n'.format(artifact_meta['event_id']))
        result_artifact = http_request('GET', '/artifacts/alerts/%s' % artifact_meta['event_id'])
        incidents.append(item_to_incident(result_artifact['alert']))

    demisto.incidents(incidents)
    demisto.setLastRun(last_run)


def poll_blobs():
    """Check if one or more blobs from provided event_id is ready for download
    """
    event_id = demisto.args().get('event_id')
    cntext = {}
    cntext['ID'] = event_id
    if demisto.args().get('timestamp'):
        timestamp = dateutil.parser.parse(demisto.args().get('timestamp'))
        now = dateutil.parser.parse(datetime.utcnow().isoformat())
        diff = now.replace(tzinfo=UTC) - timestamp.replace(tzinfo=UTC)

        # We need to wait three minutes from the time of the event since pcap
        #  are sent little later to make sure we record most of the triggered traffic
        # We used to wait here but are now using Generic Polling playbook
        #  https://xsoar.pan.dev/docs/playbooks/generic-polling
        wait_delta = timedelta(minutes=3)
        if diff < wait_delta:
            cntext['Status'] = "hold"
            return_results([
                {
                    'Type': entryTypes['note'],
                    'EntryContext': {'CTS.Blobs(val.ID && val.ID == obj.ID)': cntext},
                    'HumanReadable': 'CTS blob delayed\n'
                                     + 'The download has been delayed for '
                                     + str(wait_delta.seconds - diff.seconds)
                                     + ' seconds',
                    'Contents': cntext,
                    'ContentsFormat': formats['json']
                }])
        else:
            cntext['Status'] = "release"
            result_blobs = http_request('GET', '/artifacts/blobs/%s' % event_id)
            if 'blobs' in result_blobs and len(result_blobs['blobs']) > 0:
                return_results([
                    {
                        'Type': entryTypes['note'],
                        'EntryContext': {'CTS.Blobs(val.ID && val.ID == obj.ID)': cntext},
                        'HumanReadable': 'CTS blob(s) was found and has been sceduled for download',
                        'Contents': cntext,
                        'ContentsFormat': formats['json']
                    }])
            else:
                return_results([
                    {
                        'Type': entryTypes['note'],
                        'EntryContext': {'CTS.Blobs(val.ID && val.ID == obj.ID)': cntext},
                        'HumanReadable': 'CTS blob(s) was not found',
                        'Contents': cntext,
                        'ContentsFormat': formats['json']
                    }])


def fetch_blobs():
    """Download one or more blobs from provided event_id
    """
    event_id = demisto.args().get('event_id')
    blob_list = []
    result_blobs = http_request('GET', '/artifacts/blobs/%s' % event_id)
    if 'blobs' in result_blobs and len(result_blobs['blobs']) > 0:
        for blob in result_blobs['blobs']:
            blob_id = blob['blob_id']
            d = download(blob['url'])
            blob_list.append(blob_id + '.pcap')
            return_results(fileResult(blob_id + '.pcap', base64.decodebytes(d.content)))
        ec = {'CTS.HasBlob': True}
        return_results([
            {
                'Type': entryTypes['note'],
                'EntryContext': ec,
                'HumanReadable': 'CTS blob(s) downloaded:\n' + str(blob_list),
                'Contents': ec,
                'ContentsFormat': formats['json']
            }])
    else:
        ec = {'CTS.HasBlob': False}
        return_results([
            {
                'Type': entryTypes['note'],
                'EntryContext': ec,
                'HumanReadable': 'CTS blob(s) was not found',
                'Contents': ec,
                'ContentsFormat': formats['json']
            }])


def test_module():
    """Test module to verify settings
    """
    errors = []
    data = {}

    if TENANT_ID == '0000000-0000-0000-000000000' or TENANT_ID == '':
        errors.append('Incorrect tenant id')
    if str(DAYS_BACK).isdigit():
        if int(DAYS_BACK) <= 0 or int(DAYS_BACK) > 100:
            errors.append('DAYS_BACK must be in range > 0 and <= 100')
    else:
        errors.append('DAYS_BACK has to be an integer')
    if str(ITEMS_TO_FETCH).isdigit():
        if int(ITEMS_TO_FETCH) <= 0 or int(ITEMS_TO_FETCH) > 100:
            errors.append('ITEMS_TO_FETCH must be in range > 0 and <= 100')
    else:
        errors.append('ITEMS_TO_FETCH has to be an integer')
    if len(errors) > 0:
        return_results(
            {"Type": entryTypes["error"],
             "ContentsFormat": formats["text"],
             "Contents": "Errors:\n{}".format("\n".join(errors))})

    # So far so good, now test the API call
    data['test'] = True
    result = http_request('POST', '/artifacts/alerts', json_dict=data)
    if 'msg' in result and result['msg'] == "Test OK":
        return_results('ok')
    else:
        return_results(
            {"Type": entryTypes["error"],
             "ContentsFormat": formats["text"],
             "Contents": "Errors:\n%s" % repr(result)})


"""COMMANDS MANAGER / SWITCH PANEL
"""
COMMANDS = {
    'test-module': test_module,
    'fetch-incidents': fetch_incidents,
    'ntt-cyber-threat-sensor-fetch-blobs': fetch_blobs,
    'ntt-cyber-threat-sensor-poll-blobs': poll_blobs
}


def main():
    """Main function
    """
    cmd = demisto.command()
    demisto.debug(f'Command being called is {cmd}')

    try:
        if cmd in COMMANDS:
            COMMANDS[cmd]()
        else:
            demisto.debug(f'Command {cmd} not implemented')

    # Log exceptions
    except Exception as e:
        import traceback
        demisto.debug(traceback.format_exc())

        if demisto.command() == 'fetch-incidents':
            demisto.debug(str(e))
            raise
        else:
            return_error(f'An error occurred: {str(e)}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

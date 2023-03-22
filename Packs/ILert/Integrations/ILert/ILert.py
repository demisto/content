import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
import urllib3
urllib3.disable_warnings()

''' GLOBAL VARS '''
# iLert API works only with secured communication.
USE_SSL = not demisto.params().get('insecure', False)

USE_PROXY = demisto.params().get('proxy', True)
INTEGRATION_KEY = demisto.params().get('integrationKey', '')

BASE_URL = demisto.params().get('url', '').strip('/')

DEFAULT_HEADERS = {
    'accept': 'application/json',
    'content-type': 'application/json'
}

'''HANDLE PROXY'''
if not USE_PROXY:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' HELPER FUNCTIONS '''


def test_module():
    create_new_incident_event(summary="Test incident")
    demisto.results('ok')


def http_request(method, url_suffix, params_dict=None, data=None):
    url = urljoin(BASE_URL, url_suffix)
    try:
        res = requests.request(method,
                               url,
                               verify=USE_SSL,
                               params=params_dict,
                               headers=DEFAULT_HEADERS,
                               data=data
                               )
        res.raise_for_status()

        return res.json()

    except Exception as e:
        LOG(e)
        raise


def create_new_incident_event(event_type="ALERT", summary='', details='No description',
                              incident_key=None, priority=None, integrationKey=INTEGRATION_KEY):
    """Send incident related event to iLert."""

    if integrationKey is None:
        raise Exception('You must enter an integrationKey as integration '
                        'parameters or in the command to process this action.')

    if event_type == 'ALERT' and not summary:
        raise Exception('You must enter a summary in the command to process this action.')

    if event_type != 'ALERT' and incident_key is None:
        raise Exception('You must enter an incident_key in the command to process this action.')

    payload = {
        'apiKey': integrationKey,
        'eventType': event_type,
        'summary': summary,
        'details': details,
        'incidentKey': incident_key,
        'priority': priority
    }

    return http_request('POST', '/events', data=json.dumps(payload))


def submit_new_event_command(event_type='ALERT', summary='', details='No description',
                             incident_key=None, priority=None, integrationKey=INTEGRATION_KEY):
    """Create new incident."""

    create_new_incident_event(event_type, summary, details, incident_key,
                              priority, integrationKey)

    return "Incident has been created"


def submit_acknowledge_event_command(summary, incident_key=None, integrationKey=INTEGRATION_KEY):
    """Acknowledge existing incident."""

    create_new_incident_event(event_type='ACCEPT', summary=summary, incident_key=incident_key,
                              integrationKey=integrationKey)

    return "Incident has been acknowledged"


def submit_resolve_event_command(summary, incident_key=None, integrationKey=INTEGRATION_KEY):
    """Resolve existing incident."""

    create_new_incident_event(event_type='RESOLVE', summary=summary, incident_key=incident_key,
                              integrationKey=integrationKey)

    return "Incident has been resolved"


''' EXECUTION CODE '''


def main():
    LOG('command is %s' % (demisto.command(),))
    try:
        if demisto.command() == 'test-module':
            test_module()
        elif demisto.command() == 'ilert-submit-event':
            demisto.results(submit_new_event_command(**demisto.args()))
        elif demisto.command() == 'ilert-acknowledge-event':
            demisto.results(submit_acknowledge_event_command(**demisto.args()))
        elif demisto.command() == 'ilert-resolve-event':
            demisto.results(submit_resolve_event_command(**demisto.args()))
    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from distutils.util import strtobool
from sixgill.sixgill_alert_client import SixgillAlertClient
from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

CHANNEL_CODE = '31335bc6357f0eb6e3370803b9a6a318'
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'
DEMISTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
FETCH_TIME = demisto.params().get('fetch_time', '30 days')
THREAT_LEVEL_TO_SEVERITY = {
    'imminent': 3,
    'emerging': 2
}
''' HELPER FUNCTIONS '''


def item_to_incident(item):
    incident = dict()
    incident['name'] = item.get('title', 'Sixgill Alert')
    incident_date = datetime.strptime(item.get('date'), DATETIME_FORMAT)
    incident['occurred'] = incident_date.strftime(DEMISTO_DATETIME_FORMAT)
    incident['details'] = item.get('content', 'No details')
    incident['severity'] = THREAT_LEVEL_TO_SEVERITY[item.get('threat_level', 0)]
    incident['type'] = 'SixgillAlert'
    item.pop('user_id', None)
    item.pop('id', None)
    item.pop('severity', None)
    incident['rawJSON'] = json.dumps(item)
    return incident


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic Auth request
    """
    response = SixgillAuthRequest(CHANNEL_CODE, demisto.params()['client_id'], demisto.params()['client_secret']).send()
    if not response.ok:
        raise Exception("Auth request failed - please verify client_id, and client_secret.")


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)

    sixgill_alert_client = SixgillAlertClient(demisto.params()['client_id'], demisto.params()['client_secret'],
                                              CHANNEL_CODE)

    incidents = []
    for alert in sixgill_alert_client.get_alerts():
        sixgill_alert_client.mark_digested_item(alert)
        incident = item_to_incident(alert)
        incidents.append(incident)

    demisto.setLastRun({'time': last_fetch})
    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        test_module()
        demisto.results('ok')

    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()

# Log exceptions
except Exception as e:
    LOG(e.message)
    LOG.print_log()
    raise


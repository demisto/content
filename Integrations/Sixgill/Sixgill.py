import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import copy
import requests

from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
from sixgill.sixgill_alert_client import SixgillAlertClient
from sixgill.sixgill_darkfeed_client import SixgillDarkFeedClient
from typing import Dict, List, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

CHANNEL_CODE = '7698e8287dfde53dcd13082be750a85a'
FETCH_INCIDENTS_LIMIT = 20
FETCH_INDICATORS_LIMIT = 100
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'
DEMISTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
FETCH_TIME = demisto.params().get('fetch_time', '30 days')
THREAT_LEVEL_TO_SEVERITY = {
    'imminent': 3,
    'emerging': 2
}


''' HELPER FUNCTIONS '''


def get_limit(str_limit, default_limit):
    try:
        return int(str_limit, default_limit)
    except Exception:
        return default_limit


def get_incident_init_params():
    return {
        'sort_by': demisto.params().get('sort_by', None),
        'sort_order': demisto.params().get('sort_order', None),
        'is_read': demisto.params().get('is_read', None),
        'severity': demisto.params().get('severity', None),
        'threat_level': demisto.params().get('threat_level', None),
        'threat_type': demisto.params().get('threat_type', None)
    }


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
    response = SixgillAuthRequest(demisto.params()['client_id'], demisto.params()['client_secret']).send()
    if not response.ok:
        raise Exception("Auth request failed - please verify client_id, and client_secret.")


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')
    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)

    fetch_incidents_limit = get_limit(demisto.params().get('fetch_incidents_limit', FETCH_INCIDENTS_LIMIT),
                                      FETCH_INCIDENTS_LIMIT)

    sixgill_alerts_client = SixgillAlertClient(demisto.params()['client_id'], demisto.params()['client_secret'],
                                               CHANNEL_CODE, bulk_size=fetch_incidents_limit)

    filter_alerts_kwargs = get_incident_init_params()

    incidents: List[Dict[str, Any]] = []

    for raw_incident in sixgill_alerts_client.get_alert(**filter_alerts_kwargs):

        incident = item_to_incident(copy.deepcopy(raw_incident))
        sixgill_alerts_client.mark_digested_item(raw_incident)
        incidents.append(incident)

        if len(incidents) >= fetch_incidents_limit:
            sixgill_alerts_client.commit_digested_items(force=True)
            break

    demisto.setLastRun({'time': last_fetch})
    demisto.incidents(incidents)


def get_indicators():
    fetch_indicators_limit = get_limit(demisto.args().get('fetch_indicators_limit', FETCH_INDICATORS_LIMIT),
                                       FETCH_INDICATORS_LIMIT)

    sixgill_darkfeed_client = SixgillDarkFeedClient(demisto.params()['client_id'], demisto.params()['client_secret'],
                                                    CHANNEL_CODE, bulk_size=fetch_indicators_limit)

    bundle = sixgill_darkfeed_client.get_bundle()
    sixgill_darkfeed_client.commit_indicators()

    demisto.results(fileResult(f'{bundle.get("id", "bundle")}.json', json.dumps(bundle)))


''' COMMANDS MANAGER / SWITCH PANEL '''

try:
    if demisto.command() == 'test-module':
        test_module()
        demisto.results('ok')

    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()

    elif demisto.command() == 'sixgill-get-indicators':
        get_indicators()

except Exception as e:
    return_error("Failed to execute {} command. Error: {}".format(demisto.command(), str(e)))

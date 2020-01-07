import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from distutils.util import strtobool

from sixgill.sixgill_darkfeed_client import SixgillDarkFeedClient
from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
from typing import Dict, List

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

CHANNEL_CODE = '7698e8287dfde53dcd13082be750a85a'
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'
DEMISTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
FETCH_TIME = demisto.params().get('fetch_time', '30 days')
THREAT_LEVEL_TO_SEVERITY = {
    'imminent': 3,
    'emerging': 2
}
''' HELPER FUNCTIONS '''


def is_ioc(item):
    return True if "feed" in item.get("alert_name", "").lower() else False


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

    include_delivered_items = bool(strtobool(demisto.args().get('include_delivered_items', 'false')))

    sixgill_darkfeed_client = SixgillDarkFeedClient(demisto.params()['client_id'], demisto.params()['client_secret'],
                                                    CHANNEL_CODE)

    incidents = []
    iocs: Dict[str, List] = {}
    extracted_iocs = 0

    for raw_incident in sixgill_darkfeed_client.get_incidents(include_delivered_items):
        sixgill_darkfeed_client.mark_digested_item(raw_incident)

        if is_ioc(raw_incident):
            indicator = raw_incident.get("consumer_specific_info", {})
            indicator_type = indicator.get('fields', {}).get("itype", None)
            if indicator_type:
                iocs.update({indicator_type: iocs.get(indicator_type, []) + [indicator]})
                extracted_iocs += 1

        else:
            incident = item_to_incident(raw_incident)
            incidents.append(incident)

    demisto.setLastRun({'time': last_fetch})
    demisto.incidents(incidents)

    return f"Successfully extracted {extracted_iocs} IOCs of the following types: {iocs.keys()} ", iocs


''' COMMANDS MANAGER / SWITCH PANEL '''

try:
    if demisto.command() == 'test-module':
        test_module()
        demisto.results('ok')

    elif demisto.command() == 'fetch-incidents':
        return_outputs(*fetch_incidents())

except Exception as e:
    return_error("Failed to execute {} command. Error: {}".format(demisto.command(), str(e)))

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests

from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
from sixgill.sixgill_alert_client import SixgillAlertClient
from sixgill.sixgill_darkfeed_client import SixgillDarkFeedClient
from sixgill.sixgill_utils import is_indicator
from typing import Dict, List, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

CHANNEL_CODE = '7698e8287dfde53dcd13082be750a85a'
MAX_INCIDENTS = 20
MAX_INDICATORS = 100
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'
DEMISTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
FETCH_TIME = demisto.params().get('fetch_time', '30 days')
THREAT_LEVEL_TO_SEVERITY = {
    'imminent': 3,
    'emerging': 2
}
SCORE_LIST = ["Low", "Medium", "High"]
MAX_SIXGILL_SEVERITY = 100
SEVERITY_RATIO = (MAX_SIXGILL_SEVERITY + 1) // len(SCORE_LIST)

''' HELPER FUNCTIONS '''


def to_demisto_score(score):
    return SCORE_LIST[score // SEVERITY_RATIO]


def get_limit(str_limit, default_limit):
    try:
        return int(str_limit)
    except Exception:
        return default_limit


def get_incident_init_params():
    params = {}

    if demisto.params().get('severity'):
        params['threat_level'] = demisto.params().get('severity')

    if demisto.params().get('threat_level'):
        params['threat_level'] = demisto.params().get('threat_level')

    if demisto.params().get('threat_type'):
        params['threat_type'] = demisto.params().get('threat_type')

    return params


def item_to_incident(item):
    incident = dict()
    incident['name'] = item.get('title', 'Sixgill Alert')
    incident_date = datetime.strptime(item.get('date'), DATETIME_FORMAT)
    incident['occurred'] = incident_date.strftime(DEMISTO_DATETIME_FORMAT)
    incident['details'] = item.get('content', 'No details')
    incident['severity'] = THREAT_LEVEL_TO_SEVERITY[item.get('threat_level', 0)]
    item['sixgill_severity'] = item.pop('severity', None)
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
    # API is handling last run by marking items that was read and not receiving the same items.

    max_incidents = get_limit(demisto.params().get('maxIncidents', MAX_INCIDENTS), MAX_INCIDENTS)

    sixgill_alerts_client = SixgillAlertClient(demisto.params()['client_id'], demisto.params()['client_secret'],
                                               CHANNEL_CODE, bulk_size=max_incidents, logger=demisto)

    filter_alerts_kwargs = get_incident_init_params()

    incidents: List[Dict[str, Any]] = []

    for raw_incident in sixgill_alerts_client.get_alert(**filter_alerts_kwargs):

        incident = item_to_incident(raw_incident)
        sixgill_alerts_client.mark_digested_item(raw_incident)
        incidents.append(incident)

        if len(incidents) >= max_incidents:
            sixgill_alerts_client.commit_digested_items(force=True)
            break

    demisto.incidents(incidents)


def sixgill_get_indicators_command():
    max_indicators = get_limit(demisto.args().get('maxIndicators', MAX_INDICATORS), MAX_INDICATORS)

    sixgill_darkfeed_client = SixgillDarkFeedClient(demisto.params()['client_id'], demisto.params()['client_secret'],
                                                    CHANNEL_CODE, bulk_size=max_indicators, logger=demisto)

    bundle = sixgill_darkfeed_client.get_bundle()
    sixgill_darkfeed_client.commit_indicators()
    num_of_indicators = 0

    for stix_item in bundle.get("objects"):
        if is_indicator(stix_item):
            num_of_indicators += 1

            if stix_item.get("sixgill_severity"):
                stix_item['score'] = to_demisto_score(stix_item.get("sixgill_severity", 0))

    human_readable = f"# Fetched {num_of_indicators} DarkFeed indicators"
    bundle_id = bundle.get("id", "bundle")
    entry = fileResult(f'{bundle_id}.json', json.dumps(bundle), entryTypes['entryInfoFile'])

    entry["HumanReadable"] = human_readable
    entry["ContentsFormat"] = formats["markdown"]

    demisto.results(entry)


''' COMMANDS MANAGER / SWITCH PANEL '''


try:
    if demisto.command() == 'test-module':
        test_module()
        demisto.results('ok')

    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()

    elif demisto.command() == 'sixgill-get-indicators':
        sixgill_get_indicators_command()

except Exception as e:
    return_error("Failed to execute {} command. Error: {}".format(demisto.command(), str(e)))

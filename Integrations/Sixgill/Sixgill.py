import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import copy
import requests
from distutils.util import strtobool

from sixgill.sixgill_darkfeed_client import SixgillDarkFeedClient
from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
from typing import Dict, List, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

CHANNEL_CODE = '7698e8287dfde53dcd13082be750a85a'
FETCH_INCIDENTS_LIMIT = 20
FETCH_INDICATORS_LIMIT = 1000
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'
DEMISTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
FETCH_TIME = demisto.params().get('fetch_time', '30 days')
THREAT_LEVEL_TO_SEVERITY = {
    'imminent': 3,
    'emerging': 2
}


indicator_mapping = {
    "suspicious_ip": ("IP(val.Address == obj.Address)", '{{"Address": "{}"}}'),
    "proxy_ip": ("IP(val.Address == obj.Address)", '{{"Address": "{}"}}'),
    "mal_domain": ("Domain(val.Name == obj.Name)", '{{"Name": "{}"}}'),
    "mal_md5": ("File(val.MD5 == obj.MD5)", '{{"MD5": "{}", "Tags": "{}"}}'),
    "crypto_wallet": ("Sixgill.Indicator.Cryptocurrency(val.Address == obj.Address)",
                      '{{"Address": "{}", "Tags": "{}"}}')
}

HEADER_ID = 'ID'
HEADER_TYPE = 'Type'
HEADER_INDICATOR_VALUE = 'Indicator Value'
HEADER_TAGS = 'Tags'

headers = [HEADER_ID, HEADER_TYPE, HEADER_INDICATOR_VALUE, HEADER_TAGS]

''' HELPER FUNCTIONS '''


def is_ioc(item):
    return True if "feed" in item.get("alert_name", "").lower() else False


def get_limit(str_limit, default_limit):
    try:
        return int(str_limit, default_limit)
    except:
        return default_limit


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


def indicator_to_demisto_format(raw_incident):
    try:
        indicator = raw_incident.get("consumer_specific_info", {})
        indicator_type = indicator.get('fields', {}).get("itype", None)
        if indicator_type:
            indicator_name, formatted_indicator_str = indicator_mapping.get(indicator_type, (None, None))

            if indicator_name and formatted_indicator_str:
                if indicator_type == 'mal_md5' or indicator_type == 'crypto_wallet':
                    formatted_indicator = formatted_indicator_str.format(indicator.get('fields', {}).get('value'),
                                                                         ", ".join(indicator.get('fields',
                                                                                                 {}).get('tags', [])))
                else:
                    formatted_indicator = formatted_indicator_str.format(indicator.get('fields', {}).get('value'))

                indicator_dict = json.loads(formatted_indicator)

                return indicator_name, indicator_dict

        return None, None

    except Exception:
        return None, None


def to_readable(indicator_name, raw_incident):
    indicator = raw_incident.get("consumer_specific_info", {})
    indicator_value = indicator.get('fields', {}).get("value", None)
    indicator_tags = ", ".join(indicator.get('fields', {}).get('tags', []))

    return {HEADER_ID: raw_incident.get("id", None),
            HEADER_TYPE: indicator_name[:indicator_name.find("(")],
            HEADER_INDICATOR_VALUE: indicator_value,
            HEADER_TAGS: indicator_tags}


def handle_indicator(iocs: Dict[str, List[Dict[str, Any]]], readable_iocs: List[Dict[str, Any]], raw_incident):

    if is_ioc(raw_incident):
        indicator_name, indicator_dict = indicator_to_demisto_format(raw_incident)
        raw_incident["id"] = raw_incident.get("doc_id")
        readable_iocs.append(to_readable(indicator_name, raw_incident))
        if indicator_name:
            iocs.update({indicator_name: iocs.get(indicator_name, []) + [indicator_dict]})
            return True
    return False


def handle_alerts(incidents: List[Dict[str, Any]], raw_incident):
    if not is_ioc(raw_incident):
        incident = item_to_incident(raw_incident)
        incidents.append(incident)
        return True
    return False


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

    sixgill_darkfeed_client = SixgillDarkFeedClient(demisto.params()['client_id'], demisto.params()['client_secret'],
                                                    CHANNEL_CODE)

    fetch_incidents_limit = get_limit(demisto.params().get('fetch_incidents_limit', FETCH_INCIDENTS_LIMIT),
                                      FETCH_INCIDENTS_LIMIT)

    incidents: List[Dict[str, Any]] = []

    for raw_incident in sixgill_darkfeed_client.get_incidents():

        if handle_alerts(incidents, copy.deepcopy(raw_incident)):
            sixgill_darkfeed_client.mark_digested_item(raw_incident)

        if len(incidents) >= fetch_incidents_limit:
            sixgill_darkfeed_client.submit_digested_items(force=True)
            break

    demisto.setLastRun({'time': last_fetch})
    demisto.incidents(incidents)


def get_indicators():

    include_delivered_items = bool(strtobool(demisto.args().get('include_delivered_items', 'false')))

    sixgill_darkfeed_client = SixgillDarkFeedClient(demisto.params()['client_id'], demisto.params()['client_secret'],
                                                    CHANNEL_CODE)

    readable_iocs: List[Dict[str, Any]] = []
    raw_iocs: List[Dict[str, Any]] = []
    iocs: Dict[str, List[Dict[str, Any]]] = {}
    extracted_iocs = 0

    fetch_indicators_limit = get_limit(demisto.args().get('fetch_indicators_limit', FETCH_INDICATORS_LIMIT),
                                       FETCH_INDICATORS_LIMIT)

    for raw_incident in sixgill_darkfeed_client.get_incidents(include_delivered_items):
        raw_iocs.append(raw_incident)

        if handle_indicator(iocs, readable_iocs, raw_incident):
            sixgill_darkfeed_client.mark_digested_item(raw_incident)
            extracted_iocs += 1

        if extracted_iocs >= fetch_indicators_limit:
            sixgill_darkfeed_client.submit_digested_items(force=True)
            break

    return tableToMarkdown("Sixgill's DarkFeed indicators:", readable_iocs, headers=headers), iocs, raw_iocs


''' COMMANDS MANAGER / SWITCH PANEL '''

try:
    if demisto.command() == 'test-module':
        test_module()
        demisto.results('ok')

    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()

    elif demisto.command() == 'sixgill-get-indicators':
        return_outputs(*get_indicators())

except Exception as e:
    return_error("Failed to execute {} command. Error: {}".format(demisto.command(), str(e)))

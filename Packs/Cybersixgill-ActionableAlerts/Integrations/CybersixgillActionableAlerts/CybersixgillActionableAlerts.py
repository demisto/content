import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import copy
import requests
import urllib3

from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
from sixgill.sixgill_actionable_alert_client import SixgillActionableAlertClient

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

CHANNEL_CODE = '7698e8287dfde53dcd13082be750a85a'
MAX_INCIDENTS = 25
DEFAULT_INCIDENTS = '25'
MAX_DAYS_BACK = 30
DEFAULT_DAYS_BACK = '1'
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'
DEMISTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
THREAT_LEVEL_TO_SEVERITY = {
    'imminent': 3,
    'emerging': 2,
    'unknown': 0
}
TO_DEMISTO_STATUS = {
    'in_treatment': 1,
    'resolved': 2,
    'treatment_required': 0
}
VERIFY = not demisto.params().get("insecure", True)
SESSION = requests.Session()

''' HELPER FUNCTIONS '''


def get_incident_init_params():
    params_dict = {
        'threat_level': demisto.params().get('threat_level', None),
        'threat_type': demisto.params().get('threat_type', None)
    }
    return {param_k: param_v for param_k, param_v in params_dict.items() if param_v}


def item_to_incidents(item_info, sixgill_alerts_client):
    incident: Dict[str, Any] = {}
    incidents = []
    items = []
    # get fields that are shared in case of sub alerts
    add_sub_alerts_shared_fields(incident, item_info)
    sub_alerts = item_info.pop('sub_alerts', None)
    if sub_alerts:
        # add any sub alert as incident
        for sub_alert in sub_alerts:
            sub_item = copy.deepcopy(item_info)
            sub_item.update(sub_alert)
            items.append(sub_item)
    else:
        items.append(item_info)
    for item in items:
        sub_incident = copy.deepcopy(incident)
        # add all other fields
        add_sub_alerts_fields(sub_incident, item, sixgill_alerts_client)
        sub_incident['rawJSON'] = json.dumps(item)
        incidents.append(sub_incident)
    return incidents


def add_sub_alerts_shared_fields(incident, item_info):
    incident['name'] = item_info.get('title', 'Cybersixgill Alert')
    incident_date = datetime.strptime(item_info.get('date'), DATETIME_FORMAT)
    incident['occurred'] = incident_date.strftime(DEMISTO_DATETIME_FORMAT)
    incident['severity'] = THREAT_LEVEL_TO_SEVERITY[item_info.get('threat_level', 'unknown')]
    incident['CustomFields'] = {
        'cybersixgillthreatlevel': item_info.get('threat_level', 'unknown'),
        'cybersixgillthreattype': item_info.get('threats', []),
        'cybersixgillassessment': item_info.get('assessment', None),
        'cybersixgillrecommendations': '\n\n-----------\n\n'.join(item_info.get('recommendations', [])),
        'incidentlink': f"https://portal.cybersixgill.com/#/?actionable_alert={item_info.get('id', '')}",
        'cve': None,
        'cybersixgillattributes': None
    }


def add_sub_alerts_fields(incident, item_info, sixgill_alerts_client):
    status = item_info.get('status', {}).get('name', 'treatment_required')
    incident['status'] = TO_DEMISTO_STATUS[status]

    content_item = {'creator': None, 'title': '', 'content': '', 'description': item_info.get('description', '')}
    try:
        get_alert_content(content_item, item_info, incident, sixgill_alerts_client)
    except Exception as e:
        demisto.error(f"Could not get alert content: {e}")
    incident['details'] = f"{content_item.get('description', '')}\n\n{content_item.get('title', '')}\n" \
                          f"\n{content_item.get('content', '')}\n{content_item.get('Repository Name', '')}" \
                          f"\n{content_item.get('Customer Keywords', '')}\n{content_item.get('GitURL', '')}" \
                          f"\n{content_item.get('Actor', '')}\n{content_item.get('BIN', '')}" \
                          f"\n{content_item.get('Site', '')}\n{content_item.get('Text', '')}" \
                          f"\n{content_item.get('Detection time', '')}\n{content_item.get('IP addresses', '')}" \
                          f"\n{content_item.get('Suspicious domain', '')}\n{content_item.get('Triggered domain', '')}" \
                          f"\n{content_item.get('Already Seen', '')}\n{content_item.get('Breach Date', '')}" \
                          f"\n{content_item.get('Description', '')}\n{content_item.get('Email', '')}" \
                          f"\n{content_item.get('Created Time', '')}"
    triggered_assets = []
    for key, value in item_info.get('additional_info', {}).items():
        if 'matched_' in key:
            triggered_assets.extend(value)
    incident['CustomFields'].update({
        'cybersixgillstatus': status.replace('_', ' ').title(),
        'cybersixgillsite': item_info.get('site', None),
        'cybersixgillactor': content_item.get('creator', None),
        'cybersixgilltriggeredassets': triggered_assets
    })


def get_alert_content(content_item, item_info, incident, sixgill_alerts_client):
    # cve alert
    cve_id = item_info.get('additional_info').get('cve_id')
    es_id = item_info.get('es_id')
    if cve_id:
        content_item['content'] = f'https://portal.cybersixgill.com/#/cve/{cve_id}'
        additional_info = item_info.get("additional_info", {})
        incident['CustomFields']['cve'] = cve_id
        attributes = []
        for attribute in additional_info.get("attributes", []):
            if attribute.get("value", False):
                attributes.append(additional_info.get("description"))
        attributes = '\n\n-----------\n\n'.join(attributes)
        incident['CustomFields']['cybersixgillattributes'] = attributes
    elif es_id == "Not Applicable":
        content = sixgill_alerts_client.get_actionable_alert_content(actionable_alert_id=item_info.get('id'),
                                                                     fetch_only_current_item=True,
                                                                     organization_id=demisto.params().get('org_id', None))
        content_items = content.get('items')
        if content_items:
            for item in content_items:
                additional_keywords = item.get('Additional Keywords')  # for Github Alert
                alert_actor = item.get('Actor')  # For Compromised Alerts
                alert_detection = item.get('Detection time')  # For Phishing Alerts
                breach_date = item.get('breach_date')
                if additional_keywords is not None:
                    content_item['Repository name'] = "Repository name: " + item.get("Repository name", "")
                    content_item['Customer Keywords'] = "Customer Keywords: " + item.get("Customer Keywords", "")
                    content_item['GitURL'] = "GitURL: " + item.get("URL", "")
                elif alert_actor is not None:
                    content_item['Actor'] = "Actor: " + alert_actor
                    content['BIN'] = "BIN: " + item.get("BIN", "")
                    content_item['Site'] = "Site: " + item.get("Site", "")
                    content_item['Text'] = "Text: " + item.get("Text", "")
                elif alert_detection is not None:
                    content_item['Detection time'] = "Detection time: " + alert_detection
                    content_item['IP addresses'] = "IP addresses: " + item.get("IP addresses", "")
                    content_item['Suspicious domain'] = "Suspicious domain: " + item.get("Suspicious domain", "")
                    content_item['Triggered domain'] = "Triggered domain: " + item.get("Triggered domain", "")
                elif breach_date is not None:
                    content_item['Already Seen'] = "Already Seen: " + item.get("already_seen", "")
                    content_item['Breach Date'] = "Breach Date: " + breach_date
                    content_item['Description'] = "Description: " + item.get("description", "")
                    content_item['Email'] = "Email: " + item.get("email", "")
                    content_item['Created Time'] = "Created Time: " + item.get("create_time", "")
    else:
        aggregate_alert_id = item_info.get('aggregate_alert_id', None)
        if not isinstance(aggregate_alert_id, int):
            aggregate_alert_id = None
        content = sixgill_alerts_client.get_actionable_alert_content(actionable_alert_id=item_info.get('id'),
                                                                     aggregate_alert_id=aggregate_alert_id,
                                                                     fetch_only_current_item=True,
                                                                     organization_id=demisto.params().get('org_id', None))
        # get item full content
        content = content.get('items', None)
        if content and content[0].get('_id'):
            es_items = content[0].get('_source')
            if es_items:
                content_item['title'] = es_items.get('title')
                content_item['content'] = es_items.get('content')
                content_item['creator'] = es_items.get('creator')


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic Auth request
    """
    response = SESSION.send(request=SixgillAuthRequest(demisto.params()['client_id'],
                                                       demisto.params()['client_secret'],
                                                       CHANNEL_CODE).prepare(), verify=VERIFY)
    if not response.ok:
        raise Exception("Auth request failed - please verify client_id, and client_secret.")


def fetch_incidents():
    last_run = demisto.getLastRun()

    if 'last_fetch_time' in last_run:
        last_fetch_time = last_run['last_fetch_time']
        demisto.info(f'Found last run, fetching new alerts from {last_fetch_time}')
    else:
        days_back = int(demisto.params().get('first_fetch_days', DEFAULT_DAYS_BACK))
        if days_back > MAX_DAYS_BACK:
            demisto.info(f'Days back({days_back}) is larger than the maximum, setting to {MAX_DAYS_BACK}')
            days_back = MAX_DAYS_BACK
        last_fetch_time = (datetime.now() - timedelta(days=days_back)).strftime(DATETIME_FORMAT)
        demisto.info(f'First run, fetching alerts from {last_fetch_time}')

    max_incidents_to_return = int(demisto.params().get('max_fetch', DEFAULT_INCIDENTS))
    if max_incidents_to_return > MAX_INCIDENTS:
        demisto.info(f'Max incidents({max_incidents_to_return}) is larger than the maximum, setting to {MAX_INCIDENTS}')
        max_incidents_to_return = MAX_INCIDENTS

    sixgill_alerts_client = SixgillActionableAlertClient(client_id=demisto.params()['client_id'],
                                                         client_secret=demisto.params()['client_secret'],
                                                         channel_id=CHANNEL_CODE,
                                                         logger=demisto,
                                                         session=SESSION,
                                                         verify=VERIFY,
                                                         num_of_attempts=3)

    filter_alerts_kwargs = get_incident_init_params()
    items = sixgill_alerts_client.get_actionable_alerts_bulk(limit=max_incidents_to_return, from_date=last_fetch_time,
                                                             sort_order='asc', **filter_alerts_kwargs,
                                                             organization_id=demisto.params().get('org_id', None))
    if len(items) > 0:
        demisto.info(f'Found {len(items)} new alerts since {last_fetch_time}')

        # getting more info about oldest ~max_incidents_to_return(can be more because of sub alerts)
        newest_incident_date = items[-1].get('date')
        incidents = []
        for item in items:
            try:
                item_info = sixgill_alerts_client.get_actionable_alert(actionable_alert_id=item.get('id'),
                                                                       organization_id=demisto.params().get('org_id', None))
                item_info['date'] = item.get('date')
                new_incidents = item_to_incidents(item_info, sixgill_alerts_client)
                incidents.extend(new_incidents)
                # can increase because of sub alerts
                if len(incidents) >= max_incidents_to_return:
                    newest_incident_date = item.get('date')
                    break
            except Exception as e:
                demisto.error(f"Could not get alert info: {e}")

        if len(incidents) > 0:
            demisto.info(f'Adding {len(incidents)} to demisto')
            demisto.incidents(incidents)

            demisto.info(f'Update last fetch time to: {newest_incident_date}')
            demisto.setLastRun({
                'last_fetch_time': newest_incident_date
            })
    else:
        demisto.info(f'No new alerts since {last_fetch_time}')
        demisto.incidents([])


def update_alert_status():
    """
    Updates the actionable alert status.
    """
    args = demisto.args()
    alert_status = args.get('alert_status')
    alert_id = args.get('alert_id')
    aggregate_alert_id = args.get('aggregate_alert_id')
    demisto.info(f"update_alert_status: status- {alert_status}, alert_id - {alert_id}, aggregate_alert_id - {aggregate_alert_id}")
    aggregate_alert_id = [int(aggregate_alert_id)] if aggregate_alert_id else aggregate_alert_id
    alert_body = {
        "status": {
            "status": alert_status
        }
    }

    sixgill_alerts_client = SixgillActionableAlertClient(client_id=demisto.params()['client_id'],
                                                         client_secret=demisto.params()['client_secret'],
                                                         channel_id=CHANNEL_CODE,
                                                         logger=demisto,
                                                         session=SESSION,
                                                         verify=VERIFY)

    res = sixgill_alerts_client.update_actionable_alert(actionable_alert_id=alert_id, json_body=alert_body,
                                                        sub_alert_indexes=aggregate_alert_id,
                                                        organization_id=demisto.params().get('org_id', None))

    if res.get('status') == 200:
        demisto.results("Actionable alert status updated")


''' COMMANDS MANAGER / SWITCH PANEL '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        SESSION.proxies = handle_proxy()
        command = demisto.command()

        if command == 'test-module':
            test_module()
            demisto.results('ok')

        elif command == "fetch-incidents":
            fetch_incidents()

        elif command == "cybersixgill-update-alert-status":
            update_alert_status()

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")

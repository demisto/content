
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import copy
import requests

from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
from sixgill.sixgill_actionable_alert_client import SixgillActionableAlertClient

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

CHANNEL_CODE = '7698e8287dfde53dcd13082be750a85a'
MAX_INCIDENTS = 100
DEFAULT_INCIDENTS = '50'
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
    return {param_k: param_v for param_k, param_v in params_dict.items() if param_v is not None}


def item_to_incident(item_info, sixgill_alerts_client):
    incident: Dict[str, Any] = dict()
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
        'incidentlink': f"https://portal.cybersixgill.com/#/?actionable_alert={item_info.get('id', '')}"
    }


def add_sub_alerts_fields(incident, item_info, sixgill_alerts_client):
    status = item_info.get('status', {}).get('name', 'treatment_required')
    incident['status'] = TO_DEMISTO_STATUS[status]
    content_item = {'creator': None, 'title': '', 'content': '', 'description': item_info.get('description', '')}
    # cve alert
    if item_info.get('content_type', '') == 'cve_item':
        content_item['content'] = f'https://portal.cybersixgill.com/#/cve/{item_info.get("additional_info",{}).get("cve_id", "")}'
    else:
        content = sixgill_alerts_client.get_actionable_alert_content(actionable_alert_id=item_info.get('id'),
                                                                     aggregate_alert_id=item_info.get('aggregate_alert_id', None))
        # get item full content
        content = content.get('items', None)
        if content:
            if content[0].get('_id'):
                es_items = [item['_source'] for item in content if item['_id'] == item_info['es_id']]
                if es_items:
                    content_item['title'] = es_items[0].get('title')
                    content_item['content'] = es_items[0].get('content')
                    content_item['creator'] = es_items[0].get('creator')
            else:
                # github alert
                content_item['content'] = '\n\n-----------\n\n'.join(
                    [f'Repository name: {github_item.get("Repository name", "")}\nCustomer Keywords:'
                     f' {github_item.get("Customer Keywords", "")}\n URL: {github_item.get("URL", "")}'
                     for github_item in content])
    incident['details'] = f"{content_item.get('description')}\n\n{content_item.get('title', '')}\n" \
                          f"\n{content_item.get('content', '')}"
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
        last_fetch_time = datetime.strptime(last_run['last_fetch_time'], DATETIME_FORMAT)
        demisto.info(f'Found last run, fetching new alerts from {last_fetch_time}')
    else:
        days_back = int(demisto.params().get('first_fetch_days', DEFAULT_DAYS_BACK))
        if days_back > MAX_DAYS_BACK:
            demisto.info(f'Days back({days_back}) is larger than the maximum, setting to {MAX_DAYS_BACK}')
            days_back = MAX_DAYS_BACK
        last_fetch_time = datetime.now() - timedelta(days=days_back)
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
                                                         verify=VERIFY)

    filter_alerts_kwargs = get_incident_init_params()
    incidents = []
    items = sixgill_alerts_client.get_actionable_alerts_bulk(limit=MAX_INCIDENTS, **filter_alerts_kwargs)
    newest_incident_date = datetime.strptime(items[0].get('date'), DATETIME_FORMAT)
    offset = 0
    items_to_add = []
    if newest_incident_date > last_fetch_time:
        # finding all new alerts since last fetch time
        while items:
            for item in items:
                if datetime.strptime(item.get('date'), DATETIME_FORMAT) > last_fetch_time:
                    items_to_add.append(item)

            if len(items_to_add) - offset == len(items):
                offset += len(items)
                items = sixgill_alerts_client.get_actionable_alerts_bulk(limit=MAX_INCIDENTS, offset=offset,
                                                                         **filter_alerts_kwargs)
            else:
                items = []
    demisto.info(f'Found {len(items_to_add)} new alerts since {last_fetch_time}')

    # getting more info about oldest ~max_incidents_to_return(can be more because of sub alerts)
    if len(items_to_add):
        items_to_add.reverse()
        newest_incident_date = items_to_add[-1].get('date')
        for item in items_to_add:
            item_info = sixgill_alerts_client.get_actionable_alert(actionable_alert_id=item.get('id'))
            item_info['date'] = item.get('date')
            new_incidents = item_to_incident(item_info, sixgill_alerts_client)
            incidents.extend(new_incidents)
            if len(incidents) >= max_incidents_to_return:
                newest_incident_date = item.get('date')
                break

    demisto.info(f'Adding {len(incidents)} to demisto')
    demisto.incidents(incidents)

    if len(incidents):
        demisto.info(f'Update last fetch time to: {newest_incident_date}')
        demisto.setLastRun({
            'last_fetch_time': newest_incident_date
        })


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

    except Exception as e:
        return_error("Failed to execute {} command. Error: {}".format(demisto.command(), str(e)))

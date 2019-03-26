import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
from distutils.util import strtobool

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

APIKEY = demisto.params().get('apikey')
SERVER = demisto.params()['url'][:-1] if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else \
    demisto.params()['url']
USE_SSL = not demisto.params().get('insecure', False)
FETCH_TIME = demisto.params().get('fetch_time', '7 days')
BASE_URL = SERVER + '/api/v1/'
HEADERS = {
    'Accept': 'application/json',
    'Authorization': 'ExtraHop apikey={}'.format(APIKEY)
}
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']
response = []

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, data=None, payload=None):
    data = json.dumps(data)
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        data=data,
        headers=HEADERS,
        params=payload
    )
    # Handle error responses gracefully
    if res.status_code == 204:
        return demisto.results('Successful Modification')
    if demisto.command() == 'extrahop-add-alert' or 'extrahop-modify-alert' and res.status_code == 400:
        resp = res.json()
        return_error('Error in request format - [%s]' % resp['error_message'])
    if demisto.command() == 'extrahop-add-alert' or 'extrahop-modify-alert' and res.status_code == 201:
        return demisto.results('Alert successfully added')
    elif res.status_code not in {200, 204, 201}:
        return_error('Error in API call to ExtraHop [%d] - %s' % (res.status_code, res.reason))
    return res


''' COMMANDS + REQUESTS FUNCTIONS '''


def item_to_incident(item):
    epoch_occured = item.get('mod_time')
    incident = {
        'name': item.get('name'),
        'occurred': timestamp_to_datestring(epoch_occured),
        'rawJSON': json.dumps(item)}
    return incident


def test_module():
    """
    Performs basic get request to check ExtraHop version
    """
    test_result = http_request('GET', 'extrahop')
    return test_result


def get_alerts():
    res_raw = http_request('GET', 'alerts')
    res = res_raw.json()
    return res


def paginate(can_paginate, cursor):
    while can_paginate is True:
        body = {
            "cursor": cursor,
            "context_ttl": 400000
        }
        res_raw = http_request('POST', 'records/cursor', body)
        res = res_raw.json()
        response.append(res)
        if 'cursor' in res:
            paginate(True, res['cursor'])
        else:
            break
        return response


def query_records(field, value, operator, query_from, limit):
    data = {
        "filter": {
            "field": str(field),
            "operand": str(value),
            "operator": str(operator)
        },
        "from": int(query_from),
        "limit": int(limit)
    }
    res_raw = http_request('POST', 'records/search', data)
    res = res_raw.json()
    response.append(res)
    if 'cursor' in res:
        response.append(paginate(True, res['cursor']))
    return response


def devices():
    active_from = demisto.args().get('active_from')
    active_until = demisto.args().get('active_until')
    search_type = demisto.args().get('search_type')
    limit = demisto.args().get('limit')
    payload = {}
    if active_from:
        payload['active_from'] = active_from
    if active_until:
        payload['active_until'] = active_until
    if limit:
        payload['limit'] = limit
    payload['search_type'] = search_type
    res_raw = http_request('GET', 'devices', data=None, payload=payload)
    res = res_raw.json()
    return res


def format_alerts(alerts):
    for alert in alerts:
        hr = tableToMarkdown('Found Device', alert, headerTransform=string_to_table_header, removeNull=True)
        ec = {
            "Extrahop": {
                "Device": createContext(alert, keyTransform=string_to_context_key, removeNull=True)
            }
        }
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': alert,
            'HumanReadable': hr,
            'EntryContext': ec
        })


def format_device_results(data):
    for device in data:
        hr = tableToMarkdown('Found Device', device, headerTransform=string_to_table_header, removeNull=True)
        ec = {
            "Extrahop": {
                "Device": createContext(device, keyTransform=string_to_context_key, removeNull=True)
            }
        }
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': device,
            'HumanReadable': hr,
            'EntryContext': ec
        })


def devices_command():
    found_devices = devices()
    format_device_results(found_devices)


def whitelist_modify(add, remove):
    assignments = {}
    if add:
        add_items = add.split(',')
        add_items = list(map(int, add_items))
        assignments['assign'] = add_items
    if remove:
        remove_items = remove.split(',')
        remove_items = list(map(int, remove_items))
        assignments['unassign'] = remove_items
    res_raw = http_request('POST', 'whitelist/devices', data=assignments)
    res = res_raw.json()
    return res


def whitelist_modify_command():
    add = demisto.args().get('add')
    demisto.results(str(repr(add)))
    remove = demisto.args().get('remove')
    whitelist_modify(add, remove)


def whitelist_retrieve():
    res_raw = http_request('GET', 'whitelist/devices')
    res = res_raw.json()
    return res


def whitelist_retrieve_command():
    res = whitelist_retrieve()
    if len(res) == 0:
        demisto.results('No devices found in whitelist')
    elif len(res) > 0:
        format_device_results(res)


def query_records_command():
    field = demisto.args().get('field')
    value = demisto.args().get('value')
    operator = demisto.args().get('operator')
    query_from = demisto.args().get('query_from')
    limit = demisto.args().get('limit')
    res = query_records(field, value, operator, query_from, limit)
    source = res[0]['records']
    hr = ''
    ec = {
        "ExtraHop": {
            "Query": []
        }
    }
    for record in source:
        hr += tableToMarkdown('Incident result for ID {}'.format(record['_id']), record['_source'])
        ec['ExtraHop']['Query'].append(createContext(record, keyTransform=string_to_context_key, removeNull=True))
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': source,
        'HumanReadable': hr,
        'EntryContext': createContext(ec, removeNull=True)
    })


def get_alerts_command():
    res = get_alerts()
    format_alerts(res)


def add_alert(apply_all, disabled, name, notify_snmp, refire_interval, severity, alert_type, object_type,
              protocols, field_name, stat_name, units, interval_length, operand, operator, field_name2, field_op,
              param, param2, alert_id=None):
    data = {
        "apply_all": apply_all,
        "disabled": disabled,
        "name": name,
        "notify_snmp": notify_snmp,
        "refire_interval": int(refire_interval),
        "severity": int(severity),
        "type": alert_type
    }
    if alert_type == 'detection':
        data['object_type'] = object_type
        data['protocols'] = [str(protocols)]
    elif alert_type == 'threshold':
        data['field_name'] = field_name
        data['stat_name'] = stat_name
        data['units'] = units
        data['interval_length'] = int(interval_length)
        data['operand'] = operand
        data['operator'] = operator
        if demisto.args().get('field_name2'):
            data['field_name2'] = field_name2
        if demisto.args().get('field_op'):
            data['field_op'] = field_op
        if demisto.args().get('param'):
            data['param'] = param
        if demisto.args().get('param2'):
            data['param2'] = param2
    if alert_id:
        res = http_request('PATCH', 'alerts/{}'.format(alert_id), data=data)
    else:
        res = http_request('POST', 'alerts', data=data)
    return res


def add_alert_command():
    apply_all = bool(strtobool(demisto.args().get('apply_all', False)))
    disabled = bool(strtobool(demisto.args().get('disabled', False)))
    name = demisto.args().get('name')
    notify_snmp = bool(strtobool(demisto.args().get('notify_snmp', False)))
    field_name = demisto.args().get('field_name')
    stat_name = demisto.args().get('stat_name')
    units = demisto.args().get('units')
    interval_length = demisto.args().get('interval_length')
    operand = demisto.args().get('operand')
    refire_interval = demisto.args().get('refire_interval')
    severity = demisto.args().get('severity')
    alert_type = demisto.args().get('type')
    object_type = demisto.args().get('object_type')
    protocols = demisto.args().get('protocols')
    operator = demisto.args().get('operator')
    field_name2 = demisto.args().get('field_name2')
    field_op = demisto.args().get('field_op')
    param = demisto.args().get('param')
    param2 = demisto.args().get('param2')
    add_alert(apply_all, disabled, name, notify_snmp, refire_interval, severity, alert_type, object_type,
              protocols, field_name, stat_name, units, interval_length, operand, operator, field_name2, field_op,
              param, param2)


def modify_alert_command():
    alert_id = demisto.args().get('alert_id')
    apply_all = bool(strtobool(demisto.args().get('apply_all', False)))
    disabled = bool(strtobool(demisto.args().get('disabled', False)))
    name = demisto.args().get('name')
    notify_snmp = bool(strtobool(demisto.args().get('notify_snmp', False)))
    field_name = demisto.args().get('field_name')
    stat_name = demisto.args().get('stat_name')
    units = demisto.args().get('units')
    interval_length = demisto.args().get('interval_length')
    operand = demisto.args().get('operand')
    refire_interval = demisto.args().get('refire_interval')
    severity = demisto.args().get('severity')
    alert_type = demisto.args().get('type')
    object_type = demisto.args().get('object_type')
    protocols = demisto.args().get('protocols')
    operator = demisto.args().get('operator')
    field_name2 = demisto.args().get('field_name2')
    field_op = demisto.args().get('field_op')
    param = demisto.args().get('param')
    param2 = demisto.args().get('param2')
    add_alert(apply_all, disabled, name, notify_snmp, refire_interval, severity, alert_type, object_type,
              protocols, field_name, stat_name, units, interval_length, operand, operator, field_name2, field_op,
              param, param2, alert_id)


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)

    incidents = []
    items = get_alerts()
    for item in items:
        incident = item_to_incident(item)
        incident_date = date_to_timestamp(incident['occurred'], '%Y-%m-%dT%H:%M:%S.%fZ')
        # Update last run and add incident if the incident is newer than last fetch
        if incident_date > last_fetch:
            last_fetch = incident_date
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
    elif demisto.command() == 'extrahop-get-alerts':
        get_alerts()
    elif demisto.command() == 'extrahop-query':
        query_records_command()
    elif demisto.command() == 'extrahop-devices':
        devices_command()
    elif demisto.command() == 'extrahop-whitelist-modify':
        whitelist_modify_command()
    elif demisto.command() == 'extrahop-whitelist-retrieve':
        whitelist_retrieve_command()
    elif demisto.command() == 'extrahop-add-alert':
        add_alert_command()
    elif demisto.command() == 'extrahop-modify-alert':
        modify_alert_command()

# Log exceptions
except Exception, e:
    LOG(e.message)
    LOG.print_log()
    raise

import demistomock as demisto
from CommonServerPython import *


''' IMPORTS '''

import json
import requests
from ipaddress import ip_address
from distutils.util import strtobool
from typing import DefaultDict
from collections import defaultdict

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

APIKEY = demisto.params().get('apikey')
SERVER = SERVER = demisto.params().get('url', '').strip('/')
USE_SSL = not demisto.params().get('insecure', False)
BASE_URL = SERVER + '/api/v1/'
HEADERS = {
    'Accept': 'application/json',
    'Authorization': 'ExtraHop apikey={key}'.format(key=APIKEY)
}
handle_proxy()


''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, data=None, params=None, raw_response=False):
    data = json.dumps(data)
    demisto.debug("EH - Request Endpoint: {url} \n EH - Request params: {params} \n EH - Request data: {body}".format(
        url=BASE_URL + url_suffix, params=params, body=data))
    try:
        res = requests.request(
            method,
            BASE_URL + url_suffix,
            verify=USE_SSL,
            data=data,
            headers=HEADERS,
            params=params
        )
    except requests.exceptions.RequestException:
        return_error('Failed to connect to - {url} - Please check the URL'.format(url=BASE_URL))
    # Handle error responses gracefully
    if res.status_code not in {200, 201, 204}:
        error_reason = res.reason
        try:
            resp = res.json()
            error_reason = resp.get('error_message', resp.get('cpc_error', resp.get('failures', res.reason)))
        except Exception:
            pass
        return_error('Error in API call to ExtraHop {code} - {reason}'.format(code=res.status_code, reason=error_reason))
    # Handle no content responses gracefully
    elif not raw_response:
        if res.status_code == 201:
            return demisto.results('Successfully Created')
        elif res.status_code == 204:
            return demisto.results('Successful Modification')
    return res


def format_protocol_stack(protocol_list):
    if len(protocol_list) > 1:
        protos = protocol_list[1:]
    else:
        protos = protocol_list

    return ":".join(protos)


def sort_protocols(protos_by_weight):
    sorted_protos = sorted(protos_by_weight.items(), key=lambda x: x[1], reverse=True)
    return [proto_tuple[0] for proto_tuple in sorted_protos]


def parse_location_header(location):
    # Parse the object id from the location header
    if location:
        last_slash_index = location.rindex('/') + 1
        location_id = location[last_slash_index:]
        if location_id.isdigit():
            return location_id
    # return error in any other case
    return_error("Error unable to parse ExtraHop API response location header")


def next_page(cursor):
    body = {
        "cursor": cursor
    }
    params = {
        "context_ttl": 30000
    }
    res_raw = http_request('POST', 'records/cursor', data=body, params=params)
    res = res_raw.json()
    return res.get('records', [])


def format_alerts(alerts):
    hr_table = []
    ec = {
        "ExtraHop": {
            "Alert": []
        }
    }  # type: dict
    for alert in alerts:
        hr_table.append(alert)
        ec['ExtraHop']['Alert'].append(createContext(alert, keyTransform=string_to_context_key, removeNull=True))
    if len(alerts) == 0:
        demisto.results('No Alerts were found')
    else:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': alerts,
            'HumanReadable': tableToMarkdown("Found {} Alert(s)".format(len(alerts)),
                                             hr_table, headerTransform=string_to_table_header, removeNull=True),
            'EntryContext': ec
        })


def format_devices(devices, appliance_uuids, hr_title="{} Device(s) Found", no_results_msg="No Devices were found"):
    hr_table = []
    ec = {
        "ExtraHop": {
            "Device": []
        }
    }  # type: dict
    headers = ['Display Name', 'IP Address', 'MAC Address', 'Role', 'Vendor', 'URL']

    for device in devices:
        hr = {
            'Display Name': device.get('display_name'),
            'IP Address': device.get('ipaddr4', device.get('ipaddr6')),
            'MAC Address': device.get('macaddr'),
            'Role': device.get('role'),
            'Vendor': device.get('vendor')
        }

        device_url = "{}/extrahop/#/metrics/devices/{}.{}/overview/".format(
            SERVER, appliance_uuids[device.get('node_id')], device.get('discovery_id'))
        hr['URL'] = "[{}]({})".format("View Device in ExtraHop", device_url)
        device['url'] = device_url

        if 'client_protocols' in device or 'server_protocols' in device:
            hr['Protocols'] = {}
            # re-arrange headers to add protocol information
            headers = ['Display Name', 'IP Address', 'MAC Address', 'Role', 'Protocols', 'URL', 'Vendor']
            if 'client_protocols' in device:
                hr['Protocols']['Client'] = ', '.join(device.get('client_protocols', []))
            if 'server_protocols' in device:
                hr['Protocols']['Server'] = ', '.join(device.get('server_protocols', []))

        hr_table.append(hr)
        ec['ExtraHop']['Device'].append(createContext(device, keyTransform=string_to_context_key, removeNull=True))
    if len(devices) == 0:
        demisto.results(no_results_msg)
    else:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': devices,
            'HumanReadable': tableToMarkdown(hr_title.format(len(devices)), hr_table, headers=headers),
            'EntryContext': ec
        })


def format_device_with_protocols(device, appliance_uuids):
    if not device.get('client_protocols') and not device.get('server_protocols'):
        demisto.results("No Protocol activity found")
    else:
        ec = {
            "ExtraHop": {
                "Device": []
            }
        }  # type: dict
        headers = ['Display Name', 'IP Address', 'MAC Address',
                   'Protocols (Client)', 'Protocols (Server)', 'Role', 'Vendor', 'URL']

        hr = {
            'Display Name': device.get('display_name'),
            'IP Address': device.get('ipaddr4', device.get('ipaddr6')),
            'MAC Address': device.get('macaddr'),
            'Protocols (Client)': {},
            'Protocols (Server)': {},
            'Role': device.get('role'),
            'Vendor': device.get('vendor')
        }

        device_url = "{}/extrahop/#/metrics/devices/{}.{}/overview/".format(
            SERVER, appliance_uuids[device.get('node_id')], device.get('discovery_id'))
        hr['URL'] = "[{}]({})".format("View Device in ExtraHop", device_url)
        device['url'] = device_url

        hr['Protocols (Client)'] = ', '.join(device.get('client_protocols', []))
        hr['Protocols (Server)'] = ', '.join(device.get('server_protocols', []))

        ec['ExtraHop']['Device'].append(createContext(device, keyTransform=string_to_context_key, removeNull=True))
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': device,
            'HumanReadable': tableToMarkdown("Device Activity Found", hr, headers=headers),
            'EntryContext': ec
        })


def format_records(res):
    records = res.get("records")

    hr_table = []
    ec = {
        "ExtraHop": {
            "Record": []
        }
    }  # type: dict
    for record in records:
        hr_table.append(record['_source'])
        ec['ExtraHop']['Record'].append(createContext(record, keyTransform=string_to_context_key, removeNull=True))
    if len(records) == 0:
        demisto.results('No Records were found')
    else:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': res,
            'HumanReadable': tableToMarkdown("Showing {results} out of {total} Record(s) Found.".format(total=res.get('total', 0),
                                             results=len(records)), hr_table),
            'EntryContext': createContext(ec, removeNull=True)
        })


''' REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to check ExtraHop version
    """
    test_result = http_request('GET', 'extrahop')
    return test_result


def get_appliance_uuids():
    res_raw = http_request('GET', 'networks')
    networks = res_raw.json()
    uuid_lookup = {}
    for network in networks:
        uuid_lookup[network['node_id']] = network['appliance_uuid']
    return uuid_lookup


def get_device_by_ip(ip, active_from=None, active_until=None, limit=None, offset=None):
    devices = device_search(name=None, ip=ip, mac=None, role=None, software=None, vendor=None, tag=None, discover_time=None,
                            vlan=None, activity=None, operator="=", match_type="and", active_from=active_from,
                            active_until=active_until, limit=limit, l3_only=True)
    if devices:
        return devices[0]
    else:
        return_error("Error the IP Address {} was not found in ExtraHop.".format(ip))


def get_device_by_id(api_id):
    return http_request('GET', 'devices/{id}'.format(id=api_id)).json()


def get_devices_by_ip_or_id(devices_str, active_from=None, active_until=None, limit=None, id_only=False):
    devices = []
    for item in str(devices_str).split(','):
        if item.isdigit():
            if id_only:
                devices.append(int(item))
            else:
                device = get_device_by_id(item)
                devices.append(device)
        else:
            try:
                ip_address(item)
            except ValueError:
                return_error("Error parsing IP Address {}".format(item))

            device = get_device_by_ip(item, active_from, active_until, limit)

            if id_only:
                devices.append(int(device['id']))
            else:
                devices.append(device)

    return devices


def get_alerts():
    res_raw = http_request('GET', 'alerts')
    res = res_raw.json()
    return res


def query_records(query_from, query_until, limit, offset,
                  field1, operator1, value1, field2, operator2, value2, match_type, types):
    data = {}
    if query_from:
        data['from'] = query_from
    if query_until:
        data['until'] = query_until
    if limit:
        if int(limit) > 1000:
            data['limit'] = 1000
            data['context_ttl'] = "30s"
        else:
            data['limit'] = int(limit)
    if offset:
        data['offset'] = int(offset)
    if types:
        try:
            data['types'] = ['~' + rec_type for rec_type in types.split(',')]
        except Exception:
            return_error('Error parsing the types argument, expected a comma separated list of types.')

    if field1 or value1 or field2 or value2:
        search_filters = [
            (field1, operator1, value1),
            (field2, operator2, value2)
        ]
        data['filter'] = {
            "operator": match_type,
            "rules": []
        }
        for search_filter in search_filters:
            if search_filter[0]:
                rule = {
                    "field": search_filter[0],
                    "operator": search_filter[1],
                    "operand": search_filter[2] or ""
                }
                data['filter']['rules'].append(rule)

    res_raw = http_request('POST', 'records/search', data)
    res = res_raw.json()
    cursor = res.get('cursor')
    if cursor and res.get('total', 0) > data['limit']:
        additional_records = next_page(cursor)
        while len(additional_records) > 0:
            res['records'].extend(additional_records)
            additional_records = next_page(cursor)
    return res


def device_search(name, ip, mac, role, software, vendor, tag, discover_time, vlan, activity,
                  operator, match_type, active_from, active_until, limit, l3_only):

    fields = {
        "name": name,
        "ipaddr": ip,
        "macaddr": mac,
        "role": role,
        "software": software,
        "vendor": vendor,
        "tag": tag,
        "discover_time": discover_time,
        "vlan": vlan,
        "activity": activity
    }

    data = {}
    if active_from:
        data['active_from'] = active_from
    if active_until:
        data['active_until'] = active_until
    if limit:
        data['limit'] = int(limit)
    if any([val is not None for val in fields.values()]):
        data['filter'] = {
            "operator": match_type,
            "rules": []
        }
        rules_list = data['filter']['rules']

        if l3_only:
            rules_list.append(
                {
                    "field": "ipaddr",
                    "operator": "exists"
                }
            )
            if match_type != "and":
                data['filter']['operator'] = "and"
                rules_list.append(
                    {
                        "operator": match_type,
                        "rules": []
                    }
                )
                rules_list = data['filter']['rules'][1]['rules']

        for field in fields.items():
            if field[1]:
                search_filter = {
                    "field": field[0],
                    "operator": operator,
                    "operand": field[1]
                }
                rules_list.append(search_filter)

    res_raw = http_request('POST', 'devices/search', data=data)
    res = res_raw.json()
    return res


def get_peers(ip_or_id, query_from, query_until, peer_role, protocol):
    device = get_devices_by_ip_or_id(ip_or_id)[0]
    api_id = int(device['id'])

    if device['analysis'] == 'discovery':
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': ("This Device is in Discovery Mode. "
                         "Configure your [Analysis Priorities](https://docs.extrahop.com/current/analysis_priorities/) "
                         "or add this device to the "
                         "[Watchlist](https://docs.extrahop.com/current/analysis-priorities-faq/#what-is-the-watchlist) "
                         "manually with: `!extrahop-edit-watchlist add={}`".format(api_id))
        })

    body = {
        "edge_annotations": ["protocols"],
        "from": query_from,
        "walks": [{
            "origins": [{
                "object_id": api_id,
                "object_type": "device"
            }],
            "steps": [{
                "relationships": [{
                    "protocol": protocol,
                    "role": peer_role
                }]
            }]
        }]
    }
    if query_until:
        body['until'] = query_until

    activitymap_raw = http_request('POST', 'activitymaps/query', data=body)
    activitymap = activitymap_raw.json()

    peers = defaultdict(lambda: {
        'weight': 0,
        'client_protocols': defaultdict(int),
        'server_protocols': defaultdict(int)
    })  # type: DefaultDict[str, dict]

    for edge in activitymap['edges']:
        if edge["to"] == api_id:
            peer_id = edge['from']
            role_key = 'client_protocols'
        else:
            peer_id = edge['to']
            role_key = 'server_protocols'

        peers[peer_id]['weight'] += edge['weight']

        # add protocols
        if 'annotations' in edge and 'protocols' in edge['annotations']:
            for protocol_list in edge['annotations']['protocols']:
                proto_stack = format_protocol_stack(protocol_list['protocol'])
                peers[peer_id][role_key][proto_stack] += protocol_list['weight']

    peer_devices = []
    peer_ids_by_weight = [peer[0] for peer in sorted(peers.items(), key=lambda x:x[1]['weight'], reverse=True)]
    # Lookup each peer device by id
    for peer_id in peer_ids_by_weight:
        device = get_device_by_id(peer_id)
        if peer_role in ('any', 'client'):
            device['client_protocols'] = sort_protocols(peers[peer_id]['client_protocols'])
        if peer_role in ('any', 'server'):
            device['server_protocols'] = sort_protocols(peers[peer_id]['server_protocols'])
        peer_devices.append(device)
    return peer_devices


def get_protocols(ip_or_id, query_from, query_until):
    device = get_devices_by_ip_or_id(ip_or_id)[0]
    api_id = int(device['id'])

    if device['analysis'] == 'discovery':
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': ("This Device is in Discovery Mode. "
                         "Configure your [Analysis Priorities](https://docs.extrahop.com/current/analysis_priorities/) "
                         "or add this device to the "
                         "[Watchlist](https://docs.extrahop.com/current/analysis-priorities-faq/#what-is-the-watchlist) "
                         "manually with: `!extrahop-edit-watchlist add={}`".format(api_id))
        })

    body = {
        "edge_annotations": ["protocols"],
        "from": query_from,
        "walks": [{
            "origins": [{
                "object_id": api_id,
                "object_type": "device"
            }],
            "steps": [{}]
        }]
    }
    if query_until:
        body['until'] = query_until

    activitymap_raw = http_request('POST', 'activitymaps/query', data=body)
    activitymap = activitymap_raw.json()

    client_protocols = defaultdict(int)  # type: DefaultDict[str, int]
    server_protocols = defaultdict(int)  # type: DefaultDict[str, int]
    for edge in activitymap['edges']:
        if 'annotations' in edge and 'protocols' in edge['annotations']:
            for protocol_list in edge['annotations']['protocols']:
                proto_stack = format_protocol_stack(protocol_list['protocol'])
                if edge["from"] == api_id:
                    client_protocols[proto_stack] += protocol_list['weight']
                elif edge["to"] == api_id:
                    server_protocols[proto_stack] += protocol_list['weight']

    device['client_protocols'] = sort_protocols(client_protocols)
    device['server_protocols'] = sort_protocols(server_protocols)

    return device


def edit_watchlist(add, remove):
    body = {}
    if add:
        body['assign'] = get_devices_by_ip_or_id(add, id_only=True)
    if remove:
        body['unassign'] = get_devices_by_ip_or_id(remove, id_only=True)

    res = http_request('POST', 'whitelist/devices', data=body)

    return res


def get_watchlist():
    res_raw = http_request('GET', 'whitelist/devices')
    res = res_raw.json()
    return res


def create_alert(apply_all, disabled, name, notify_snmp, refire_interval, severity, alert_type, object_type,
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
        if field_name2:
            data['field_name2'] = field_name2
        if field_op:
            data['field_op'] = field_op
        if param:
            data['param'] = param
        if param2:
            data['param2'] = param2
    if alert_id:
        method = 'PATCH'
        url_suffix = 'alerts/{alert_id}'.format(alert_id=alert_id)
    else:
        method = 'POST'
        url_suffix = 'alerts'

    res = http_request(method, url_suffix, data=data)
    return res


def track_ticket(incident_id, detection_id, incident_owner, incident_status, incident_close_reason):
    detection_status = {
        'ticket_id': incident_id
    }

    status_map = {
        "0": 'new',           # pending
        "1": 'in_progress',   # active
        "2": 'closed',        # done
        "3": 'closed'         # archived
    }
    detection_status['status'] = status_map.get(str(incident_status))

    # Assignee cannot be an empty string
    detection_status['assignee'] = incident_owner if incident_owner else None
    # Only set Resolution if the incident is closed
    if detection_status['status'] == 'closed' and incident_close_reason:
        if incident_close_reason in ('Resolved'):
            detection_status['resolution'] = 'action_taken'
        elif incident_close_reason in ('False Positive', 'Duplicate'):
            detection_status['resolution'] = 'no_action_taken'
    else:
        # Clear resolution to avoid error
        detection_status['resolution'] = None

    res = http_request('PATCH', 'detections/{id}'.format(id=detection_id), data=detection_status, raw_response=True)
    return res


def tag_devices(tag, add, remove):
    body = {}
    if add:
        body['assign'] = get_devices_by_ip_or_id(add, id_only=True)
    if remove:
        body['unassign'] = get_devices_by_ip_or_id(remove, id_only=True)

    all_tags = http_request('GET', 'tags').json()
    for t in all_tags:
        if t['name'] == tag:
            tag_id = t['id']
            break
    else:
        if remove and not add:
            return_warning("Warning: tag {} does not exist, nothing to remove.".format(tag))
        tag_create_res = http_request('POST', 'tags', data={'name': tag}, raw_response=True)
        tag_location = tag_create_res.headers.get('location')
        tag_id = parse_location_header(tag_location)

    res = http_request('POST', "tags/{}/devices".format(tag_id), data=body)

    return res


def get_activity_map(ip_or_id, time_interval, from_time, until_time, peer_role, protocol):
    device = get_devices_by_ip_or_id(ip_or_id)[0]

    time_intervals = {
        '30 minutes': (30, 'MIN'),
        '6 hours': (6, 'HR'),
        '1 day': (1, 'DAY'),
        '1 week': (1, 'WK')
    }

    if from_time or until_time:
        if from_time and until_time:
            interval = 'DT'
            start = from_time
            end = until_time
        else:
            raise ValueError("When using a fixed time range both from_time and until_time timestamps need to be provided.")
    else:
        start, interval = time_intervals.get(time_interval, (30, 'MIN'))
        end = 0

    activity_map_params = {
        'server': SERVER,
        'app_id': get_appliance_uuids()[device.get('node_id')],
        'disc_id': device.get('discovery_id'),
        'start': start,
        'interval': interval,
        'obj': "device",
        'proto': protocol,
        'role': peer_role,
        'end': end
    }

    activity_map_link_format = ("{server}/extrahop/#/activitymaps"
                                "?appliance_id={app_id}"
                                "&discovery_id={disc_id}"
                                "&from={start}"
                                "&interval_type={interval}"
                                "&object_type={obj}"
                                "&protocol={proto}"
                                "&role={role}"
                                "&until={end}")

    activity_map_link = activity_map_link_format.format(**activity_map_params)

    return activity_map_link


def search_packets(output, limit_bytes, limit_search_duration, query_from, query_until, bpf, ip1, port1, ip2, port2):
    params = {
        'output': output,
        'limit_bytes': limit_bytes,
        'limit_search_duration': limit_search_duration,
        'always_return_body': 'false',
        'from': query_from,
        'until': query_until,
        'bpf': bpf,
        'ip1': ip1,
        'port1': port1,
        'ip2': ip2,
        'port2': port2
    }

    res = http_request("GET", "packets/search", params=params, raw_response=True)

    return res


''' COMMANDS FUNCTIONS '''


def create_or_edit_alert_command():
    dargs = demisto.args()
    alert_id = dargs.get('alert_id')
    apply_all = bool(strtobool(dargs.get('apply_all', False)))
    disabled = bool(strtobool(dargs.get('disabled', False)))
    name = dargs.get('name')
    notify_snmp = bool(strtobool(dargs.get('notify_snmp', False)))
    field_name = dargs.get('field_name')
    stat_name = dargs.get('stat_name')
    units = dargs.get('units')
    interval_length = dargs.get('interval_length')
    operand = dargs.get('operand')
    refire_interval = dargs.get('refire_interval')
    severity = dargs.get('severity')
    alert_type = dargs.get('type')
    object_type = dargs.get('object_type')
    protocols = dargs.get('protocols')
    operator = dargs.get('operator')
    field_name2 = dargs.get('field_name2')
    field_op = dargs.get('field_op')
    param = dargs.get('param')
    param2 = dargs.get('param2')
    create_alert(apply_all, disabled, name, notify_snmp, refire_interval, severity, alert_type, object_type,
                 protocols, field_name, stat_name, units, interval_length, operand, operator, field_name2, field_op,
                 param, param2, alert_id)


def get_alerts_command():
    res = get_alerts()
    format_alerts(res)


def edit_watchlist_command():
    dargs = demisto.args()
    add = dargs.get('add')
    remove = dargs.get('remove')
    edit_watchlist(add, remove)


def query_records_command():
    dargs = demisto.args()
    query_from = dargs.get('query_from')
    query_until = dargs.get('query_until')
    limit = dargs.get('limit')
    offset = dargs.get('offset')
    field1 = dargs.get('field1')
    operator1 = dargs.get('operator1')
    value1 = dargs.get('value1')
    field2 = dargs.get('field2')
    operator2 = dargs.get('operator2')
    value2 = dargs.get('value2')
    match_type = dargs.get('match_type')
    types = dargs.get('types')
    res = query_records(query_from, query_until, limit, offset, field1, operator1, value1,
                        field2, operator2, value2, match_type, types)
    format_records(res)


def get_watchlist_command():
    res = get_watchlist()
    if len(res) == 0:
        demisto.results('No Devices were found in the watchlist')
    elif len(res) > 0:
        format_devices(res, get_appliance_uuids())


def device_search_command():
    dargs = demisto.args()
    name = dargs.get('name')
    ip = dargs.get('ip')
    mac = dargs.get('mac')
    role = dargs.get('role')
    software = dargs.get('software')
    vendor = dargs.get('vendor')
    tag = dargs.get('tag')
    discover_time = dargs.get('discover_time')
    vlan = dargs.get('vlan')
    activity = dargs.get('activity')
    operator = dargs.get('operator')
    match_type = dargs.get('match_type')
    active_from = dargs.get('active_from')
    active_until = dargs.get('active_until')
    limit = dargs.get('limit')
    l3_only = bool(strtobool(dargs.get('l3_only', True)))
    found_devices = device_search(name, ip, mac, role, software, vendor, tag, discover_time,
                                  vlan, activity, operator, match_type, active_from, active_until, limit, l3_only)
    format_devices(found_devices, get_appliance_uuids())


def track_ticket_command():
    dargs = demisto.args()
    incident_id = dargs.get('incident_id')
    detection_id = dargs.get('detection_id')
    incident_owner = dargs.get('incident_owner')
    incident_status = dargs.get('incident_status')
    incident_close_reason = dargs.get('incident_close_reason')
    track_ticket(incident_id, detection_id, incident_owner, incident_status, incident_close_reason)
    ec = {
        "ExtraHop": {
            "TicketId": incident_id
        }
    }  # type: dict
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': ec,
        'HumanReadable': 'Successful Modification',
        'EntryContext': createContext(ec, removeNull=True)
    })


def get_peers_command():
    dargs = demisto.args()
    ip_or_id = dargs.get('ip_or_id')
    query_from = dargs.get('query_from', '-30m')
    query_until = dargs.get('query_until')
    peer_role = dargs.get('peer_role')
    protocol = dargs.get('protocol')
    peer_devices = get_peers(ip_or_id, query_from, query_until, peer_role, protocol)
    format_devices(peer_devices, get_appliance_uuids(), hr_title="{} Peer Device(s) Found",
                   no_results_msg="No Peer Devices were found")


def get_protocols_command():
    dargs = demisto.args()
    ip_or_id = dargs.get('ip_or_id')
    query_from = dargs.get('query_from')
    query_until = dargs.get('query_until')
    device = get_protocols(ip_or_id, query_from, query_until)
    format_device_with_protocols(device, get_appliance_uuids())


def tag_devices_command():
    dargs = demisto.args()
    tag = dargs.get('tag')
    add = dargs.get('add')
    remove = dargs.get('remove')
    tag_devices(tag, add, remove)


def get_activity_map_command():
    dargs = demisto.args()
    ip_or_id = dargs.get('ip_or_id')
    time_interval = dargs.get('time_interval')
    from_time = dargs.get('from_time')
    until_time = dargs.get('until_time')
    peer_role = dargs.get('peer_role')
    protocol = dargs.get('protocol')
    activity_map_link = get_activity_map(ip_or_id, time_interval, from_time, until_time, peer_role, protocol)

    ec = {
        "ExtraHop": {
            "ActivityMap": activity_map_link
        }
    }  # type: dict
    return_outputs('[View Live Activity Map in ExtraHop]({})'.format(activity_map_link), createContext(ec, removeNull=True), ec)


def search_packets_command():
    dargs = demisto.args()
    output = dargs.get('output')
    limit_bytes = dargs.get('limit_bytes')
    limit_search_duration = dargs.get('limit_search_duration')
    query_from = dargs.get('query_from')
    query_until = dargs.get('query_until')
    bpf = dargs.get('bpf')
    ip1 = dargs.get('ip1')
    port1 = dargs.get('port1')
    ip2 = dargs.get('ip2')
    port2 = dargs.get('port2')

    res_raw = search_packets(output, limit_bytes, limit_search_duration, query_from, query_until, bpf, ip1, port1, ip2, port2)
    if res_raw.status_code == 204:
        demisto.results('Search matched no packets.')
    else:
        filename_header = res_raw.headers.get('content-disposition')
        f_attr = 'filename='
        if filename_header and f_attr in filename_header:
            quoted_filename = filename_header[filename_header.index(f_attr) + len(f_attr):]
            filename = quoted_filename.replace('"', '')
        else:
            return_error('Error filename could not be found in response header.')

        demisto.results(fileResult(filename, res_raw.content))


''' COMMANDS MANAGER / SWITCH PANEL '''


try:
    if demisto.command() == 'test-module':
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'extrahop-get-alerts':
        get_alerts_command()
    elif demisto.command() == 'extrahop-query-records':
        query_records_command()
    elif demisto.command() == 'extrahop-device-search':
        device_search_command()
    elif demisto.command() == 'extrahop-edit-watchlist':
        edit_watchlist_command()
    elif demisto.command() == 'extrahop-get-watchlist':
        get_watchlist_command()
    elif demisto.command() == 'extrahop-create-alert':
        create_or_edit_alert_command()
    elif demisto.command() == 'extrahop-edit-alert':
        create_or_edit_alert_command()
    elif demisto.command() == 'extrahop-track-ticket':
        track_ticket_command()
    elif demisto.command() == 'extrahop-get-peers':
        get_peers_command()
    elif demisto.command() == 'extrahop-get-protocols':
        get_protocols_command()
    elif demisto.command() == 'extrahop-tag-devices':
        tag_devices_command()
    elif demisto.command() == 'extrahop-get-activity-map':
        get_activity_map_command()
    elif demisto.command() == 'extrahop-search-packets':
        search_packets_command()

# Log exceptions
except Exception as e:
    return_error('Failed to execute {} command. Error: {}'.format(demisto.command(), str(e)))

import demistomock as demisto
from CommonServerPython import *
import json
import requests
import socket
from typing import Dict, Any, List
from netaddr import IPNetwork, IPAddress

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''
Templates for change requests

Change these templates if you have customized your Firewall Change Request or Server Decommission Request worflows to match
your workflow.  To view the JSON structure of your customized workflows, create a sample ticket then view the data via the
API: https://<SecureChange IP Address>/securechangeworkflow/api/securechange/tickets/<tickt_ID>.json
'''

FW_CHANGE_REQ = json.loads('''{ "ticket": { "subject": "", "priority": "", "workflow": { "name": "Firewall Change Request",
                           "uses_topology": true }, "steps": { "step": [ { "name": "Submit Access Request", "tasks": { "task":
                           { "fields": { "field": { "@xsi.type": "multi_access_request", "name": "Required Access",
                           "access_request": { "use_topology": true, "targets": { "target": { "@type": "ANY" } },
                           "users": { "user": [ "Any" ] }, "sources": { "source": [ { "@type": "IP", "ip_address": "",
                           "netmask": "255.255.255.255", "cidr": 32 } ] }, "destinations": { "destination": [ { "@type": "IP",
                           "ip_address": "", "netmask": "255.255.255.255", "cidr": 32 } ] }, "services": { "service":
                            [ { "@type": "PROTOCOL", "protocol": "", "port": 0 } ] }, "action": "" } } } } } } ] },
                            "comments": "" } }''')
SERVER_DECOM_REQ = json.loads('''{ "ticket": { "subject": "", "priority": "", "workflow": { "name":
                              "Server Decommission Request", "uses_topology": false }, "steps": { "step": [ {
                              "name": "Server Decommission Request", "tasks": { "task": { "fields": { "field": { "@xsi.type":
                              "multi_server_decommission_request", "name": "Request verification",
                              "server_decommission_request": { "servers": { "server": { "@type": "IP", "ip_address": "",
                              "netmask": "255.255.255.255", "cidr": 32 } }, "targets": { "target": { "@type": "ANY" } },
                              "comment": "" } } } } } } ] }, "comments": "" }}''')

# remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


def tos_request(tos_app, req_type, path, params=None, headers=None, data=None):
    """ Function to access TOS via REST API """
    if headers is None:
        headers = {
            'accept': 'application/json',
            'content-type': 'application/json',
            'cache-control': 'no-cache'
        }

    # Get Configuration
    tos_ip = ""
    tos_user = ""
    tos_pass = ""
    if tos_app == "st":
        tos_ip = demisto.params()['SecureTrack-Server']
        tos_user = demisto.params()['SecureTrack-User']['identifier']
        tos_pass = demisto.params()['SecureTrack-User']['password']
    elif tos_app == "sc":
        tos_ip = demisto.params()['SecureChange-Server']
        tos_user = demisto.params()['SecureChange-User']['identifier']
        tos_pass = demisto.params()['SecureChange-User']['password']
    elif tos_app == "sa":
        tos_ip = demisto.params()['SecureApp-Server']
        tos_user = demisto.params()['SecureApp-User']['identifier']
        tos_pass = demisto.params()['SecureApp-User']['password']
    verify_ssl = not demisto.params().get('unsecure', False)
    url = 'https://' + tos_ip + path

    # Go do
    if req_type.upper() == 'GET':
        try:
            res = requests.get(url, params=params, headers=headers, auth=(tos_user, tos_pass), verify=verify_ssl)
        except requests.exceptions.RequestException as e:
            return_error(str(e))

        # Check output
        if res.status_code == 200 or res.status_code == 201:
            try:
                return res.json()
            except json.decoder.JSONDecodeError:
                return res.content
        else:
            if res.status_code == 401:
                return_error('TOS Reached, Auth Failed. Please check your credentials')
            else:
                return_error('Error {} Reaching {} to TOS: {}'.format(res.status_code, res.url, res.reason))
    elif req_type.upper() == 'POST':
        try:
            res = requests.post(url, data=data, params=params, headers=headers, auth=(tos_user, tos_pass),
                                verify=verify_ssl)
        except requests.exceptions.RequestException as e:
            return_error(str(e))

        # Check output
        if res.status_code == 200 or res.status_code == 201:
            try:
                return res.json()
            except json.decoder.JSONDecodeError:
                return res.content
        else:
            if res.status_code == 401:
                return_error('TOS Reached, Auth Failed. Please check your credentials')
            else:
                return_error('Error {} Reaching {} to TOS: {}'.format(res.status_code, res.url, res.reason))


def valid_ip(ipa):
    # ipaddress module not installed by default, using this approach
    try:
        socket.inet_aton(ipa)
        return True
    except socket.error:
        return False


def path_finder(querystring):
    # Define the basic output for the function, augmenting later with TOS data
    entry: Dict[str, Any] = {
        'Type': entryTypes['note'],
        'Contents': '',
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '',
        'EntryContext': {}
    }

    # Ask TOS for the path
    o = tos_request('st', 'GET', '/securetrack/api/topology/path', querystring)

    # Verify the data and return
    try:
        entry['EntryContext']['Tufin1.Topology.TrafficAllowed'] = o['path_calc_results']['traffic_allowed']
        entry['EntryContext']['Tufin1.Topology.TrafficDevices'] = [d['name'] for d in
                                                                   o['path_calc_results']['device_info']]
        entry['Contents'] = o['path_calc_results']['device_info']
        entry['HumanReadable'] = tableToMarkdown(
            'Tufin1 Topology Search for {} to {} via Service {}. Traffic is {}'.format(querystring['src'],
                                                                                       querystring['dst'],
                                                                                       querystring['service'],
                                                                                       ('**Denied**', '**Allowed**')[
                                                                                           o['path_calc_results'][
                                                                                               'traffic_allowed']]),
            {'Start': querystring['src'], 'Devices in Path': '-->'.join(
                ['**' + d['name'] + '**' + ' ({})'.format(d['vendor']) for d in o['path_calc_results']['device_info']]),
             'End': querystring['dst']}, ['Start', 'Devices in Path', 'End'])

    except KeyError:
        return_error('Unknown Output Returned')
    # Send back to Demisto inside function
    return entry


def path_finder_command():
    ''' Sample query: querystring = {'src':'10.80.80.0','dst':'172.16.200.80',
        'service':'tcp:22','includeIncompletePaths':'true'} '''
    # Build the query from user input
    querystring = {
        'src': demisto.args()['source'],
        'dst': demisto.args()['destination'],
        'service': demisto.args().get('service', 'Any'),
        'includeIncompletePaths': 'true'
    }
    e = path_finder(querystring)
    demisto.results(e)


def path_finder_image(querystring):
    entry = {
        'Type': entryTypes['note'],
        'Contents': '',
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '',
        'EntryContext': {}
    }

    try:
        headers = {'accept': 'image/png', 'content-type': 'application/json', 'cache-control': 'no-cache'}
        img = tos_request('st', 'GET', '/securetrack/api/topology/path_image', querystring, headers)
        # simple check if we have an image or error message.
        if len(img) > 20:
            # Send back to Demisto inside function
            return fileResult('topo.png', img, entryTypes['image'])
        else:
            entry['HumanReadable'] = 'No Valid Path Found'
            entry['Contents'] = 'No Valid Path Found'
            # Send back to Demisto inside function
            return entry
    except Exception as e:
        return_error('Error Running Query: {}'.format(e))


def path_finder_image_command():
    ''' Sample query: querystring = {'src':'10.80.80.0','dst':'172.16.200.80',
        'service':'tcp:80','includeIncompletePaths':'true','displayBlockedStatus':'true'} '''
    querystring = {
        'src': demisto.args()['source'],
        'dst': demisto.args()['destination'],
        'service': demisto.args().get('service', 'Any'),
        'includeIncompletePaths': 'true',
        'displayBlockedStatus': 'true'
    }
    e = path_finder_image(querystring)
    demisto.results(e)


def device_name(devices, device_id):
    return [e['name'] + ' ({} {})'.format(e['vendor'], e['model']) for e in devices if int(e['id']) == int(device_id)][
        0]


def object_lookup(querystring):
    entry: Dict[str, Any] = {
        'Type': entryTypes['note'],
        'Contents': '',
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '',
        'EntryContext': {}
    }

    return_json: Dict[str, List] = {'objects': []}

    o = tos_request('st', 'GET', '/securetrack/api/network_objects/search', querystring)

    # Validate result
    try:
        total = int(o['network_objects']['count'])
    except KeyError:
        total = 0

    if total > 0:
        device_json = tos_request('st', 'GET', '/securetrack/api/devices')['devices']['device']
        objs = o['network_objects']['network_object']
        if not isinstance(o['network_objects']['network_object'], list):
            objs = [objs]
        for obj in objs:
            # display_name device_id
            return_json['objects'].append({'object_name': obj['display_name'], 'device': device_name(device_json,
                                                                                                     obj['device_id']),
                                           'comment': obj['comment']})
    else:
        entry['HumanReadable'] = 'No Results'
        entry['EntryContext']['Tufin1.ObjectResolve.NumberOfObjects'] = 0
        return entry

    # Return to Demisto
    entry['Contents'] = json.dumps(return_json)
    entry['EntryContext']['Tufin1.ObjectResolve.NumberOfObjects'] = total
    entry['HumanReadable'] = tableToMarkdown('Object Lookup for {}'.format(querystring['exact_subnet']),
                                             return_json['objects'],
                                             ['object_name', 'device', 'comment'], underscoreToCamelCase,
                                             removeNull=True)
    # Send back to Demisto inside function
    return entry


def object_lookup_command():
    """ Sample query: querystring = {'filter':'subnet','count':'50','exact_subnet':'1.1.1.1'} """
    querystring = {
        'filter': 'subnet',
        'count': '50',
        'exact_subnet': demisto.args()['ip']
    }
    if not valid_ip(querystring['exact_subnet']):
        return_error('Invalid IP Address')
        return False

    e = object_lookup(querystring)
    demisto.results(e)


def policy_search(querystring, max_rules_per_device=100):
    """ Search policy across all devices.  See docs for syntax """
    u = '/securetrack/api/rule_search'
    entry: Dict[str, Any] = {
        'Type': entryTypes['note'],
        'Contents': '',
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '',
        'EntryContext': {}
    }

    matches = tos_request('st', 'GET', u, querystring)
    search_devices = [e['device_id'] for e in matches['device_list']['device'] if int(e['rule_count']) > 0]

    if not len(search_devices):
        entry['HumanReadable'] = 'No Results Found'
        entry['EntryContext']['Tufin1.Policysearch.NumberRulesFound'] = 0
        # Send back to Demisto inside function
        return entry
    else:
        rule_total = 0
        querystring['count'] = max_rules_per_device
        querystring['start'] = 0
        rule_return = []
        device_json = tos_request('st', 'GET', '/securetrack/api/devices')['devices']['device']
        for d in search_devices:
            rules = tos_request('st', 'GET', u + '/{}'.format(d), querystring)
            # If no matches(there should be) just break the iteration
            if rules['rules']['count'] == 0:
                break

            current_device = device_name(device_json, d)

            for rule in rules['rules']['rule']:
                rule_total = rule_total + 1
                rule_return.append({
                    'Device': current_device,
                    'Source': [d['display_name'] for d in rule['src_network']],
                    'Source Service': [d['display_name'] for d in rule['src_service']],
                    'Destination': [d['display_name'] for d in rule['dst_network']],
                    'Destination Service': [d['display_name'] for d in rule['dst_service']],
                    'Action': rule['action']
                })
        # Send back to Demisto
        entry['Contents'] = json.dumps(rule_return)
        entry['EntryContext']['Tufin1.Policysearch.NumberRulesFound'] = rule_total
        entry['HumanReadable'] = tableToMarkdown('Policy Search Results for {}'.format(querystring['search_text']),
                                                 rule_return, ['Device', 'Source', 'Source Service', 'Destination',
                                                               'Destination Service', 'Action'], removeNull=True)
        # Send back to Demisto inside function
        return entry


def policy_search_command():
    max_rules_per_device = demisto.params()['MaxRules']
    querystring = {'search_text': demisto.args()['search']}
    e = policy_search(querystring, max_rules_per_device)
    demisto.results(e)


def zone_match(ipaddr):
    """ Find the zone for the given IP address """
    entry: Dict[str, Any] = {
        'Type': entryTypes['note'],
        'Contents': '',
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '',
        'EntryContext': {}
    }

    try:
        zone_list = tos_request('st', 'GET', '/securetrack/api/zones/')
        for zone in zone_list['zones']['zone']:
            zone_subnets = tos_request('st', 'GET', '/securetrack/api/zones/%s/entries' % zone['id'])
            zone.update(zone_subnets)
            for subnet in zone_subnets['zone_entries']['zone_entry']:
                ipnet = '%s/%s' % (subnet['ip'], subnet['prefix'])
                if IPAddress(ipaddr) in IPNetwork(ipnet):
                    z = {}
                    z['Name'] = zone['name']
                    z['ID'] = int(zone['id'])
                    entry['EntryContext']['Tufin1.Zone'] = [z]
                    entry['Contents'] = zone
                    entry['HumanReadable'] = tableToMarkdown('Tufin1 Zone Search for {}'.format(ipaddr),
                                                             {'Name': zone['name'], 'ID': zone['id']},
                                                             ['Name', 'ID'], removeNull=True)
                    return entry
    except Exception as e:
        return_error(f'Error retrieving zone: {str(e)}')
    entry['EntryContext']['Tufin1.Zones'] = [{'Name': 'None', 'ID': 'None'}]
    entry['Contents'] = 'Not Found'
    entry['HumanReadable'] = tableToMarkdown('Tufin1 Zone Search for {}'.format(ipaddr),
                                             {'Name': 'Not Found', 'ID': '0'}, ['Name', 'ID'], removeNull=True)
    return entry


def zone_match_command():
    ipaddr = demisto.getArg('ip')
    e = zone_match(ipaddr)
    demisto.results(e)


def change_req(req_type, subj, priority, src, dst='', proto='', port='', action='', comment=''):
    """ Submit a change request to SecureChange """
    entry: Dict[str, Any] = {
        'Type': entryTypes['note'],
        'Contents': '',
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '',
        'EntryContext': {}
    }
    try:
        if req_type.lower() == 'firewall change request':
            # Check for valid input
            if (dst == '' or proto == '' or port == '' or action == ''
                    or dst is None or proto is None or port is None or action is None):
                return_error('''Request Type, Subject, Priority, Source, Destination, Protocol,
                             Port and Action parameters are mandatory for this request type''')
            if not priority.capitalize() in ['Critical', 'High', 'Normal', 'Low']:
                return_error('Priority must be Critical, High, Normal or Low')
            if not proto.upper() in ['TCP', 'UDP']:
                return_error('Protocol must be TCP or UDP')
            if not action.capitalize() in ['Accept', 'Drop', 'Remove']:
                return_error('Action must be Accept, Drop or Remove')
            if not port.isdigit():
                return_error('Port must be an integer')
            # Build change request JSON
            req = FW_CHANGE_REQ
            req['ticket']['subject'] = subj
            req['ticket']['priority'] = priority.capitalize()
            (req['ticket']['steps']['step'][0]['tasks']['task']['fields']['field']
            ['access_request']['sources']['source'][0]['ip_address']) = src
            (req['ticket']['steps']['step'][0]['tasks']['task']['fields']['field']
            ['access_request']['destinations']['destination'][0]['ip_address']) = dst
            (req['ticket']['steps']['step'][0]['tasks']['task']['fields']['field']
            ['access_request']['services']['service'][0]['protocol']) = proto.upper()
            (req['ticket']['steps']['step'][0]['tasks']['task']['fields']['field']
            ['access_request']['services']['service'][0]['port']) = int(port)
            (req['ticket']['steps']['step'][0]['tasks']['task']['fields']['field']
            ['access_request']['action']) = action.capitalize()
            req['ticket']['comment'] = comment
            tos_request('sc', 'POST', '/securechangeworkflow/api/securechange/tickets', data=json.dumps(req))
            entry['Contents'] = {'status': 'Ticket Created'}
            entry['HumanReadable'] = tableToMarkdown('{} ticket request'.format(req_type),
                                                     {'status': 'Success'}, ['status'], removeNull=True)
            entry['EntryContext']['Tufin1.Request.Status'] = 'Success'
            return entry
        elif req_type.lower() == 'server decommission request':
            # Check for valid input
            if not priority.capitalize() in ['Critical', 'High', 'Normal', 'Low']:
                return_error('Priority must be Critical, High, Normal or Low')
            # Build change request JSON
            req = SERVER_DECOM_REQ
            req['ticket']['subject'] = subj
            req['ticket']['priority'] = priority.capitalize()
            (req['ticket']['steps']['step'][0]['tasks']['task']['fields']['field']
            ['server_decommission_request']['servers']['server']['ip_address']) = src
            req['ticket']['comment'] = comment
            tos_request('st', 'POST', '/securechangeworkflow/api/securechange/tickets', data=json.dumps(req))
            entry['Contents'] = {'status': 'Ticket Created'}
            entry['HumanReadable'] = tableToMarkdown('{} ticket request'.format(req_type),
                                                     {'status': 'Success'}, ['status'], removeNull=True)
            entry['EntryContext']['Tufin1.Request.Status'] = 'Success'
            return entry
    except Exception as e:
        return_error(f'Error submitting request: {str(e)}')
    return entry


def change_req_command():
    req_type = demisto.getArg('request-type')
    subject = demisto.getArg('subject')
    priority = demisto.getArg('priority')
    source = demisto.getArg('source')
    destination = demisto.getArg('destination')
    protocol = demisto.getArg('protocol')
    port = demisto.getArg('port')
    action = demisto.getArg('action')
    comment = demisto.getArg('comment')
    e = change_req(req_type, subject, priority, source, destination, protocol, port, action, comment)
    demisto.results(e)


def dev_search(name='', ip='', vendor='', model=''):
    """ Search SecureTrack Devices """
    entry: Dict[str, Any] = {
        'Type': entryTypes['note'],
        'Contents': '',
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '',
        'EntryContext': {}
    }
    dev_list = []
    try:
        qstr = '?show_os_version=true'
        if not name == '' and name is not None:
            qstr = '{}&name={}'.format(qstr, name)
        if not ip == '' and ip is not None:
            qstr = '{}&ip={}'.format(qstr, ip)
        if not vendor == '' and vendor is not None:
            qstr = '{}&vendor={}'.format(qstr, vendor)
        if not model == '' and model is not None:
            qstr = '{}&model={}'.format(qstr, model)
        url = '/securetrack/api/devices{}'.format(qstr)
        devices = tos_request('st', 'GET', url)
        if devices['devices']['count'] > 0:
            for device in devices['devices']['device']:
                if 'ip' in device.keys():
                    dev_list.append({'ID': int(device['id']), 'Name': device['name'], 'IP': device['ip'],
                                     'Vendor': device['vendor'], 'Model': device['model']})
                else:
                    dev_list.append({'ID': int(device['id']), 'Name': device['name'], 'IP': '0.0.0.0',
                                     'Vendor': device['vendor'], 'Model': device['model']})
            entry['Contents'] = devices
            entry['EntryContext'] = {'Tufin1.Device': dev_list}
            entry['HumanReadable'] = tableToMarkdown('Device Search Results', dev_list,
                                                     ['ID', 'Name', 'IP', 'Vendor', 'Model'], removeNull=True)
    except Exception as e:
        return_error(f'Error submitting request: {str(e)}')
    return entry


def dev_search_command():
    name = demisto.getArg('name')
    ip = demisto.getArg('ip')
    vendor = demisto.getArg('vendor')
    model = demisto.getArg('model')
    e = dev_search(name, ip, vendor, model)
    demisto.results(e)


def change_info(ticket_id):
    """ Get the information from a change request """
    entry: Dict[str, Any] = {
        'Type': entryTypes['note'],
        'Contents': '',
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '',
        'EntryContext': {}
    }
    try:
        url = '/securechangeworkflow/api/securechange/tickets/{}'.format(ticket_id)
        ticket = tos_request('sc', 'GET', url)
        cur_step = ''
        if type(ticket['ticket']['current_step']) != str:
            cur_step = ticket['ticket']['current_step']['name']
        else:
            cur_step = ''
        comments = ''
        if type(ticket['ticket']['comments']) != str:
            for comment in ticket['ticket']['comments']['comment']:
                comments = '{}\n{}: {}'.format(comments, comment['created'], comment['content'])
        else:
            comments = ''
        entry['Contents'] = ticket['ticket']
        chg = {}
        chg['ID'] = ticket['ticket']['id']
        chg['Subject'] = ticket['ticket']['subject']
        chg['Priority'] = ticket['ticket']['priority']
        chg['Status'] = ticket['ticket']['status']
        chg['CurrentStep'] = cur_step
        chg['Requester'] = ticket['ticket']['requester']
        chg['WorkflowID'] = ticket['ticket']['workflow']['id']
        chg['WorkflowName'] = ticket['ticket']['workflow']['name']
        entry['EntryContext']['Tufin1.Ticket'] = [chg]
        entry['HumanReadable'] = tableToMarkdown('Ticket ID {}'.format(ticket_id), {'ID': ticket['ticket']['id'],
                                                                                    'Subject': ticket['ticket'][
                                                                                        'subject'],
                                                                                    'Priority': ticket['ticket'][
                                                                                        'priority'],
                                                                                    'Status': ticket['ticket'][
                                                                                        'status'],
                                                                                    'CurrentStep': cur_step,
                                                                                    'Requester': ticket['ticket'][
                                                                                        'requester'],
                                                                                    'Comments': comments},
                                                 ['ID', 'Subject', 'Priority', 'Status', 'CurrentStep',
                                                  'Requester', 'Comments'])
    except Exception as e:
        return_error(f'Error submitting request: {str(e)}')
    return entry


def change_info_command():
    ticket_id = demisto.getArg('ticket-id')
    e = change_info(ticket_id)
    demisto.results(e)


def app_search(name=''):
    """ Search for applications in SecureApp """
    entry: Dict[str, Any] = {
        'Type': entryTypes['note'],
        'Contents': '',
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '',
        'EntryContext': {}
    }
    try:
        url = '/securechangeworkflow/api/secureapp/repository/applications'
        if name is not None and name != '':
            url = '{}?name={}'.format(url, name)
        apps = tos_request('sa', 'GET', url)
        app_list = []
        for app in apps['applications']['application']:
            app_list.append({'ID': app['id'], 'Name': app['name'], 'Status': app['status'],
                             'Decommissioned': app['decommissioned'], 'OwnerID': app['owner']['id'],
                             'OwnerName': app['owner']['name'], 'Comments': app['comment']})
        entry['Contents'] = app_list
        entry['EntryContext']['Tufin1.App'] = app_list
        entry['HumanReadable'] = tableToMarkdown('Application Search Results', app_list,
                                                 ['ID', 'Name', 'Status', 'OwnerName', 'Comments'], removeNull=True)
    except Exception as e:
        return_error(f'Error submitting request: {str(e)}')
    return entry


def app_search_command():
    name = demisto.getArg('name')
    e = app_search(name)
    demisto.results(e)


def app_conns(app_id):
    """ Get application connections from SecureApp """
    entry: Dict[str, Any] = {
        'Type': entryTypes['note'],
        'Contents': '',
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '',
        'EntryContext': {}
    }
    try:
        url = '/securechangeworkflow/api/secureapp/repository/applications/{}/connections'.format(app_id)
        conns = tos_request('sa', 'GET', url)
        conn_list = []
        conn_md = '### Connections for application ID: {}'.format(app_id)
        for conn in conns['connections']['connection']:
            conn_md = '{}\n#### Connection: {} ({})\nStatus: **{}**\nExternal: **{}**\nComment: **{}**'.format(conn_md,
                                                                                                               conn[
                                                                                                                   'name'],
                                                                                                               conn[
                                                                                                                   'id'],
                                                                                                               conn[
                                                                                                                   'status'],
                                                                                                               conn[
                                                                                                                   'external'],
                                                                                                               conn[
                                                                                                                   'comment'])
            # Get sources
            source_list = []
            conn_md = '{}\n\n**Source:**\nid|type|name\n---|---|---'.format(conn_md)
            for source in conn['sources']['source']:
                source_list.append(source['name'])
                conn_md = '{}\n{} | {} | {}'.format(conn_md, source['id'], source['type'], source['name'])
            # Get destinations
            dest_list = []
            conn_md = '{}\n\n**Destination:**\nid|type|name\n---|---|---'.format(conn_md)
            for dest in conn['destinations']['destination']:
                dest_list.append(dest['name'])
                conn_md = '{}\n{} | {} | {}'.format(conn_md, dest['id'], dest['type'], dest['name'])
            # Get services
            service_list = []
            conn_md = '{}\n\n**Service:**\nid|name\n---|---'.format(conn_md)
            for service in conn['services']['service']:
                service_list.append(service['name'])
                conn_md = '{}\n{} | {}'.format(conn_md, service['id'], service['name'])
            # Add to connection list
            conn_list.append({'ID': conn['id'], 'Name': conn['name'], 'AppID': app_id, 'Status': conn['status'],
                              'External': conn['external'], 'Source': source_list, 'Destination': dest_list,
                              'Service': service_list, 'Comment': conn['comment']})
        entry['Contents'] = conn_list
        entry['EntryContext']['Tufin1.AppConnection'] = conn_list
        entry['HumanReadable'] = conn_md
    except Exception as e:
        return_error(f'Error submitting request: {str(e)}')
    return entry


def app_conns_command():
    app_id = demisto.getArg('application-id')
    e = app_conns(app_id)
    demisto.results(e)


def test_command():
    tos_request('st', 'GET', '/securetrack/api/devices')
    demisto.results('ok')


# Demisto Command Routing
try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_command()
    elif demisto.command() == 'tufin-search-topology':
        path_finder_command()
    elif demisto.command() == 'tufin-object-resolve':
        object_lookup_command()
    elif demisto.command() == 'tufin-search-topology-image':
        path_finder_image_command()
    elif demisto.command() == 'tufin-policy-search':
        policy_search_command()
    elif demisto.command() == 'tufin-get-zone-for-ip':
        zone_match_command()
    elif demisto.command() == 'tufin-submit-change-request':
        change_req_command()
    elif demisto.command() == 'tufin-search-devices':
        dev_search_command()
    elif demisto.command() == 'tufin-get-change-info':
        change_info_command()
    elif demisto.command() == 'tufin-search-applications':
        app_search_command()
    elif demisto.command() == 'tufin-search-application-connections':
        app_conns_command()
except Exception as e:
    return_error(e)

"""    Gigamon ThreatINSIGHT Integration for Cortex XSOAR (aka Demisto)
        
       This integration allows fetching detections, entities, events and 
       saved searches from Gigamon ThreatINSIGHT APIs, also allows for 
       some management operations like creating scheduled pcap tasks, 
       updating detection rules and resolving detections.
"""
''' IMPORTS '''

import requests
import json
import re

# Global for setting up headers
HEADERS = {}
TRAINING_ACC = 'f6f6f836-8bcd-4f5d-bd61-68d303c4f634'
MAX_DETECTIONS = 100

''' HELPER FUNCTIONS '''

def sendRequest(method, api, endpoint=None, data=None, args=None):
    # dump data if supplied
    if data:
        data = json.dumps(data)
    # set api url
    if api == 'Events':
        url = 'https://events.icebrg.io/v2/query/'
    elif api == 'Detections':
        url = 'https://detections.icebrg.io/v1/'
    elif api == 'Sensors':
        url = 'https://sensor.icebrg.io/v1/'
    elif api == 'Entity':
        url = 'https://entity.icebrg.io/v1/entity/'
    # adjust url according to endpoint and args
    if endpoint is not None:
        url = url + endpoint
    if args is not None:
        url = url + args
    # attempt API call
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=HEADERS,
            data=data,
        )
    except requests.exceptions.RequestException:
        return_error('API error')
    # check response
    if response.status_code == 200:
        r_json = response.json()
        return r_json
    elif response.status_code >= 400:
        r_json = response.json()
        demisto.results("Error: " + str(response.status_code) + " " + response.reason + ": "
                        + str(r_json['error']['message']) + "\n" + url)
    else:
        demisto.results(response.reason)


def getArgs():
    args = demisto.args()
    arguments = {}
    for arg in args:
        arguments[arg] = demisto.getArg(arg)
    return arguments


def encodeArgsToURL(args):
    url = ''
    first = True
    for arg in args:
        this_arg = str(arg) + "=" + str(args[arg])
        if first:
            url = url + "?" + this_arg
            first = False
        else:
            url = url + "&" + this_arg
    return url


def formatEvents(r_json, response_type):
    if response_type == "metadata":
        data = []
        metadata = {}
        for field in r_json:
            if field != "events" and field != "aggregations":
                metadata[field] = r_json[field]
        data.append(metadata)
        r_json['data'] = data
    elif response_type == "aggregations":
        # Get group by statement
        for x in r_json['aggregations']:
            group_by = x
        fields = []
        aggregations = []
        for column in r_json['aggregations'][group_by]['columns']:
            fields.append(column['field'])
        for datum in r_json['aggregations'][group_by]['data']:
            aggregation = {}
            for i in range(0, len(fields)):
                aggregation[fields[i]] = datum[i]
            aggregations.append(aggregation)
        r_json['data'] = aggregations
    else:
        for event in r_json['events']:
            # flatten dict values, convert lists to string
            new_fields = {}
            for field in event:
                if isinstance(event[field], list):
                    event[field] = str(json.dumps(event[field]))
                if isinstance(event[field], dict):
                    new_fields.update(flattenFieldDict(field, event[field]))
                    event[field] = "REMOVE"
            event.update(new_fields)
        # remove fields
        for i in range(0, len(r_json['events'])):
            r_json['events'][i] = {k: v for k, v in r_json['events'][i].items() if v != "REMOVE"}
    return r_json


def flattenFieldDict(field, field_dict):
    new_dict = {}
    for key in field_dict:
        if isinstance(field_dict[key], dict):
            new_dict.update(flattenFieldDict(field + "_" + key, field_dict[key]))
        else:
            new_dict[field + "_" + key] = field_dict[key]
    return new_dict


def flattenList(lt):
    string = ''
    for i in range(0, len(lt)):
        if isinstance(lt[i], dict):
            string = string + flattenDict(lt[i])
            if i + 1 < len(lt):
                string = string + "---" + "\n"
        elif isinstance(lt[i], list):
            string = string + flattenList(lt[i])
        else:
            string = string + str(lt[i])
            if i + 1 < len(lt):
                string = string + ", "
    return string


def flattenDict(dt):
    string = ''
    for key in dt:
        if isinstance(dt[key], list):
            string = string + str(key) + ": " + flattenList(dt[key]) + "\n"
        elif isinstance(dt[key], dict):
            string = string + str(key) + ": " + flattenDict(dt[key]) + "\n"
        else:
            string = string + str(key) + ": " + str(dt[key]) + "\n"
    return string


''' COMMANDS + REQUESTS FUNCTIONS '''

def fetchIncidents(account_uuid):
    last_run = demisto.getLastRun()

    if last_run and 'last_run_time' in last_run:
        last_fetch = last_run.get('last_run_time')
    else:
        last_fetch = '2022-01-01T00:00:00.000Z'

    args = {'created_or_shared_start_date': last_fetch, 'include': 'rules', 'limit': '100'}

    if account_uuid:
        args['account_uuid'] = account_uuid

    response = sendRequest('GET', 'Detections', 'detections', None, encodeArgsToURL(args))
    if response['total_count'] > MAX_DETECTIONS:
        # pull the remaining detections incrementally
        response = getDetectionsInc(response, args)
        response = addDetectionRules(response)

    detections = []
    for detection in response['detections']:
        # filter out training detections
        if detection['account_uuid'] != TRAINING_ACC:
            for rule in response['rules']:
                if rule['uuid'] == detection['rule_uuid']:
                    detection['rule_name'] = str(rule['name'])
                    detection['rule_description'] = str(rule['description'])
                    detection['rule_severity'] = str(rule['severity'])
                    detection['rule_category'] = str(rule['category'])
                    detection['rule_confidence'] = str(rule['confidence'])
                    # detection['rule_signature'] = str(rule['signature'])

                    if rule['severity'] == 'high':
                        severity = 3
                    elif rule['severity'] == 'moderate':
                        severity = 2
                    elif rule['severity'] == 'low':
                        severity = 1
                    else:
                        severity = 0

            this_detection = {
                'occurred': detection['first_seen'],
                'name': detection['rule_name'],
                'severity': severity,
                'details': detection['rule_description'].encode("utf-8"),
                'rawJSON': json.dumps(detection),
            }
            detections.append(this_detection)

    demisto.setLastRun({'last_run_time': str(datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"))})
    demisto.incidents(detections)


def getDetectionsInc(r_json, args):
    total_detections = r_json['total_count']
    offset = MAX_DETECTIONS
    while total_detections > MAX_DETECTIONS and offset < total_detections:
        args['offset'] = offset
        response = sendRequest('GET', 'Detections', 'detections', None, encodeArgsToURL(args))
        for detection in response['detections']:
            r_json['detections'].append(detection)
        if 'include' in args:
            if args['include'] == 'rules':
                for rule in response['rules']:
                    r_json['rules'].append(rule)
        offset += MAX_DETECTIONS
    return r_json


def addDetectionRules(r_json):
    for detection in r_json['detections']:
        for rule in r_json['rules']:
            if detection['rule_uuid'] == rule['uuid']:
                rule_name = rule['name']
                rule_description = rule['description']
                rule_severity = rule['severity']
                rule_confidence = rule['confidence']
                rule_category = rule['category']
                rule_signature = rule['query_signature']
        detection.update({'rule_name': rule_name})
        detection.update({'rule_description': rule_description})
        detection.update({'rule_severity': rule_severity})
        detection.update({'rule_confidence': rule_confidence})
        detection.update({'rule_category': rule_category})
        detection.update({'rule_signature': rule_signature})
    return r_json


def responseToEntry(r_json, path, title):
    # set data and type
    data = []
    data_type = title.lower().replace(" ", "_")
    # set context path
    contextPath = "Insight." + path
    context = {contextPath: []}  # type: dict
    # check for exclusions
    if data_type == 'device_list':
        r_json = r_json['devices']
    # iterate based on data type
    if data_type in ('data'):
        for i in range(0, len(r_json[data_type])):
            new_item = {}
            if isinstance(r_json[data_type][i], list):
                for j in range(0, len(r_json[data_type][i])):
                    new_pair = {r_json['columns'][j]: r_json[data_type][i][j]}
                    new_item.update(new_pair)
            elif isinstance(r_json[data_type][i], dict):
                for item in r_json[data_type][i]:
                    if isinstance(r_json[data_type][i][item], int):
                        new_pair = {str(item): int(r_json[data_type][i][item])}
                    else:
                        new_pair = {str(item): str(r_json[data_type][i][item])}
                    new_item.update(new_pair)
            data.append(new_item)
            context[contextPath].append(createContext(new_item))
    elif data_type in ('pcap_task', 'summary', 'file'):
        new_item = {}
        for item in r_json[data_type]:
            if isinstance(r_json[data_type][item], dict):
                r_json[data_type][item] = flattenDict(r_json[data_type][item])
            if isinstance(r_json[data_type][item], list):
                r_json[data_type][item] = flattenList(r_json[data_type][item])
            new_pair = {item: str(r_json[data_type][item])}
            new_item.update(new_pair)
        data.append(new_item)
        context[contextPath].append(createContext(new_item))
    else:
        for item in r_json[data_type]:
            new_item = {}
            for field in item:
                # if there are any unicode characters, encode them to utf8
                if isinstance(item[field], str):
                    item[field] = str(item[field].encode("utf-8"))
                new_pair = {field: str(item[field])}
                new_item.update(new_pair)
            data.append(new_item)
            context[contextPath].append(createContext(new_item))
    # submit results
    demisto.results({'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': data, 'EntryContext': context})


def main():
    # get command and args
    command = demisto.command()
    args = getArgs()
    
    # initialize common args
    api_key = demisto.params().get('api_key')
    account_uuid = demisto.params().get('account_uuid')
    global HEADERS
    HEADERS = {
        'Authorization': 'IBToken ' + api_key,
        'User-Agent': 'Cortex_Insight.v3',
        'Content-Type': 'application/json',
    }
    # attempt command execution
    try:
        if command == 'test-module':
            response = sendRequest('GET', 'Sensors', 'sensors')
            demisto.results('ok')
        if command == 'fetch-incidents':
            fetchIncidents(account_uuid)
        elif command == 'insight-get-events':
            if args['response_type'] == "metadata":
                response_type = "metadata"
            elif args['response_type'] == "aggregations":
                pattern = r"^.*[Gg][Rr][Oo][Uu][Pp]\s+[Bb][Yy].*$"
                if not re.search(pattern, args['query']):
                    demisto.results("Error: No 'group by' statement in query. Aggregation requires a 'group by' statement.")
                else:
                    response_type = "aggregations"
            else:
                response_type = "events"
            args.pop('response_type')
            response = sendRequest('POST', 'Events', None, args)
            response = formatEvents(response, response_type)
            if response_type in ("metadata", "aggregations"):
                responseToEntry(response, 'Events', 'Data')
            else:
                responseToEntry(response, 'Events', 'Events')
        elif command == 'insight-get-history':
            response = sendRequest('GET', 'Events', 'history')
            responseToEntry(response, 'UserQueryHistory', 'History')

        elif command == 'insight-get-saved-searches':
            response = sendRequest('GET', 'Events', 'saved')
            responseToEntry(response, 'SavedSearches', 'Saved Queries')

        elif command == 'insight-get-sensors':
            response = sendRequest('GET', 'Sensors', 'sensors')
            responseToEntry(response, 'Sensors', 'Sensors')

        elif command == 'insight-get-devices':
            response = sendRequest('GET', 'Sensors', 'devices')
            responseToEntry(response, 'Devices', 'Device List')

        elif command == 'insight-get-tasks':
            if 'task_uuid' in args:
                endpoint = 'pcaptasks/' + args['task_uuid']
                response = sendRequest('GET', 'Sensors', endpoint)
                responseToEntry(response, 'Tasks', 'PCAP Task')
            else:
                response = sendRequest('GET', 'Sensors', 'pcaptasks')
                responseToEntry(response, 'Tasks', 'PCAPTasks')

        elif command == 'insight-create-task':
            sensor_ids = [args['sensor_ids']]
            args.pop('sensor_ids')
            args['sensor_ids'] = sensor_ids
            response = sendRequest('POST', 'Sensors', 'pcaptasks', args)
            demisto.results("Task created successfully")

        elif command == 'insight-get-detections':
            response = sendRequest('GET', 'Detections', 'detections', None, encodeArgsToURL(args))
            if response['total_count'] > MAX_DETECTIONS:
                if 'limit' not in args or int(args['limit']) > MAX_DETECTIONS:
                    # pull the remaining detections incrementally
                    response = getDetectionsInc(response, args)
            # filter out training detections
            detections = []
            for detection in response['detections']:
                if detection['account_uuid'] != TRAINING_ACC:
                    detections.append(detection)
            response['detections'] = detections
            if 'include' in args:
                if args['include'] == 'rules':
                    response = addDetectionRules(response)
            responseToEntry(response, 'Detections', 'Detections')

        elif command == 'insight-get-detection-rules':
            response = sendRequest('GET', 'Detections', 'rules', None, encodeArgsToURL(args))
            responseToEntry(response, 'Rules', 'Rules')

        elif command == 'insight-get-detection-rule-events':
            rule_uuid = args['rule_uuid']
            endpoint = "rules/" + rule_uuid + "/events"
            args.pop('rule_uuid')
            response = sendRequest('GET', 'Detections', endpoint, None, encodeArgsToURL(args))
            responseToEntry(response, 'Detections', 'Events')

        elif command == 'insight-resolve-detection':
            endpoint = "detections/" + args['detection_uuid'] + "/resolve"
            body = {"resolution": args['resolution'], "resolution_comment": args['resolution_comment']}
            sendRequest('PUT', 'Detections', endpoint, body, None)
            demisto.results("Detection resolved successfully")

        elif command == 'insight-create-detection-rule':
            run_accts = [args['run_account_uuids']]
            dev_ip_fields = [args['device_ip_fields']]
            args.pop('run_account_uuids')
            args.pop('device_ip_fields')
            args['run_account_uuids'] = run_accts
            args['device_ip_fields'] = dev_ip_fields
            sendRequest('POST', 'Detections', 'rules', args, None)
            demisto.results("Rule created successfully")

        elif command == 'insight-get-entity-summary':
            endpoint = args['entity'] + "/summary"
            response = sendRequest('GET', 'Entity', endpoint, None, None)
            responseToEntry(response, 'Entity.Summary', 'Summary')

        elif command == 'insight-get-entity-pdns':
            endpoint = args['entity'] + "/pdns"
            response = sendRequest('GET', 'Entity', endpoint, None, None)
            responseToEntry(response, 'Entity.PDNS', 'PassiveDNS')

        elif command == 'insight-get-entity-dhcp':
            endpoint = args['entity'] + "/dhcp"
            response = sendRequest('GET', 'Entity', endpoint, None, None)
            responseToEntry(response, 'Entity.DHCP', 'DHCP')

        elif command == 'insight-get-entity-file':
            endpoint = args['hash'] + "/file"
            response = sendRequest('GET', 'Entity', endpoint, None, None)
            responseToEntry(response, 'Entity.File', 'File')

        elif command == 'insight-get-telemetry-events':
            response = sendRequest('GET', 'Sensors', 'telemetry/events', None, encodeArgsToURL(args))
            responseToEntry(response, 'Telemetry.Events', 'Data')

        elif command == 'insight-get-telemetry-network':
            response = sendRequest('GET', 'Sensors', 'telemetry/network', None, encodeArgsToURL(args))
            responseToEntry(response, 'Telemetry.Network', 'Data')

        elif command == 'insight-get-telemetry-packetstats':
            response = sendRequest('GET', 'Sensors', 'telemetry/packetstats', None, encodeArgsToURL(args))
            responseToEntry(response, 'Telemetry.Packetstats', 'Data')
    # catch exceptions
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

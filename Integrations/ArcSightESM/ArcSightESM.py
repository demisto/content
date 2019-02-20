import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """
from collections import deque
from datetime import datetime
import requests

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

""" GLOBALS """
URL, PORT = demisto.params().get('server'), demisto.params().get('port')
BASE_URL = URL.rstrip('/:') + ':' + PORT + '/'
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

REQ_SOAP_BODY = """<?xml version="1.0" encoding="UTF-8"?>
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:act="http://ws.v1.service.resource.manager.product.arcsight.com/activeListService/">
    <soapenv:Header />
        <soapenv:Body>
            <act:{function}>
                <act:authToken>{auth_token}</act:authToken>
                <act:resourceId>{resource_id}</act:resourceId>
                {entryList}
            </act:{function}>
        </soapenv:Body>
    </soapenv:Envelope>
""".format

ENTRY_LIST = "<entryList>{}</entryList>".format
ENTRY = "<entry>{}</entry>".format
COLUMN = "<columns>{}</columns>".format
BODY = "<act:entryList>{}</act:entryList>".format

if not demisto.params().get("proxy", False):
    del os.environ["HTTP_PROXY"]
    del os.environ["HTTPS_PROXY"]
    del os.environ["http_proxy"]
    del os.environ["https_proxy"]


@logger
def int_to_ip(num):
    """ IP stored as an int within the ArcSight DB. This function transform it into IPv4 format """
    if num and isinstance(num, int):
        return "{}.{}.{}.{}".format((num >> 24) & 255, (num >> 16) & 255, (num >> 8) & 255, num & 255)
    return num


@logger
def parse_timestamp_to_datestring(timestamp):
    if timestamp and timestamp > 0:
        try:
            return datetime.fromtimestamp(timestamp / 1000.0).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except (ValueError, TypeError) as e:
            LOG(e.message)
            return timestamp


@logger
def beautifully_json(d, depth=0):
    """ Converts some of the values from ArcSight DB into a more useful & readable format """
    # arcsight stores some None values as follows
    NONE_VALUES = [-9223372036854776000, -9223372036854775808, -2147483648]
    # arcsight stores IP addresses as int, in the following keys
    IP_FIELDS = ['address', 'Destination Address', 'Source Address']
    # arcsight stores Dates as timeStamps in the following keys, need to format them into Date
    TIMESTAMP_FIELDS = ['createdTimestamp', 'modifiedTimestamp', 'deviceReceiptTime', 'startTime', 'endTime',
                        'stageUpdateTime', 'modificationTime', 'managerReceiptTime', 'createTime', 'agentReceiptTime']
    if depth < 10:
        if isinstance(d, list):
            return [beautifully_json(d_, depth + 1) for d_ in d]
        if isinstance(d, dict):
            for key, value in d.items():
                if isinstance(value, dict):
                    beautifully_json(value, depth + 1)
                elif value in NONE_VALUES:
                    d.pop(key, None)
                elif key in IP_FIELDS and isinstance(value, int):
                    d[key] = int_to_ip(value)
                elif key in TIMESTAMP_FIELDS:
                    key = key.replace('Time', 'Date').replace('stamp', '')
                    d[key] = parse_timestamp_to_datestring(value)
    return d


@logger
def login():
    query_path = 'www/core-service/rest/LoginService/login'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }
    params = {
        'login': demisto.get(demisto.params(), 'credentials.identifier'),
        'password': demisto.get(demisto.params(), 'credentials.password'),
        'alt': 'json'
    }
    res = send_request(query_path, headers=headers, params=params)
    if not res.ok:
        demisto.debug(res.text)
        return_error('Failed to login, check integration parameters.')

    try:
        res_json = res.json()
        if 'log.loginResponse' in res_json and 'log.return' in res_json.get('log.loginResponse'):
            auth_token = res_json.get('log.loginResponse').get('log.return')
            demisto.setIntegrationContext({'auth_token': auth_token})
            return auth_token

        return_error('Failed to login. Have not received token after login')
    except ValueError:
        return_error('Failed to login. Please check URL and Credentials')


@logger
def logout():
    query_path = 'www/core-service/rest/LoginService/logout'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }
    params = {
        'authToken': AUTH_TOKEN,
        'alt': 'json'
    }
    res = send_request(query_path, headers=headers, params=params)
    if not res.ok:
        demisto.debug(res.text)
        return_error('Failed to login, check integration parameters.')


@logger
def send_request(query_path, body=None, params=None, json=None, headers=None, method='post'):
    if headers is None:
        headers = HEADERS
    full_url = BASE_URL + query_path
    try:
        res = requests.request(
            method,
            full_url,
            headers=headers,
            verify=VERIFY_CERTIFICATE,
            data=body,
            params=params,
            json=json
        )

        if not res.ok:
            params['authToken'] = login()
            return requests.request(
                method,
                full_url,
                headers=headers,
                verify=VERIFY_CERTIFICATE,
                data=body,
                params=params,
                json=json
            )
        return res

    except Exception as e:
        demisto.debug(e.message.message)
        return_error('Connection Error. Please check URL')


@logger
def test():
    """
    Login (already done in global).
    Test if fetch query viewers are valid.
    Run query viewer if fetch defined.
    """
    events_query_viewer_id = demisto.params().get('events_query_viewer_id')
    cases_query_viewer_id = demisto.params().get('cases_query_viewer_id')
    is_fetch = demisto.params().get('isFetch')

    if is_fetch and not events_query_viewer_id and not cases_query_viewer_id:
        return_error('If fetch is enabled, you must provide query viewer Resource ID for Cases or Events')

    if events_query_viewer_id:
        fields, results = get_query_viewer_results(events_query_viewer_id)
        if 'Event ID' not in fields or 'Start Time' not in fields:
            return_error('Query "{}" must contain "Start Time" and "Event ID" fields'.format(cases_query_viewer_id))

    if cases_query_viewer_id:
        fields, results = get_query_viewer_results(cases_query_viewer_id)
        if 'ID' not in fields or 'Create Time' not in fields:
            return_error('Query "{}" must contain "Create Time" and "ID" fields'.format(cases_query_viewer_id))


@logger
def get_query_viewer_results(query_viewer_id):
    query_path = 'www/manager-service/rest/QueryViewerService/getMatrixData'
    params = {
        'authToken': AUTH_TOKEN,
        'id': query_viewer_id,
        'alt': 'json'
    }
    res = send_request(query_path, params=params, method='get')

    if not res.ok:
        demisto.debug(res.text)
        if 'ResourceNotFoundException' in res.text:
            return_error('Invalid resource ID {} for Query Viewer(ResourceNotFoundException)'.format(query_viewer_id))
        else:
            return_error('Failed to get query viewer results.')

    return_object = None
    res_json = res.json()
    if "qvs.getMatrixDataResponse" in res_json and "qvs.return" in res_json["qvs.getMatrixDataResponse"]:
        # ArcSight ESM version 6.7 & 6.9 rest API supports qvs.getMatrixDataResponse
        return_object = res_json.get("qvs.getMatrixDataResponse").get("qvs.return")

    elif "que.getMatrixDataResponse" in res_json and "que.return" in res_json["que.getMatrixDataResponse"]:
        # ArcSight ESM version 6.1 rest API supports que.getMatrixDataResponse
        return_object = res_json.get("que.getMatrixDataResponse").get("que.return")

    else:
        return_error('Invalid response structure. Open ticket to Demisto support and attach the logs')

    fields = return_object.get('columnHeaders', [])
    if not isinstance(fields, (list,)):
        fields = [fields]

    results = return_object.get("rows", [])
    if not isinstance(results, (list,)):
        results = [results]

    if len(fields) == 0 or len(results) == 0:
        return fields, results

    """
    we parse the rows by column headers and create formatted result

    "columnHeaders": [
        "ID",
        "Event-Event ID",
    ],
    "rows": [
        {
            "@xsi.type": "listWrapper",
            "value": [
                {
                    "@xsi.type": "xs:string",
                    "$": "<ID1>"
                },
                {
                    "@xsi.type": "xs:string",
                    "$": "<Event-Event ID1>"
                }
            ]
        },
        {
            "@xsi.type": "listWrapper",
            "value": [
                {
                    "@xsi.type": "xs:string",
                    "$": "<ID2>"
                },
                {
                    "@xsi.type": "xs:string",
                    "$": "<Event-Event ID2>"
                }
            ]
        }
    ]

    convert to ===>

    query_results = [
        {
            Event-Event ID:<Event-Event ID1>
            ID:<ID1>
        },
        {
            Event-Event ID:<Event-Event ID2>
            ID:<ID2>
        }
    ]
    """
    results = [{field: result.get('value')[idx].get('$') for idx, field in enumerate(fields)} for result in results]
    return fields, results


@logger
def get_query_viewer_results_command():
    resource_id = demisto.args().get('ids')
    columns, query_results = get_query_viewer_results(query_viewer_id=resource_id)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': {'results': query_results}
    })


@logger
def fetch():
    """
    Query viewer should be defined in ArcSight ESM. fetch incidents fetches the results of query viewer
    and converts them to Demisto incidents. We can query Cases or Events. If Cases are fetched then the
    query viewer query must return fields ID and Create Time. If Events are fetched then Event ID and Start Time.
    """
    events_query_viewer_id = demisto.params().get('events_query_viewer_id')
    cases_query_viewer_id = demisto.params().get('cases_query_viewer_id')

    last_run = demisto.getLastRun()
    last_create_time = last_run.get('last_create_time', 0)
    already_fetched = deque(last_run.get('already_fetched', []), maxlen=1000)
    latest_created_time = last_create_time

    fields, query_results = get_query_viewer_results(events_query_viewer_id or cases_query_viewer_id)
    incidents = []
    for result in query_results:
        # convert case or event to demisto incident
        r_id = result.get('ID') or result.get('Event ID')
        create_time = int(result.get('Start Time') or result.get('Create Time'))
        if create_time >= last_create_time or r_id not in already_fetched:
            # check if case/event already was fetched before
            latest_created_time = create_time if create_time > latest_created_time else latest_created_time

            result['Create Time'] = parse_timestamp_to_datestring(create_time)
            incident = {
                'name': 'ArcSight Case #{}'.format(r_id),
                'occurred': result['Create Time'],
                'labels': [{'type': key, 'value': str(value)} for key, value in result.items()],
                'rawJSON': json.dumps(result)
            }
            incidents.append(incident)
            already_fetched.append(r_id)

    last_run['last_create_time'] = latest_created_time
    last_run['already_fetched'] = list(already_fetched)
    demisto.setLastRun(last_run)
    beautifully_json(incidents)

    if demisto.command() == 'as-fetch-incidents':
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {
                'incidents': incidents,
                'last_create_time': latest_created_time,
                'already_fetched': list(already_fetched)}
        })
    demisto.incidents(incidents)


@logger
def get_case(resource_id, fetch_base_events=False):
    query_path = 'www/manager-service/rest/CaseService/getResourceById'
    params = {
        'authToken': AUTH_TOKEN,
        'resourceId': resource_id,
    }
    res = send_request(query_path, params=params, method='get')

    if not res.ok:
        demisto.debug(res.text)
        if 'InvalidResourceIDException: Invalid resource ID' in res.text and 'for Case' in res.text:
            return_error('Invalid resource ID {} for Case'.format(resource_id))
        else:
            return_error('Failed to get case. StatusCode: {}'.format(res.status_code))

    res_json = res.json()
    if 'cas.getResourceByIdResponse' in res_json and 'cas.return' in res_json.get('cas.getResourceByIdResponse'):
        case = res_json.get('cas.getResourceByIdResponse').get('cas.return')

        if 'eventIDs' in case and case['eventIDs'] and isinstance(case['eventIDs'], int):
            # if eventIDs is single id then convert to list
            case['eventIDs'] = [case['eventIDs']]

        if fetch_base_events:
            case['events'] = get_security_events(case['eventIDs'])

        return case

    return_error('Case {} not found'.format(resource_id))


@logger
def get_case_command():
    resource_id = demisto.args().get('resourceId')
    with_base_events = demisto.args().get('withBaseEvents')

    raw_case = get_case(resource_id, fetch_base_events=with_base_events == 'true')
    case = {
        'Name': raw_case.get('name'),
        'EventIDs': raw_case.get('eventIDs'),
        'Action': raw_case.get('action'),
        'Stage': raw_case.get('stage'),
        'CaseID': raw_case.get('resourceid'),
        'Severity': raw_case.get('consequenceSeverity'),
        'CreatedTime': FormatADTimestamp(raw_case.get('createdTimestamp'))
    }
    if with_base_events:
        case['events'] = raw_case.get('events')
    entry_context = beautifully_json(raw_case)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': entry_context,
        'HumanReadable': tableToMarkdown(name='Case {}'.format(resource_id), t=case, removeNull=True),
        'EntryContext': {'ArcSightESM.Cases(val.resourceid===obj.resourceid)': entry_context}
    })


@logger
def get_all_cases_command():
    query_path = 'www/manager-service/rest/CaseService/findAllIds'
    params = {
        'authToken': AUTH_TOKEN,
        'alt': 'json'
    }
    res = send_request(query_path, params=params, method='get')

    if not res.ok:
        demisto.debug(res.text)
        return_error('Failed to get case list. StatusCode: {}'.format(res.status_code))

    all_cases = res.json().get('cas.findAllIdsResponse').get('cas.return')
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': all_cases,
        'HumanReadable': tableToMarkdown(name='All cases', headers='caseID', t=all_cases, removeNull=True),
        'EntryContext': {'ArcSightESM.AllCaseIDs': all_cases}
    })


@logger
def get_security_events_command():
    ids = demisto.args().get('ids')
    last_date_range = demisto.args().get('lastDateRange')

    ids = argToList(ids)
    raw_events = get_security_events(ids, last_date_range)

    if raw_events:
        events = []
        for raw_event in beautifully_json(raw_events):
            event = {
                'Event ID': raw_event.get('eventId'),
                'Time': timestamp_to_datestring(raw_event.get('endTime'), '%Y-%m-%d, %H:%M:%S'),
                'Source Address': int_to_ip(demisto.get(raw_event, 'source.address')),
                'Destination Address': int_to_ip(demisto.get(raw_event, 'destination.address')),
                'Name': raw_event.get('name'),
                'Source Port': demisto.get(raw_event, 'source.port'),
                'Base Event IDs': raw_event.get('baseEventIds')
            }
            events.append(event)

        entry_context = beautifully_json(raw_events)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': entry_context,
            'HumanReadable': tableToMarkdown('Security Event: {}'.format(str(ids)[1:-1]), events, removeNull=True),
            'EntryContext': {'ArcSightESM.SecurityEvents(val.eventId===obj.eventId)': entry_context}
        })
    else:
        demisto.results('No events were found')


@logger
def get_security_events(event_ids, last_date_range=None):
    start_time, end_time = -1, -1
    if last_date_range:
        # Must of format 'number date_range_unit'
        # Examples: (2 hours, 4 minutes, 6 month, 1 day, etc.)
        start_time, end_time = parse_date_range(last_date_range, to_timestamp=True)

    query_path = 'www/manager-service/rest/SecurityEventService/getSecurityEvents'
    params = {
        'alt': 'json'
    }
    json_ = {
        "sev.getSecurityEvents": {
            "sev.authToken": AUTH_TOKEN,
            "sev.ids": event_ids,
            "sev.startMillis": start_time,
            "sev.endMillis": end_time
        }
    }
    res = send_request(query_path, json=json_, params=params)

    if not res.ok:
        demisto.debug(res.text)
        return_error(
            'Failed to get security events with ids {}.\nFull URL: {}\nStatus Code: {}\nResponse Body: {}'.format(
                event_ids, BASE_URL + query_path, res.status_code, res.text))

    res_json = res.json()
    if res_json.get('sev.getSecurityEventsResponse') and res_json.get('sev.getSecurityEventsResponse').get(
            'sev.return'):
        events = res_json.get('sev.getSecurityEventsResponse').get('sev.return')
        return events if isinstance(events, list) else [events]

    return_error('Events are empty for some reason. Response Body: {}'.format(res.text))


@logger
def update_case_command():
    case_id = demisto.args().get('caseId')
    stage = demisto.args().get('stage')
    severity = demisto.args().get('severity')

    raw_updated_case = update_case(case_id, stage, severity)
    updated_case = {
        'Name': raw_updated_case.get('name'),
        'EventIDs': raw_updated_case.get('eventIDs'),
        'Action': raw_updated_case.get('action'),
        'Stage': raw_updated_case.get('stage'),
        'CaseID': raw_updated_case.get('resourceid'),
        'Severity': raw_updated_case.get('consequenceSeverity'),
        'CreatedTime': FormatADTimestamp(raw_updated_case.get('createdTimestamp'))
    }
    entry_context = beautifully_json(raw_updated_case)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': entry_context,
        'HumanReadable': tableToMarkdown(name='Case {}'.format(case_id), t=updated_case, removeNull=True),
        'EntryContext': {'ArcSightESM.Cases(val.resourceid===obj.resourceid)': entry_context}
    })


@logger
def update_case(case_id, stage, severity):
    # get the case from arcsight
    case = get_case(case_id)
    case['stage'] = stage
    case['consequenceSeverity'] = severity if severity else case['consequenceSeverity']

    # update its stage and send it back to arcsight
    query_path = 'www/manager-service/rest/CaseService/update'
    params = {
        'alt': 'json'
    }
    json_ = {
        "cas.update": {
            "cas.authToken": AUTH_TOKEN,
            "cas.resource": case,
        }
    }
    res = send_request(query_path, json=json_, params=params)

    if not res.ok:
        demisto.debug(res.text)
        return_error('Failed to get security update case {}\nFull URL: {}\nStatus Code: {}\nResponse Body: {}'.format(
            case_id, BASE_URL + query_path, res.status_code, res.text))

    res_json = res.json()
    if 'cas.updateResponse' in res_json and 'cas.return' in res_json.get('cas.updateResponse'):
        return case

    return_error('Failed to update case, fail to parse response. Response Body: {}'.format(res.text))


@logger
def get_case_event_ids_command():
    case_id = demisto.args().get('caseId')

    query_path = 'www/manager-service/rest/CaseService/getCaseEventIDs'
    params = {
        'authToken': AUTH_TOKEN,
        'caseId': case_id
    }

    res = send_request(query_path, params=params, method='get')
    if not res.ok:
        demisto.debug(res.text)
        return_error("Failed to get Event IDs with:\nStatus Code: {}\nResponse: {}".format(res.status_code, res.text))

    res_json = res.json()
    if 'cas.getCaseEventIDsResponse' in res_json and 'cas.return' in res_json.get('cas.getCaseEventIDsResponse'):
        event_ids = res_json.get('cas.getCaseEventIDsResponse').get('cas.return')
        if not isinstance(event_ids, list):
            event_ids = [event_ids]

        entry_context = beautifully_json(res_json)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': entry_context,
            'HumanReadable': tableToMarkdown(name='Case {}'.format(case_id), headers='Event ID', t=event_ids,
                                             removeNull=True),
            'EntryContext': {'ArcSightESM.CaseEvents': event_ids}
        })
    else:
        demisto.results('No IDs were found')


@logger
def delete_case_command():
    case_id = demisto.args().get('caseId')

    query_path = 'www/manager-service/rest/CaseService/deleteByUUID'
    req_body = json.dumps({
        'cas.deleteByUUID': {
            'cas.authToken': AUTH_TOKEN,
            'cas.id': case_id
        }
    })
    params = {
        'alt': 'json'
    }
    res = send_request(query_path, params=params, body=req_body)
    if not res.ok:
        demisto.debug(res.text)
        return_error("Failed to delete case:\nStatus Code: {}\nResponse: {}".format(res.status_code, res.text))


@logger
def get_entries_command():
    resource_id = demisto.args().get('resourceId')
    entry_filter = demisto.args().get('entryFilter')

    query_path = 'www/manager-service/services/ActiveListService/'
    body = REQ_SOAP_BODY(function='getEntries', auth_token=AUTH_TOKEN, resource_id=resource_id, entryList=None)

    res = send_request(query_path, body=body)

    if not res.ok:
        demisto.debug(res.text)
        return_error("Failed to get entries:\nResource ID: {}\nStatus Code: {}\nRequest Body: {}\nResponse: {}".format(
            resource_id, res.status_code, body, res.text))

    res_json = json.loads(xml2json(res.text))
    raw_entries = demisto.get(res_json, 'Envelope.Body.getEntriesResponse.return')
    if 'entryList' in raw_entries:
        entry_list = raw_entries['entryList'] if isinstance(raw_entries['entryList'], list) else [
            raw_entries['entryList']]
        entry_list = [d['entry'] for d in entry_list if 'entry' in d]
        keys = raw_entries.get('columns')
        entries = [dict(zip(keys, values)) for values in entry_list]
        filtered = entries
        # if the user wants only entries that contain certain 'field:value' sets (filters)
        # e.g., "name:myName,eventId:0,:ValueInUnknownField"
        # if the key is empty, search in every key
        if entry_filter:
            for f in entry_filter.split(','):
                k, v = f.split(':')
                filtered = [entry for entry in filtered if ((entry.get(k) == v) if k else (v in entry.values()))]

        entry_context = beautifully_json(filtered)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': entry_context,
            'HumanReadable': tableToMarkdown(name='Active List entries', t=filtered, removeNull=True),
            'EntryContext': {'ArcSightESM.ActiveList.{id}'.format(id=resource_id): entry_context}
        })
    else:
        demisto.results('No Entries were found for this Active List.')


@logger
def clear_entries_command():
    resource_id = demisto.args().get('resourceId')
    query_path = 'www/manager-service/services/ActiveListService/'
    body = REQ_SOAP_BODY(function='clearEntries', auth_token=AUTH_TOKEN, resource_id=resource_id, entryList=None)
    res = send_request(query_path, body=body)

    if not res.ok:
        demisto.debug(res.text)
        return_error(
            "Failed to clear entries with:\nResource ID: {}\nStatus Code: {}\nRequest Body: {}\nResponse: {}".format(
                resource_id, res.status_code, body, res.text))

    demisto.results("Success")


@logger
def add_entries_command():
    resource_id = demisto.args().get('resourceId')
    entries = demisto.args().get('entries')
    query_path = 'www/manager-service/services/ActiveListService/'
    if not isinstance(entries, dict):
        try:
            entries = json.loads(entries)
        except ValueError as e:
            demisto.debug(e.message.message)
            return_error('Entries must be in JSON format. Must be array of objects.')
        if not all([entry.keys() == entries[0].keys() for entry in entries[1:]]):
            return_error('All entries must have the same fields')

    columns = ''.join(COLUMN(column) for column in entries[0])  # the fields in the entryList matrix are the columns
    entry_list = BODY(columns + ''.join(ENTRY_LIST(''.join(ENTRY(v) for v in en.values())) for en in entries))
    body = REQ_SOAP_BODY(function='addEntries', auth_token=AUTH_TOKEN, resource_id=resource_id, entryList=entry_list)
    res = send_request(query_path, body=body)

    if not res.ok:
        demisto.debug(res.text)
        return_error(
            "Failed to clear entries with:\nResource ID: {}\nStatus Code: {}\nRequest Body: {}\nResponse: {}".format(
                resource_id, res.status_code, body, res.text))

    demisto.results("Success")


@logger
def get_all_query_viewers_command():
    query_path = 'www/manager-service/rest/QueryViewerService/findAllIds'
    params = {
        'authToken': AUTH_TOKEN,
        'alt': 'json'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }
    res = send_request(query_path, headers=headers, params=params)
    if not res.ok:
        demisto.debug(res.text)
        return_error("Failed to get query viewers:\nStatus Code: {}\nResponse: {}".format(res.status_code, res.text))

    res_json = res.json()
    if 'qvs.findAllIdsResponse' in res_json and 'qvs.return' in res_json.get('qvs.findAllIdsResponse'):
        query_viewers = res_json.get('qvs.findAllIdsResponse').get('qvs.return')

        entry_context = beautifully_json(query_viewers)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': entry_context,
            'HumanReadable': tableToMarkdown(name='Query Viewers', t=query_viewers, headers='Query Viewers ID',
                                             removeNull=True),
            'EntryContext': {'ArcSightESM.AllQueryViewers': entry_context}
        })
    else:
        demisto.results('No Query Viewers were found')


AUTH_TOKEN = demisto.getIntegrationContext().get('auth_token') or login()
try:
    if demisto.command() == 'test-module':
        test()
        demisto.results('ok')

    elif demisto.command() == 'as-fetch-incidents' or demisto.command() == 'fetch-incidents':
        if demisto.args().get('lastRun'):
            last_run = json.loads(demisto.args().get('lastRun'))
            demisto.setLastRun(last_run)

        fetch()

    elif demisto.command() == 'as-get-matrix-data' or demisto.command() == 'as-get-query-viewer-results':
        get_query_viewer_results_command()

    elif demisto.command() == 'as-get-all-cases':
        get_all_cases_command()

    elif demisto.command() == 'as-get-case':
        get_case_command()

    elif demisto.command() == 'as-update-case':
        update_case_command()

    elif demisto.command() == 'as-case-delete':
        delete_case_command()

    elif demisto.command() == 'as-get-security-events':
        get_security_events_command()

    elif demisto.command() == 'as-get-entries':
        get_entries_command()

    elif demisto.command() == 'as-add-entries':
        add_entries_command()

    elif demisto.command() == 'as-clear-entries':
        clear_entries_command()

    elif demisto.command() == 'as-get-case-event-ids':
        get_case_event_ids_command()

    elif demisto.command() == 'as-get-all-query-viewers':
        get_all_query_viewers_command()

    LOG.print_log()


except Exception, e:
    LOG(e.message)
    LOG.print_log()
    return_error(e.message)
finally:
    logout()

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


""" GLOBALS """
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


@logger
def int_to_ip(num):
    return f"{(num >> 24) & 255}.{(num >> 16) & 255}.{(num >> 8) & 255}.{num & 255}"


@logger
def decode_ip(address_by_bytes):
    """ Decodes the enigmatic ways IPs are stored in ArcSight DB into IPv4/6 format """
    str_address_by_bytes = str(address_by_bytes)
    if is_ip_valid(str_address_by_bytes) or is_ipv6_valid(str_address_by_bytes):
        return address_by_bytes

    if isinstance(address_by_bytes, int):
        return int_to_ip(address_by_bytes)

    try:
        # if it's not an int, it should be Base64 encoded string
        decoded_string = base64.b64decode(address_by_bytes).hex()
        if len(address_by_bytes) >= 20:
            # split the IPv6 address into 8 chunks of 4
            decoded_string = [decoded_string[i:i + 4] for i in range(0, len(decoded_string), 4)]  # type: ignore
            return "{}:{}:{}:{}:{}:{}:{}:{}".format(*decoded_string)
        elif len(address_by_bytes) >= 6:
            decoded_string = int(decoded_string, 16)  # type: ignore
            return int_to_ip(decoded_string)
        else:
            return address_by_bytes

    except Exception as e:
        # sometimes ArcSight would not encode IPs, this will cause the decoder to
        # throw an exception, and in turn, we will return the input in its original form.
        demisto.debug(str(e))
        return address_by_bytes


@logger
def parse_timestamp_to_datestring(timestamp):
    if timestamp and timestamp > 0:
        try:
            return datetime.fromtimestamp(timestamp / 1000.0).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except (ValueError, TypeError) as e:
            demisto.debug(str(e))
            if timestamp == '31 Dec 1969 19:00:00 EST':
                # Unix epoch 00:00:00 UTC
                return 'None'
            return timestamp
    return None


@logger
def decode_arcsight_output(d, depth=0, remove_nones=True):
    """ Converts some of the values from ArcSight DB into a more useful & readable format """
    # ArcSight stores some None values as follows
    NONE_VALUES = [-9223372036854776000, -9223372036854775808, -2147483648, 5e-324]
    # ArcSight stores IP addresses as int, in the following keys
    IP_FIELDS = ['address', 'addressAsBytes', 'Destination Address', 'Source Address']
    # ArcSight stores Dates as timeStamps in the following keys, -> reformat into Date
    TIMESTAMP_FIELDS = ['createdTimestamp', 'modifiedTimestamp', 'deviceReceiptTime', 'startTime', 'endTime',
                        'stageUpdateTime', 'modificationTime', 'managerReceiptTime', 'createTime', 'agentReceiptTime']
    if depth < 10:
        if isinstance(d, list):
            return [decode_arcsight_output(d_, depth + 1) for d_ in d]
        if isinstance(d, dict):
            for key, value in d.copy().items():
                if isinstance(value, list):
                    for value_ in value:
                        decode_arcsight_output(value_, depth + 1)
                if isinstance(value, dict):
                    decode_arcsight_output(value, depth + 1)
                elif value in NONE_VALUES:
                    if remove_nones:
                        d.pop(key, None)
                    else:
                        d[key] = 'None'

                elif key in IP_FIELDS:
                    key = 'decodedAddress' if key == 'addressAsBytes' else key
                    d[key] = decode_ip(value)
                elif key in TIMESTAMP_FIELDS:
                    key = key.replace('Time', 'Date').replace('stamp', '')
                    d[key] = parse_timestamp_to_datestring(value)
                elif key in ['eventId', 'baseEventIds']:
                    d[key] = str(value)
                elif isinstance(value, int) and value > 10000000000000000:
                    # the platform rounds number larger than 10000000000000000
                    # so we cast them to string to keep as is
                    d[key] = str(value)
                elif isinstance(value, bytes):
                    d[key] = value.decode()
    return d


@logger
def filter_entries(entries, entry_filter):
    """ Filters the entries according to the entry_filter given """
    if not entry_filter:
        return entries

    filtered_entries = []
    filters = entry_filter.split(',')
    for entry in entries:
        append_flag = True

        for f in filters:
            k, v = f.split(':')
            if k:
                if entry.get(k) != v:
                    # if there is a key and its value is not equal to the entry_filter value
                    append_flag = False
            elif v not in entry.values():
                # if there is no key check that the value exists in one of the entry's keys
                append_flag = False

        if append_flag:
            filtered_entries.append(entry)

    return filtered_entries


def repair_malformed_json(malformed_json: str) -> str:
    """
    Repairs a malformed JSON string by properly escaping quotes within dollar-sign ($) values.

    This function addresses a specific issue where quotes within dollar-sign values are not
    properly escaped, causing JSON parsing errors. It splits the input string into segments,
    identifies dollar-sign values, and escapes inner quotes while preserving the outermost quotes.

    Args:
        malformed_json (str): The input string containing malformed JSON data.

    Returns:
        str: A repaired JSON string with properly escaped quotes within dollar-sign values.

    Example:
        >>> malformed_json = '{"$": "value "with" quotes"}, {"$": "another "quoted" value"}'
        >>> repaired_json = repair_malformed_json(malformed_json)
        >>> print(repaired_json)
        '{"$": "value \\"with\\" quotes"}, {"$": "another \\"quoted\\" value"}'
    """
    def find_unescaped_quotes(json_value: str) -> List[int]:
        quote_positions = []
        search_start = 0
        while True:
            quote_pos = json_value.find('\"', search_start)
            if quote_pos == -1:  # No more occurrences found
                break
            # Check if the quote is already escaped
            if quote_pos == 0 or json_value[quote_pos - 1] != '\\':
                quote_positions.append(quote_pos)
            search_start = quote_pos + 1  # Move start position to just after the found index
        return quote_positions

    def escape_inner_quotes(json_value, quote_indices):
        # We need to escape all quotes except the first and last found quotes
        json_chars = list(json_value)
        for i in range(1, len(quote_indices) - 1):  # Skip first and last quotes
            json_chars[quote_indices[i]] = '\\"'
        return ''.join(json_chars)

    # Split the text by "},{"
    parts = malformed_json.split('},{')

    modified_parts = []
    for part in parts:
        # Split by "$": and get the last part
        dollar_key_parts = part.split('"$":')

        if len(dollar_key_parts) > 1:
            prefix = '"$":'.join(dollar_key_parts[:-1]) + '"$":'  # Keep all parts before the last `"$":`
            json_value = dollar_key_parts[-1].strip()  # Get the last value

            quote_positions = find_unescaped_quotes(json_value)

            if '\"' in json_value and len(quote_positions) > 2:
                json_value = escape_inner_quotes(json_value, quote_positions)
            modified_parts.append(prefix + json_value)
        else:
            modified_parts.append(part)

    # Join the parts back together
    return '},{'.join(modified_parts)


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
    res = send_request(query_path, headers=headers, body=params, is_login=True)
    if not res.ok:
        demisto.debug(res.text)
        return_error('Failed to login, check integration parameters.')

    try:
        res_json = parse_json_response(res)
        if 'log.loginResponse' in res_json and 'log.return' in res_json.get('log.loginResponse'):
            auth_token = res_json.get('log.loginResponse').get('log.return')
            if demisto.command() not in ['test-module', 'fetch-incidents']:
                # this is done to bypass setting integration context outside of the cli
                demisto.setIntegrationContext({'auth_token': auth_token})
            return auth_token

        return_error('Failed to login. Have not received token after login')
    except ValueError:
        return_error('Failed to login. Please check integration parameters')


def send_request(query_path, body=None, params=None, json=None, headers=None, method='post', is_login=False):
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

        if not res.ok and not is_login:
            if params and not body:
                params['authToken'] = login()
            elif 'Authorization' in headers:
                headers['Authorization'] = f'Bearer {login()}'
            else:
                body = body.replace(demisto.getIntegrationContext().get('auth_token'), login())
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

    except Exception as ex:
        demisto.debug(str(ex))
        return_error('Connection Error. Please check integration parameters')


def test():
    """
    Login (already done in global).
    Test if fetch query viewers are valid.
    Run query viewer if fetch defined.
    """
    events_query_viewer_id = demisto.params().get('viewerId')
    cases_query_viewer_id = demisto.params().get('casesQueryViewerId')
    is_fetch = demisto.params().get('isFetch')

    if is_fetch and not events_query_viewer_id and not cases_query_viewer_id:
        return_error('If fetch is enabled, you must provide query viewer Resource ID for Cases or Events')

    if events_query_viewer_id:
        fields, results = get_query_viewer_results(events_query_viewer_id)
        if 'Event ID' not in fields or 'Start Time' not in fields:
            return_error(f'Query "{events_query_viewer_id}" must contain "Start Time" and "Event ID" fields')

    if cases_query_viewer_id:
        fields, results = get_query_viewer_results(cases_query_viewer_id)
        if 'ID' not in fields or 'Create Time' not in fields:
            return_error(f'Query "{cases_query_viewer_id}" must contain "Create Time" and "ID" fields')


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
            return_error(f'Invalid resource ID {query_viewer_id} for Query Viewer(ResourceNotFoundException)')
        else:
            return_error('Failed to get query viewer results.')

    return_object = None
    res_json = parse_json_response(res)

    if "qvs.getMatrixDataResponse" in res_json and "qvs.return" in res_json["qvs.getMatrixDataResponse"]:
        # ArcSight ESM version 6.7 & 6.9 rest API supports qvs.getMatrixDataResponse
        return_object = res_json.get("qvs.getMatrixDataResponse").get("qvs.return")

    elif "que.getMatrixDataResponse" in res_json and "que.return" in res_json["que.getMatrixDataResponse"]:
        # ArcSight ESM version 6.1 rest API supports que.getMatrixDataResponse
        return_object = res_json.get("que.getMatrixDataResponse").get("que.return")

    else:
        return_error('Invalid response structure. Open ticket to Demisto support and attach the logs')
        return None

    fields = return_object.get('columnHeaders', [])
    if not isinstance(fields, list):
        fields = [fields]

    results = return_object.get("rows", [])
    if not isinstance(results, list):
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
    resource_id = demisto.args().get('id')
    only_columns = demisto.args().get('onlyColumns')
    columns, query_results = get_query_viewer_results(query_viewer_id=resource_id)

    demisto.debug('printing Query Viewer column headers')
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': columns,
        'HumanReadable': tableToMarkdown(name='', headers='Column Headers', t=columns, removeNull=True)
    })
    if only_columns == 'false':
        demisto.debug('printing Query Viewer results')

        contents = query_results
        human_readable = tableToMarkdown(name=f'Query Viewer Results: {resource_id}', t=contents,
                                         removeNull=True)
        outputs = {'ArcSightESM.QueryViewerResults': contents}
        return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)


@logger
def fetch():
    """
    Query viewer should be defined in ArcSight ESM. fetch incidents fetches the results of query viewer
    and converts them to Demisto incidents. We can query Cases or Events. If Cases are fetched then the
    query viewer query must return fields ID and Create Time. If Events are fetched then Event ID and Start Time.
    """
    events_query_viewer_id = demisto.params().get('viewerId')
    cases_query_viewer_id = demisto.params().get('casesQueryViewerId')
    type_of_incident = 'case' if events_query_viewer_id else 'event'
    last_run = json.loads(demisto.getLastRun().get('value', '{}'))
    already_fetched = last_run.get('already_fetched', [])

    fields, query_results = get_query_viewer_results(events_query_viewer_id or cases_query_viewer_id)
    # sort query_results by creation time
    query_results.sort(key=lambda k: int(k.get('Start Time') or k.get('Create Time')))

    incidents = []
    for result in query_results:
        # convert case or event to demisto incident
        r_id = result.get('ID') or result.get('Event ID')
        if r_id not in already_fetched:
            create_time_epoch = int(result.get('Start Time') or result.get('Create Time'))
            result['Create Time'] = parse_timestamp_to_datestring(create_time_epoch)
            incident_name = result.get('Name') or f'New {type_of_incident} from arcsight at {datetime.now()}'
            labels = [{'type': key.encode('utf-8'), 'value': value.encode('utf-8') if value else value} for key, value
                      in result.items()]
            incident = {
                'name': incident_name,
                'occurred': result['Create Time'],
                'labels': labels,
                'rawJSON': json.dumps(result)
            }

            incidents.append(incident)

            if len(already_fetched) > MAX_UNIQUE:
                already_fetched.pop(0)
            already_fetched.append(r_id)

            if len(incidents) >= FETCH_CHUNK_SIZE:
                break

    last_run = {
        'already_fetched': already_fetched,
    }
    demisto.setLastRun({'value': json.dumps(last_run)})
    decode_arcsight_output(incidents)

    if demisto.command() == 'as-fetch-incidents':
        contents = {
            'last_run': last_run,
            'last_run_updated': demisto.getLastRun(),
            'incidents': incidents,
            'already_fetched': already_fetched
        }
        return_outputs(readable_output='', outputs={}, raw_response=contents)
    else:
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
            return_error(f'Invalid resource ID {resource_id} for Case')
        else:
            return_error(f'Failed to get case. StatusCode: {res.status_code}')

    res_json = parse_json_response(res)
    if 'cas.getResourceByIdResponse' in res_json and 'cas.return' in res_json.get('cas.getResourceByIdResponse'):
        case = res_json.get('cas.getResourceByIdResponse').get('cas.return')

        if case.get('eventIDs') and not isinstance(case['eventIDs'], list):
            # if eventIDs is single id then convert to list
            case['eventIDs'] = [case['eventIDs']]

        if case.get('eventIDs') and fetch_base_events:
            case['events'] = decode_arcsight_output(get_security_events(case['eventIDs'], ignore_empty=True),
                                                    remove_nones=False)

        return case

    return_error(f'Case {resource_id} not found')
    return None


@logger
def get_case_command():
    resource_id = demisto.args().get('resourceId')
    with_base_events = demisto.args().get('withBaseEvents') == 'true'

    raw_case = get_case(resource_id, fetch_base_events=with_base_events)
    case = {
        'Name': raw_case.get('name'),
        'EventIDs': raw_case.get('eventIDs'),
        'Action': raw_case.get('action'),
        'Stage': raw_case.get('stage'),
        'CaseID': raw_case.get('resourceid'),
        'Severity': raw_case.get('consequenceSeverity'),
        'CreatedTime': epochToTimestamp(raw_case.get('createdTimestamp'))
    }
    if with_base_events:
        case['events'] = raw_case.get('events')

    contents = decode_arcsight_output(raw_case)
    if contents.get('events'):
        contents['events'] = decode_arcsight_output(contents['events'])
    human_readable = tableToMarkdown(name=f'Case {resource_id}', t=case, removeNull=True)
    outputs = {'ArcSightESM.Cases(val.resourceid===obj.resourceid)': contents}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)


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
        return_error(f'Failed to get case list. StatusCode: {res.status_code}')

    res_json = parse_json_response(res)
    contents = res_json.get('cas.findAllIdsResponse').get('cas.return')
    human_readable = tableToMarkdown(name='All cases', headers='caseID', t=contents, removeNull=True)
    outputs = {'ArcSightESM.AllCaseIDs': contents}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)


@logger
def get_security_events_command():
    ids = demisto.args().get('ids')
    last_date_range = demisto.args().get('lastDateRange')
    ids = argToList(str(ids) if isinstance(ids, int) else ids)
    raw_events = get_security_events(ids, last_date_range)
    if raw_events:
        events = []
        contents = decode_arcsight_output(raw_events)
        for raw_event in contents:
            event = {
                'Event ID': raw_event.get('eventId'),
                'Time': timestamp_to_datestring(raw_event.get('endTime'), '%Y-%m-%d, %H:%M:%S'),
                'Source Address': decode_ip(demisto.get(raw_event, 'source.address')),
                'Destination Address': decode_ip(demisto.get(raw_event, 'destination.address')),
                'Name': raw_event.get('name'),
                'Source Port': demisto.get(raw_event, 'source.port'),
                'Base Event IDs': raw_event.get('baseEventIds')
            }
            events.append(event)

        human_readable = tableToMarkdown('Security Event: {}'.format(','.join(map(str, ids))), events, removeNull=True)
        outputs = {'ArcSightESM.SecurityEvents(val.eventId===obj.eventId)': contents}
        return_outputs(human_readable, outputs, contents)
    else:
        demisto.results('No events were found')


@logger
def get_security_events(event_ids, last_date_range=None, ignore_empty=False):
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
            f'Failed to get security events with ids {event_ids}.\n'
            f'Full URL: {BASE_URL + query_path}\nStatus Code: {res.status_code}\nResponse Body: {res.text}'
        )

    res_json = parse_json_response(res)
    if res_json.get('sev.getSecurityEventsResponse') and res_json.get('sev.getSecurityEventsResponse').get(
            'sev.return'):
        events = res_json.get('sev.getSecurityEventsResponse').get('sev.return')
        return events if isinstance(events, list) else [events]

    demisto.debug(res.text)
    if not ignore_empty:
        demisto.results('No events were found')
        return None
    return None


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
        'CreatedTime': epochToTimestamp(raw_updated_case.get('createdTimestamp'))
    }
    contents = decode_arcsight_output(raw_updated_case)
    human_readable = tableToMarkdown(name=f'Case {case_id}', t=updated_case, removeNull=True)
    outputs = {'ArcSightESM.Cases(val.resourceid===obj.resourceid)': contents}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)


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
        return_error(f'Failed to get security update case {case_id}. \nPlease make sure user have edit permissions,'
                     f' or case is unlocked. \nStatus Code: {res.status_code}\nResponse Body: {res.text}')

    res_json = parse_json_response(res)
    if 'cas.updateResponse' in res_json and 'cas.return' in res_json.get('cas.updateResponse'):
        return case

    return_error(f'Failed to update case, fail to parse response. Response Body: {res.text}')
    return None


@logger
def get_correlated_events_ids(event_ids):
    related_ids = set(event_ids)
    correlated_events = decode_arcsight_output(get_security_events(event_ids, ignore_empty=True))

    if correlated_events:
        for raw_event in correlated_events:
            base_event_ids = raw_event.get('baseEventIds')
            if base_event_ids:
                if isinstance(base_event_ids, list):
                    related_ids.update(base_event_ids)
                else:
                    related_ids.add(base_event_ids)

    return list(related_ids)


@logger
def get_case_event_ids_command():
    case_id = demisto.args().get('caseId')
    with_correlated_events = demisto.args().get('withCorrelatedEvents') == 'true'
    query_path = 'www/manager-service/rest/CaseService/getCaseEventIDs'
    params = {
        'authToken': AUTH_TOKEN,
        'caseId': case_id
    }

    res = send_request(query_path, params=params, method='get')
    if not res.ok:
        demisto.debug(res.text)
        return_error(f"Failed to get Event IDs with:\nStatus Code: {res.status_code}\nResponse: {res.text}")

    res_json = parse_json_response(res)
    if 'cas.getCaseEventIDsResponse' in res_json and 'cas.return' in res_json.get('cas.getCaseEventIDsResponse'):
        event_ids = res_json.get('cas.getCaseEventIDsResponse').get('cas.return')
        if not isinstance(event_ids, list):
            event_ids = [event_ids]

        if with_correlated_events:
            event_ids = get_correlated_events_ids(event_ids)

        contents = decode_arcsight_output(res_json)
        human_readable = tableToMarkdown(name='', headers=f'Case {case_id} Event IDs', t=event_ids,
                                         removeNull=True)
        outputs = {'ArcSightESM.CaseEvents': event_ids}
        return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)
    else:
        demisto.results('No result returned')


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
        return_error(f"Failed to delete case.\nStatus Code: {res.status_code}\nResponse: {res.text}")

    entry_context = {
        'resourceid': case_id,
        'deleted': 'True'
    }
    contents = f'Case {case_id}  was deleted successfully'
    human_readable = f'Case {case_id} successfully deleted'
    outputs = {'ArcSightESM.Cases(val.resourceid===obj.resourceid)': entry_context}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)


@logger
def get_entries_command(use_rest, args):
    resource_id = args.get('resourceId')
    entry_filter = args.get('entryFilter')

    if use_rest:
        query_path = 'www/manager-service/rest/ActiveListService/getEntries'
        params = {
            'alt': 'json'
        }
        body = {
            "act.getEntries": {
                "act.authToken": AUTH_TOKEN,
                "act.resourceId": resource_id,
            }
        }  # type: Union[str, Dict[str, Dict[str, Any]]]
        res = send_request(query_path, json=body, params=params)
    else:
        query_path = 'www/manager-service/services/ActiveListService/'
        body = REQ_SOAP_BODY(function='getEntries', auth_token=AUTH_TOKEN, resource_id=resource_id, entryList=None)
        res = send_request(query_path, body=body)

    if not res.ok:
        demisto.debug(res.text)
        return_error(
            f"Failed to get entries:\nResource ID: {resource_id}\n"
            f"Status Code: {res.status_code}\nRequest Body: {body}\nResponse: {res.text}"
        )

    if use_rest:
        res_json = parse_json_response(res)
        raw_entries = res_json.get('act.getEntriesResponse', {}).get('act.return', {})
    else:
        res_json = json.loads(xml2json((res.text).encode('utf-8')))
        raw_entries = demisto.get(res_json, 'Envelope.Body.getEntriesResponse.return')

    # retrieve columns
    cols = demisto.get(raw_entries, 'columns')
    if cols:
        hr_columns = tableToMarkdown(name='', headers=['Columns'], t=cols,
                                     removeNull=True) if cols else 'Active list has no columns'
        contents = cols
        return_outputs(readable_output=hr_columns, outputs={}, raw_response=contents)

    if 'entryList' in raw_entries:
        entry_list = raw_entries['entryList'] if isinstance(raw_entries['entryList'], list) else [
            raw_entries['entryList']]
        entry_list = [(d['entry'] if not isinstance(d['entry'], STRING_TYPES) else (d['entry'],)) for d in entry_list if
                      'entry' in d]
        keys = raw_entries.get('columns')
        entries = [dict(zip(keys, values)) for values in entry_list]

        # if the user wants only entries that contain certain 'field:value' sets (filters)
        # e.g., "name:myName,eventId:0,:ValueInUnknownField"
        # if the key is empty, search in every key
        filtered_entries = filter_entries(entries, entry_filter)

        contents = decode_arcsight_output(filtered_entries)
        ActiveListContext = {
            'ResourceID': resource_id,
            'Entries': contents,
        }
        outputs = {
            f'ArcSightESM.ActiveList.{resource_id}': contents,
            'ArcSightESM.ActiveList(val.ResourceID===obj.ResourceID)': ActiveListContext
        }
        human_readable = tableToMarkdown(name=f'Active List entries: {resource_id}', t=filtered_entries,
                                         removeNull=True)
        return_outputs(readable_output=human_readable, outputs=outputs, raw_response=entries)

    else:
        demisto.results('Active List has no entries')


@logger
def clear_entries_command(use_rest, args):
    resource_id = args.get('resourceId')

    if use_rest:
        query_path = 'www/manager-service/rest/ActiveListService/clearEntries'
        params = {
            'alt': 'json'
        }
        body = {
            "act.clearEntries": {
                "act.authToken": AUTH_TOKEN,
                "act.resourceId": resource_id,
            }
        }  # type: Union[str, Dict[str, Dict[str, Any]]]
        res = send_request(query_path, json=body, params=params)
    else:
        query_path = 'www/manager-service/services/ActiveListService/'
        body = REQ_SOAP_BODY(function='clearEntries', auth_token=AUTH_TOKEN, resource_id=resource_id, entryList=None)
        res = send_request(query_path, body=body)

    if not res.ok:
        demisto.debug(res.text)
        return_error(
            f"Failed to clear entries.\nResource ID: {resource_id}\n"
            f"Status Code: {res.status_code}\nRequest Body: {body}\nResponse: {res.text}"
        )

    demisto.results("Success")


@logger
def entries_command(func):
    resource_id = demisto.args().get('resourceId')
    entries = demisto.args().get('entries')
    query_path = 'www/manager-service/services/ActiveListService/'
    if not isinstance(entries, dict):
        try:
            entries = json.loads(entries)
        except ValueError as ex:
            demisto.debug(str(ex))
            return_error('Entries must be in JSON format. Must be array of objects.')
        if not all(entry.keys() == entries[0].keys() for entry in entries[1:]):
            return_error('All entries must have the same fields')

    columns = ''.join(COLUMN(column) for column in entries[0])  # the fields in the entryList matrix are the columns
    entry_list = BODY(columns + ''.join(ENTRY_LIST(''.join(ENTRY(v) for v in en.values())) for en in entries))
    body = REQ_SOAP_BODY(function=func, auth_token=AUTH_TOKEN, resource_id=resource_id, entryList=entry_list)
    res = send_request(query_path, body=body)

    if not res.ok:
        demisto.debug(res.text)
        return_error(f"Failed to {func}. Please make sure to enter Active List resource ID"
                     f"\nResource ID: {resource_id}\nStatus Code: {res.status_code}\nRequest Body: {body}\nResponse: {res.text}")

    demisto.results("Success")


def add_entries_command(args):
    resource_id = args.get('resourceId')
    entries_arg = args.get('entries')
    query_path = f'detect-api/rest/activelists/{resource_id}/entries'
    fields = []
    entries = []

    if not isinstance(entries_arg, list):
        try:
            entries_arg = json.loads(entries_arg)

        except ValueError as ex:
            demisto.error(str(ex))
            raise ValueError('entries must be in JSON format. Must be array of objects.')

    if len(entries_arg) > 0:
        if len(entries_arg) > 0:
            fields = list(entries_arg[0].keys())

        if not all(entry.keys() == entries_arg[0].keys() for entry in entries_arg[1:]):
            return_error('All entries must have the same fields')

        for entry_input in entries_arg:
            entry = []
            for k in fields:
                val = entry_input[k]
                entry.append(val)

            entries.append({
                'fields': entry
            })

    body = {
        'fields': fields,
        'entries': entries
    }
    headers = HEADERS
    headers['Authorization'] = f'Bearer {AUTH_TOKEN}'

    body = json.dumps(body)
    res = send_request(query_path, body=body)

    if not res.ok:
        raise ValueError(
            "Failed to add entries. Please make sure to enter Active List resource ID"
            f"\nResource ID: {resource_id}\nStatus Code: {res.status_code}\n"
            f"Request Body: {body}\nResponse: {res.text}"
        )

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
        return_error(f"Failed to get query viewers:\nStatus Code: {res.status_code}\nResponse: {res.text}")

    res_json = parse_json_response(res)
    if 'qvs.findAllIdsResponse' in res_json and 'qvs.return' in res_json.get('qvs.findAllIdsResponse'):
        query_viewers = res_json.get('qvs.findAllIdsResponse').get('qvs.return')

        contents = decode_arcsight_output(query_viewers)
        outputs = {'ArcSightESM.AllQueryViewers': contents}
        human_readable = tableToMarkdown(name='', t=query_viewers, headers='Query Viewers', removeNull=True)
        return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)

    else:
        demisto.results('No Query Viewers were found')


def parse_json_response(response: requests.Response):
    """
    Parse the response to JSON.
    If the parsing fails due to an invalid escape sequence, the function will attempt to fix the response data.

    Args:
        response: The response to parse.

    Raises:
        JSONDecodeError: If the response data could not be parsed to JSON.
    """
    try:
        return response.json()

    except requests.exceptions.JSONDecodeError as e:
        demisto.debug(f'Failed to parse response to JSON.\n'
                      f'HTTP status code: {response.status_code}\n'
                      f'Headers: {response.headers}\n'
                      f'Response:\n{response.text}\n\n'
                      'Attempting to fix invalid escape sequences and parse the response again.')

        # Replace triple backslashes (where the last one doesn't escape anything) with two backslashes.
        fixed_response_text = re.sub(r'(?<!\\)((\\\\)*)\\(?![\\"])', r'\1\\\\', response.text)

        try:
            fixed_response_json = json.loads(fixed_response_text)

        except json.JSONDecodeError as json_error:
            demisto.debug(f'Failed to parse fixed response as JSON. Error: {json_error}')
            demisto.debug('Attempt two to fix the modified response as JSON.')
            try:
                fixed_response_json = json.loads(repair_malformed_json(fixed_response_text))
            except json.JSONDecodeError:
                demisto.debug('Failed to parse modified response as JSON. Raising original exception.')
                raise e  # Raise the original exception

        demisto.debug('Response successfully parsed after fixing invalid escape sequences.')
        return fixed_response_json


AUTH_TOKEN: str
MAX_UNIQUE: int
FETCH_CHUNK_SIZE: int
BASE_URL: str
VERIFY_CERTIFICATE: bool


def main():
    global BASE_URL
    BASE_URL = demisto.params().get('server').rstrip('/') + '/'

    handle_proxy()

    global MAX_UNIQUE
    MAX_UNIQUE = int(demisto.params().get('max_unique', 2000))

    global FETCH_CHUNK_SIZE
    FETCH_CHUNK_SIZE = int(demisto.params().get('fetch_chunk_size', 50))
    FETCH_CHUNK_SIZE = min(300, FETCH_CHUNK_SIZE)  # fetch size should no exceed 300

    global VERIFY_CERTIFICATE
    VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)

    use_rest = demisto.params().get('use_rest', False)

    global AUTH_TOKEN
    AUTH_TOKEN = demisto.getIntegrationContext().get('auth_token') or login()

    use_detect_api = demisto.params().get('productVersion') == '7.4 and above'

    try:
        if demisto.command() == 'test-module':
            test()
            demisto.results('ok')

        elif demisto.command() == 'as-fetch-incidents' or demisto.command() == 'fetch-incidents':
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
            get_entries_command(use_rest, demisto.args())

        elif demisto.command() == 'as-add-entries':
            if use_detect_api:
                add_entries_command(demisto.args())
            else:
                entries_command(func='addEntries')

        elif demisto.command() == 'as-delete-entries':
            entries_command(func='deleteEntries')

        elif demisto.command() == 'as-clear-entries':
            clear_entries_command(use_rest, demisto.args())

        elif demisto.command() == 'as-get-case-event-ids':
            get_case_event_ids_command()

        elif demisto.command() == 'as-get-all-query-viewers':
            get_all_query_viewers_command()

    except Exception as e:
        return_error('Error:' + str(e), error=traceback.format_exc())


# python2 uses __builtin__ python3 uses builtins
if __name__ in ("__builtin__", "builtins", "__main__"):
    main()

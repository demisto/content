import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

"""

IMPORTS

"""
from datetime import datetime, timedelta

import requests
import json
import re

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

"""

HELPERS

"""


def dict_list_to_str(dict_list):
    """

    parses a list of dictionaries into a string representation

    """
    if not dict_list:
        return ''
    string_list = []
    for dict in dict_list:
        key_values = ["{}: {}".format(k, v) for k, v in dict.items()]
        string_list.append(', '.join(key_values))
    return '\n'.join(string_list)


"""

AUTHENTICATION

"""


def get_token_request(username, password):
    """

    returns a token on successful get_token request

    raises an exception on:

        - http request failure
        - response status code different from 200
        - response body does not contain valid json (ValueError)

    """
    username_password = "username={}&password={}".format(username, password)
    url = '{}/auth/userpass'.format(BASE_PATH)
    get_token_headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=ISO-8859-1',
        'Accept': 'application/json; charset=UTF-8',
        'NetWitness-Version': VERSION
    }

    response = requests.post(url, headers=get_token_headers, data=username_password, verify=USE_SSL)

    # successful get_token
    if response.status_code == 200:
        return response.json()
    # bad request - NetWitness returns a common json structure for errors
    error_lst = response.json().get('errors')
    raise ValueError('get_token failed with status: {}\n{}'.format(response.status_code, dict_list_to_str(error_lst)))


def get_token():
    """

    returns a token to be used in future requests to NetWitness server

    raises an exception on:

        - unexpected response from the server

    """
    LOG('Attempting to get token')
    response_body = get_token_request(
        USERNAME,
        PASSWORD
    )
    LOG('Token received')
    token = response_body.get('accessToken')
    if not token:
        raise ValueError('Failed to access get_token token (Unexpected response)')
    return token


"""

GLOBAL VARS

"""
SERVER_URL = demisto.params()['server']
BASE_PATH = '{}/rest/api'.format(SERVER_URL)
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
USE_SSL = not demisto.params()['insecure']
VERSION = demisto.params()['version']
IS_FETCH = demisto.params()['isFetch']
FETCH_TIME = demisto.params().get('fetch_time', '1 days')
FETCH_LIMIT = int(demisto.params().get('fetch_limit', '100'))
TOKEN = None
DEFAULT_HEADERS = {
    'Content-Type': 'application/json;charset=UTF-8',
    'Accept': 'application/json; charset=UTF-8',
    'NetWitness-Version': VERSION
}

"""

COMMAND HANDLERS

"""


def http_request(method, url, body=None, headers=None, url_params=None):
    """
    returns the http response body

    uses TOKEN global var to send requests to RSA end (this enables using a token for multiple requests and avoiding
     unnecessary creation of a new token)
    catches and handles token expiration: in case of 'request timeout' the  token will be renewed and the request
    will be resent once more.

    """

    if headers is None:
        headers = {}
    global TOKEN

    # add token to headers
    headers['NetWitness-Token'] = TOKEN

    request_kwargs = {
        'headers': headers,
        'verify': USE_SSL
    }

    # add optional arguments if specified
    if body is not None:
        request_kwargs['data'] = body
    if url_params is not None:
        request_kwargs['params'] = url_params

    LOG('Attempting {} request to {}\nWith params:{}\nWith body:\n{}'.format(method, url,
                                                                             json.dumps(url_params, indent=4),
                                                                             json.dumps(body, indent=4)))
    response = requests.request(
        method,
        url,
        **request_kwargs
    )
    # handle timeout (token expired): renew token and try again
    if response.status_code == 408:
        LOG('Timeout detected -  renewing token')
        TOKEN = get_token()
        headers['NetWitness-Token'] = TOKEN
        response = requests.request(
            method,
            url,
            **request_kwargs
        )
    # successful request
    if response.status_code == 200:
        try:
            return response.json()
        except Exception as e:
            demisto.debug('Could not parse response as a JSON.\nResponse is: {}.'
                          '\nError is: {}'.format(response.content, e.message))
            return None
    # bad request - NetWitness returns a common json structure for errors; a list of error objects
    error_lst = response.json().get('errors')
    raise ValueError('Request failed with status: {}\n{}'.format(response.status_code, dict_list_to_str(error_lst)))


def get_incident_request(incident_id):
    """

    returns the response body

    raises an exception on:

        - http request failure
        - response status code different from 200
        - response body does not contain valid json (ValueError)

    """
    url = '{}/incidents/{}'.format(BASE_PATH, incident_id)

    response = http_request(
        'GET',
        url,
        headers=DEFAULT_HEADERS
    )
    return response


def get_incident():
    """

    return incidents main attributes to the war room

    raises an exception on:
        - missing arguments
    """
    args = demisto.args()
    incident_id = args.get('incidentId')
    LOG('Requesting information on incident ' + incident_id)
    # call get_incident_request(), given user arguments
    # returns the response body on success
    # raises an exception on failed request
    incident = get_incident_request(
        incident_id
    )

    md_content = create_incident_md_table(incident)
    md_title = "## NetWitness Get Incident {}".format(incident_id)

    entry = {
        'Type': entryTypes['note'],
        'Contents': incident,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '\n'.join([md_title, md_content]),
        'EntryContext': {
            "NetWitness.Incidents(obj.id==val.id)": incident
        }
    }
    demisto.results(entry)


def get_incidents_request(since=None, until=None, page_number=None, page_size=10):
    """

    returns the response body

    arguments:
        - keywords: url params

    raises an exception on:

        - http request failure
        - response status code diff from 200
        - response body does not contain valid json (ValueError)

    """

    url_params = {
        'since': since,
        'until': until,
        'pageNumber': page_number,
        'pageSize': page_size
    }
    url = '{}/incidents'.format(BASE_PATH)

    response = http_request(
        'GET',
        url,
        headers=DEFAULT_HEADERS,
        url_params=url_params
    )
    return response


def get_all_incidents(since=None, until=None, limit=None, page_number=0):
    """

    returns
    1. all/up to limit incidents in a time window
    2. has_next
    3. next_page

    """

    # if limit is None, set to infinity
    if not limit:
        limit = float('inf')
    page_size = 10 if limit > 10 else limit
    has_next = True
    incidents = []  # type: list
    LOG('Requesting for incidents in timeframe of: {s} - {u}'.format(s=since or 'not specified',
                                                                     u=until or 'not specified'))
    while has_next and limit > len(incidents):
        # call get_incidents_request(), given user arguments
        # returns the response body on success
        # raises an exception on failed request
        LOG('Requesting for page {}'.format(page_number))
        response_body = get_incidents_request(
            since=since,
            until=until,
            page_number=page_number,
            page_size=page_size
        )
        incidents.extend(response_body.get('items'))
        has_next = response_body.get('hasNext')
        page_number += 1

    # if incidents list larger then limit - fit to limit
    if len(incidents) > limit:
        incidents = incidents[:limit]

    return incidents, has_next, page_number


def get_all_incidents_from_beginning(since=None, until=None, limit=None, page_number=0, last_fetched_id=None):
    """

    returns
    1. all/up to limit incidents in a time window
    2. has_next
    3. next_page

    """
    # if limit is None, set to infinity
    if not limit:
        limit = float('inf')
    has_next = True
    incidents_result = []  # type: list
    continue_loop = True
    LOG('Requesting for incidents in timeframe of: {s} - {u}'.format(s=since or 'not specified',
                                                                     u=until or 'not specified'))
    while has_next and continue_loop:
        # call get_incidents_request(), given user arguments
        # returns the response body on success
        # raises an exception on failed request
        LOG('Requesting for page {}'.format(page_number))
        response_body = get_incidents_request(
            since=since,
            until=until,
            page_number=page_number,
            page_size=30,
        )

        if not response_body:
            break

        incidents = response_body.get('items')
        # clear incidents after last_fetched_id
        for inc in incidents:
            if inc.get('id') == last_fetched_id:
                continue_loop = False
                break
            incidents_result.append(inc)
        has_next = response_body.get('hasNext')
        page_number += 1

    incidents_result.reverse()
    # if incidents list larger then limit - fit to limit
    if len(incidents_result) > limit:
        return incidents_result[:limit]
    return incidents_result


def get_incidents():
    """

    returns list of incidents in a specific time window to the war room (main attributes only)

    raises an exception on:
        - missing arguments
    """
    args = demisto.args()

    # validate one of the following was passed - until, since
    if not any([args.get('since'), args.get('until'), args.get('lastDays')]):
        raise ValueError(
            "Please provide one or both of the following parameters: since, until. Alternatively, use lastDays")

    num_of_days = args.get('lastDays')
    if num_of_days:
        since = datetime.now() - timedelta(days=int(num_of_days))
        # convert to ISO 8601 format and add Z suffix
        timestamp = since.isoformat() + 'Z'
        args['since'] = timestamp
        args['until'] = None

    limit = args.get('limit')
    # parse limit argument to int
    if limit:
        limit = int(limit)
    page_number = args.get('pageNumber')
    if page_number:
        page_number = int(page_number)

    incidents, has_next, next_page = get_all_incidents(
        since=args.get('since'),
        until=args.get('until'),
        limit=limit,
        page_number=page_number
    )

    md_content = create_incidents_list_md_table(incidents)
    md_title = "## NetWitness Get Incidents"

    entry = {
        'Type': entryTypes['note'],
        'Contents': incidents,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '\n'.join([md_title, md_content]),
        'EntryContext': {
            "NetWitness.Incidents(obj.id==val.id)": incidents
        }
    }
    if has_next:
        entry['HumanReadable'] += '\n### Not all incidents were fetched. Next page: {}'.format(next_page)
    demisto.results(entry)


def update_incident_request(incident_id, assignee=None, status=None):
    """
    returns the response body

    arguments:
        - keywords: url params

    raises an exception on:

        - http request failure
        - response status code diff from 200
        - response body does not contain valid json (ValueError)

    """
    LOG('Requesting to update incident ' + incident_id)

    body = {
        'assignee': assignee,
        'status': status
    }
    url = '{}/incidents/{}'.format(BASE_PATH, incident_id)
    response = http_request(
        'PATCH',
        url,
        headers=DEFAULT_HEADERS,
        body=json.dumps(body)
    )
    return response


def update_incident():
    """

    returns the updated incident main attributes

    raises an exception on:
        - missing arguments
    """

    args = demisto.args()

    # validate at least one of the following was passed: status, assignee.
    if not any([args.get('status'), args.get('assignee')]):
        raise ValueError("Please provide one or both of the following parameters: status, assignee.")

    # call update_incident_request(), given user arguments
    # returns the response body on success
    # raises an exception on failed request
    incident = update_incident_request(
        args.get('incidentId'),
        status=args.get('status'),
        assignee=args.get('assignee')
    )

    md_content = create_incident_md_table(incident)

    entry = {
        'Type': entryTypes['note'],
        'Contents': incident,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "## NetWitness Update Incident\n" + md_content,
        'EntryContext': {
            "NetWitness.Incidents(obj.id==val.id)": incident
        }
    }
    demisto.results(entry)


def delete_incident_request(incident_id):
    """
    returns the response body

    arguments:
        - incident_id: the id of the incident to delete

    raises an exception on:

        - http request failure
        - response status code diff from 204

    """
    LOG('Requesting to delete incident ' + incident_id)
    url = '{}/incidents/{}'.format(BASE_PATH, incident_id)
    response = http_request(
        'DELETE',
        url,
        headers=DEFAULT_HEADERS
    )
    return response


def delete_incident():
    """

    returns a success message to the war room

    """

    args = demisto.args()
    incident_id = args.get('incidentId')

    # call delete_incident_request() function
    # no return value on successful request
    # raises an exception on failed request
    delete_incident_request(
        incident_id
    )

    entry = {
        'Type': entryTypes['note'],
        'Contents': 'Incident {} deleted successfully'.format(incident_id),
        'ContentsFormat': formats['text']
    }
    demisto.results(entry)


def get_alerts_request(incident_id, page_number=None, page_size=None):
    """
    returns the response body

    arguments:
        - incident_id: the id of the incident

    raises an exception on:

        - http request failure
        - response status code diff from 204

    """

    url = '{}/incidents/{}/alerts'.format(BASE_PATH, incident_id)
    url_params = {
        'pageNumber': page_number,
        'pageSize': page_size
    }

    response = http_request(
        'GET',
        url,
        headers=DEFAULT_HEADERS,
        url_params=url_params
    )
    return response


def get_all_alerts(incident_id):
    """
    returns the alerts that are associated with an incident

    """
    has_next = True
    page_number = 0
    alerts = []  # type: list

    LOG('Requesting for data on alerts related to incident ' + incident_id)
    while has_next:
        # call get_alerts_request(), given user arguments
        # returns the response body on success
        # raises an exception on failed request
        LOG('Requesting for page {}'.format(page_number))
        response_body = get_alerts_request(
            incident_id,
            page_number=page_number
        )
        alerts.extend(response_body.get('items'))
        has_next = response_body.get('hasNext')
        page_number += 1

    return alerts


def get_alerts():
    """
    returns all alerts associated with an incident to the war room

    """
    args = demisto.args()
    incident_id = args.get('incidentId')
    alerts = get_all_alerts(
        incident_id
    )

    alerts_parsed = []
    for alert in alerts:
        # add incident id for each alert
        alert['incidentId'] = incident_id

        # parse each alert to markdown representation, to display in the war room
        parsed_alert = parse_alert_to_md_representation(alert)
        alerts_parsed.append(parsed_alert)

    md_content = '\n'.join(alerts_parsed)
    title = '## Incident {} Alerts'.format(incident_id)

    entry = {
        'Type': entryTypes['note'],
        'Contents': alerts,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '\n'.join([title, md_content]),
        'EntryContext': {
            "NetWitness.Alerts(obj.id==val.id)": alerts
        }
    }
    demisto.results(entry)


def get_timestamp(timestamp):
    """Gets a timestamp and parse it

    Args:
        timestamp (str): timestamp

    Returns:
        datetime

    Examples:
        ("2019-08-13T09:56:02.000000Z", "2019-08-13T09:56:02.440")

    """
    new_timestamp = timestamp
    iso_format = "%Y-%m-%dT%H:%M:%S.%fZ"
    if not new_timestamp.endswith('Z'):  # Adds Z if somehow previous task didn't
        new_timestamp += 'Z'
    timestamp_min_four_position = new_timestamp[-4]
    if timestamp_min_four_position == ':':  # if contains no milisecs
        new_timestamp = new_timestamp[:-1] + '.00000Z'
    elif timestamp_min_four_position == '.':  # if contains only 3 milisecs
        new_timestamp = new_timestamp[:-1] + '000Z'
    try:
        return datetime.strptime(new_timestamp, iso_format)
    except ValueError:
        raise ValueError("Could not parse timestamp [{}]".format(timestamp))


def fetch_incidents():
    """
    By default, fetch is limited to 100 results, however it is user configurable.
    """
    last_run = demisto.getLastRun()

    # if last timestamp was recorded- use it, else generate timestamp for one day prior to current date
    if last_run and last_run.get('timestamp'):
        timestamp = last_run.get('timestamp')
        last_fetched_id = last_run.get('last_fetched_id')
    else:
        last_fetch, _ = parse_date_range(FETCH_TIME)
        # convert to ISO 8601 format and add Z suffix
        timestamp = last_fetch.isoformat() + 'Z'
        last_fetched_id = None

    LOG('Fetching incidents since {}'.format(timestamp))
    netwitness_incidents = get_all_incidents_from_beginning(
        since=timestamp,
        limit=FETCH_LIMIT,
        last_fetched_id=last_fetched_id
    )

    demisto_incidents = []
    iso_format = "%Y-%m-%dT%H:%M:%S.%fZ"

    last_incident_datetime = get_timestamp(timestamp)
    last_incident_timestamp = timestamp

    # set boolean flag for fetching alerts per incident
    import_alerts = demisto.params().get('importAlerts')

    for incident in netwitness_incidents:
        incident_timestamp = incident.get('created')
        if incident_timestamp == timestamp:
            continue

        # parse timestamp to datetime format to be able to compare with last_incident_datetime
        try:
            incident_datetime = datetime.strptime(incident_timestamp, iso_format)
        except ValueError:
            incident_datetime = datetime.strptime(incident_timestamp, "%Y-%m-%dT%H:%M:%SZ")
        if incident_datetime > last_incident_datetime:
            # update last_incident_datetime
            last_incident_datetime = incident_datetime
            last_incident_timestamp = incident_timestamp

        # add to incident object an array of all related alerts
        if import_alerts:
            try:
                incident['alerts'] = get_all_alerts(incident.get('id'))
            except ValueError:
                LOG('Failed to fetch alerts related to incident ' + incident.get('id'))
        demisto_incidents.append(parse_incident(incident))

    demisto.incidents(demisto_incidents)
    last_run = {'timestamp': last_incident_timestamp}
    if netwitness_incidents:
        last_run['last_fetched_id'] = netwitness_incidents[-1].get('id')
    demisto.setLastRun(last_run)
    return demisto_incidents


def parse_incident(netwitness_incident):
    incident_fields = [
        'id',
        'title',
        'summary',
        'riskScore',
        'status',
        'alertCount',
        'created',
        'lastUpdated',
        'assignee',
        'sources',
        'categories'
    ]
    incident_labels = [{'type': field, 'value': json.dumps(netwitness_incident.get(field))} for field in
                       incident_fields]
    alerts = netwitness_incident.get('alerts')
    if alerts:
        alerts_ids = [alert.get('id') for alert in alerts]
        incident_labels.append({'type': 'alerts ids', 'value': ', '.join(alerts_ids)})
    incident = {
        'name': netwitness_incident.get('title'),
        'occurred': netwitness_incident.get('created'),
        'severity': priority_to_severity(netwitness_incident.get('priority')),
        'labels': incident_labels,
        'rawJSON': json.dumps(netwitness_incident)
    }
    return incident


"""

ADDITIONAL FUNCTIONS

"""


def create_incident_md_table(incident):
    # list of fields to be presented in 'incident details' md table, by order of appearance
    incident_entry_fields = [
        'id',
        'title',
        'summary',
        'riskScore',
        'status',
        'alertCount',
        'created',
        'lastUpdated',
        'assignee',
        'sources',
        'categories'
    ]

    # list of fields to be presented in 'journal' md table, by order of appearance
    journal_entry_fields = [
        'created',
        'author',
        'notes',
        'milestone'
    ]

    # create incident entry
    incident_entry = {k: v for k, v in incident.items() if k in incident_entry_fields}

    # if category field exists and not empty - update incident entry 'category' field with a
    # short string representation of the categories-list as value
    categories = incident.get('categories')
    if categories:
        incident_entry['categories'] = ', '.join(
            ["{}:{}".format(category['parent'], category['name']) for category in categories])
    else:
        incident_entry['categories'] = ''

    # if source fields exists and not empty - update incident entry 'source' field with a short string
    # representation of the source-list as value
    source_list = incident.get('sources')
    if source_list and source_list[0]:
        incident_entry['sources'] = ', '.join(source_list)
    else:
        incident_entry['sources'] = ''

    incident_table = tableToMarkdown(
        'Incident Details',
        incident_entry,
        headers=incident_entry_fields,
        headerTransform=header_transformer
    )

    # if journalEntries field exists and not empty - create journal entry
    journal = incident.get('journalEntries')
    journal_table = ''
    if journal:
        journal_entry = [{k: v for k, v in enrty.items() if k in journal_entry_fields} for enrty in journal]
        journal_table = tableToMarkdown(
            'Incident Journal',
            journal_entry,
            headers=journal_entry_fields,
            headerTransform=header_transformer
        )

    md_content = '\n'.join([incident_table, journal_table])
    return md_content


def create_incidents_list_md_table(incidents):
    # list of fields to be presented in 'incident details' md table, by order of appearance
    incident_entry_fields = [
        'id',
        'title',
        'summary',
        'riskScore',
        'status',
        'alertCount',
        'created',
        'lastUpdated',
        'assignee',
        'sources',
        'categories'
    ]

    incidents_list = []
    for incident in incidents:
        # create incident entry to hold the fields to be presented in the md table
        incident_entry = {k: v for k, v in incident.items() if k in incident_entry_fields}
        # if category field exists and not empty - update incident entry 'category' field with a
        # short string representation of the categories-list as value
        categories = incident.get('categories')
        if categories:
            incident_entry['categories'] = ', '.join(
                ["{}:{}".format(category['parent'], category['name']) for category in categories])
        else:
            incident_entry['categories'] = ''

        # if source fields exists and not empty - update incident entry 'source' field with a
        # short string representation of the source-list as value
        source_list = incident.get('sources')
        if source_list:
            incident_entry['sources'] = ', '.join(source_list)
        else:
            incident_entry['sources'] = ''

        incidents_list.append(incident_entry)

    incident_table = tableToMarkdown(
        'Incident Details',
        incidents_list,
        headers=incident_entry_fields,
        headerTransform=header_transformer
    )

    return incident_table


def parse_alert_to_md_representation(alert):
    # list of fields to be presented in 'alert details' md table, by order of appearance
    alert_entry_fields = [
        'id',
        'title',
        'detail',
        'created',
        'source',
        'riskScore',
        'type'
    ]

    alert_entry = {k: v for k, v in alert.items() if k in alert_entry_fields}
    alert_events = alert.get('events', [])

    # add 'total events' to alert entry
    alert_entry['totalEvents'] = len(alert_events)
    alert_entry_fields.append('totalEvents')

    alert_md_table = tableToMarkdown(
        'Alert Details',
        alert_entry,
        headers=alert_entry_fields,
        headerTransform=header_transformer
    )

    events = []
    for event in alert_events:
        events.append(parse_event_to_md_representation(event))

    events_md = '\n'.join(events)
    md_content = '\n'.join([alert_md_table, events_md])
    return md_content


def parse_event_to_md_representation(event):
    event_details = "### Event Details \
    \n*Domain:* {domain} \
    \n*Source:* {source} \
    \n*ID:* {id} \
    ".format(
        domain=event.get('domain', ''),
        source=event.get('eventSource', ''),
        id=event.get('eventSourceId', '')
    )

    event_source = event.get('source')
    event_destination = event.get('destination')

    def parse_device(device):
        device_entry = {
            'Device IP': device.get('ipAddress'),
            'Device Port': device.get('port'),
            'Device MAC': device.get('macAddress'),
            'DNS Hostname': device.get('dnsHostname'),
            'DNS Domain': device.get('dnsDomain')
        }
        return device_entry

    def parse_user(user):
        user_entry = {
            'User UserName': user.get('username'),
            'User Email': user.get('emailAddress'),
            'Active Directory UserName': user.get('adUsername'),
            'Active Directory Domain': user.get('adDomain')
        }
        return user_entry

    # resource table headers in order of appearance
    all_headers = [
        'Device IP',
        'Device Port',
        'Device MAC',
        'DNS Hostname',
        'DNS Domain',
        'User UserName',
        'User Email',
        'Active Directory UserName',
        'Active Directory Domain'
    ]

    def resource_md(resource, resource_type):
        resource_entry = {}  # type: dict
        device = resource.get('device')
        user = resource.get('user')
        resource_entry.update(parse_device(device))
        resource_entry.update(parse_user(user))
        # reduce headers to fields that hold actual value in resource_entry
        headers = [field for field in all_headers if resource_entry.get(field)]
        resource_md = tableToMarkdown(
            resource_type,
            resource_entry,
            headers=headers)
        return resource_md

    source_md = resource_md(event_source, 'Source')
    destination_md = resource_md(event_destination, 'Destination')

    md_content = '\n'.join([event_details, source_md, destination_md])
    return md_content


def header_transformer(header):
    """
    e.g. input: 'someHeader' output: 'Some Header '

    """

    return re.sub("([a-z])([A-Z])", "\g<1> \g<2>", header).capitalize()


def priority_to_severity(priority):
    """
    coverts NetWitness priority to Demisto severity grade

    input:
        - 'Low'
        - 'Medium'
        - 'High'
        - 'Critical'
    output:
        - 0 Unknown
        - 1 Low
        - 2 Medium
        - 3 High
        - 4 Critical
    """

    priority_grade_map = {
        'Low': 1,
        'Medium': 2,
        'High': 3,
        'Critical': 4
    }

    grade = priority_grade_map.get(priority, 0)
    return grade


def test_module():
    if IS_FETCH:
        parse_date_range(FETCH_TIME)

    since = datetime.now() - timedelta(days=int(10))
    timestamp = since.isoformat() + 'Z'

    incidents, _, __ = get_all_incidents(
        since=timestamp,
        until=None,
        limit=100
    )
    if incidents is not None:
        return 'ok'


"""

EXECUTION

"""


def main():
    global TOKEN
    command = demisto.command()
    try:
        handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
        TOKEN = get_token()
        if command == 'test-module':
            demisto.results(test_module())
        elif command == 'fetch-incidents':
            fetch_incidents()
        elif command == 'netwitness-get-incident':
            get_incident()
            get_alerts()
        elif command == 'netwitness-get-incidents':
            get_incidents()
        elif command == 'netwitness-update-incident':
            update_incident()
        elif command == 'netwitness-delete-incident':
            delete_incident()
        elif command == 'netwitness-get-alerts':
            get_alerts()
    except ValueError as e:
        if command == 'fetch-incidents':  # fetch-incidents supports only raising exceptions
            LOG(e.message)
            LOG.print_log()
            raise
        return_error(str(e))


if __name__ in ('__builtin__', 'builtins'):
    main()

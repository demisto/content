import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import requests
from datetime import date, timedelta

import dateparser

import urllib3

urllib3.disable_warnings()

''' GLOBAL VARS '''
TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
BASE_URL = demisto.params().get('url')
if BASE_URL and BASE_URL[-1] != '/':
    BASE_URL += '/'
API_KEY = demisto.params().get('credentials', {}).get('password') or demisto.params().get('apikey')
VERIFY_CERTIFICATE = not demisto.params().get('insecure')
# How many time before the first fetch to retrieve incidents
FIRST_FETCH, _ = parse_date_range(demisto.params().get('first_fetch', '12 hours') or '12 hours',
                                  date_format=TIME_FORMAT)

''' COMMAND FUNCTIONS '''


def get_list(list_id):
    fullurl = BASE_URL + f'api/lists/{list_id}/members.json'
    res = requests.get(
        fullurl,
        headers={
            'Content-Type': 'application/json',
            'Authorization': API_KEY
        },
        verify=VERIFY_CERTIFICATE
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error(f'Get list failed. URL: {fullurl}, StatusCode: {res.status_code}')

    return res.json()


def get_list_command():
    ''' Retrieves all indicators of a the given list ID in Threat Response '''
    list_id = demisto.args().get('list-id')
    list_items = get_list(list_id)

    demisto.results({'list': list_items})


def add_to_list(list_id, indicator, comment, expiration):
    fullurl = BASE_URL + f'api/lists/{list_id}/members.json'

    indicator = {
        'member': indicator
    }
    if comment:
        indicator['description'] = comment

    if expiration:
        indicator['expiration'] = expiration

    res = requests.post(
        fullurl,
        headers={
            'Authorization': API_KEY
        },
        verify=VERIFY_CERTIFICATE,
        json=indicator
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error(f'Add to list failed. URL: {fullurl}, Request Body: {json.dumps(indicator)}')

    return res.json()


def add_to_list_command():
    ''' Adds given indicators to the given list ID in Threat Response '''
    list_id = demisto.args().get('list-id')
    indicators = argToList(demisto.args().get('indicator'))
    comment = demisto.args().get('comment')
    expiration = demisto.args().get('expiration')

    message = ''
    for indicator in indicators:
        add_to_list(list_id, indicator, comment, expiration)
        message += f'{indicator} added successfully to {list_id}\n'

    demisto.results(message)


def block_ip_command():
    ''' Adds given IPs to the relevant blacklist in Threat Response '''
    list_id = demisto.params().get('blacklist_ip', demisto.args().get('blacklist_ip'))
    ips = argToList(demisto.args().get('ip'))
    expiration = demisto.args().get('expiration')

    message = ''
    for ip in ips:
        add_to_list(list_id, ip, None, expiration)
        message += f'{ip} added successfully to block_ip list\n'

    demisto.results(message)


def block_domain_command():
    ''' Adds given domains to the relevant blacklist in Threat Response '''
    list_id = demisto.params().get('blacklist_domain', demisto.args().get('blacklist_domain'))
    domains = argToList(demisto.args().get('domain'))
    expiration = demisto.args().get('expiration')

    message = ''
    for domain in domains:
        add_to_list(list_id, domain, None, expiration)
        message += f'{domain} added successfully to block_domain list\n'

    demisto.results(message)


def block_url_command():
    ''' Adds given URLs to the relevant blacklist in Threat Response '''
    list_id = demisto.params().get('blacklist_url', demisto.args().get('blacklist_url'))
    urls = argToList(demisto.args().get('url'))
    expiration = demisto.args().get('expiration')

    message = ''
    for url in urls:
        add_to_list(list_id, url, None, expiration)
        message += f'{url} added successfully to block_url list\n'

    demisto.results(message)


def block_hash_command():
    ''' Adds given hashes to the relevant blacklist in Threat Response '''
    list_id = demisto.params().get('blacklist_hash', demisto.args().get('blacklist_hash'))
    hashes = argToList(demisto.args().get('hash'))
    expiration = demisto.args().get('expiration')

    message = ''
    for h in hashes:
        add_to_list(list_id, h, None, expiration)
        message += f'{h} added successfully to block_hash list\n'

    demisto.results(message)


def search_indicators(list_id, indicator_filter):
    list_indicators = get_list(list_id)
    found_items = []
    for item in list_indicators:
        item_indicator = demisto.get(item, 'host.host')
        if item_indicator and indicator_filter in item_indicator:
            found_items.append(item)

    return found_items


def search_indicator_command():
    ''' Retrieves indicators of a list, using a filter '''
    list_id = demisto.args().get('list-id')
    indicator_filter = demisto.args().get('filter')
    found = search_indicators(list_id, indicator_filter)

    demisto.results({'indicators': found})


def delete_indicator(list_id, indicator_filter):
    indicator = search_indicators(list_id, indicator_filter)
    if len(indicator) == 0:
        return_error(f'{indicator_filter} not exists in {list_id}')

    indicator_id = indicator.get('id')  # pylint: disable=E1101
    fullurl = BASE_URL + f'api/lists/{list_id}/members/{indicator_id}.json'
    res = requests.delete(
        fullurl,
        headers={
            'Authorization': API_KEY
        },
        verify=VERIFY_CERTIFICATE
    )
    if res.status_code < 200 or res.status_code >= 300:
        return_error(f'Delete indicator failed. URL: {fullurl}, StatusCode: {res.status_code}')


def delete_indicator_command():
    ''' Deletes an indicator from a list '''
    list_id = demisto.args().get('list-id')
    indicator = demisto.args().get('indicator')
    delete_indicator(list_id, indicator)

    demisto.results(f'{list_id} deleted successfully from list {indicator}')


def test():
    """Perform API call to check that the API is accessible.

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    integration_params = demisto.params()
    if integration_params.get('isFetch') and not integration_params.get('states'):
        raise DemistoException("Missing argument - You must provide at least one incident state.")
    get_incidents_request(
        {
            'created_after': date.today(),
            'state': 'open'
        }
    )
    demisto.results('ok')


# TRAP API
def create_incident_field_context(incident):
    """Parses the 'incident_fields' entry of the incident and returns it

    Args:
        incident (dict): The incident to parse

    Returns:
        list. The parsed incident fields list
    """
    incident_field_values = {}
    for incident_field in incident.get('incident_field_values', []):
        incident_field_values[incident_field['name'].replace(" ", "_")] = incident_field['value']

    return incident_field_values


def get_emails_context(event):
    """Returns the context of the emails in the event

    Args:
        event (dict): The event to parse the emails from

    Returns:
        list. The parsed emails list from the event
    """
    emails_context = []
    for email in event.get('emails', []):
        email_obj = {
            'sender': email.get('sender', {}).get('email'),
            'recipient': email.get('recipient', {}).get('email'),
            'subject': email.get('subject'),
            'message_id': email.get('messageId'),
            'body': email.get('body'),
            'body_type': email.get('bodyType'),
            'headers': email.get('headers'),
            'urls': email.get('urls'),
            'sender_vap': email.get('sender', {}).get('vap'),
            'recipient_vap': email.get('recipient', {}).get('vap'),
            'attachments': email.get('attachments'),
        }
        message_delivery_time = email.get('messageDeliveryTime', {})
        if message_delivery_time and isinstance(message_delivery_time, dict):
            email_obj['message_delivery_time'] = message_delivery_time.get('millis')
        elif message_delivery_time and isinstance(message_delivery_time, str):
            email_obj['message_delivery_time'] = message_delivery_time
        emails_context.append(
            assign_params(**email_obj)
        )

    return emails_context


def create_incidents_context(incidents_list):
    """Parses the incidents list and returns the incidents context

    Args:
        incidents_list (list): The incidents list to parse

    Returns:
        list. The context created from the incidents list
    """
    context = list(incidents_list)
    for incident in context:
        incident['incident_field_values'] = create_incident_field_context(incident)

        if incident.get('events'):
            for event in incident['events']:
                event['emails'] = get_emails_context(event)

    return context


def create_incidents_human_readable(human_readable_message, incidents_list):
    """Creates the human readable entry for incidents

    Args:
        human_readable_message (str): The title of the human readable table
        incidents_list (list): The incidents list to insert to the table

    Returns:
        str. The incidents human readable in markdown format
    """
    human_readable = []
    human_readable_headers = ['ID', 'Created At', 'Type', 'Summary', 'Score', 'Event Count', 'Assignee',
                              'Successful Quarantines', 'Failed Quarantines', 'Pending Quarantines']
    for incident in incidents_list:
        human_readable.append({
            'Created At': incident.get('created_at'),
            'ID': incident.get('id'),
            'Type': incident.get('type'),
            'Summary': incident.get('summary'),
            'Score': incident.get('score'),
            'Event Count': incident.get('event_count'),
            'Assignee': incident.get('assignee'),
            'Successful Quarantines': incident.get('successful_quarantine'),
            'Failed Quarantines': incident.get('failed_quarantines'),
            'Pending Quarantines': incident.get('pending_quarantines')
        })

    return tableToMarkdown(human_readable_message, human_readable, human_readable_headers, removeNull=True)


def list_incidents_command():
    """ Retrieves incidents from ProofPoint API """
    args = demisto.args()
    limit = int(args.pop('limit'))

    incidents_list = get_incidents_request(args)

    incidents_list = incidents_list[:limit]
    human_readable = create_incidents_human_readable('List Incidents Results:', incidents_list)
    context = create_incidents_context(incidents_list)

    return_outputs(human_readable, {'ProofPointTRAP.Incident(val.id === obj.id)': context}, incidents_list)


def get_incident_command():
    """
        Retrieves a single incident from ProofPoint API
    """
    args = demisto.args()
    incident_id = args.pop('incident_id')
    expand_events = args.get('expand_events')
    fullurl = BASE_URL + f'api/incidents/{incident_id}.json'
    incident_data = requests.get(
        fullurl,
        headers={
            'Content-Type': 'application/json',
            'Authorization': API_KEY
        },
        params={
            'expand_events': expand_events,
        },
        verify=VERIFY_CERTIFICATE,
    )

    if incident_data.status_code < 200 or incident_data.status_code >= 300:
        return_error(f'Get incident failed. URL: {fullurl}, StatusCode: {incident_data.status_code}')

    incident_data = incident_data.json()
    human_readable = create_incidents_human_readable('Incident Results:', [incident_data])
    context = create_incidents_context([incident_data])

    return_outputs(human_readable, {'ProofPointTRAP.Incident(val.id === obj.id)': context}, incident_data)


def pass_sources_list_filter(incident, sources_list):
    """Checks whether the event sources of the incident contains at least one of the sources in the sources list.

    Args:
        incident (dict): The incident to check
        sources_list (list): The list of sources from the customer

    Returns:
        bool. Whether the incident has passed the filter or not
    """
    if len(sources_list) == 0:
        return True

    return any(source in incident.get('event_sources') for source in sources_list)


def pass_abuse_disposition_filter(incident, abuse_disposition_values):
    """Checks whether the incident's 'Abuse Disposition' value is in the abuse_disposition_values list.

    Args:
        incident (dict): The incident to check
        abuse_disposition_values (list): The list of relevant values from the customer

    Returns:
        bool. Whether the incident has passed the filter or not
    """
    if len(abuse_disposition_values) == 0:
        return True

    for incident_field in incident.get('incident_field_values', []):
        if incident_field['name'] == 'Abuse Disposition' and incident_field['value'] in abuse_disposition_values:
            return True

    return False


def filter_incidents(incidents_list):
    """Filters the incidents list by 'abuse disposition' and 'source list' values

    Args:
        incidents_list (list): The incidents list to filter

    Returns:
        list. The filtered incidents list
    """
    filtered_incidents_list = []
    params = demisto.params()
    sources_list = argToList(params.get('event_sources'))
    abuse_disposition_values = argToList(params.get('abuse_disposition'))

    if not sources_list and not abuse_disposition_values:
        return incidents_list

    for incident in incidents_list:
        if pass_sources_list_filter(incident, sources_list) and pass_abuse_disposition_filter(incident,
                                                                                              abuse_disposition_values):
            filtered_incidents_list.append(incident)

    return filtered_incidents_list


def get_incidents_request(params):
    """Perform an API request to get incidents from ProofPoint.

    Args:
        params(dict): The params of the request

    Returns:
        list. The incidents returned from the API call
    """
    fullurl = BASE_URL + 'api/incidents'
    incidents_list = requests.get(
        fullurl,
        headers={
            'Content-Type': 'application/json',
            'Authorization': API_KEY
        },
        params=params,
        verify=VERIFY_CERTIFICATE
    )
    if incidents_list.status_code < 200 or incidents_list.status_code >= 300:
        if incidents_list.status_code == 502 or incidents_list.status_code == 504:
            return_error('The operation failed. There is a possibility you are trying to get too many incidents.\n'
                         'You may consider adding a filter argument to the command.\n'
                         'URL: {}, StatusCode: {}'.format(fullurl, incidents_list.status_code))
        else:
            return_error(f'The operation failed. URL: {fullurl}, StatusCode: {incidents_list.status_code}')

    return incidents_list.json()


def get_time_delta(fetch_delta):
    """Gets the time delta from a string that is combined with a number and a string of (minute/hour)
    Args:
        fetch_delta(str): The fetch delta param.
    Returns:
        The time delta.
    """
    fetch_delta_split = fetch_delta.strip().split(' ')
    if len(fetch_delta_split) != 2:
        raise Exception(
            'The fetch_delta is invalid. Please make sure to insert both the number and the unit of the fetch delta.')

    unit = fetch_delta_split[1].lower()
    number = int(fetch_delta_split[0])

    if unit not in ['minute', 'minutes',
                    'hour', 'hours',
                    ]:
        raise Exception('The unit of fetch_delta is invalid. Possible values are "minutes" or "hours".')

    if 'hour' in unit:
        time_delta = timedelta(hours=number)  # batch by hours
    else:
        time_delta = timedelta(minutes=number)  # batch by minutes
    return time_delta


def get_new_incidents(request_params, last_fetched_id):
    """Perform an API request to get incidents from ProofPoint , filters then according to params, order them and
    return only the new incidnts.

    As the api does not return the results in an specific order, we query the api on specific time frames using
    created_before and created_after using the fetch delta parameter.
    Args:
        request_params(dict): The params of the request
        last_fetched_id(int): The ID of the last incident that was fetched in the previous fetch.
    Returns:
        list. The incidents returned from after the necessary actions.
    """
    incidents = get_incidents_request(request_params)
    filtered_incidents_list = filter_incidents(incidents)
    ordered_incidents = sorted(filtered_incidents_list, key=lambda k: (k['created_at'], k['id']))
    return list(filter(lambda incident: int(incident.get('id')) > last_fetched_id, ordered_incidents))


def get_incidents_batch_by_time_request(params):
    """Perform an API request to get incidents from ProofPoint in batches to prevent a timeout.

    As the api does not return the results in an specific order, we query the api on specific time frames using
    created_before and created_after using the fetch delta parameter.
    Args:
        params(dict): The params of the request

    Returns:
        list. The incidents returned from the API call
    """
    incidents_list = []  # type:list

    fetch_delta = params.get('fetch_delta', '6 hours')
    fetch_limit = int(params.get('fetch_limit', '50'))
    last_fetched_id = int(params.get('last_fetched_id', '0'))

    current_time = datetime.now()

    time_delta = get_time_delta(fetch_delta)

    created_after = datetime.strptime(params.get('created_after'), TIME_FORMAT)
    created_before = created_after + time_delta

    request_params = {
        'state': params.get('state'),
        'created_after': created_after.isoformat().split('.')[0] + 'Z',
        'created_before': created_before.isoformat().split('.')[0] + 'Z'
    }

    # while loop relevant for fetching old incidents
    while created_before < current_time and len(incidents_list) < fetch_limit:
        demisto.debug(
            "PTR: Entered the batch loop , with fetch_limit {} and incidents list {} and incident length {} "
            "with created_after {} and created_before {}.".format(
                str(fetch_limit), str([incident.get('id') for incident in incidents_list]), str(len(incidents_list)),
                str(request_params['created_after']), str(request_params['created_before'])))

        new_incidents = get_new_incidents(request_params, last_fetched_id)
        incidents_list.extend(new_incidents)

        # advancing fetch time by given fetch delta time
        created_after = created_before
        created_before = created_before + time_delta

        # updating params according to the new times
        request_params['created_after'] = created_after.isoformat().split('.')[0] + 'Z'
        request_params['created_before'] = created_before.isoformat().split('.')[0] + 'Z'
        demisto.debug(f"PTR: End of the current batch loop with {str(len(incidents_list))} incidents")

    # fetching the last batch when created_before is bigger then current time = fetching new incidents
    if len(incidents_list) < fetch_limit:
        # fetching the last batch
        request_params['created_before'] = current_time.isoformat().split('.')[0] + 'Z'
        new_incidents = get_new_incidents(request_params, last_fetched_id)
        incidents_list.extend(new_incidents)

        demisto.debug(
            "PTR: Finished the last batch, with fetch_limit {} and incidents list {} and incident length {}".format(
                str(fetch_limit), str([incident.get('id') for incident in incidents_list]), str(len(incidents_list))))

    incidents_list_limit = incidents_list[:fetch_limit]
    return incidents_list_limit


def fetch_incidents_command():
    """
        Fetches incidents from the ProofPoint API.
    """
    integration_params = demisto.params()
    last_fetch = demisto.getLastRun().get('last_fetch', {})
    last_fetched_id = demisto.getLastRun().get('last_fetched_incident_id', {})

    fetch_delta = integration_params.get('fetch_delta', '6 hours')
    fetch_limit = integration_params.get('fetch_limit', '50')

    incidents_states = integration_params.get('states')
    for state in incidents_states:
        if not last_fetch.get(state):
            last_fetch[state] = FIRST_FETCH

    for state in incidents_states:
        if not last_fetched_id.get(state):
            last_fetched_id[state] = '0'

    incidents = []
    for state in incidents_states:
        request_params = {
            'created_after': last_fetch[state],
            'last_fetched_id': last_fetched_id[state],
            'fetch_delta': fetch_delta,
            'state': state,
            'fetch_limit': fetch_limit
        }
        id = last_fetched_id[state]
        incidents_list = get_incidents_batch_by_time_request(request_params)
        for incident in incidents_list:
            id = incident.get('id')
            inc = {
                'name': f'ProofPoint_TRAP - ID {id}',
                'rawJSON': json.dumps(incident),
                'occurred': incident['created_at']
            }
            incidents.append(inc)

        if incidents:
            last_fetch_time = incidents[-1]['occurred']
            last_fetch[state] = \
                (datetime.strptime(last_fetch_time, TIME_FORMAT) - timedelta(minutes=1)).isoformat().split('.')[0] + 'Z'
            last_fetched_id[state] = id

    demisto.debug("PTR: End of current fetch function with last_fetch {} and last_fetched_id {}".format(str(last_fetch), str(
        last_fetched_id)))

    demisto.setLastRun({'last_fetch': last_fetch})
    demisto.setLastRun({'last_fetched_incident_id': last_fetched_id})

    demisto.info(f'extracted {len(incidents)} incidents')

    demisto.incidents(incidents)


def create_add_comment_human_readable(incident):
    """Creates the human readable entry for the 'add_comment_to_incident' command

    Args:
        incident (dict): The incident to parse

    Returns:
        str. The command human readable in markdown format
    """
    human_readable = []
    human_readable_headers = ['Incident ID', 'Created At', 'Details', 'Comments Summary', 'Action ID']
    incident_id = incident.get('incident_id')
    human_readable.append({
        'Created At': incident.get('created_at'),
        'Incident ID': incident_id,
        'Details': incident.get('detail'),
        'Comments Summary': incident.get('summary'),
        'Action ID': incident.get('id')
    })

    return tableToMarkdown(f'Comments added successfully to incident:{incident_id}', human_readable,
                           human_readable_headers, removeNull=True)


def add_comment_to_incident_command():
    """
        Adds comments to an incident by incident ID
    """
    args = demisto.args()
    incident_id = args.get('incident_id')
    comments_to_add = args.get('comments')
    details = args.get('details')
    request_body = {
        "summary": comments_to_add,
        "detail": details
    }

    fullurl = BASE_URL + f'api/incidents/{incident_id}/comments.json'
    incident_data = requests.post(
        fullurl,
        headers={
            'Content-Type': 'application/json',
            'Authorization': API_KEY
        },
        json=request_body,
        verify=VERIFY_CERTIFICATE
    )

    if incident_data.status_code < 200 or incident_data.status_code >= 300:
        return_error('Add comment to incident command failed. URL: {}, '
                     'StatusCode: {}'.format(fullurl, incident_data.status_code))

    incident_data = incident_data.json()
    human_readable = create_add_comment_human_readable(incident_data)

    return_outputs(human_readable,
                   {'ProofPointTRAP.IncidentComment(val.incident_id === obj.incident_id)': incident_data},
                   incident_data)


def add_user_to_incident_command():
    """
        Adds user to an incident by incident ID
    """
    args = demisto.args()
    incident_id = args.get('incident_id')
    attackers = argToList(args.get('attackers'))
    targets = argToList(args.get('targets'))
    request_body = {
        "targets": targets,
        "attackers": attackers
    }

    fullurl = BASE_URL + 'api/incidents/{incident_id}/users.json'
    incident_data = requests.post(
        fullurl,
        headers={
            'Content-Type': 'application/json',
            'Authorization': API_KEY
        },
        json=request_body,
        verify=VERIFY_CERTIFICATE
    )

    if incident_data.status_code < 200 or incident_data.status_code >= 300:
        return_error('Add comment to incident command failed. URL: {}, '
                     'StatusCode: {}'.format(fullurl, incident_data.status_code))

    return_outputs(f'The user was added successfully to incident {incident_id}', {}, {})


def parse_json_argument(argument_string_value, argument_name):
    parsed_arg = {}
    try:
        parsed_arg = json.loads(argument_string_value)
    except ValueError as error:
        return_error(f"The '{argument_name}' argument is not a valid json. Error: {error}")
    if not parsed_arg.get(argument_name):
        return_error(f"The '{argument_name}' json argument should start with a key named '{argument_name}'")

    return parsed_arg


def prepare_ingest_alert_request_body(args):
    json_arguments = ['attacker', 'cnc_host', 'detector', 'email', 'forensics_hosts', 'target', 'threat_info',
                      'custom_fields']
    request_body = {}  # type: dict
    for argument_name, argument_value in args.items():
        if argument_name in json_arguments:
            parsed_argument = parse_json_argument(argument_value, argument_name)
            request_body.update(parsed_argument)

        else:
            request_body[argument_name] = argument_value
    return request_body


def ingest_alert_command():
    """
        Ingest an alert into Threat Response.
    """
    args = demisto.args()
    json_source_id = args.pop('post_url_id', demisto.params().get('post_url_id'))

    if not json_source_id:
        return_error("To ingest alert into TRAP, you mast specify a post_url_id,"
                     "either as an argument or as an integration parameter.")

    request_body = prepare_ingest_alert_request_body(assign_params(**args))
    fullurl = BASE_URL + f'threat/json_event/events/{json_source_id}'
    alert_data = requests.post(
        fullurl,
        headers={
            'Content-Type': 'application/json'
        },
        json=request_body,
        verify=VERIFY_CERTIFICATE
    )

    if alert_data.status_code < 200 or alert_data.status_code >= 300:
        return_error('Failed to ingest the alert into TRAP. URL: {}, '
                     'StatusCode: {}'.format(fullurl, alert_data.status_code))

    return_outputs('The alert was successfully ingested to TRAP', {}, {})


def close_incident_command():
    args = demisto.args()
    incident_id = args.get('incident_id')
    details = args.get('details')
    summary = args.get('summary')
    request_body = {
        "summary": summary,
        "detail": details
    }

    fullurl = BASE_URL + f'api/incidents/{incident_id}/close.json'
    incident_data = requests.post(
        fullurl,
        headers={
            'Content-Type': 'application/json',
            'Authorization': API_KEY
        },
        json=request_body,
        verify=VERIFY_CERTIFICATE
    )

    if incident_data.status_code < 200 or incident_data.status_code >= 300:
        return_error('Incident closure failed. URL: {}, '
                     'StatusCode: {}'.format(fullurl, incident_data.status_code))

    return_outputs(f'The incident {incident_id} was successfully closed', {}, {})

def format_datetime(date) -> int | None:
    if isinstance(date, datetime):
        return int(date.timestamp())
    else:
        return_error("Timestamp was bad")
        return None

def search_quarantine():
    args = demisto.args()
    arg_time = dateparser.parse(args.get('time'))
    demisto.debug(f"{arg_time=}")
    incidentTAPtime = format_datetime(arg_time)
    demisto.debug(f"{incidentTAPtime=}")
    lstAlert = []
    mid = args.get('message_id')
    recipient = args.get('recipient')
    limit_quarantine_occurred_time = argToBoolean(args.get('limit_quarantine_occurred_time'))
    quarantine_timestamp_limit = arg_to_number(args.get('quarantine_timestamp_limit'))
    compare_message_time = argToBoolean(args.get('compare_message_time'))


    request_params = {
        'created_after': datetime.strftime(arg_time - get_time_delta('1 hour'), TIME_FORMAT),  # for safety
        'fetch_delta': '6 hours',
        'fetch_limit': '50'
    }

    incidents_list = get_incidents_batch_by_time_request(request_params)
    demisto.debug(f"PTR {incidents_list=}")

    found = {'email': False, 'mid': False, 'quarantine': False}
    resQ = []

    # Collecting emails inside alert to find those with same recipient and messageId
    for incident in incidents_list:
        demisto.debug(f"{incident=}")
        for alert in incident.get('events'):
            demisto.debug(f'New alert being processed with Alertid = {alert.get("id")}')
            for email in alert.get('emails'):
                demisto.debug(f'New email being processed with messageid {email.get("messageId")}')
                message_delivery_time = email.get('messageDeliveryTime', {})
                demisto.debug(f'PTR: Got {message_delivery_time=} with type {type(message_delivery_time)}.')
                if message_delivery_time and isinstance(message_delivery_time, dict):
                    message_delivery_time = message_delivery_time.get('millis')
                    demisto.debug(f'Message delivery time processed as dict and set to {message_delivery_time}')
                elif message_delivery_time and isinstance(message_delivery_time, str):
                    message_delivery_time = dateparser.parse(message_delivery_time)
                    if message_delivery_time:
                        message_delivery_time = int(message_delivery_time.timestamp() * 1000)
                        demisto.debug(f'Message delivery time processed as str and converted to integer with value {message_delivery_time}')
                    else:
                        demisto.info(f'PTR: Could not parse time of incident {incident.get("id")}, got '
                                        f'{email.get("messageDeliveryTime", "")=}')
                        continue
                if email.get('messageId') == mid and email.get('recipient').get('email') == recipient and message_delivery_time:
                    found['mid'] = True
                    demisto.debug('PTR: Found the email, adding the alert')
                    emailTRAPtimestamp = int(message_delivery_time / 1000)
                    demisto.debug(f'PTR: {emailTRAPtimestamp=}, {compare_message_time=}, {incidentTAPtime=}')
                    if ((not compare_message_time) or (incidentTAPtime == emailTRAPtimestamp)):
                        demisto.debug(f'PTR: Adding the alert with id {alert.get("id")}')
                        found['email'] = True
                        lstAlert.append({
                            'incidentid': incident.get('id'),
                            'alertid': alert.get('id'),
                            'alerttime': alert.get('received'),
                            'incidenttime': incident.get('created_at'),
                            'messageId': mid,
                            'quarantine_results': incident.get('quarantine_results')
                        })
                    else:
                        demisto.debug(f'PTR: Alert id {alert.get("id")} found but not added to lstAlert list as emailTAPtime ({emailTAPtime}) did not match emailTRAPtimestamp ({emailTRAPtimestamp})')
                else:
                    demisto.debug(f'Email metadata did not match user inputs, skipped.  mid from email = {email.get("messageId")} vs user input {mid}. Recipient from alert = {email.get("recipient").get("email")} vs user input {recipient}.')

    quarantineFoundcpt = 0

    # Go though the alert list, and check the quarantine results:
    for alert in lstAlert:
        for quarantine in alert.get('quarantine_results'):
            if quarantine.get('messageId') == mid and quarantine.get('recipient') == recipient:
                found['quarantine'] = True
                tsquarantine = dateparser.parse(quarantine.get("startTime"))
                tsalert = dateparser.parse(alert.get("alerttime"))
                if isinstance(tsquarantine, datetime) and isinstance(tsalert, datetime):
                    diff = (tsquarantine - tsalert).total_seconds()
                    # we want to make sure quarantine starts within the timestamp limit set after creating the alert if limit_quarantine_occurred_time is set to true, if false return quarantine regardless.
                    if not limit_quarantine_occurred_time or 0 < diff < quarantine_timestamp_limit:
                        resQ.append({
                            'quarantine': quarantine,
                            'alert': {
                                'id': alert.get('alertid'),
                                'time': alert.get('alerttime')
                            },
                            'incident': {
                                'id': alert.get('incidentid'),
                                'time': alert.get('incidenttime')
                            }
                        })
                    else:
                        quarantineFoundcpt += 1
                        demisto.debug(f'PTR: Quarantine found for {quarantine.get("messageId")} but not returned as it did not meet filter requirements.  limit_quarantine_occurred_time = {limit_quarantine_occurred_time} with type {type(limit_quarantine_occurred_time)}. diff = {diff}, quarantine_timestamp_limit = {quarantine_timestamp_limit}')
                else:
                    demisto.debug(f"PTR: Failed to parse timestamp of incident: {alert=} {quarantine=}.")

    if quarantineFoundcpt > 0:
        return CommandResults(
            readable_output=f"{mid} Message ID matches to {quarantineFoundcpt} emails quarantined but time alert does not match")
    if not found['mid']:
        return CommandResults(readable_output=f"Message ID {mid} not found in TRAP incidents")

    midtxt = f'{mid} Message ID found in TRAP alerts,'
    if not found['email']:
        return CommandResults(
            readable_output=f"{midtxt} but timestamp between email delivery time and time given as argument doesn't match")
    elif not found['quarantine']:
        demisto.debug("PTR: " + "\n".join([json.dumps(alt, indent=4) for alt in lstAlert]))
        return CommandResults(f"{midtxt} but not in the quarantine list meaning that email has not be quarantined.")

    return CommandResults(
        outputs_prefix='ProofPointTRAP.Quarantine',
        outputs=resQ,
        readable_output=tableToMarkdown("Quarantine Result", resQ),
        raw_response=resQ
    )


''' EXECUTION CODE '''


def main():
    handle_proxy(demisto.params().get('proxy'))
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    if command == 'test-module':
        test()

    elif command == 'fetch-incidents':
        fetch_incidents_command()

    elif command == 'proofpoint-tr-get-list':
        get_list_command()

    elif command == 'proofpoint-tr-add-to-list':
        add_to_list_command()

    elif command == 'proofpoint-tr-block-ip':
        block_ip_command()

    elif command == 'proofpoint-tr-block-domain':
        block_domain_command()

    elif command == 'proofpoint-tr-block-url':
        block_url_command()

    elif command == 'proofpoint-tr-block-hash':
        block_hash_command()

    elif command == 'proofpoint-tr-delete-indicator':
        delete_indicator_command()

    elif command == 'proofpoint-tr-search-indicator':
        search_indicator_command()

    elif command == 'proofpoint-tr-list-incidents':
        list_incidents_command()

    elif command == 'proofpoint-tr-get-incident':
        get_incident_command()

    elif command == 'proofpoint-tr-update-incident-comment':
        add_comment_to_incident_command()

    elif command == 'proofpoint-tr-add-user-to-incident':
        add_user_to_incident_command()

    elif command == 'proofpoint-tr-ingest-alert':
        ingest_alert_command()

    elif command == 'proofpoint-tr-close-incident':
        close_incident_command()

    elif command == 'proofpoint-tr-verify-quarantine':
        return_results(search_quarantine())


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

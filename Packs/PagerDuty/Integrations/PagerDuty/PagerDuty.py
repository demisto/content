import demistomock as demisto
from CommonServerUserPython import *

from CommonServerPython import *


''' GLOBAL VARS '''
# PagerDuty API works only with secured communication.
USE_SSL = not demisto.params().get('insecure', False)

USE_PROXY = demisto.params().get('proxy', True)
API_KEY = demisto.params().get("credentials_api_key", {}).get('password') or demisto.params().get('APIKey')
SERVICE_KEY = demisto.params()['ServiceKey']
FETCH_INTERVAL = demisto.params()['FetchInterval']
DEFAULT_REQUESTOR = demisto.params().get('DefaultRequestor', '')

SERVER_URL = 'https://api.pagerduty.com/'
CREATE_EVENT_URL = 'https://events.pagerduty.com/v2/enqueue'

INCIDENT_API_LIMIT = 100

DEFAULT_HEADERS = {
    'Authorization': f'Token token={API_KEY}',
    'Accept': 'application/vnd.pagerduty+json;version=2',
}

'''HANDLE PROXY'''
if not USE_PROXY:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

'''PARAMS'''
UTC_PARAM = '&time_zone=UTC'
STATUSES = 'statuses%5B%5D'
INCLUDED_FIELDS = '&include%5B%5D=first_trigger_log_entries&include%5B%5D=assignments'

'''SUFFIX ENDPOINTS'''
GET_SCHEDULES_SUFFIX = 'schedules'
CREATE_INCIDENT_SUFFIX = 'incidents'
GET_INCIDENT_SUFFIX = 'incidents/'
GET_SERVICES_SUFFIX = 'services'
ON_CALL_BY_SCHEDULE_SUFFIX = 'schedules/{0}/users'
ON_CALLS_USERS_SUFFIX = 'oncalls?include%5B%5D=users'
USERS_NOTIFICATION_RULE = 'users/{0}/notification_rules'
GET_INCIDENTS_SUFFIX = 'incidents?include%5B%5D=assignees'
USERS_CONTACT_METHODS_SUFFIX = 'users/{0}/contact_methods'
RESPONDER_REQUESTS_SUFFIX = 'incidents/{0}/responder_requests'
RESPONSE_PLAY_SUFFIX = 'response_plays/{0}/run'

'''CONTACT_METHOD_TYPES'''
SMS_CONTACT_TYPE = 'sms_contact_method'
EMAIL_CONTACT_TYPE = 'email_contact_method'
PHONE_CONTACT_TYPE = 'phone_contact_method'
PUSH_CONTACT_TYPE = 'push_notification_contact_method'

CONTACT_METHODS_TO_HUMAN_READABLE = {
    '': 'Unknown',
    SMS_CONTACT_TYPE: 'SMS',
    PUSH_CONTACT_TYPE: 'Push',
    EMAIL_CONTACT_TYPE: 'Email',
    PHONE_CONTACT_TYPE: 'Phone'
}

'''TABLE NAMES'''
SERVICES = 'Service List'
SCHEDULES = 'All Schedules'
TRIGGER_EVENT = 'Trigger Event'
RESOLVE_EVENT = 'Resolve Event'
ACKNOWLEDGE_EVENT = 'Acknowledge Event'
USERS_ON_CALL = 'Users On Call'
INCIDENTS_LIST = 'PagerDuty Incidents'
INCIDENT = 'PagerDuty Incident'
CONTACT_METHODS = 'Contact Methods'
USERS_ON_CALL_NOW = 'Users On Call Now'
NOTIFICATION_RULES = 'User notification rules'

'''TABLE HEADERS'''
CONTACT_METHODS_HEADERS = ['ID', 'Type', 'Details']
SERVICES_HEADERS = ['ID', 'Name', 'Status', 'Created At', 'Integration']
NOTIFICATION_RULES_HEADERS = ['ID', 'Type', 'Urgency', 'Notification timeout(minutes)']
SCHEDULES_HEADERS = ['ID', 'Name', 'Today', 'Time Zone', 'Escalation Policy', 'Escalation Policy ID']
USERS_ON_CALL_NOW_HEADERS = ['ID', 'Schedule ID', 'Email', 'Name', 'Role', 'User Url', 'Time Zone']
INCIDENTS_HEADERS = ['ID', 'Title', 'Description', 'Status', 'Created On', 'Urgency', 'Html Url', 'Incident key',
                     'Assigned To User', 'Service ID', 'Service Name', 'Escalation Policy', 'Last Status Change On',
                     'Last Status Change By', 'Number Of Escalations', 'Resolved By User', 'Resolve Reason']

''' HELPER FUNCTIONS '''


def http_request(method: str, url: str, params_dict=None, data=None, json_data=None, additional_headers=None):  # pragma: no cover
    demisto.debug(f'running {method} request with url={url}\nparams={json.dumps(params_dict)}')
    headers = DEFAULT_HEADERS.copy()
    if not additional_headers:
        additional_headers = {}
    headers.update(additional_headers)
    try:
        res = requests.request(method,
                               url,
                               verify=USE_SSL,
                               params=params_dict,
                               headers=headers,
                               data=data,
                               json=json_data
                               )
        res.raise_for_status()

        return unicode_to_str_recur(res.json())

    except Exception as e:
        demisto.debug(e)
        raise


def translate_severity(sev: str) -> int:
    if sev.lower() == 'high':
        return 3
    elif sev.lower() == 'low':
        return 1
    return 0


def unicode_to_str_recur(obj):
    """Converts unicode elements of obj (incl. dictionary and list) to string recursively"""
    if IS_PY3:
        return obj
    if isinstance(obj, dict):
        obj = {unicode_to_str_recur(k): unicode_to_str_recur(v) for k, v in list(obj.items())}
    elif isinstance(obj, list):
        obj = list(map(unicode_to_str_recur, obj))
    elif isinstance(obj, str):
        obj = obj.encode('utf-8', 'ignore')
    return obj


def test_module():  # pragma: no cover
    get_on_call_now_users_command()
    demisto.results('ok')


def extract_on_call_user_data(users: list[dict], schedule_id=None) -> CommandResults:
    """Extract data about user from a given schedule."""
    outputs = []
    contexts = []
    for user in users:
        output = {}
        context = {}
        if schedule_id:
            output['Schedule ID'] = schedule_id
            context['ScheduleID'] = output['Schedule ID']

        output['ID'] = user.get('id')
        output['Name'] = user.get('name')
        output['Role'] = user.get('role')
        output['Email'] = user.get('email')
        output['Time Zone'] = user.get('time_zone')
        output['User Url'] = user.get('html_url')

        context['ID'] = output['ID']
        context['Role'] = output['Role']
        context['Email'] = output['Email']
        context['Username'] = output['Name']
        context['DisplayName'] = output['Name']
        context['TimeZone'] = output['Time Zone']

        outputs.append(output)
        contexts.append(context)

    return CommandResults(
        outputs_prefix='PagerDutyUser',
        outputs_key_field='ID',
        outputs=contexts,
        raw_response=users,
        readable_output=tableToMarkdown(USERS_ON_CALL, outputs, USERS_ON_CALL_NOW_HEADERS, removeNull=True),
    )


def extract_on_call_now_user_data(users_on_call_now: dict[str, Any]) -> CommandResults:
    """Extract the user data from the oncalls json."""
    outputs: list[dict] = []
    contexts: list[dict] = []
    oncalls: list[dict] = users_on_call_now.get('oncalls', [{}])

    for oncall in oncalls:
        output = {}
        context = {}

        data = oncall
        user: dict = data.get('user', {})
        schedule_id = (data.get('schedule') or {}).get('id')
        if schedule_id:
            output['Schedule ID'] = schedule_id
            context['ScheduleID'] = output['Schedule ID']
        output['ID'] = user.get('id')
        output['Name'] = user.get('name')
        output['Role'] = user.get('role')
        output['Email'] = user.get('email')
        output['User Url'] = user.get('html_url')
        output['Time Zone'] = user.get('time_zone')

        context['ID'] = output['ID']
        context['Role'] = output['Role']
        context['Email'] = output['Email']
        context['Username'] = output['Name']
        context['DisplayName'] = output['Name']
        context['TimeZone'] = output['Time Zone']

        escal_level = data.get('escalation_level', 1)
        outputs.insert(escal_level - 1, output)
        contexts.insert(escal_level - 1, context)

    return CommandResults(
        outputs_prefix='PagerDutyUser',
        outputs_key_field='ID',
        outputs=contexts,
        raw_response=users_on_call_now,
        readable_output=tableToMarkdown(USERS_ON_CALL_NOW, outputs, USERS_ON_CALL_NOW_HEADERS, removeNull=True),
    )


def parse_incident_data(incidents) -> tuple[list, list, list]:
    """Parse incident data to output,context format"""
    outputs = []
    contexts = []
    raw_response = []
    for _i, incident in enumerate(incidents):
        output = {}
        context = {}

        context['ID'] = output['ID'] = incident.get('id')
        context['Title'] = output['Title'] = incident.get('summary')
        output['Description'] = incident.get('first_trigger_log_entry', {}).get('channel', {}).get('details', '')
        context['Description'] = output['Description']
        context['Status'] = output['Status'] = incident.get('status')
        context['created_at'] = output['Created On'] = incident.get('created_at')
        context['urgency'] = output['Urgency'] = incident.get('urgency', '')
        output['Html Url'] = incident.get('html_url')
        context['incident_key'] = incident.get('incident_key')
        output['Incident key'] = incident.get('incident_key')

        if len(incident.get('assignments', [])) > 0:
            output['Assigned To User'] = incident['assignments'][0].get('assignee', {}).get('name')
        else:
            output['Assigned To User'] = '-'

        context['assignee'] = output['Assigned To User']

        context['service_id'] = output['Service ID'] = incident.get('service', {}).get('id')
        context['service_name'] = output['Service Name'] = incident.get('service', {}).get('summary')

        output['Escalation Policy'] = incident.get('escalation_policy', {}).get('summary')
        context['escalation_policy'] = output['Escalation Policy']

        context['last_status_change_at'] = output['Last Status Change On'] = incident.get('last_status_change_at')
        output['Last Status Change By'] = incident.get('last_status_change_by', {}).get('summary')
        context['last_status_change_by'] = output['Last Status Change By']

        context['number_of_escalations'] = output['Number Of Escalations'] = incident.get('number_of_escalations')

        if output['Status'] == 'resolved':
            output['Resolved By User'] = output['Last Status Change By']
        else:
            output['Resolved By User'] = '-'

        context['resolved_by'] = output['Assigned To User']
        context['resolve_reason'] = output['Resolve reason'] = incident.get('resolve_reason', '')

        context['teams'] = []
        for team in incident.get('teams', [{}]):
            team_id = team.get('id', '')
            team_name = team.get('summary', '')

            team_data = {
                "ID": team_id,
                "Name": team_name
            }

            context['teams'].append(team_data)

        assignment = incident.get('assignments', [{}, ])
        if len(assignment) > 0:
            context['assignment'] = {
                "time": assignment[0].get('at', ''),
                "assignee": assignment[0].get('assignee', {}).get('summary', ''),
                "assigneeId": assignment[0].get('assignee', {}).get('id', ''),
            }
        else:
            context['assignment'] = {}

        acknowledgements = incident.get('acknowledgements', [{}, ])
        if len(acknowledgements) > 0:
            context['acknowledgement'] = {
                "time": assignment[0].get('at', ''),
                "acknowledger": assignment[0].get('acknowledger', {}).get('summary', ''),
                "acknowledgerId": assignment[0].get('acknowledger', {}).get('id', ''),
            }
        else:
            context['acknowledgement'] = {}

        outputs.append(output)
        contexts.append(context)
        raw_response.append(incident)

    return outputs, contexts, raw_response


def extract_incidents_data(incidents: list[dict], table_name: str) -> dict:
    """Extract data about incidents."""
    outputs, contexts, _ = parse_incident_data(incidents)

    return {
        'Type': entryTypes['note'],
        'Contents': incidents,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(table_name, outputs, INCIDENTS_HEADERS, removeNull=True),
        'EntryContext': {
            'PagerDuty.Incidents(val.ID==obj.ID)': contexts
        }
    }


def extract_all_schedules_data(schedules: list[dict]) -> dict:
    """Extract the data about all the schedules."""
    outputs = []
    contexts = []
    for schedule in schedules:
        context: dict = {}
        data = schedule

        output = {
            'ID': data.get('id'),
            'Name': data.get('name'),
            'Time Zone': data.get('time_zone'),
            'Today': datetime.today().strftime('%Y-%m-%d'),
        }
        escalation_policies: list[dict] = data.get('escalation_policies', [{}])
        if escalation_policies:
            output['Escalation Policy ID'] = escalation_policies[0].get('id')
            output['Escalation Policy'] = escalation_policies[0].get('summary')

            context['escalation_policies'] = [{}, ]
            context['escalation_policies'][0]['name'] = output['Escalation Policy']
            context['escalation_policies'][0]['id'] = output['Escalation Policy ID']
        else:
            output['Escalation Policy'] = '-'
            output['Escalation Policy ID'] = '-'

        context['id'] = output['ID']
        context['name'] = output['Name']
        context['today'] = output['Today']
        context['time_zone'] = output['Time Zone']

        outputs.append(output)
        contexts.append(context)

    return {
        'Type': entryTypes['note'],
        'Contents': schedules,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(SCHEDULES, outputs, SCHEDULES_HEADERS),
        'EntryContext': {
            'PagerDuty.Schedules(val.id==obj.id)': contexts,
        }
    }


def create_new_incident(source, summary, severity, action, description='No description', group='',
                        event_class='', component='', incident_key=None, service_key=SERVICE_KEY) -> dict:
    """Create a new incident in the PagerDuty instance."""
    payload = {
        'routing_key': service_key,
        'event_action': action,
        'dedup_key': incident_key,
        'images': [],
        'links': [],
        'payload': {
            'summary': summary,
            'source': source,
            'severity': severity,
            'group': group,
            'class': event_class,
            'component': component,
            'custom_details': {
                'description': description
            }
        }
    }

    return http_request('POST', CREATE_EVENT_URL, data=json.dumps(payload))


def resolve_or_ack_incident(action, incident_key, service_key=SERVICE_KEY) -> dict:
    """Resolve or Acknowledge an incident in the PagerDuty instance."""
    payload = {
        'routing_key': service_key,
        'event_action': action,
        'dedup_key': incident_key
    }

    return http_request('POST', CREATE_EVENT_URL, data=json.dumps(payload))


def extract_new_event_data(table_name: str, response: dict) -> dict:
    """Extract the data from the response of creating a new command."""
    output = {
        'Status': response.get('status', ''),
        'Message': response.get('message', ''),
        'Incident key': response.get('dedup_key', ''),
    }
    context = {
        'Status': output['Status'],
        'Message': output['Message'],
        'incident_key': output['Incident key'],
    }
    return {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(table_name, output),
        'EntryContext': {
            'PagerDuty.Event(val.incident_key==obj.dedup_key)': context,
            'Event.ID(val.ID==obj.dedup_key)': context['incident_key']
        }
    }


def extract_users_contact_methods(user_contact_methods: dict) -> dict:
    """Extract all the contact methods of a given user."""
    outputs = []
    contexts = []
    contact_methods: list[dict] = user_contact_methods.get('contact_methods', [{}])
    for contact_method in contact_methods:
        output = {
            'ID': contact_method.get('id'),
            'Type': CONTACT_METHODS_TO_HUMAN_READABLE[contact_method.get('type', '')]
        }

        country_code = str(contact_method.get('country_code', ''))
        address = contact_method.get('address', '')
        output['Details'] = country_code + address

        outputs.append(output)

        del contact_method['address']
        if output['Type'] in ['SMS', 'Phone']:
            del contact_method['country_code']
            contact_method['phone'] = output['Details']
        else:
            contact_method['email'] = output['Details']

        contexts.append(contact_method)

    return {
        'Type': entryTypes['note'],
        'Contents': user_contact_methods,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(CONTACT_METHODS, outputs, CONTACT_METHODS_HEADERS),
        'EntryContext': {
            'PagerDuty.Contact_methods(val.id==obj.id)': contexts,
        }
    }


def extract_users_notification_role(user_notification_role: dict) -> dict:
    """Extract the notification role of a given user."""
    outputs = []
    notification_rules: list[dict] = user_notification_role.get('notification_rules', [{}])
    for notification_rule in notification_rules:
        output = {
            'ID': notification_rule.get('id'),
            'Type': notification_rule.get('type', ''),
            'Urgency': notification_rule.get('urgency'),
            'Notification timeout(minutes)': notification_rule.get('start_delay_in_minutes')}

        outputs.append(output)

    return {
        'Type': entryTypes['note'],
        'Contents': user_notification_role,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(NOTIFICATION_RULES, outputs, NOTIFICATION_RULES_HEADERS),
        'EntryContext': {
            'PagerDuty.Notification_rules(val.id==obj.id)': notification_rules,
        }
    }


def extract_responder_request(responder_request_response) -> CommandResults:
    """Extract the users that were requested to respond"""
    outputs = []
    responder_request = responder_request_response.get("responder_request")
    for request in responder_request.get("responder_request_targets", []):
        request = request.get("responder_request_target")
        output = {"Type": request.get("type"), "ID": request.get("id")}
        if output["Type"] == "user":
            responder_user = request.get("incidents_responders", [])[0].get("user")
        else:
            responder_user = [x.get("user") for x in request.get("incidents_responders", [])]
        output["ResponderType"] = responder_user.get("type")
        output["ResponderName"] = responder_user.get("summary")
        output["Message"] = responder_request.get("message")
        output["IncidentID"] = (responder_request.get("incident") or {}).get("id")
        output["RequesterID"] = responder_request.get("requester", {}).get("id")
        output["IncidentSummary"] = (responder_request.get("incident") or {}).get("summary")
        outputs.append(output)
    return CommandResults(
        outputs_prefix='PagerDuty.ResponderRequests',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=outputs,
        readable_output=tableToMarkdown(CONTACT_METHODS, outputs, CONTACT_METHODS_HEADERS, removeNull=True)
    )


'''COMMANDS'''


def fetch_incidents():
    param_dict = {}
    now_time = datetime.utcnow()
    now = datetime.isoformat(now_time)
    lastRunObject = demisto.getLastRun()
    if lastRunObject:
        param_dict['since'] = lastRunObject['time']
    else:
        param_dict['since'] = datetime.isoformat(now_time - timedelta(minutes=int(FETCH_INTERVAL)))

    param_dict['until'] = now

    url = SERVER_URL + GET_INCIDENTS_SUFFIX + configure_status()
    res = http_request('GET', url, param_dict)
    _, parsed_incidents, raw_responses = parse_incident_data(res.get('incidents', []))

    incidents = []
    for incident, raw_response in zip(parsed_incidents, raw_responses):
        incidents.append({
            'name': incident['ID'] + ' - ' + incident['Title'],
            'occurred': incident['created_at'],
            'severity': translate_severity(incident['urgency']),
            'rawJSON': json.dumps(raw_response)
        })

    demisto.incidents(incidents)
    demisto.setLastRun({'time': now})


def configure_status(status='triggered,acknowledged') -> str:
    statuses = status.split(',')
    statuses_string = f"&{STATUSES}="
    statuses = statuses_string.join(statuses)
    status_request = f'&{STATUSES}={statuses}'

    status_request = status_request + INCLUDED_FIELDS + UTC_PARAM
    return status_request


def pagination_incidents(param_dict: dict, pagination_dict: dict, url: str) -> list[dict]:
    """
    Retrieves incident data through paginated requests.

    Args:
        param_dict (dict): A dictionary containing parameters for controlling pagination, including:
            - 'page': Current page number (optional).
            - 'page_size': Number of incidents per page (optional).
            - 'limit': Maximum number of incidents to retrieve (optional).
            - Additional parameters to include in the API request.

        url (str): The URL of the API endpoint for incident data.

    Returns:
        list[dict]: A list of dictionaries, where each dictionary represents an incident.

    Notes:
        This function supports pagination for efficient retrieval of large datasets. It calculates
        the appropriate 'limit' and 'offset' values based on the provided arguments.

    Examples:
        To retrieve incidents for the second page with a page size of 20:
        >>> pagination_incidents({'page': 2, 'page_size': 20}, 'https://api.example.com/incidents', {})

        To retrieve the first 50 incidents without explicit pagination:
        >>> pagination_incidents({'limit': 50}, 'https://api.example.com/incidents', {'status': 'open'})
    """
    def _get_page(**pagination_args) -> list[dict]:
        # param_dict must be before pagination_args for merging to work correctly
        return http_request('GET', url, param_dict | pagination_args).get("incidents", [{}])

    page: list = []

    page_number = arg_to_number(pagination_dict.get("page"))
    page_size = arg_to_number(pagination_dict.get("page_size"))

    if page_number is not None and page_size is not None:
        if page_size > INCIDENT_API_LIMIT:
            raise DemistoException(f"The max size for page is {INCIDENT_API_LIMIT}. Please provide a lower page size.")
        limit = page_size
        offset = (page_number - 1) * page_size

    else:
        limit = arg_to_number(pagination_dict.get("limit")) or 50
        offset = 0

        if limit > INCIDENT_API_LIMIT:
            for offset in range(0, limit - INCIDENT_API_LIMIT, INCIDENT_API_LIMIT):
                page += _get_page(
                    limit=INCIDENT_API_LIMIT,
                    offset=offset)

            # the remaining call can be less than OR equal the api_limit but not empty
            limit = limit % INCIDENT_API_LIMIT or INCIDENT_API_LIMIT
            offset += INCIDENT_API_LIMIT

    page += _get_page(
        limit=limit,
        offset=offset)

    return page


def get_incidents_command(args: dict[str, str]) -> dict:
    """Get incidents command."""
    param_dict: dict = {
        "since": args.get("since"),
        "until": args.get("until"),
        "sortBy": args.get("sortBy"),
        "incident_key": args.get("incident_key"),
        "user_ids[]": argToList(args.get("user_id")),
        "urgencies[]": args.get("urgencies"),
        "date_range": args.get("date_range")
    }
    pagination_args = {
        "page": arg_to_number(args.get("page")),
        "page_size": arg_to_number(args.get("page_size")),
        "limit": arg_to_number(args.get("limit", 50))
    }
    remove_nulls_from_dictionary(pagination_args)
    remove_nulls_from_dictionary(param_dict)

    url = SERVER_URL + GET_INCIDENTS_SUFFIX + configure_status(args.get("status", 'triggered,acknowledged'))
    incidents: list[dict] = pagination_incidents(param_dict, pagination_args, url)

    return extract_incidents_data(incidents, INCIDENTS_LIST)


def submit_event_command(source, summary, severity, action, description='No description', group='',
                         event_class='', component='', incident_key=None, serviceKey=SERVICE_KEY):
    """Create new event."""
    if serviceKey is None:
        raise Exception('You must enter a ServiceKey at the integration '
                        'parameters or in the command to process this action.')

    res = create_new_incident(source, summary, severity, action, description,
                              group, event_class, component, incident_key, serviceKey)
    return extract_new_event_data(TRIGGER_EVENT, res)


def get_all_schedules_command(query=None, limit=None) -> dict:
    """Get all the schedules."""
    param_dict = {}
    if query is not None:
        param_dict['query'] = query
    if limit is not None:
        param_dict['limit'] = limit

    url = SERVER_URL + GET_SCHEDULES_SUFFIX
    res = http_request('GET', url, param_dict)
    schedules = res.get('schedules', [{}])
    return extract_all_schedules_data(schedules)


def get_on_call_users_command(scheduleID: str, since=None, until=None) -> CommandResults:
    """Get the list of user on call in a from scheduleID"""
    param_dict = {}
    if since is not None:
        param_dict['since'] = since
    if until is not None:
        param_dict['until'] = until

    url = SERVER_URL + ON_CALL_BY_SCHEDULE_SUFFIX.format(scheduleID)
    users_on_call = http_request('GET', url, param_dict)
    return extract_on_call_user_data(users_on_call.get('users', [{}]), scheduleID)


def get_on_call_now_users_command(limit=None, escalation_policy_ids=None, schedule_ids=None) -> CommandResults:
    """Get the list of users that are on call now."""
    param_dict = {}
    if limit is not None:
        param_dict['limit'] = limit
    if escalation_policy_ids is not None:
        param_dict['escalation_policy_ids[]'] = argToList(escalation_policy_ids)
    if schedule_ids is not None:
        param_dict['schedule_ids[]'] = argToList(schedule_ids)

    url = SERVER_URL + ON_CALLS_USERS_SUFFIX
    users_on_call_now: dict = http_request('GET', url, param_dict)
    return extract_on_call_now_user_data(users_on_call_now)


def get_users_contact_methods_command(UserID: str):
    """Get the contact methods of a given user."""
    url = SERVER_URL + USERS_CONTACT_METHODS_SUFFIX.format(UserID)
    user_contact_methods = http_request('GET', url, {})
    return extract_users_contact_methods(user_contact_methods)


def get_users_notification_command(UserID) -> dict:
    """Get the notification rule of a given user"""
    url = SERVER_URL + USERS_NOTIFICATION_RULE.format(UserID)
    user_notification_role: dict = http_request('GET', url, {})
    return extract_users_notification_role(user_notification_role)


def resolve_event(incident_key=None, serviceKey=SERVICE_KEY) -> dict:
    if serviceKey is None:
        raise Exception('You must enter a ServiceKey at the integration '
                        'parameters or in the command to process this action.')

    action_response = resolve_or_ack_incident('resolve', incident_key, serviceKey)
    time.sleep(3)  # wait until the incident will update

    res = http_request('GET', SERVER_URL + GET_INCIDENTS_SUFFIX, {'incident_key': incident_key})
    _, contexts, _ = parse_incident_data(res.get('incidents', []))
    if contexts[0]['Status'] != "resolved":
        raise Exception('Could not resolve incident, you may have created it with different Service Key')

    return extract_new_event_data(RESOLVE_EVENT, action_response)


def acknowledge_event(incident_key=None, serviceKey=SERVICE_KEY) -> dict:
    if serviceKey is None:
        raise Exception('You must enter a ServiceKey at the integration '
                        'parameters or in the command to process this action.')

    action_response = resolve_or_ack_incident('acknowledge', incident_key, serviceKey)
    time.sleep(3)  # wait until the incident will update

    res = http_request('GET', SERVER_URL + GET_INCIDENTS_SUFFIX, {'incident_key': incident_key})
    _, contexts, _ = parse_incident_data(res.get('incidents', []))
    if contexts[0]['Status'] != "acknowledged":
        raise Exception('Could not acknowledge incident, you may have created it with different Service Key')

    return extract_new_event_data(ACKNOWLEDGE_EVENT, action_response)


def get_incident_data(args: dict):
    incident_id = args['incident_id']

    url = SERVER_URL + GET_INCIDENT_SUFFIX + incident_id
    res = http_request('GET', url, {})
    return extract_incidents_data([res.get('incident', {})], INCIDENT)


def get_service_keys() -> dict:
    offset = 0
    url = SERVER_URL + GET_SERVICES_SUFFIX
    res = http_request('GET', url, {"offset": offset})
    raw_response = [res]
    outputs = []
    contexts = []
    while res.get('services', []):
        services: list[dict] = res.get('services', [{}])
        for service in services:
            context = {'ID': service.get('id'), 'Name': service.get('name'), 'Status': service.get('status'),
                       'CreatedAt': service.get('created_at')}

            integration_list = []
            integration_string = ""
            for integration in service.get('integrations', []):
                integration_url = integration.get('self', '')
                if integration_url:
                    integration_res = http_request('GET', integration_url, {}).get('integration', {})
                    integration_data = {
                        'Name': integration_res.get('service', {}).get(
                            'summary', ''
                        )
                    }
                    integration_data['Key'] = integration_res.get('integration_key', '')
                    vendor_value = integration_res.get('vendor', {})
                    if not vendor_value:
                        integration_data['Vendor'] = 'Missing Vendor information'
                    else:
                        integration_data['Vendor'] = vendor_value.get('summary', 'Missing Vendor information')

                    integration_list.append(integration_data)
                    integration_string += (f"Name: {integration_data['Name']}, "
                                           f"Vendor: {integration_data['Vendor']}, "
                                           f"Key: {integration_data['Key']}\n"
                                           )

            output = {'Integration': integration_string}
            context['Integration'] = integration_list

            outputs.append(output)
            contexts.append(context)

        offset += 25
        res = http_request('GET', url, {"offset": offset})
        raw_response.append(res)

    return {
        'Type': entryTypes['note'],
        'Contents': raw_response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(SERVICES, outputs, SERVICES_HEADERS),
        'EntryContext': {
            'PagerDuty.Service(val.ID==obj.ID)': contexts,
        }
    }


def add_responders_to_incident(incident_id, message, user_requests=None, escalation_policy_requests="",
                               requestor_id=None):
    """
    Send a new responder request for the specified incident. A responder is a specific User to respond to the Incident.
    If the Requestor ID is not specified in command arguments, the Default Requestor defined in instance
    parameter is used.

    Args:
        incident_id (str): The ID of the PagerDuty Incident
        message (str): The message sent with the responder request.
        user_requests (str): Comma separated list of User targets the responder request is being sent to
        escalation_policy_requests (str): Comma separated list of
            escalation policy targets the responder request is being sent to.
        requestor_id (str): The user id of the requester.
    """

    if not user_requests:
        user_requests = DEFAULT_REQUESTOR
    if not requestor_id:
        requestor_id = DEFAULT_REQUESTOR
    url = SERVER_URL + RESPONDER_REQUESTS_SUFFIX.format(incident_id)
    body = {
        'requester_id': requestor_id,
        'message': message,
        'responder_request_targets': []
    }
    for user_id in user_requests.split(","):
        body['responder_request_targets'].append({
            'responder_request_target': {
                "id": user_id,
                "type": 'user_reference'
            }
        })
    for escalation_policy_id in escalation_policy_requests:
        body['responder_request_targets'].append({
            'responder_request_target': {
                "id": escalation_policy_id,
                "type": 'escalation_policy_reference'
            }
        })
    response = http_request('POST', url, json_data=body)
    return extract_responder_request(response)


def run_response_play(incident_id, from_email, response_play_uuid):
    """
    Run a specified response play on a given incident.
    Response Plays are a package of Incident Actions that can be applied during an Incident's life cycle.
    Args:
        incident_id:string The ID of the PagerDuty Incident
        from_email:string, The email address of a valid user associated with the account making the request.
        response_play_uuid:list, The response play ID of the response play associated with the request.
    """
    url = SERVER_URL + RESPONSE_PLAY_SUFFIX.format(response_play_uuid)
    body = {
        'incident': {
            'id': incident_id,
            'type': 'incident_reference'
        }
    }
    response = http_request('POST', url, json_data=body, additional_headers={"From": from_email})
    if response != {"status": "ok"}:
        raise Exception(f"Status NOT Ok - {response}")
    return CommandResults(
        readable_output=f"Response play successfully run to the incident {incident_id} by {from_email}",
        raw_response=response,
    )


''' EXECUTION CODE '''


def main():
    command = demisto.command()
    args = demisto.args()

    if not API_KEY:
        raise DemistoException('API key must be provided.')
    demisto.debug(f'command is {command}')
    try:
        if command == 'test-module':
            test_module()
        elif command == 'fetch-incidents':
            fetch_incidents()
        elif command == 'PagerDuty-incidents':
            demisto.results(get_incidents_command(args))
        elif command == 'PagerDuty-submit-event':
            demisto.results(submit_event_command(**args))
        elif command == 'PagerDuty-get-users-on-call':
            return_results(get_on_call_users_command(**args))
        elif command == 'PagerDuty-get-all-schedules':
            demisto.results(get_all_schedules_command(**args))
        elif command == 'PagerDuty-get-users-on-call-now':
            return_results(get_on_call_now_users_command(**args))
        elif command == 'PagerDuty-get-contact-methods':
            demisto.results(get_users_contact_methods_command(**args))
        elif command == 'PagerDuty-get-users-notification':
            demisto.results(get_users_notification_command(**args))
        elif command == 'PagerDuty-resolve-event':
            demisto.results(resolve_event(**args))
        elif command == 'PagerDuty-acknowledge-event':
            demisto.results(acknowledge_event(**args))
        elif command == 'PagerDuty-get-incident-data':
            demisto.results(get_incident_data(args))
        elif command == 'PagerDuty-get-service-keys':
            demisto.results(get_service_keys())
        elif command == 'PagerDuty-add-responders':
            return_results(add_responders_to_incident(**args))
        elif command == 'PagerDuty-run-response-play':
            return_results(run_response_play(**args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

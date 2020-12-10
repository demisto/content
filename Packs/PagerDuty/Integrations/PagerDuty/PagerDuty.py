import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
"""" IMPORTS """
import json
import requests
from datetime import datetime, timedelta

reload(sys)
sys.setdefaultencoding('utf8')  # pylint: disable=no-member

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
# PagerDuty API works only with secured communication.
USE_SSL = not demisto.params().get('insecure', False)

USE_PROXY = demisto.params().get('proxy', True)
API_KEY = ''
SERVICE_KEY = ''
FETCH_INTERVAL = ''

SERVER_URL = 'https://api.pagerduty.com/'
CREATE_EVENT_URL = 'https://events.pagerduty.com/v2/enqueue'

DEFAULT_HEADERS = {}  # type: Dict[str, str]

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
ACKNOLWEDGE_EVENT = 'Acknowledge Event'
USERS_ON_CALL = 'Users On Call'
INCIDETS_LIST = 'PagerDuty Incidents'
INCIDENT = 'PagerDuty Incident'
CONTACT_METHODS = 'Contact Methods'
USERS_ON_CALL_NOW = 'Users On Call Now'
NOTIFICATION_RULES = 'User notification rules'

'''TABLE HEADERS'''
CONTACT_METHODS_HEADERS = ['ID', 'Type', 'Details']
SERVICES_HEADERS = ['ID', 'Name', 'Status', 'Created At', 'Integration']
NOTIFICATION_RULES_HEADERS = ['ID', 'Type', 'Urgency', 'Notification timeout(minutes)']
SCHEDULES_HEADERS = ['ID', 'Name', 'Today', 'Time Zone', 'Escalation Policy', 'Escalation Policy ID']
USERS_ON_CALL_NOW_HEADERS = ['ID', 'Email', 'Name', 'Role', 'User Url', 'Time Zone']
INCIDENTS_HEADERS = ['ID', 'Title', 'Description', 'Status', 'Created On', 'Urgency', 'Html Url',
                     'Assigned To User', 'Service ID', 'Service Name', 'Escalation Policy', 'Last Status Change On',
                     'Last Status Change By', 'Number Of Escalations', 'Resolved By User', 'Resolve Reason']


''' HELPER FUNCTIONS '''


def http_request(method, url, params_dict=None, data=None):
    LOG('running %s request with url=%s\nparams=%s' % (method, url, json.dumps(params_dict)))
    try:
        res = requests.request(method,
                               url,
                               verify=USE_SSL,
                               params=params_dict,
                               headers=DEFAULT_HEADERS,
                               data=data
                               )
        res.raise_for_status()

        return unicode_to_str_recur(res.json())

    except Exception as e:
        LOG(e)
        raise


def translate_severity(sev):
    if sev == 'high':
        return 3
    elif sev == 'Low':
        return 1
    return 0


def unicode_to_str_recur(obj):
    """Converts unicode elements of obj (incl. dictionary and list) to string recursively"""
    if IS_PY3:
        return obj
    if isinstance(obj, dict):
        obj = {unicode_to_str_recur(k): unicode_to_str_recur(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        obj = map(unicode_to_str_recur, obj)
    elif isinstance(obj, unicode):
        obj = obj.encode('utf-8', 'ignore')
    return obj


def test_module():
    try:
        get_on_call_now_users_command()
    except Exception as e:
        return_error(e)

    demisto.results('ok')


def extract_on_call_user_data(users):
    """Extact data about user from a given schedule."""
    outputs = []
    contexts = []
    for user in users:
        output = {}
        context = {}

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

    return {
        'Type': entryTypes['note'],
        'Contents': users,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(USERS_ON_CALL, outputs, USERS_ON_CALL_NOW_HEADERS),
        'EntryContext': {
            'PagerDutyUser(val.ID==obj.ID)': contexts
        }
    }


def extract_on_call_now_user_data(users_on_call_now):
    """Extract the user data from the oncalls json."""
    outputs = []  # type: List[Dict]
    contexts = []  # type: List[Dict]
    oncalls = users_on_call_now.get('oncalls', {})

    for i in xrange(len(oncalls)):
        output = {}
        context = {}

        data = oncalls[i]
        user = data.get('user')

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

    return {
        'Type': entryTypes['note'],
        'Contents': users_on_call_now,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(USERS_ON_CALL_NOW, outputs, USERS_ON_CALL_NOW_HEADERS),
        'EntryContext': {
            'PagerDutyUser(val.ID===obj.ID)': contexts
        }
    }


def parse_incident_data(incidents):
    """Parse incident data to output,context format"""
    outputs = []
    contexts = []
    raw_response = []
    for i, incident in enumerate(incidents):
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
        for team in incident.get('teams', []):
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
            }
        else:
            context['assignment'] = {}

        acknowledgements = incident.get('acknowledgements', [{}, ])
        if len(acknowledgements) > 0:
            context['acknowledgement'] = {
                "time": assignment[0].get('at', ''),
                "acknowledger": assignment[0].get('acknowledger', {}).get('summary', ''),
            }
        else:
            context['acknowledgement'] = {}

        outputs.append(output)
        contexts.append(context)
        raw_response.append(incident)

    return outputs, contexts, raw_response


def extract_incidents_data(incidents, table_name):
    """Extact data about incidents."""
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


def extract_all_schedules_data(schedules):
    """Extract the data about all the schedules."""
    outputs = []
    contexts = []
    for i in range(len(schedules)):
        output = {}
        context = {}  # type: Dict
        data = schedules[i]

        output['ID'] = data.get('id')
        output['Name'] = data.get('name')
        output['Time Zone'] = data.get('time_zone')
        output['Today'] = datetime.today().strftime('%Y-%m-%d')
        escalation_policies = data.get('escalation_policies', [])
        if len(escalation_policies) > 0:
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
                        event_class='', component='', incident_key=None, service_key=SERVICE_KEY):
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


def resolve_or_ack_incident(action, incident_key, service_key=SERVICE_KEY):
    """Resolve or Acknowledge an incident in the PagerDuty instance."""
    payload = {
        'routing_key': service_key,
        'event_action': action,
        'dedup_key': incident_key
    }

    return http_request('POST', CREATE_EVENT_URL, data=json.dumps(payload))


def extract_new_event_data(table_name, response):
    """Extract the data from the response of creating a new command."""
    output = {}
    context = {}

    output['Status'] = response.get('status', '')
    output['Message'] = response.get('message', '')
    output['Incident key'] = response.get('dedup_key', '')

    context['Status'] = output['Status']
    context['Message'] = output['Message']
    context['incident_key'] = output['Incident key']

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


def extract_users_contact_methods(user_contact_methods):
    """Extract all the contact methods of a given user."""
    outputs = []
    contexts = []
    contact_methods = user_contact_methods.get('contact_methods')
    for contact_method in contact_methods:
        output = {}

        output['ID'] = contact_method.get('id')
        output['Type'] = CONTACT_METHODS_TO_HUMAN_READABLE[contact_method.get('type', '')]

        country_code = str(contact_method.get('country_code', ''))
        address = contact_method.get('address', '')
        output['Details'] = country_code + address

        outputs.append(output)

        del contact_method['address']
        if output['Type'] == 'SMS' or output['Type'] == 'Phone':
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


def extract_users_notification_role(user_notication_role):
    """Extract the notification role of a given user."""
    outputs = []
    notification_rules = user_notication_role.get('notification_rules')
    for notification_rule in notification_rules:
        output = {}

        output['ID'] = notification_rule.get('id')
        output['Type'] = notification_rule.get('type', '')
        output['Urgency'] = notification_rule.get('urgency')
        output['Notification timeout(minutes)'] = notification_rule.get('start_delay_in_minutes')

        outputs.append(output)

    return {
        'Type': entryTypes['note'],
        'Contents': user_notication_role,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(NOTIFICATION_RULES, outputs, NOTIFICATION_RULES_HEADERS),
        'EntryContext': {
            'PagerDuty.Notification_rules(val.id==obj.id)': notification_rules,
        }
    }


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


def configure_status(status='triggered,acknowledged'):
    statuses = status.split(',')
    statuses_string = "&" + STATUSES + '='
    statuses = statuses_string.join(statuses)
    status_request = '&' + STATUSES + '=' + statuses

    status_request = status_request + INCLUDED_FIELDS + UTC_PARAM
    return status_request


def get_incidents_command(since=None, until=None, status='triggered,acknowledged', sortBy=None):
    """Get incidents command."""
    param_dict = {}
    if since is not None:
        param_dict['since'] = since
    if until is not None:
        param_dict['until'] = until
    if sortBy is not None:
        param_dict['sortBy'] = sortBy

    url = SERVER_URL + GET_INCIDENTS_SUFFIX + configure_status(status)
    res = http_request('GET', url, param_dict)
    return extract_incidents_data(res.get('incidents', []), INCIDETS_LIST)


def submit_event_command(source, summary, severity, action, description='No description', group='',
                         event_class='', component='', incident_key=None, serviceKey=SERVICE_KEY):
    """Create new event."""
    if serviceKey is None:
        raise Exception('You must enter a ServiceKey at the integration '
                        'parmaters or in the command to process this action.')

    res = create_new_incident(source, summary, severity, action, description,
                              group, event_class, component, incident_key, serviceKey)
    return extract_new_event_data(TRIGGER_EVENT, res)


def get_all_schedules_command(query=None, limit=None):
    """Get all the schedules."""
    param_dict = {}
    if query is not None:
        param_dict['query'] = query
    if limit is not None:
        param_dict['limit'] = limit

    url = SERVER_URL + GET_SCHEDULES_SUFFIX
    res = http_request('GET', url, param_dict)
    schedules = res.get('schedules', [])
    return extract_all_schedules_data(schedules)


def get_on_call_users_command(scheduleID, since=None, until=None):
    """Get the list of user on call in a from scheduleID"""
    param_dict = {}
    if since is not None:
        param_dict['since'] = since
    if until is not None:
        param_dict['until'] = until

    url = SERVER_URL + ON_CALL_BY_SCHEDULE_SUFFIX.format(scheduleID)
    users_on_call = http_request('GET', url, param_dict)
    return extract_on_call_user_data(users_on_call.get('users', []))


def get_on_call_now_users_command(limit=None, escalation_policy_ids=None, schedule_ids=None):
    """Get the list of users that are on call now."""
    param_dict = {}
    if limit is not None:
        param_dict['limit'] = limit
    if escalation_policy_ids is not None:
        param_dict['escalation_policy_ids[]'] = argToList(escalation_policy_ids)
    if schedule_ids is not None:
        param_dict['schedule_ids[]'] = argToList(schedule_ids)

    url = SERVER_URL + ON_CALLS_USERS_SUFFIX
    users_on_call_now = http_request('GET', url, param_dict)
    return extract_on_call_now_user_data(users_on_call_now)


def get_users_contact_methods_command(UserID):
    """Get the contact methods of a given user."""
    url = SERVER_URL + USERS_CONTACT_METHODS_SUFFIX.format(UserID)
    user_contact_methods = http_request('GET', url, {})
    return extract_users_contact_methods(user_contact_methods)


def get_users_notification_command(UserID):
    """Get the notification rule of a given user"""
    url = SERVER_URL + USERS_NOTIFICATION_RULE.format(UserID)
    user_notication_role = http_request('GET', url, {})
    return extract_users_notification_role(user_notication_role)


def resolve_event(incident_key=None, serviceKey=SERVICE_KEY):
    if serviceKey is None:
        raise Exception('You must enter a ServiceKey at the integration '
                        'parmaters or in the command to process this action.')

    action_response = resolve_or_ack_incident('resolve', incident_key, serviceKey)

    res = http_request('GET', SERVER_URL + GET_INCIDENTS_SUFFIX, {'incident_key': incident_key})
    _, contexts, _ = parse_incident_data(res.get('incidents', []))
    if contexts[0]['Status'] != "resolved":
        raise Exception('Could not resolve incident, you may have created it with different Service Key')

    return extract_new_event_data(RESOLVE_EVENT, action_response)


def acknowledge_event(incident_key=None, serviceKey=SERVICE_KEY):
    if serviceKey is None:
        raise Exception('You must enter a ServiceKey at the integration '
                        'parmaters or in the command to process this action.')

    action_response = resolve_or_ack_incident('acknowledge', incident_key, serviceKey)

    res = http_request('GET', SERVER_URL + GET_INCIDENTS_SUFFIX, {'incident_key': incident_key})
    _, contexts, _ = parse_incident_data(res.get('incidents', []))
    if contexts[0]['Status'] != "acknowledged":
        raise Exception('Could not acknowledge incident, you may have created it with different Service Key')

    return extract_new_event_data(ACKNOLWEDGE_EVENT, action_response)


def get_incident_data():
    incident_id = demisto.args().get('incident_id')

    url = SERVER_URL + GET_INCIDENT_SUFFIX + incident_id
    res = http_request('GET', url, {})
    return extract_incidents_data([res.get('incident', {})], INCIDENT)


def get_service_keys():
    offset = 0
    raw_response = []

    url = SERVER_URL + GET_SERVICES_SUFFIX
    res = http_request('GET', url, {"offset": offset})
    raw_response.append(res)

    outputs = []
    contexts = []
    while res.get('services', []):
        services = res.get('services', [])
        for service in services:
            output = {}
            context = {}
            context['ID'] = output['ID'] = service.get('id')
            context['Name'] = output['Name'] = service.get('name')
            context['Status'] = output['Status'] = service.get('status')
            context['CreatedAt'] = output['Created At'] = service.get('created_at')

            integration_list = []
            integration_string = ""
            for integration in service.get('integrations', []):
                integration_url = integration.get('self', '')
                if integration_url:
                    integration_data = {}
                    integration_res = http_request('GET', integration_url, {}).get('integration', {})
                    integration_data['Name'] = integration_res.get('service', {}).get('summary', '')
                    integration_data['Key'] = integration_res.get('integration_key', '')
                    vendor_value = integration_res.get('vendor', {})
                    if not vendor_value:
                        integration_data['Vendor'] = 'Missing Vendor information'
                    else:
                        integration_data['Vendor'] = vendor_value.get('summary', 'Missing Vendor information')

                    integration_list.append(integration_data)
                    integration_string += "Name: {}, Vendor: {}, Key: {}\n".format(integration_data['Name'],
                                                                                   integration_data['Vendor'],
                                                                                   integration_data['Key'])

            output['Integration'] = integration_string
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


''' EXECUTION CODE '''


def main():
    LOG('command is %s' % (demisto.command(), ))

    global API_KEY, SERVICE_KEY, FETCH_INTERVAL, DEFAULT_HEADERS
    API_KEY = demisto.params()['APIKey']
    SERVICE_KEY = demisto.params()['ServiceKey']
    FETCH_INTERVAL = demisto.params()['FetchInterval']
    DEFAULT_HEADERS = {
        'Authorization': 'Token token=' + API_KEY,
        'Accept': 'application/vnd.pagerduty+json;version=2'
    }

    try:
        if demisto.command() == 'test-module':
            test_module()
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()
        elif demisto.command() == 'PagerDuty-incidents':
            demisto.results(get_incidents_command(**demisto.args()))
        elif demisto.command() == 'PagerDuty-submit-event':
            demisto.results(submit_event_command(**demisto.args()))
        elif demisto.command() == 'PagerDuty-get-users-on-call':
            demisto.results(get_on_call_users_command(**demisto.args()))
        elif demisto.command() == 'PagerDuty-get-all-schedules':
            demisto.results(get_all_schedules_command(**demisto.args()))
        elif demisto.command() == 'PagerDuty-get-users-on-call-now':
            demisto.results(get_on_call_now_users_command(**demisto.args()))
        elif demisto.command() == 'PagerDuty-get-contact-methods':
            demisto.results(get_users_contact_methods_command(**demisto.args()))
        elif demisto.command() == 'PagerDuty-get-users-notification':
            demisto.results(get_users_notification_command(**demisto.args()))
        elif demisto.command() == 'PagerDuty-resolve-event':
            demisto.results(resolve_event(**demisto.args()))
        elif demisto.command() == 'PagerDuty-acknowledge-event':
            demisto.results(acknowledge_event(**demisto.args()))
        elif demisto.command() == 'PagerDuty-get-incident-data':
            demisto.results(get_incident_data())
        elif demisto.command() == 'PagerDuty-get-service-keys':
            demisto.results(get_service_keys())
    except Exception as e:
        return_error(e)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

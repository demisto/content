import json
from typing import Dict, Any
import dateparser
import demistomock as demisto
import requests
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DEFAULT_INCIDENT_TO_FETCH = 50

SEVERITY_OPTIONS = {
    'Low': 0,
    'Medium': 1,
    'High': 2
}

RESOLUTION_STATUS_OPTIONS = {
    'Open': 0,
    'Dismissed': 1,
    'Resolved': 2
}

# Note that number 4 is missing
SOURCE_TYPE_OPTIONS = {
    'Access_control': 0,
    'Session_control': 1,
    'App_connector': 2,
    'App_connector_analysis': 3,
    'Discovery': 5,
    'MDATP': 6
}

FILE_TYPE_OPTIONS = {
    'Other': 0,
    'Document': 1,
    'Spreadsheet': 2,
    'Presentation': 3,
    'Text': 4,
    'Image': 5,
    'Folder': 6
}

FILE_SHARING_OPTIONS = {
    'Private': 0,
    'Internal': 1,
    'External': 2,
    'Public': 3,
    'Public_Internet': 4
}

IP_CATEGORY_OPTIONS = {
    'Corporate': 1,
    'Administrative': 2,
    'Risky': 3,
    'VPN': 4,
    'Cloud_provider': 5,
    'Other': 6
}

IS_EXTERNAL_OPTIONS = {
    'External': True,
    'Internal': False,
    'No_value': None
}

STATUS_OPTIONS = {
    'N/A': 0,
    'Staged': 1,
    'Active': 2,
    'Suspended': 3,
    'Deleted': 4
}


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def list_alerts(self, url_suffix, request_data):
        data = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_data
        )
        return data

    def dismiss_bulk_alerts(self, request_data):
        data = self._http_request(
            method='POST',
            url_suffix='/alerts/dismiss_bulk/',
            json_data=request_data
        )
        return data

    def resolve_bulk_alerts(self, request_data):
        data = self._http_request(
            method='POST',
            url_suffix='/alerts/resolve/',
            json_data=request_data
        )
        return data

    def list_activities(self, url_suffix, request_data):
        data = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_data
        )
        return data

    def list_users_accounts(self, url_suffix, request_data):
        data = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_data
        )
        return data

    def list_files(self, url_suffix, request_data):
        data = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_data
        )
        return data

    def list_incidents(self, filters, limit):
        return self._http_request(
            method='POST',
            url_suffix='/alerts/',
            json_data={
                'filters': filters,
                'limit': limit
            }
        )


def arg_to_timestamp(arg):
    if isinstance(arg, str) and arg.isdigit():
        return int(arg)
    if isinstance(arg, str):
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True})
        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        return int(arg)


def generate_specific_key_by_command_name(url_suffix):
    service_key, instance_key, username_key = '', '', ''
    if url_suffix == '/entities/':
        service_key, instance_key, username_key = 'app', 'instance', 'entity'
    elif url_suffix == '/files/':
        service_key, instance_key, username_key = 'service', 'instance', 'owner.entity'
    elif url_suffix == '/alerts/':
        service_key, instance_key, username_key = 'entity.service', 'entity.instance', 'entity.entity'
    elif url_suffix == '/activities/':
        service_key, instance_key, username_key = 'service', 'instance', 'entity'
    return service_key, instance_key, username_key


def args_or_params_to_filter(arguments, url_suffix='', args_or_params='args'):
    service_key, instance_key, username_key = '', '', ''
    if args_or_params == 'args':
        service_key, instance_key, username_key = generate_specific_key_by_command_name(url_suffix)
    request_data: Dict[str, Any] = {}
    filters: Dict[str, Any] = {}
    for key, value in arguments.items():
        if key in ['skip', 'limit']:
            request_data[key] = int(value)
        if key == 'service':
            filters[service_key] = {'eq': int(value)}
        if key == 'instance':
            filters[instance_key] = {'eq': int(value)}
        if key == 'source':
            filters[key] = {'eq': SOURCE_TYPE_OPTIONS[value]}
        if key == 'ip_category':
            filters['ip.category'] = {'eq': IP_CATEGORY_OPTIONS[value]}
        if key == 'ip':
            filters['ip.address'] = {'eq': value}
        if key == 'username':
            filters[username_key] = {'eq': json.loads(value)}
        if key == 'taken_action':
            filters['activity.takenAction'] = {'eq': value}
        if key == 'severity':
            filters[key] = {'eq': SEVERITY_OPTIONS[value]}
        if key == 'resolution_status':
            filters['resolutionStatus'] = {'eq': RESOLUTION_STATUS_OPTIONS[value]}
        if key == 'file_type':
            filters['fileType'] = {'eq': FILE_TYPE_OPTIONS[value]}
        if key == 'sharing':
            filters[key] = {'eq': FILE_SHARING_OPTIONS[value]}
        if key == 'extension':
            filters[key] = {'eq': value}
        if key == 'quarantined':
            filters[key] = {'eq': argToBoolean(value)}
        if key == 'type':
            filters[key] = {'eq': value}
        if key == 'group_id':
            filters['userGroups'] = {'eq': value}
        if key == 'is_admin':
            filters['isAdmin'] = {'eq': value}
        if key == 'is_external':
            filters['isExternal'] = {'eq': IS_EXTERNAL_OPTIONS[value]}
        if key == 'status':
            filters[key] = {'eq': STATUS_OPTIONS[value]}
    if args_or_params == 'params':
        return filters
    request_data['filters'] = filters
    return request_data


def build_filter_and_url_to_search_with(url_suffix, customer_filters, arguments, specific_id_to_search=''):
    request_data = {}
    if specific_id_to_search:
        url_suffix += specific_id_to_search
    elif customer_filters:
        request_data = json.loads(customer_filters)
    else:
        request_data = args_or_params_to_filter(arguments, url_suffix)
    return request_data, url_suffix


def args_to_filter_for_dismiss_and_resolve_alerts(alert_id, customer_filters, comments):
    request_data = {}
    filters = {}
    if alert_id:
        ids = {'eq': alert_id.split(',')}
        filters['id'] = ids
        if comments:
            request_data['comment'] = comments
        request_data['filters'] = filters
    elif customer_filters:
        request_data = json.loads(customer_filters)
    return request_data

#
# def params_to_filter(parameters):
#     """
#     Turns the parameters to filters.
#     Args:
#         parameters: The parameters that should to be filter.
#     Returns:
#         The filter we built using the parameters.
#     """
#     filters = {}
#     if 'severity' in parameters.keys():
#         filters['severity'] = {'eq': SEVERITY_OPTIONS[parameters['severity']]}
#     if 'resolution_status' in parameters.keys():
#         filters['resolutionStatus'] = {'eq': RESOLUTION_STATUS_OPTIONS[parameters['resolution_status']]}
#     if 'service' in parameters.keys():
#         filters['entity.service'] = {'eq': (int(parameters['service']))}
#     if 'instance' in parameters.keys():
#         filters['entity.instance'] = {'eq': (int(parameters['instance']))}
#     return filters
#


def test_module(client):
    try:
        client.list_alerts(url_suffix='/alerts/', request_data={})
        if demisto.params().get('isFetch'):
            client.list_incidents(filters={}, limit=1)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set.'
        return str(e)
    return 'ok'


def alert_to_human_readable(alert):
    readable_output = assign_params(alert_id=alert.get('_id'), title=alert.get('title'),
                                    description=alert.get('description'),
                                    status_value=[key for key, value in STATUS_OPTIONS.items()
                                                  if alert.get('statusValue') == value],
                                    severity_value=[key for key, value in SEVERITY_OPTIONS.items()
                                                    if alert.get('severityValue') == value],
                                    alert_date=datetime.fromtimestamp(alert.get('timestamp') / 1000.0).isoformat())
    return readable_output


def alerts_to_human_readable(alerts, alert_id):
    if not alert_id:
        alerts_readable_outputs = []
        for alert in alerts:
            alerts_readable_outputs.append(alert_to_human_readable(alert))
    else:
        alerts_readable_outputs = alert_to_human_readable(alerts)
    headers = ['alert_id', 'alert_date', 'title', 'description', 'status_value', 'severity_value']
    human_readable = tableToMarkdown('Results', alerts_readable_outputs, headers, removeNull=True)
    return human_readable


def list_alerts_command(client, args):
    url_suffix = '/alerts/'
    alert_id = args.get('alert_id')
    customer_filters = args.get('customer_filters')
    arguments = assign_params(skip=args.get('skip'), limit=args.get('limit'), severity=args.get('severity'),
                              service=args.get('service'), instance=args.get('instance'),
                              resolution_status=args.get('resolution_status'), username=args.get('username'))
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, customer_filters, arguments, alert_id)
    alerts = client.list_alerts(url_suffix, request_data)
    alerts = arrange_alerts_by_incident_type(alerts)
    human_readable = alerts_to_human_readable(alerts, alert_id)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MicrosoftCloudAppSecurity.Alerts',
        outputs_key_field='alert_id',
        outputs=alerts
    )


def bulk_dismiss_alert_command(client, args):
    alert_id = args.get('alert_id')
    customer_filters = args.get('customer_filters')
    comment = args.get('comment')
    request_data = args_to_filter_for_dismiss_and_resolve_alerts(alert_id, customer_filters, comment)
    try:
        dismiss_alerts = client.dismiss_bulk_alerts(request_data)
    except DemistoException as e:
        return str(e)
    return CommandResults(
        readable_output=dismiss_alerts,
        outputs_prefix='MicrosoftCloudAppSecurity.AlertDismiss',
        outputs_key_field='alert_id',
        outputs=dismiss_alerts
    )


def bulk_resolve_alert_command(client, args):
    alert_id = args.get('alert_id')
    customer_filters = args.get('customer_filters')
    comment = args.get('comment')
    request_data = args_to_filter_for_dismiss_and_resolve_alerts(alert_id, customer_filters, comment)
    try:
        resolve_alerts = client.resolve_bulk_alerts(request_data)
    except DemistoException as e:
        return str(e)
    return CommandResults(
        readable_output=resolve_alerts,
        outputs_prefix='MicrosoftCloudAppSecurity.AlertResolve',
        outputs_key_field='alert_id',
        outputs=resolve_alerts
    )


def activity_to_human_readable(activity):
    readable_output = assign_params(activity_id=activity.get('_id'), severity=activity.get('severity'),
                                    activity_date=datetime.fromtimestamp(activity.get('timestamp') / 1000.0)
                                    .isoformat(),
                                    app_name=activity.get('appName'), description=activity.get('description'))
    return readable_output


def activities_to_human_readable(activities, activity_id):
    if not activity_id:
        activities_readable_outputs = []
        for activity in activities:
            activities_readable_outputs.append(activity_to_human_readable(activity))
    else:
        activities_readable_outputs = (activity_to_human_readable(activities))
    headers = ['activity_id', 'activity_date', 'app_name', 'description', 'severity']
    human_readable = tableToMarkdown('Results', activities_readable_outputs, headers, removeNull=True)
    return human_readable


def arrange_entity_data(activity):
    entities_data = []
    if 'entityData' in activity.keys():
        entity_data = activity['entityData']
        if entity_data:
            for key, value in entity_data.items():
                if value:
                    entities_data.append(value)
            activity['entityData'] = entities_data


def arrange_entities_data(activities, activity_id):
    if not activity_id:
        for activity in activities:
            arrange_entity_data(activity)
    else:
        arrange_entity_data(activities)
    return activities


def list_activities_command(client, args):
    url_suffix = '/activities/'
    activity_id = args.get('activity_id')
    customer_filters = args.get('customer_filters')
    arguments = assign_params(skip=args.get('skip'), limit=args.get('limit'), service=args.get('service'),
                              instance=args.get('instance'), ip=args.get('ip'), ip_category=args.get('ip_category'),
                              username=args.get('username'), taken_action=args.get('taken_action'),
                              source=args.get('source'))
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, customer_filters, arguments, activity_id)
    activities = client.list_activities(url_suffix, request_data)
    if activities.get('data'):  # more than one activity
        activities = activities.get('data')
    activities = arrange_entities_data(activities, activity_id)
    human_readable = activities_to_human_readable(activities, activity_id)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MicrosoftCloudAppSecurity.Activities',
        outputs_key_field='activity_id',
        outputs=activities
    )


def file_to_human_readable(file):
    readable_output = assign_params(owner_name=file.get('ownerName'), file_create_date=file.get('createdDate'),
                                    file_type=file.get('fileType'), file_name=file.get('name'),
                                    file_access_level=file.get('fileAccessLevel'), app_name=file.get('appName'),
                                    file_status=file.get('fileStatus'))
    return readable_output


def files_to_human_readable(files, file_id):
    if not file_id:
        files_readable_outputs = []
        for file in files:
            files_readable_outputs.append(file_to_human_readable(file))
    else:
        files_readable_outputs = file_to_human_readable(files)
    headers = ['owner_name', 'file_create_date', 'file_type', 'file_name', 'file_access_level', 'file_status',
               'app_name']
    human_readable = tableToMarkdown('Results', files_readable_outputs, headers, removeNull=True)
    return human_readable


def list_files_command(client, args):
    url_suffix = '/files/'
    file_id = args.get('file_id')
    customer_filters = args.get('customer_filters')
    arguments = assign_params(skip=args.get('skip'), limit=args.get('limit'), service=args.get('service'),
                              instance=args.get('instance'), file_type=args.get('file_type'),
                              username=args.get('username'), sharing=args.get('sharing'),
                              extension=args.get('extension'), quarantined=args.get('quarantined'))
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, customer_filters, arguments, file_id)
    files = client.list_files(url_suffix, request_data)
    if files.get('data'):
        files = files.get('data')
    human_readable = files_to_human_readable(files, file_id)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MicrosoftCloudAppSecurity.Files',
        outputs_key_field='file_id',
        outputs=files
    )


def user_account_to_human_readable(entity):
    readable_output = assign_params(display_name=entity.get('displayName'), last_seen=entity.get('lastSeen'),
                                    is_admin=entity.get('isAdmin'), is_external=entity.get('isExternal'),
                                    email=entity.get('email'), username=entity.get('username'))
    return readable_output


def users_accounts_to_human_readable(users_accounts, username):
    if not username:
        users_accounts_readable_outputs = []
        for entity in users_accounts:
            users_accounts_readable_outputs.append(user_account_to_human_readable(entity))
    else:
        users_accounts_readable_outputs = user_account_to_human_readable(users_accounts)
    headers = ['display_name', 'last_seen', 'is_admin', 'is_external', 'email', 'username']
    human_readable = tableToMarkdown('Results', users_accounts_readable_outputs, headers, removeNull=True)
    return human_readable


def list_users_accounts_command(client, args):
    url_suffix = '/entities/'
    customer_filters = args.get('customer_filters')
    arguments = assign_params(skip=args.get('skip'), limit=args.get('limit'), service=args.get('service'),
                              instance=args.get('instance'), type=args.get('type'), username=args.get('username'),
                              group_id=args.get('group_id'), is_admin=args.get('is_admin'), status=args.get('status'),
                              is_external=args.get('is_external'))
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, customer_filters, arguments)
    users_accounts = client.list_users_accounts(url_suffix, request_data)
    if users_accounts.get('data'):
        users_accounts = users_accounts.get('data')
    if args.get('username'):
        users_accounts = users_accounts[0]
    human_readable = users_accounts_to_human_readable(users_accounts, args.get('username'))
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MicrosoftCloudAppSecurity.UsersAccounts',
        outputs_key_field='username',
        outputs=users_accounts
    )


def calculate_fetch_start_time(last_fetch, first_fetch):
    if last_fetch is None:
        if not first_fetch:
            first_fetch = '3 days'
        first_fetch_time = arg_to_timestamp(first_fetch)
        return first_fetch_time
    else:
        last_fetch = int(last_fetch)
    latest_created_time = last_fetch
    return latest_created_time


def get_max_result_number(max_results):
    if not max_results:
        return DEFAULT_INCIDENT_TO_FETCH
    return int(max_results)


def arrange_alert_by_incident_type(alert):
    incident_types: Dict[str, Any] = {}
    for entity in alert['entities']:
        if not entity['type'] in incident_types.keys():
            incident_types[entity['type']] = []
        incident_types[entity['type']].append(entity)
    alert.update(incident_types)
    del alert['entities']


def arrange_alerts_by_incident_type(alerts):
    if 'data' in alerts.keys():
        alerts = alerts['data']
        for alert in alerts:
            arrange_alert_by_incident_type(alert)
    else:
        arrange_alert_by_incident_type(alerts)
    return alerts


def alerts_to_incidents_and_fetch_start_from(alerts, fetch_start_time):
    incidents = []
    for alert in alerts['data']:
        incident_created_time = (alert['timestamp'])
        incident_created_datetime = datetime.fromtimestamp(incident_created_time / 1000.0).isoformat()
        incident_occurred = incident_created_datetime.split('.')
        incident = {
            'name': alert['title'],
            'occurred': incident_occurred[0] + 'Z',
            'rawJSON': json.dumps(alert)
        }
        incidents.append(incident)
        if incident_created_time > fetch_start_time:
            fetch_start_time = incident_created_time
    return incidents, fetch_start_time


def fetch_incidents(client, max_results, last_run, first_fetch, filters):
    max_results = get_max_result_number(max_results)
    last_fetch = last_run.get('last_fetch')
    fetch_start_time = calculate_fetch_start_time(last_fetch, first_fetch)
    filters["date"] = {"gte": fetch_start_time}
    alerts = client.list_incidents(filters, limit=max_results)
    alerts = arrange_alerts_by_incident_type(alerts)
    incidents, fetch_start_time = alerts_to_incidents_and_fetch_start_from(alerts, fetch_start_time)
    next_run = {'last_fetch': fetch_start_time}
    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    token = demisto.params().get('token')
    base_url = demisto.params().get("url", "")
    verify_certificate = not demisto.params().get('insecure', False)
    first_fetch = demisto.params().get('first_fetch')
    max_results = demisto.params().get('max_fetch')
    proxy = demisto.params().get('proxy', False)
    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': f'Token {token}'},
            proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            params = demisto.params()
            parameters = assign_params(severity=params.get('severity'), instance=params.get('instance'),
                                       resolution_status=params.get('resolutionStatus'),
                                       service=params.get('service'))
            filters = args_or_params_to_filter(parameters, url_suffix="", args_or_params="params")
            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch=first_fetch,
                filters=filters)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'microsoft-cas-alerts-list':
            return_results(list_alerts_command(client, demisto.args()))

        elif demisto.command() == 'microsoft-cas-alert-dismiss-bulk':
            return_results(bulk_dismiss_alert_command(client, demisto.args()))

        elif demisto.command() == 'microsoft-cas-alert-resolve-bulk':
            return_results(bulk_resolve_alert_command(client, demisto.args()))

        elif demisto.command() == 'microsoft-cas-activities-list':
            return_results(list_activities_command(client, demisto.args()))

        elif demisto.command() == 'microsoft-cas-files-list':
            return_results(list_files_command(client, demisto.args()))

        elif demisto.command() == 'microsoft-cas-users-accounts-list':
            return_results(list_users_accounts_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

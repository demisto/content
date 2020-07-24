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


def args_to_filter(arguments, url_suffix):
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

        request_data['filters'] = filters
    return request_data


def build_filter_and_url_to_search_with(url_suffix, customer_filters, arguments, command_id=''):
    request_data = {}
    if command_id:
        url_suffix += command_id
    elif customer_filters:
        request_data = json.loads(customer_filters)
    else:
        request_data = args_to_filter(arguments, url_suffix)
    return request_data, url_suffix


def args_to_filter_dismiss_alerts_and_resolve_alerts(alert_ids, customer_filters, comments):
    request_data = {}
    filters = {}
    if alert_ids:
        ids = {'eq': alert_ids.split(',')}
        filters['id'] = ids
        if comments:
            request_data['comment'] = comments
        request_data['filters'] = filters
    elif customer_filters:
        request_data = json.loads(customer_filters)
    return request_data


def params_to_filter(parameters):
    """
    Turns the parameters to filters.
    Args:
        parameters: The parameters that should to be filters.
    Returns:
        The filter we built using the parameters.
    """
    filters = {}
    if 'severity' in parameters.keys():
        filters['severity'] = {'eq': SEVERITY_OPTIONS[parameters['severity']]}
    if 'resolution_status' in parameters.keys():
        filters['resolutionStatus'] = {'eq': RESOLUTION_STATUS_OPTIONS[parameters['resolution_status']]}
    if 'service' in parameters.keys():
        filters['entity.service'] = {'eq': (int(parameters['service']))}
    if 'instance' in parameters.keys():
        filters['entity.instance'] = {'eq': (int(parameters['instance']))}
    return filters


def test_module(client):
    try:
        client.list_alerts(url_suffix='/alerts/', request_data={"severity": {"eq": 0}})
        if demisto.params().get('isFetch'):
            client.list_incidents(filters={"severity": {"eq": 0}}, limit=1)
    except DemistoException as e:
        return str(e)
    return 'ok'


def alerts_output_to_readable_output(alerts):
    if 'data' not in alerts:
        alerts = {'data': [alerts]}
    list_readable_output = []
    for alert in alerts['data']:
        readable_output = {}
        if alert.get('_id'):
            readable_output['alert_id'] = alert['_id']
        if alert.get('timestamp'):
            readable_output['alert_date'] = datetime.fromtimestamp(alert['timestamp'] / 1000.0).isoformat()
        if alert.get('title'):
            readable_output['title'] = alert['title']
        if alert.get('description'):
            readable_output['description'] = alert['description']
        if alert.get('statusValue'):
            readable_output['status_value'] = [key for key, value in STATUS_OPTIONS.items()
                                               if alert['statusValue'] == value]
        if alert.get('severityValue'):
            readable_output['severity_value'] = [key for key, value in SEVERITY_OPTIONS.items()
                                                 if alert['severityValue'] == value]
        list_readable_output.append(readable_output)
    headers = ['alert_id', 'alert_date', 'title', 'description', 'status_value', 'severity_value']
    human_readable = tableToMarkdown('Results', list_readable_output, headers, removeNull=True)
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
    human_readable = alerts_output_to_readable_output(alerts)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MicrosoftCloudAppSecurity.Alert',
        outputs_key_field='alert_id',
        outputs=alerts
    )


def bulk_dismiss_alert_command(client, args):
    alert_ids = args.get('alert_ids')
    customer_filters = args.get('customer_filters')
    comment = args.get('comment')
    request_data = args_to_filter_dismiss_alerts_and_resolve_alerts(alert_ids, customer_filters, comment)
    dismiss_alerts = client.dismiss_bulk_alerts(request_data)
    return CommandResults(
        readable_output=dismiss_alerts,
        outputs_prefix='MicrosoftCloudAppSecurity.AlertDismiss',
        outputs_key_field='alert_ids',
        outputs=dismiss_alerts
    )


def bulk_resolve_alert_command(client, args):
    alert_ids = args.get('alert_ids')
    customer_filters = args.get('customer_filters')
    comment = args.get('comment')
    request_data = args_to_filter_dismiss_alerts_and_resolve_alerts(alert_ids, customer_filters, comment)
    resolve_alerts = client.resolve_bulk_alerts(request_data)
    return CommandResults(
        readable_output=resolve_alerts,
        outputs_prefix='MicrosoftCloudAppSecurity.AlertResolve',
        outputs_key_field='alert_ids',
        outputs=resolve_alerts
    )


def activities_output_to_readable_output(activities):
    if 'data' not in activities:
        activities = {'data': [activities]}
    list_readable_output = []
    for activity in activities['data']:
        readable_output = {}
        if activity.get('_id'):
            readable_output['activity_id'] = activity['_id']
        if activity.get('timestamp'):
            readable_output['activity_date'] = datetime.fromtimestamp(activity['timestamp'] / 1000.0).isoformat()
        if activity.get('appName'):
            readable_output['app_name'] = activity['appName']
        if activity.get('description'):
            readable_output['description'] = activity['description']
        if activity.get('severity'):
            readable_output['severity'] = activity['severity']
        list_readable_output.append(readable_output)
    headers = ['activity_id', 'activity_date', 'app_name', 'description', 'severity']
    human_readable = tableToMarkdown('Results', list_readable_output, headers, removeNull=True)
    return human_readable


def arrange_entity_data(activities):
    entities_data = []
    if activities and 'data' in activities:
        for activity in activities['data']:
            entity_data = activity['entityData']
            if entity_data:
                for key, value in entity_data.items():
                    if value:
                        entities_data.append(value)
                print(entities_data)
                activity['entityData'] = entities_data

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
    activities = arrange_entity_data(activities)
    human_readable = activities_output_to_readable_output(activities)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MicrosoftCloudAppSecurity.Activities',
        outputs_key_field='activity_id',
        outputs=activities
    )


def files_output_to_readable_output(files):
    if 'data' not in files:
        files = {'data': [files]}
    list_readable_output = []
    for file in files['data']:
        readable_output = {}
        if file.get('ownerName'):
            readable_output['owner_name'] = file['ownerName']
        if file.get('createdDate'):
            readable_output['file_create_date'] = datetime.fromtimestamp(file['createdDate'] / 1000.0).isoformat()
        if file.get('fileType'):
            readable_output['file_type'] = file['fileType'][1]
        if file.get('name'):
            readable_output['file_name'] = file['name']
        if file.get('fileAccessLevel'):
            readable_output['file_access_level'] = file['fileAccessLevel'][1]
        if file.get('fileStatus'):
            readable_output['file_status'] = file['fileStatus'][1]
        if file.get('appName'):
            readable_output['app_name'] = file['appName']
        list_readable_output.append(readable_output)
    headers = ['owner_name', 'file_create_date', 'file_type', 'file_name', 'file_access_level', 'file_status',
               'app_name']
    human_readable = tableToMarkdown('Results', list_readable_output, headers, removeNull=True)
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
    human_readable = files_output_to_readable_output(files)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MicrosoftCloudAppSecurity.Files',
        outputs_key_field='file_id',
        outputs=files
    )


def users_accounts_output_to_readable_output(users_accounts):
    if 'data' not in users_accounts:
        users_accounts = {'data': [users_accounts]}
    list_readable_output = []
    for entity in users_accounts['data']:
        readable_output = {}
        if entity.get('displayName'):
            readable_output['display_name'] = entity['displayName']
        if entity.get('lastSeen'):
            readable_output['last_seen'] = entity['lastSeen']
        if entity.get('isAdmin'):
            readable_output['is_admin'] = entity['isAdmin']
        if entity.get('isExternal'):
            readable_output['is_external'] = entity['isExternal']
        if entity.get('email'):
            readable_output['email'] = entity['email']
        if entity.get('username'):
            readable_output['username'] = entity['username']
        list_readable_output.append(readable_output)
    headers = ['display_name', 'last_seen', 'is_admin', 'is_external', 'email', 'username']
    human_readable = tableToMarkdown('Results', list_readable_output, headers, removeNull=True)
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
    human_readable = users_accounts_output_to_readable_output(users_accounts)
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
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            params = demisto.params()
            parameters = assign_params(severity=params.get('severity'), instance=params.get('instance'),
                                       resolution_status=params.get('resolutionStatus'),
                                       service=params.get('service'))
            filters = params_to_filter(parameters)

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

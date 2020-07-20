import json

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
MAX_INCIDENTS_TO_FETCH = 200
DEFAULT_INCIDENT_TO_FETCH = 50


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
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        return int(arg)


def demisto_severity_to_api_severity(severity):
    severity_options = {
        'Low': 0,  # low severity
        'Medium': 1,  # medium severity
        'High': 2  # high severity
    }
    return severity_options[severity]


def demisto_resolution_status_to_api_resolution_status(resolution_status):
    resolution_status_options = {
        'Open': 0,
        'Dismissed': 1,
        'Resolved': 2
    }
    return resolution_status_options[resolution_status]


def demisto_source_type_to_api_source_type(source):
    source_type_option = {
        'Access_control': 0,
        'Session_control': 1,
        'App_connector': 2,
        'App_connector_analysis': 3,
        'Discovery': 5,
        'MDATP': 6
    }
    return source_type_option[source]


def demisto_file_type_to_api_file_type(file_type):
    file_type_option = {
        'Other': 0,
        'Document': 1,
        'Spreadsheet': 2,
        'Presentation': 3,
        'Text': 4,
        'Image': 5,
        'Folder': 6
    }
    return file_type_option[file_type]


def demisto_sharing_options_to_api_sharing_options(sharing):
    file_sharing_options = {
        'Private': 0,
        'Internal': 1,
        'External': 2,
        'Public': 3,
        'Public_Internet': 4
    }
    return file_sharing_options[sharing]


def demisto_ip_category_to_api_ip_category(ip_category):
    ip_category_option = {
        'Corporate': 1,
        'Administrative': 2,
        'Risky': 3,
        'VPN': 4,
        'Cloud_provider': 5,
        'Other': 6
    }
    return ip_category_option[ip_category]


def demisto_is_external_to_api_is_external(is_external):
    is_external_option = {
        'External': True,
        'Internal': False,
        'No_value': None
    }
    return is_external_option[is_external]


def demisto_status_options_to_api_status_options(status):
    status_options = {
        'N/A': 0,
        'Staged': 1,
        'Active': 2,
        'Suspended': 3,
        'Deleted': 4,
    }
    return status_options[status]


def str_to_bool(string):
    return string.lower() == 'true'


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
    request_data = {}
    filters = {}
    for key, value in arguments.items():
        if key in ['skip', 'limit']:
            request_data[key] = int(value)
        if key == 'service':
            filters[service_key] = {'eq': int(value)}
        if key == 'instance':
            filters[instance_key] = {'eq': int(value)}
        if key == 'source':
            filters[key] = {'eq': demisto_source_type_to_api_source_type(value)}
        if key == 'ip_category':
            filters['ip.category'] = {'eq': demisto_ip_category_to_api_ip_category(value)}
        if key == 'ip':
            filters['ip.address'] = {'eq': value}
        if key == 'username':
            filters[username_key] = {'eq': json.loads(value)}
        if key == 'taken_action':
            filters['activity.takenAction'] = {'eq': value}
        if key == 'severity':
            filters[key] = {'eq': demisto_severity_to_api_severity(value)}
        if key == 'resolution_status':
            filters['resolutionStatus'] = {'eq': demisto_resolution_status_to_api_resolution_status(value)}
        if key == 'file_type':
            filters['fileType'] = {'eq': demisto_file_type_to_api_file_type(value)}
        if key == 'sharing':
            filters[key] = {'eq': demisto_sharing_options_to_api_sharing_options(value)}
        if key == 'extension':
            filters[key] = {'eq': value}
        if key == 'quarantined':
            filters[key] = {'eq': str_to_bool(value)}
        if key == 'type':
            filters[key] = {'eq': value}
        if key == 'group_id':
            filters['userGroups'] = {'eq': value}
        if key == 'is_admin':
            filters['isAdmin'] = {'eq': value}
        if key == 'is_external':
            filters['isExternal'] = {'eq': demisto_is_external_to_api_is_external(value)}
        if key == 'status':
            filters[key] = {'eq': demisto_status_options_to_api_status_options(value)}
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
        filters['severity'] = {'eq': demisto_severity_to_api_severity(parameters['severity'])}
    if 'resolution_status' in parameters.keys():
        filters['resolutionStatus'] = {'eq': demisto_resolution_status_to_api_resolution_status(parameters
                                                                                                ['resolution_status'])}
    if 'service' in parameters.keys():
        filters['entity.service'] = {'eq': (int(parameters['service']))}
    if 'instance' in parameters.keys():
        filters['entity.instance'] = {'eq': (int(parameters['instance']))}
    return filters


def calculate_fetch_start_time(last_fetch, first_fetch_time):
    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)
    latest_created_time = last_fetch
    return latest_created_time


def test_module(client):
    try:
        client.alert_list(url_suffix='/alerts/', request_data={"severity": {"eq": 0}})
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            return str(e)
    return 'ok'


def list_alerts_command(client, args):
    url_suffix = '/alerts/'
    alert_id = args.get('alert_id')
    customer_filters = args.get('customer_filters')
    arguments = assign_params(skip=args.get('skip'), limit=args.get('limit'), severity=args.get('severity'),
                              service=args.get('service'), instance=args.get('instance'),
                              resolution_status=args.get('resolution_status'), username=args.get('username'))
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, customer_filters, arguments, alert_id)
    alerts = client.list_alerts(url_suffix, request_data)
    return CommandResults(
        readable_output=alerts,
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
    return CommandResults(
        readable_output=activities,
        outputs_prefix='MicrosoftCloudAppSecurity.Activities',
        outputs_key_field='activity_id',
        outputs=activities
    )


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
    return CommandResults(
        readable_output=files,
        outputs_prefix='MicrosoftCloudAppSecurity.Files',
        outputs_key_field='file_id',
        outputs=files
    )


def list_users_accounts_command(client, args):
    url_suffix = '/entities/'
    customer_filters = args.get('customer_filters')
    arguments = assign_params(skip=args.get('skip'), limit=args.get('limit'), service=args.get('service'),
                              instance=args.get('instance'), type=args.get('type'), username=args.get('username'),
                              group_id=args.get('group_id'), is_admin=args.get('is_admin'), status=args.get('status'),
                              is_external=args.get('is_external'))
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, customer_filters, arguments)
    users_accounts = client.list_users_accounts(url_suffix, request_data)
    return CommandResults(
        readable_output=users_accounts,
        outputs_prefix='MicrosoftCloudAppSecurity.UsersAccounts',
        outputs_key_field='username',
        outputs=users_accounts
    )


def preparing_max_result(max_results):
    if not max_results:
        return DEFAULT_INCIDENT_TO_FETCH
    elif max_results > MAX_INCIDENTS_TO_FETCH:
        return MAX_INCIDENTS_TO_FETCH
    return int(max_results)


def preparing_first_fetch(first_fetch):
    if not first_fetch:
        first_fetch = '3 days'
    first_fetch_time = arg_to_timestamp(first_fetch)
    return first_fetch_time


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
    max_results = preparing_max_result(max_results)
    first_fetch_time = preparing_first_fetch(first_fetch)
    last_fetch = last_run.get('last_fetch')
    fetch_start_time = calculate_fetch_start_time(last_fetch, first_fetch_time)
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
    base_url = f'{urljoin(demisto.params().get("url"))}api/v1'
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

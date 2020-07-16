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
MAX_INCIDENTS_TO_FETCH = 50


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def alert_list(self, url_suffix, request_data):
        data = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_data
        )
        return data

    def alert_dismiss_bulk(self, request_data):
        data = self._http_request(
            method='POST',
            url_suffix='/alerts/dismiss_bulk/',
            json_data=request_data
        )
        return data

    def alert_resolve_bulk(self, request_data):
        data = self._http_request(
            method='POST',
            url_suffix='/alerts/resolve/',
            json_data=request_data
        )
        return data

    def activities_list(self, url_suffix, request_data):
        data = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_data
        )
        return data

    def users_accounts_list(self, request_data):
        data = self._http_request(
            method='GET',
            url_suffix='/entities/',
            json_data=request_data
        )
        return data

    def files_list(self, url_suffix, request_data):
        data = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_data
        )
        return data

    def list_incidents(self, filters, limit):
        """
        returns dummy incident data, just for the example.
        """
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


def convert_severity(severity):
    severity_options = {
        'Low': 0,  # low severity
        'Medium': 1,  # medium severity
        'High': 2  # high severity
    }
    return severity_options[severity]


def convert_resolution_status(resolution_status):
    resolution_status_options = {
        'Low': 0,
        'Medium': 1,
        'High': 2
    }
    return resolution_status_options[resolution_status]


def convert_source_type(source):
    source_type_option = {
        'Access_control': 0,
        'Session_control': 1,
        'App_connector': 2,
        'App_connector_analysis': 3,
        'Discovery': 5,
        'MDATP': 6
    }
    return source_type_option[source]


def convert_file_type(file_type):
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


def convert_file_sharing(sharing):
    file_sharing_option = {
        'Private': 0,
        'Internal': 1,
        'External': 2,
        'Public': 3,
        'Public_Internet': 4
    }
    return file_sharing_option[sharing]


def convert_ip_category(ip_category):
    ip_category_option = {
        'Corporate': 1,
        'Administrative': 2,
        'Risky': 3,
        'VPN': 4,
        'Cloud_provider': 5,
        'Other': 6
    }
    return ip_category_option[ip_category]


def convert_is_external(is_external):
    is_external_option = {
        'External': True,
        'Internal': False,
        'No_value': None
    }
    return is_external_option[is_external]


def convert_status(status):
    status_option = {
        'N/A': 0,
        'Staged': 1,
        'Active': 2,
        'Suspended': 3,
        'Deleted': 4,
    }
    return status_option[status]


def str_to_bool(str):
    if str == 'True':
        return True
    elif str == 'False':
        return False


def args_to_json_filter_list_activity(all_params):
    request_data = {}
    filters = {}
    for key, value in all_params.items():
        if key in ['skip', 'limit']:
            request_data[key] = int(value)
        if key in ['service', 'instance']:
            filters[f'entity.{key}'] = {'eq': int(value)}
        if key == 'severity':
            filters[key] = {'eq': convert_severity(value)}
        if key == 'ip_category':
            filters['ip.category'] = {'eq': convert_ip_category(value)}
        if key == 'ip':
            filters['ip.address'] = {'eq': value}
        if key == 'username':
            filters['user.username'] = {'eq': value}
        if key == 'taken_action':
            filters['activity.takenAction'] = {'eq': value}
    request_data = {'filters': filters}
    return request_data


def args_to_json_filter_list_alert(all_params):
    request_data = {}
    filters = {}
    for key, value in all_params.items():
        if key in ['skip', 'limit']:
            request_data[key] = int(value)
        if key in ['service', 'instance']:
            filters[key] = {'eq': int(value)}
        if key == 'source':
            filters[key] = {'eq': convert_source_type(value)}
        if key == 'resolution_status':
            filters[key] = {'eq': convert_resolution_status(value)}
        if key == 'username':
            filters['entity.entity'] = {'eq': value}
    request_data = {'filters': filters}
    return request_data


def args_to_json_filter_list_files(all_params):
    request_data = {}
    filters = {}
    for key, value in all_params.items():
        if key in ['skip', 'limit']:
            request_data[key] = int(value)
        if key in ['service', 'instance']:
            filters[key] = {'eq': int(value)}
        if key == 'file_type':
            filters['fileType'] = {'eq': convert_file_type(value)}
        if key == 'sharing':
            filters[key] = {'eq': convert_file_sharing(value)}
        if key == 'extension':
            filters[key] = {'eq': value}
        if key == 'quarantined':
            filters[key] = {'eq': str_to_bool(value)}
        if key == 'owner':
            filters['owner.entity'] = {'eq': value}
    request_data = {'filters': filters}
    return request_data


def args_to_json_filter_list_users_accounts(all_params):
    request_data = {}
    filters = {}
    for key, value in all_params.items():
        if key in ['skip', 'limit']:
            request_data[key] = int(value)
        if key in ['app', 'instance']:
            filters[key] = {'eq': int(value)}
        if key == 'type':
            filters[key] = {'eq': value}
        if key == 'username':
            filters['entity'] = {'eq': json.loads(value)}
        if key == 'group_id':
            filters['userGroups'] = {'eq': value}
        if key == 'is_admin':
            filters['isAdmin'] = {'eq': value}
        if key == 'is_external':
            filters['isExternal'] = {'eq': convert_is_external(value)}
        if key == 'status':
            filters[key] = {'eq': convert_status(value)}
    request_data = {'filters': filters}
    return request_data


def args_to_json_dismiss_and_resolve_alerts(alert_ids, customer_filters, comment):
    request_data = {}
    filters = {}

    if alert_ids:
        id = {'eq': alert_ids.split(',')}
        filters['id'] = id
        if comment:
            request_data['comment'] = comment
        request_data['filters'] = filters
    elif customer_filters:
        request_data.update(json.loads(customer_filters))
    return request_data


def params_to_filter(all_params):
    filters = {}
    if 'severity' in all_params.keys():
        filters['severity'] = {'eq': convert_severity(all_params['severity'])}
    if 'resolution_status' in all_params.keys():
        filters['resolutionStatus'] = {'eq': convert_resolution_status(all_params['resolution_status'])}
    if 'service' in all_params.keys():
        filters['service'] = {'eq': (all_params['service'])}
    if 'instance' in all_params.keys():
        filters['instance'] = {'eq': (all_params['instance'])}
    return filters


def test_module(client):
    try:
        client.alert_list(url_suffix='/alerts/', request_data={"severity": {"eq": 0}})
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def alerts_list_command(client, args):
    alert_id = args.get('alert_id')
    customer_filters = args.get('customer_filters')
    all_params = assign_params(skip=args.get('skip'), limit=args.get('limit'), severity=args.get('severity'),
                               service=args.get('service'), instance=args.get('instance'),
                               resolution_status=args.get('resolution_status'), username=args.get('username'))
    request_data = {}
    url_suffix = '/alerts/'
    if alert_id:
        url_suffix += alert_id
    elif customer_filters:
        request_data.update(json.loads(customer_filters))
    else:
        request_data = args_to_json_filter_list_alert(all_params)

    alerts = client.alert_list(url_suffix, request_data)
    return CommandResults(
        readable_output=alerts,
        outputs_prefix='MicrosoftCloudAppSecurity.Alert',
        outputs_key_field='alert_id',
        outputs=alerts
    )


def alert_dismiss_bulk_command(client, args):
    alert_ids = args.get('alert_ids')
    customer_filters = args.get('customer_filters')
    comment = args.get('comment')
    request_data = args_to_json_dismiss_and_resolve_alerts(alert_ids, customer_filters, comment)
    dismiss_alerts = client.alert_dismiss_bulk(request_data)
    return CommandResults(
        readable_output=dismiss_alerts,
        outputs_prefix='MicrosoftCloudAppSecurity.AlertDismiss',
        outputs_key_field='alert_ids',
        outputs=dismiss_alerts
    )


def alert_resolve_bulk_command(client, args):
    alert_ids = args.get('alert_ids')
    customer_filters = args.get('customer_filters')
    comment = args.get('comment')
    request_data = args_to_json_dismiss_and_resolve_alerts(alert_ids, customer_filters, comment)
    resolve_alerts = client.alert_dismiss_bulk(request_data)
    return CommandResults(
        readable_output=resolve_alerts,
        outputs_prefix='MicrosoftCloudAppSecurity.AlertDismiss',
        outputs_key_field='alert_ids',
        outputs=resolve_alerts
    )


def activities_list_command(client, args):
    activity_id = args.get('activity_id')
    customer_filters = args.get('customer_filters')
    all_params = assign_params(skip=args.get('skip'), limit=args.get('limit'), service=args.get('service'),
                               instance=args.get('instance'), ip=args.get('ip'), ip_category=args.get('ip_category'),
                               username=args.get('username'), taken_action=args.get('taken_action'),
                               source=args.get('source'))
    request_data = {}
    url_suffix = '/activities/'
    if activity_id:
        url_suffix += activity_id
    elif customer_filters:
        request_data.update(json.loads(customer_filters))
    else:
        request_data = args_to_json_filter_list_activity(all_params)
    activities = client.activities_list(url_suffix, request_data)
    return CommandResults(
        readable_output=activities,
        outputs_prefix='MicrosoftCloudAppSecurity.Activities',
        outputs_key_field='activity_id',
        outputs=activities
    )


def files_list_command(client, args):
    file_id = args.get('file_id')
    customer_filters = args.get('customer_filters')
    all_params = assign_params(skip=args.get('skip'), limit=args.get('limit'), service=args.get('service'),
                               instance=args.get('instance'), file_type=args.get('file_type'), owner=args.get('owner'),
                               sharing=args.get('sharing'), extension=args.get('extension'),
                               quarantined=args.get('quarantined'))
    request_data = {}
    url_suffix = '/files/'
    if file_id:
        url_suffix += file_id
    elif customer_filters:
        request_data.update(json.loads(customer_filters))
    else:
        request_data = args_to_json_filter_list_files(all_params)
    files = client.files_list(url_suffix, request_data)
    return CommandResults(
        readable_output=files,
        outputs_prefix='MicrosoftCloudAppSecurity.Files',
        outputs_key_field='file_id',
        outputs=files
    )


def users_accounts_list_command(client, args):
    customer_filters = args.get('customer_filters')
    all_params = assign_params(skip=args.get('skip'), limit=args.get('limit'), service=args.get('service'),
                               instance=args.get('instance'), type=args.get('type'), username=args.get('username'),
                               group_id=args.get('group_id'), is_admin=args.get('is_admin'), status=args.get('status'),
                               is_external=args.get('is_external'))

    if customer_filters:
        request_data = {json.loads(customer_filters)}
    else:
        request_data = args_to_json_filter_list_users_accounts(all_params)
    users_accounts = client.users_accounts_list(request_data)
    return CommandResults(
        readable_output=users_accounts,
        outputs_prefix='MicrosoftCloudAppSecurity.UsersAccounts',
        outputs_key_field='username',
        outputs=users_accounts
    )


def fetch_incidents(client, max_results, last_run, first_fetch_time, filters):
    last_fetch = last_run.get('last_fetch')

    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)
    latest_created_time = last_fetch
    incidents = []
    filters["date"] = {"gte": latest_created_time}
    alerts = client.list_incidents(filters, limit=max_results)
    for alert in alerts['data']:
        incident_created_time = (alert['timestamp'])
        if last_fetch:
            if incident_created_time <= last_fetch:
                continue
        occurred = datetime.fromtimestamp(incident_created_time / 1000.0).isoformat() + 'Z'
        occurred_iso = occurred.split('.')
        incident = {
            'name': alert['title'],
            'occurred': occurred_iso[0] + 'Z',
            'rawJSON': json.dumps(alert)
        }
        incidents.append(incident)
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time
    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    token = demisto.params().get('token')

    # get the service API url
    base_url = f'{urljoin(demisto.params().get("url"))}api/v1'

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch = demisto.params().get('first_fetch')
    if not first_fetch:
        first_fetch = '3 days'
    first_fetch_time = arg_to_timestamp(first_fetch)
    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': f'Token {token}'},
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            params = demisto.params()
            all_params = assign_params(severity=params.get('severity'), instance=params.get('instance'),
                                       resolution_status=params.get('resolution_status'),
                                       service=params.get('service'))
            filters = params_to_filter(all_params)

            max_results = params.get('max_fetch', '50')

            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=int(max_results),
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                filters=filters)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'microsoft-cas-alerts-list':
            return_results(alerts_list_command(client, demisto.args()))

        elif demisto.command() == 'microsoft-cas-alert-dismiss-bulk':
            return_results(alert_dismiss_bulk_command(client, demisto.args()))

        elif demisto.command() == 'microsoft-cas-alert-resolve-bulk':
            return_results(alert_dismiss_bulk_command(client, demisto.args()))

        elif demisto.command() == 'microsoft-cas-activities-list':
            return_results(activities_list_command(client, demisto.args()))

        elif demisto.command() == 'microsoft-cas-files-list':
            return_results(files_list_command(client, demisto.args()))

        elif demisto.command() == 'microsoft-cas-users-accounts-list':
            return_results(users_accounts_list_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

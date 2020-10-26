import json
from typing import Dict, Any

from dateparser import parse
from pytz import utc

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
    'High': 2,
    'All': [0, 1, 2]
}

RESOLUTION_STATUS_OPTIONS = {
    'Open': 0,
    'Dismissed': 1,
    'Resolved': 2,
    'All': [0, 1, 2]
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

INTEGRATION_NAME = 'MicrosoftCloudAppSecurity'


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
                'limit': limit,
                'sortDirection': 'asc'
            }
        )


def args_to_filter(arguments):
    request_data: Dict[str, Any] = {}
    filters: Dict[str, Any] = {}
    for key, value in arguments.items():
        if key in ['skip', 'limit']:
            request_data[key] = int(value)
        if key == 'source':
            filters[key] = {'eq': SOURCE_TYPE_OPTIONS[value]}
        if key == 'ip_category':
            filters['ip.category'] = {'eq': IP_CATEGORY_OPTIONS[value]}
        if key == 'ip':
            filters['ip.address'] = {'eq': value}
        if key == 'taken_action':
            filters['activity.takenAction'] = {'eq': value}
        if key == 'severity' and value != 'All':
            filters[key] = {'eq': SEVERITY_OPTIONS[value]}
        if key == 'resolution_status' and value != 'All':
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


def build_filter_and_url_to_search_with(url_suffix, custom_filter, arguments, specific_id_to_search=''):
    """
        This function build the filters dict or url to filter with.

        Args:
            url_suffix: The url suffix.
            custom_filter: custom filters from the customer (other filters will not work).
            arguments: args to filter with.
            specific_id_to_search: filter by specific id (other filters will not work).

        Returns:
            The dict or the url to filter with.
        """
    request_data = {}
    if specific_id_to_search:
        url_suffix += specific_id_to_search
    elif custom_filter:
        request_data = json.loads(custom_filter)
    else:
        request_data = args_to_filter(arguments)
    return request_data, url_suffix


def args_to_filter_for_dismiss_and_resolve_alerts(alert_ids, custom_filter, comments):
    request_data = {}
    filters = {}
    if alert_ids:
        ids = {'eq': alert_ids.split(',')}
        filters['id'] = ids
        if comments:
            request_data['comment'] = comments
        request_data['filters'] = filters
    elif custom_filter:
        request_data = json.loads(custom_filter)
    else:
        return_error("Error: You must enter at least one of these arguments: alert ID, custom filter.")
    return request_data


def test_module(client):
    try:
        client.list_alerts(url_suffix='/alerts/', request_data={})
        if demisto.params().get('isFetch'):
            client.list_incidents(filters={}, limit=1)
            if demisto.params().get('custom_filter'):
                custom_filter = demisto.params().get('custom_filter')
                try:
                    json.loads(custom_filter)
                except ValueError:
                    return_error('Custom Filter Error: Your custom filter format is incorrect, please try again.')
    except Exception as e:
        if 'No connection' in str(e):
            return 'Connection Error: The URL you entered is probably incorrect, please try again.'
        if 'Invalid token' in str(e):
            return 'Authorization Error: make sure API Key is correctly set.'
        return str(e)
    return 'ok'


def alerts_to_human_readable(alerts):
    alerts_readable_outputs = []
    for alert in alerts:
        readable_output = assign_params(alert_id=alert.get('_id'), title=alert.get('title'),
                                        description=alert.get('description'), is_open=alert.get('is_open'),
                                        status_value=[key for key, value in STATUS_OPTIONS.items()
                                                      if alert.get('statusValue') == value],
                                        severity_value=[key for key, value in SEVERITY_OPTIONS.items()
                                                        if alert.get('severityValue') == value],
                                        alert_date=datetime.fromtimestamp(alert.get('timestamp') / 1000.0).isoformat())
        alerts_readable_outputs.append(readable_output)
    headers = ['alert_id', 'alert_date', 'title', 'description', 'status_value', 'severity_value', 'is_open']
    human_readable = tableToMarkdown('Microsoft CAS Alerts', alerts_readable_outputs, headers, removeNull=True)
    return human_readable


def extract_ip_indicators(activities):
    indicators = []
    for activity in activities:
        ip_address = dict_safe_get(activity, ['device', 'clientIP'])
        indicators.append(Common.IP(
            ip=ip_address,
            dbot_score=Common.DBotScore(
                ip_address,
                DBotScoreType.IP,
                INTEGRATION_NAME,
                Common.DBotScore.NONE,
            ),
            geo_latitude=dict_safe_get(activity, ['location', 'latitude']),
            geo_longitude=dict_safe_get(activity, ['location', 'longitude']),
        ))
    return indicators


def arrange_alerts_descriptions(alerts):
    for alert in alerts:
        if alert.get('description') and '__siteIcon__' in alert.get('description'):
            description = alert.get('description').replace('__siteIcon__', 'siteIcon')
            alert['description'] = description
    return alerts


def set_alerts_is_open(alerts):
    for alert in alerts:
        if alert.get('resolveTime'):
            alert['is_open'] = False
        else:
            alert['is_open'] = True
    return alerts


def list_alerts_command(client, args):
    url_suffix = '/alerts/'
    alert_id = args.get('alert_id')
    custom_filter = args.get('custom_filter')
    arguments = assign_params(**args)
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, custom_filter, arguments, alert_id)
    alerts_response_data = client.list_alerts(url_suffix, request_data)
    list_alert = alerts_response_data.get('data') if alerts_response_data.get('data') else [alerts_response_data]
    alerts = arrange_alerts_by_incident_type(list_alert)
    alerts = arrange_alerts_descriptions(alerts)
    alerts = set_alerts_is_open(alerts)
    human_readable = alerts_to_human_readable(alerts)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MicrosoftCloudAppSecurity.Alerts',
        outputs_key_field='_id',
        outputs=alerts
    )


def bulk_dismiss_alert_command(client, args):
    alert_ids = args.get('alert_ids')
    custom_filter = args.get('custom_filter')
    comment = args.get('comment')
    request_data = args_to_filter_for_dismiss_and_resolve_alerts(alert_ids, custom_filter, comment)
    dismissed_alerts_data = {}
    try:
        dismissed_alerts_data = client.dismiss_bulk_alerts(request_data)
    except Exception as e:
        if 'alertsNotFound' in str(e):
            return_error('Error: This alert id is already dismissed or does not exist.')
    number_of_dismissed_alerts = dismissed_alerts_data['dismissed']
    return CommandResults(
        readable_output=f'{number_of_dismissed_alerts} alerts dismissed',
        outputs_prefix='MicrosoftCloudAppSecurity.Alerts',
        outputs_key_field='_id'
    )


def bulk_resolve_alert_command(client, args):
    alert_ids = args.get('alert_ids')
    custom_filter = args.get('custom_filter')
    comment = args.get('comment')
    request_data = args_to_filter_for_dismiss_and_resolve_alerts(alert_ids, custom_filter, comment)
    resolve_alerts = client.resolve_bulk_alerts(request_data)
    number_of_resolved_alerts = resolve_alerts['resolved']
    return CommandResults(
        readable_output=f'{number_of_resolved_alerts} alerts resolved',
        outputs_prefix='MicrosoftCloudAppSecurity.Alerts',
        outputs_key_field='alert_id',
        outputs=resolve_alerts
    )


def activities_to_human_readable(activities):
    activities_readable_outputs = []
    for activity in activities:
        readable_output = assign_params(activity_id=activity.get('_id'), severity=activity.get('severity'),
                                        activity_date=datetime.fromtimestamp(activity.get('timestamp') / 1000.0)
                                        .isoformat(),
                                        app_name=activity.get('appName'), description=activity.get('description'))
        activities_readable_outputs.append(readable_output)
    headers = ['activity_id', 'activity_date', 'app_name', 'description', 'severity']
    human_readable = tableToMarkdown('Microsoft CAS Activities', activities_readable_outputs, headers, removeNull=True)
    return human_readable


def arrange_entities_data(activities):
    for activity in activities:
        entities_data = []
        if 'entityData' in activity.keys():
            entity_data = activity['entityData']
            if entity_data:
                for key, value in entity_data.items():
                    if value:
                        entities_data.append(value)
                activity['entityData'] = entities_data

    return activities


def list_activities_command(client, args):
    url_suffix = '/activities/'
    activity_id = args.get('activity_id')
    custom_filter = args.get('custom_filter')
    arguments = assign_params(**args)
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, custom_filter, arguments, activity_id)
    activities_response_data = client.list_activities(url_suffix, request_data)
    list_activities = activities_response_data.get('data') if activities_response_data.get('data') \
        else [activities_response_data]
    activities = arrange_entities_data(list_activities)
    ip_indicators = extract_ip_indicators(activities)
    human_readable = activities_to_human_readable(activities)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MicrosoftCloudAppSecurity.Activities',
        outputs_key_field='_id',
        outputs=activities,
        indicators=ip_indicators,
    )


def files_to_human_readable(files):
    files_readable_outputs = []
    for file in files:
        readable_output = assign_params(owner_name=file.get('ownerName'), file_id=file.get('_id'),
                                        file_type=file.get('fileType'), file_name=file.get('name'),
                                        file_access_level=file.get('fileAccessLevel'), app_name=file.get('appName'),
                                        file_status=file.get('fileStatus'))
        files_readable_outputs.append(readable_output)

    headers = ['owner_name', 'file_id', 'file_type', 'file_name', 'file_access_level', 'file_status',
               'app_name']
    human_readable = tableToMarkdown('Microsoft CAS Files', files_readable_outputs, headers, removeNull=True)
    return human_readable


def arrange_files_type_access_level_and_status(files):
    """
        This function refines the file to look better.

        Args:
            files: The file for refinement ("fileType": [4, TEXT]).

        Returns:
            The file when it is more refined and easier to read ("fileType": TEXT).
        """
    for file in files:
        if file.get('fileType'):
            file['fileType'] = file['fileType'][1]
        if file.get('fileAccessLevel'):
            file['fileAccessLevel'] = file['fileAccessLevel'][1]
        if file.get('fileStatus'):
            file['fileStatus'] = file['fileStatus'][1]
    return files


def list_files_command(client, args):
    url_suffix = '/files/'
    file_id = args.get('file_id')
    custom_filter = args.get('custom_filter')
    arguments = assign_params(**args)
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, custom_filter, arguments, file_id)
    files_response_data = client.list_files(url_suffix, request_data)
    list_files = files_response_data.get('data') if files_response_data.get('data') else [files_response_data]
    files = arrange_files_type_access_level_and_status(list_files)
    human_readable = files_to_human_readable(files)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MicrosoftCloudAppSecurity.Files',
        outputs_key_field='_id',
        outputs=files
    )


def users_accounts_to_human_readable(users_accounts):
    users_accounts_readable_outputs = []
    for entity in users_accounts:
        readable_output = assign_params(display_name=entity.get('displayName'), last_seen=entity.get('lastSeen'),
                                        is_admin=entity.get('isAdmin'), is_external=entity.get('isExternal'),
                                        email=entity.get('email'))
        users_accounts_readable_outputs.append(readable_output)

    headers = ['display_name', 'last_seen', 'is_admin', 'is_external', 'email', 'identifier']
    human_readable = tableToMarkdown('Microsoft CAS Users And Accounts', users_accounts_readable_outputs, headers,
                                     removeNull=True)
    return human_readable


def list_users_accounts_command(client, args):
    url_suffix = '/entities/'
    custom_filter = args.get('custom_filter')
    arguments = assign_params(**args)
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, custom_filter, arguments)
    users_accounts_response_data = client.list_users_accounts(url_suffix, request_data)
    users_accounts = users_accounts_response_data.get('data') \
        if users_accounts_response_data.get('data') else [users_accounts_response_data]
    human_readable = users_accounts_to_human_readable(users_accounts)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MicrosoftCloudAppSecurity.UsersAccounts',
        outputs_key_field='_id',
        outputs=users_accounts
    )


def calculate_fetch_start_time(last_fetch, first_fetch):
    if last_fetch is None:
        if not first_fetch:
            first_fetch = '3 days'
        first_fetch_dt = parse(first_fetch).replace(tzinfo=utc)
        first_fetch_time = int(first_fetch_dt.timestamp())
        return first_fetch_time
    else:
        return int(last_fetch)


def arrange_alerts_by_incident_type(alerts):
    for alert in alerts:
        incident_types: Dict[str, Any] = {}
        for entity in alert['entities']:
            if not entity['type'] in incident_types.keys():
                incident_types[entity['type']] = []
            incident_types[entity['type']].append(entity)
        alert.update(incident_types)
        del alert['entities']
    return alerts


def alerts_to_incidents_and_fetch_start_from(alerts, fetch_start_time):
    incidents = []
    for alert in alerts:
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
    max_results = int(max_results) if max_results else DEFAULT_INCIDENT_TO_FETCH
    last_fetch = last_run.get('last_fetch')
    fetch_start_time = calculate_fetch_start_time(last_fetch, first_fetch)
    filters["date"] = {"gte": fetch_start_time}
    alerts_response_data = client.list_incidents(filters, limit=max_results)
    alerts = alerts_response_data.get('data')
    alerts = arrange_alerts_by_incident_type(alerts)
    incidents, fetch_start_time = alerts_to_incidents_and_fetch_start_from(alerts, fetch_start_time)
    next_run = {'last_fetch': fetch_start_time}
    return next_run, incidents


def params_to_filter(severity, resolution_status):
    filters: Dict[str, Any] = {}
    if len(severity) == 1:
        filters['severity'] = {'eq': SEVERITY_OPTIONS[severity[0]]}

    else:
        severities = []
        for severity_option in severity:
            severities.append(SEVERITY_OPTIONS[severity_option])
        filters['severity'] = {'eq': severities}

    if len(resolution_status) == 1:
        filters['resolutionStatus'] = {'eq': RESOLUTION_STATUS_OPTIONS[resolution_status[0]]}

    else:
        resolution_statuses = []
        for resolution in resolution_status:
            resolution_statuses.append(RESOLUTION_STATUS_OPTIONS[resolution])
        filters['resolutionStatus'] = {'eq': resolution_statuses}
    return filters


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    params = demisto.params()
    token = demisto.params().get('token')
    base_url = f'{demisto.params().get("url")}/api/v1'
    verify_certificate = not demisto.params().get('insecure', False)
    first_fetch = demisto.params().get('first_fetch')
    max_results = demisto.params().get('max_fetch')
    proxy = demisto.params().get('proxy', False)
    severity = params.get('severity')
    resolution_status = params.get('resolution_status')
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
            if params.get('custom_filter'):
                filters = json.loads(params.get('custom_filter'))
            else:
                filters = params_to_filter(severity, resolution_status)
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

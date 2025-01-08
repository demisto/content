from dateparser import parse
from pytz import utc
import urllib3

from MicrosoftApiModule import *  # noqa: E402
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

# Disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'
DEFAULT_INCIDENT_TO_FETCH = 50

SEVERITY_OPTIONS = {
    'Low': 0,
    'Medium': 1,
    'High': 2,
    'All': [0, 1, 2],
}

RESOLUTION_STATUS_OPTIONS = {
    'Open': 0,
    'Dismissed': 1,
    'Resolved': 2,
    'All': [0, 1, 2],
}

# Note that number 4 is missing
SOURCE_TYPE_OPTIONS = {
    'Access_control': 0,
    'Session_control': 1,
    'App_connector': 2,
    'App_connector_analysis': 3,
    'Discovery': 5,
    'MDATP': 6,
}

FILE_TYPE_OPTIONS = {
    'Other': 0,
    'Document': 1,
    'Spreadsheet': 2,
    'Presentation': 3,
    'Text': 4,
    'Image': 5,
    'Folder': 6,
}

FILE_SHARING_OPTIONS = {
    'Private': 0,
    'Internal': 1,
    'External': 2,
    'Public': 3,
    'Public_Internet': 4,
}

IP_CATEGORY_OPTIONS = {
    'Corporate': 1,
    'Administrative': 2,
    'Risky': 3,
    'VPN': 4,
    'Cloud_provider': 5,
    'Other': 6,
}

IS_EXTERNAL_OPTIONS = {
    'External': True,
    'Internal': False,
    'No_value': None,
}

STATUS_OPTIONS = {
    'N/A': 0,
    'Staged': 1,
    'Active': 2,
    'Suspended': 3,
    'Deleted': 4,
}

CLOSE_BENIGN_REASON_OPTIONS = {
    'Actual severity is lower': 0,
    'Other': 1,
    'Confirmed with end user': 2,
    'Triggered by test': 3,
}

CLOSE_FALSE_POSITIVE_REASON_OPTIONS = {
    'Not of interest': 0,
    'Too many similar alerts': 1,
    'Alert is not accurate': 2,
    'Other': 3,
}

INTEGRATION_NAME = 'MicrosoftCloudAppSecurity'
# The API scope value was taken from: https://learn.microsoft.com/en-us/defender-cloud-apps/api-authentication-application
DEFAULT_API_SCOPE = '05a65629-4c1b-48c1-a78b-804c4abdd4af'


class LegacyClient(BaseClient):
    def http_request(self, **args):
        return self._http_request(**args)


class Client:
    @logger
    def __init__(self, app_id: str, verify: bool, proxy: bool, endpoint_type: str, base_url: str, auth_mode: str,
                 azure_cloud: AzureCloud, tenant_id: str = None, enc_key: str = None, headers: Optional[dict] = None):
        if headers is None:
            headers = {}
        self.auth_mode = auth_mode
        if self.auth_mode == 'legacy':
            self.ms_client = LegacyClient(
                base_url=base_url,
                verify=verify,
                headers=headers,
                proxy=proxy)

        else:
            self.client_credentials = self.auth_mode == 'client credentials'
            if '@' in app_id:
                app_id, refresh_token = app_id.split('@')
                integration_context = get_integration_context()
                integration_context.update(current_refresh_token=refresh_token)
                set_integration_context(integration_context)

            if self.auth_mode == 'device code flow':
                resource = MICROSOFT_DEFENDER_FOR_APPLICATION_API[endpoint_type]
                token_retrieval_url = (f'{MICROSOFT_DEFENDER_FOR_APPLICATION_TOKEN_RETRIEVAL_ENDPOINTS[endpoint_type]}'
                                       '/organizations/oauth2/v2.0/token')
            else:
                resource = None
                token_retrieval_url = None

            client_args = assign_params(
                base_url=base_url,
                verify=verify,
                proxy=proxy,
                ok_codes=(200, 201, 202, 204),
                scope=f'{DEFAULT_API_SCOPE}/.default',
                self_deployed=True,  # We always set the self_deployed key as True because when not using a self
                # deployed machine, the DEVICE_CODE flow should behave somewhat like a self deployed
                # flow and most of the same arguments should be set, as we're !not! using OProxy.

                auth_id=app_id,
                grant_type=CLIENT_CREDENTIALS if self.client_credentials else DEVICE_CODE,

                # used for device code flow
                resource=resource,
                token_retrieval_url=token_retrieval_url,
                # used for client credentials flow
                tenant_id=tenant_id,
                enc_key=enc_key,
                # Azure cloud
                azure_cloud=azure_cloud,
                command_prefix="microsoft-cas",
            )
            self.ms_client = MicrosoftClient(**client_args)  # type: ignore

    def list_alerts(self, url_suffix: str, request_data: dict):
        return self.ms_client.http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_data,
        )

    def dismiss_bulk_alerts(self, request_data: dict):  # pragma: no cover
        """
        Deprecated: use close_false_positive_command instead.
        """
        return self.ms_client.http_request(
            method='POST',
            url_suffix='/alerts/close_false_positive/',
            json_data=request_data,
        )

    def resolve_bulk_alerts(self, request_data: dict):  # pragma: no cover
        """
        Deprecated: use close_true_positive_command instead.
        """
        return self.ms_client.http_request(
            method='POST',
            url_suffix='/alerts/close_true_positive/',
            json_data=request_data,
        )

    def close_benign(self, request_data: dict) -> Any:
        return self.ms_client.http_request(
            method='POST',
            url_suffix='/alerts/close_benign/',
            json_data=request_data,
        )

    def close_false_positive(self, request_data: dict) -> Any:
        return self.ms_client.http_request(
            method='POST',
            url_suffix='/alerts/close_false_positive/',
            json_data=request_data,
        )

    def close_true_positive(self, request_data: dict) -> Any:
        return self.ms_client.http_request(
            method='POST',
            url_suffix='/alerts/close_true_positive/',
            json_data=request_data,
        )

    def list_activities(self, url_suffix: str, request_data: dict, timeout: int) -> Any:
        return self.ms_client.http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_data,
            timeout=timeout,
        )

    def list_users_accounts(self, url_suffix: str, request_data: dict):
        return self.ms_client.http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_data,
        )

    def list_files(self, url_suffix: str, request_data: dict):
        return self.ms_client.http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_data,
        )

    def list_incidents(self, filters: dict, limit: Union[int, str]):
        return self.ms_client.http_request(
            method='POST',
            url_suffix='/alerts/',
            json_data={
                'filters': filters,
                'limit': limit,
                'sortDirection': 'asc',
            },
        )


@logger
def start_auth(client: Client,
               args: dict  # noqa
               ) -> CommandResults:
    result = client.ms_client.start_auth('!microsoft-cas-auth-complete')  # type: ignore[attr-defined]
    return CommandResults(readable_output=result)


@logger
def complete_auth(client: Client,
                  args: dict  # noqa
                  ) -> CommandResults:
    client.ms_client.get_access_token()  # type: ignore[attr-defined]
    return CommandResults(readable_output='✅ Authorization completed successfully.')


@logger
def test_connection(client: Client) -> CommandResults:
    client.ms_client.get_access_token()  # type: ignore[attr-defined]
    # If fails, MicrosoftApiModule returns an error
    return CommandResults(readable_output='✅ Success!')


def args_to_filter(arguments: dict):
    """
    Common filters of **all** related entities (Activities, Alerts, Files and Data Entities).

    For more info please check:
        - Activities: https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters
        - Alerts: https://docs.microsoft.com/en-us/cloud-app-security/api-alerts#filters
        - Files: https://docs.microsoft.com/en-us/cloud-app-security/api-files#filters
        - Entities: https://docs.microsoft.com/en-us/cloud-app-security/api-entities#filters
    """
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


def build_filter_and_url_to_search_with(url_suffix: str, custom_filter: Optional[Any], arguments: dict,
                                        specific_id_to_search: Any = '', is_scan: bool = False):
    """
        This function build the filters dict or url to filter with.

        Args:
            url_suffix: The url suffix.
            custom_filter: custom filters from the customer (other filters will not work).
            arguments: args to filter with.
            specific_id_to_search: filter by specific id (other filters will not work).
            is_scan: is the filter a scan.

        Returns:
            The dict or the url to filter with.
        """
    request_data: dict = {}
    if specific_id_to_search:
        url_suffix += specific_id_to_search
    elif custom_filter:
        request_data = json.loads(custom_filter)
    else:
        request_data = args_to_filter(arguments)

    request_data = {'filters': request_data} if 'filters' not in request_data.keys() else request_data
    if is_scan:
        request_data['isScan'] = True  # type: ignore[assignment]
    return request_data, url_suffix


def args_to_filter_close_alerts(alert_ids: Optional[List] = None,
                                custom_filter: Optional[Union[str, dict]] = None,
                                comment: Optional[str] = None,
                                send_feedback: bool = False,
                                feedback_text: Optional[str] = None,
                                allow_contact: bool = False,
                                contact_email: Optional[str] = None,
                                reason: Optional[int] = None,
                                ):
    if custom_filter:
        request_data = json.loads(custom_filter) if isinstance(custom_filter, str) else custom_filter
    elif alert_ids:
        request_data = {
            'filters': {
                'id': {
                    'eq': alert_ids,
                },
            },
            'comment': comment,
            'reason': reason,
            'sendFeedback': send_feedback,
            'feedbackText': feedback_text,
            'allowContact': allow_contact,
            'contactEmail': contact_email,
        }
    else:
        raise DemistoException("Expecting at least one of the following arguments: alert_id, custom_filter.")

    return request_data


def args_to_filter_for_dismiss_and_resolve_alerts(alert_ids: Any, custom_filter: Any, comments: Any):  # pragma: no cover
    """
    Deprecated by args_to_filter_close_alerts.
    """
    request_data: Dict[str, Any] = {}
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
        raise DemistoException("Error: You must enter at least one of these arguments: alert ID, custom filter.")
    request_data = {'filters': request_data} if 'filters' not in request_data.keys() else request_data
    return request_data


def test_module(client: Client, is_fetch: Optional[Any], custom_filter: Optional[str]):
    try:
        if client.auth_mode == "device code flow":
            raise DemistoException(
                "To test the device code flow Please run !microsoft-cas-auth-start and "
                "!microsoft-cas-auth-complete and check the connection using !microsoft-cas-auth-test")
        client.list_alerts(url_suffix='/alerts/', request_data={})
        if is_fetch:
            client.list_incidents(filters={}, limit=1)
            if custom_filter:
                try:
                    json.loads(custom_filter)
                except ValueError as e:
                    raise DemistoException(
                        'Custom Filter Error: Your custom filter format is incorrect, please try again.') from e
    except Exception as e:
        if 'No connection' in str(e):
            return 'Connection Error: The URL you entered is probably incorrect, please try again.'
        if 'Invalid token' in str(e):
            return 'Authorization Error: make sure API Key is correctly set.'
        return str(e)
    return 'ok'


def alerts_to_human_readable(alerts: List[dict]):
    alerts_readable_outputs = []
    for alert in alerts:
        readable_output = assign_params(alert_id=alert.get('_id'), title=alert.get('title'),
                                        description=alert.get('description'), is_open=alert.get('is_open'),
                                        status_value=[key for key, value in STATUS_OPTIONS.items()
                                                      if alert.get('statusValue') == value],
                                        severity_value=[key for key, value in SEVERITY_OPTIONS.items()
                                                        if alert.get('severityValue') == value],
                                        alert_date=datetime.fromtimestamp(
                                            alert.get('timestamp', 0) / 1000.0).isoformat())
        alerts_readable_outputs.append(readable_output)
    headers = ['alert_id', 'alert_date', 'title', 'description', 'status_value', 'severity_value', 'is_open']
    return tableToMarkdown(
        'Microsoft CAS Alerts',
        alerts_readable_outputs,
        headers,
        removeNull=True,
    )


def create_ip_command_results(activities: List[dict]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    for activity in activities:
        ip_address = str(dict_safe_get(activity, ['device', 'clientIP']))
        indicator = Common.IP(
            ip=ip_address,
            dbot_score=Common.DBotScore(
                ip_address,
                DBotScoreType.IP,
                INTEGRATION_NAME,
                Common.DBotScore.NONE,
            ),
            geo_latitude=str(dict_safe_get(activity, ['location', 'latitude'])),
            geo_longitude=str(dict_safe_get(activity, ['location', 'longitude'])),
        )
        human_readable = activity_to_human_readable(activity)
        command_results.append(CommandResults(
            readable_output=human_readable,
            outputs_prefix='MicrosoftCloudAppSecurity.Activities',
            outputs_key_field='_id',
            outputs=activity,
            indicator=indicator
        ))
    return command_results


def arrange_alerts_descriptions(alerts: List[dict]):
    for alert in alerts:
        description = alert.get('description', '')
        if isinstance(description, str) and '__siteIcon__' in description:
            description = description.replace('__siteIcon__', 'siteIcon')
            alert['description'] = description
    return alerts


def set_alerts_is_open(alerts: List[dict]):
    for alert in alerts:
        alert['is_open'] = not alert.get('resolveTime')
    return alerts


def list_alerts_command(client: Client, args: dict):
    url_suffix = '/alerts/'
    alert_id = args.get('alert_id')
    custom_filter = args.get('custom_filter')
    arguments = assign_params(**args)
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, custom_filter, arguments, alert_id)
    alerts_response_data = client.list_alerts(url_suffix, request_data)
    list_alert = alerts_response_data.get('data') if 'data' in alerts_response_data else [alerts_response_data]
    if list_alert:  # organize the output
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
    else:
        human_readable = f"No alerts found for the given filter: {custom_filter}."
        return CommandResults(readable_output=human_readable)


def bulk_dismiss_alert_command(client: Client, args: dict):  # pragma: no cover
    """
    Deprecated: use close_false_positive_command instead.
    """
    alert_ids = args.get('alert_ids')
    custom_filter = args.get('custom_filter')
    comment = args.get('comment')
    request_data = args_to_filter_for_dismiss_and_resolve_alerts(alert_ids, custom_filter, comment)
    dismissed_alerts_data = {}
    try:
        dismissed_alerts_data = client.dismiss_bulk_alerts(request_data)
    except Exception as e:
        if 'alertsNotFound' in str(e):
            raise DemistoException('Error: This alert id is already dismissed or does not exist.')
    number_of_dismissed_alerts = dismissed_alerts_data['closed_false_positive']
    return CommandResults(
        readable_output=f'{number_of_dismissed_alerts} alerts dismissed',
        outputs_prefix='MicrosoftCloudAppSecurity.Alerts',
        outputs_key_field='_id'
    )


def bulk_resolve_alert_command(client: Client, args: dict):  # pragma: no cover
    """
    Deprecated: use close_true_positive_command instead.
    """
    alert_ids = args.get('alert_ids')
    custom_filter = args.get('custom_filter')
    comment = args.get('comment')
    request_data = args_to_filter_for_dismiss_and_resolve_alerts(alert_ids, custom_filter, comment)
    resolve_alerts = client.resolve_bulk_alerts(request_data)
    number_of_resolved_alerts = resolve_alerts['closed_true_positive']
    return CommandResults(
        readable_output=f'{number_of_resolved_alerts} alerts resolved',
        outputs_prefix='MicrosoftCloudAppSecurity.Alerts',
        outputs_key_field='alert_id',
        outputs=resolve_alerts
    )


def activity_to_human_readable(activity: dict):
    readable_output = assign_params(activity_id=activity.get('_id'), severity=activity.get('severity'),
                                    activity_date=datetime.fromtimestamp(activity.get('timestamp', 0) / 1000.0)
                                    .isoformat(),
                                    app_name=activity.get('appName'), description=activity.get('description'))
    headers = ['activity_id', 'activity_date', 'app_name', 'description', 'severity']
    return tableToMarkdown(
        'Microsoft CAS Activity', readable_output, headers, removeNull=True
    )


def arrange_entities_data(activities: List[dict]):
    for activity in activities:
        entities_data = []
        if 'entityData' in activity:
            entity_data = activity['entityData']
            if entity_data:
                for _key, value in entity_data.items():
                    if value:
                        entities_data.append(value)
                activity['entityData'] = entities_data

    return activities


def list_activities_command(client: Client, args: dict):
    url_suffix = '/activities/'
    activity_id = args.get('activity_id')
    custom_filter = args.get('custom_filter')
    is_scan = argToBoolean(args.get('is_scan', 'false'))
    arguments = assign_params(**args)
    timeout = arg_to_number(arguments.get('timeout', 60)) or 60
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, custom_filter, arguments, activity_id, is_scan)
    has_next = True
    list_activities: list[Any] = []
    while has_next:
        activities_response_data = client.list_activities(url_suffix, request_data, timeout)
        list_activities.extend(
            activities_response_data.get('data') or [activities_response_data]
        )
        has_next = activities_response_data.get('hasNext', False)
        request_data['filters'] = activities_response_data.get('nextQueryFilters')
        if is_scan is False:
            # This is to prevent run-away iterations
            break
    activities = arrange_entities_data(list_activities)
    return create_ip_command_results(activities)


def files_to_human_readable(files: List[dict]):
    files_readable_outputs = []
    for file in files:
        readable_output = assign_params(owner_name=file.get('ownerName'), file_id=file.get('_id'),
                                        file_type=file.get('fileType'), file_name=file.get('name'),
                                        file_access_level=file.get('fileAccessLevel'), app_name=file.get('appName'),
                                        file_status=file.get('fileStatus'))
        files_readable_outputs.append(readable_output)

    headers = ['owner_name', 'file_id', 'file_type', 'file_name', 'file_access_level', 'file_status',
               'app_name']
    return tableToMarkdown(
        'Microsoft CAS Files', files_readable_outputs, headers, removeNull=True
    )


def arrange_files_type_access_level_and_status(files: List[dict]):
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


def list_files_command(client: Client, args: dict):
    url_suffix = '/files/'
    file_id = args.get('file_id')
    custom_filter = args.get('custom_filter')
    arguments = assign_params(**args)
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, custom_filter, arguments, file_id)
    files_response_data = client.list_files(url_suffix, request_data)
    list_files = files_response_data.get('data') or [files_response_data]
    files = arrange_files_type_access_level_and_status(list_files)
    human_readable = files_to_human_readable(files)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MicrosoftCloudAppSecurity.Files',
        outputs_key_field='_id',
        outputs=files
    )


def users_accounts_to_human_readable(users_accounts: List[dict]):
    users_accounts_readable_outputs = []
    for entity in users_accounts:
        readable_output = assign_params(display_name=entity.get('displayName'), last_seen=entity.get('lastSeen'),
                                        is_admin=entity.get('isAdmin'), is_external=entity.get('isExternal'),
                                        email=entity.get('email'))
        users_accounts_readable_outputs.append(readable_output)

    headers = ['display_name', 'last_seen', 'is_admin', 'is_external', 'email', 'identifier']
    return tableToMarkdown(
        'Microsoft CAS Users And Accounts',
        users_accounts_readable_outputs,
        headers,
        removeNull=True,
    )


def list_users_accounts_command(client: Client, args: dict):
    url_suffix = '/entities/'
    custom_filter = args.get('custom_filter')
    arguments = assign_params(**args)
    request_data, url_suffix = build_filter_and_url_to_search_with(url_suffix, custom_filter, arguments)
    users_accounts_response_data = client.list_users_accounts(url_suffix, request_data)
    users_accounts = users_accounts_response_data.get('data') or [users_accounts_response_data]
    human_readable = users_accounts_to_human_readable(users_accounts)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MicrosoftCloudAppSecurity.UsersAccounts',
        outputs_key_field='_id',
        outputs=users_accounts
    )


def format_fetch_start_time_to_timestamp(fetch_start_time: Optional[str]):
    fetch_start_time_datetime = parse(fetch_start_time).replace(tzinfo=utc)  # type: ignore
    return int(fetch_start_time_datetime.timestamp() * 1000)  # type: ignore


def timestamp_to_datetime_string(timestamp: int, include_miliseconds: bool = True, is_utc: bool = False):
    datetime_string = timestamp_to_datestring(timestamp, DATE_FORMAT, is_utc=is_utc)
    if include_miliseconds:
        # return datetime string including miliseconds
        return datetime_string[:-3]
    # return datetime string includes only seconds
    return datetime_string.split('.')[0]


def arrange_alerts_by_incident_type(alerts: List[dict]):
    for alert in alerts:
        incident_types: Dict[str, Any] = {}
        for entity in alert['entities']:
            if entity['type'] not in incident_types.keys():
                incident_types[entity['type']] = []
            incident_types[entity['type']].append(entity)
        alert.update(incident_types)
        del alert['entities']
    return alerts


def alerts_to_xsoar_incidents(alerts: List[dict]):
    incidents = []

    for alert in alerts:
        alert_timestamp = alert['timestamp']
        alert_occurred_time_utc = timestamp_to_datetime_string(alert_timestamp, is_utc=True)
        alert_occurred_time_current_timezone = timestamp_to_datetime_string(alert_timestamp)
        alert_id = alert.get('_id') or ''
        alert_title = alert.get('title') or ''
        alert_description = alert.get('description') or ''
        alert_description = alert_description[:100]
        demisto.debug(
            f"{alert_id=}, {alert_timestamp=}, {alert_occurred_time_utc=}, "
            f"{alert_occurred_time_current_timezone=}, {alert_title=}, {alert_description=}"
        )
        incident = {
            'name': alert['title'],
            'occurred': f'{timestamp_to_datetime_string(alert_timestamp, include_miliseconds=False)}Z',
            'rawJSON': json.dumps(alert),
        }
        incidents.append(incident)
        alert['timestamp'] = alert_occurred_time_utc

    return incidents


def fetch_incidents(client: Client, max_results: Optional[str], last_run: dict, first_fetch: Optional[str],
                    filters: dict, look_back: int):
    if not first_fetch:
        first_fetch = '3 days'
    max_results = int(max_results) if max_results else DEFAULT_INCIDENT_TO_FETCH

    if not last_run.get("time") and last_run.get("last_fetch"):
        demisto.debug(f"last fetch from old version is: {str(last_run.get('last_fetch'))}")
        last_fetch_time = datetime.fromtimestamp(last_run.get("last_fetch", 0) / 1000.0).isoformat()
        last_run["time"] = last_fetch_time

    fetch_start_time, fetch_end_time = get_fetch_run_time_range(
        last_run=last_run, first_fetch=first_fetch, look_back=look_back, date_format=DATE_FORMAT
    )

    # removing last 3 digits since api supports 13-digits
    fetch_start_time, fetch_end_time = fetch_start_time[:-3], fetch_end_time[:-3]

    formatted_fetch_start_time_timestamp = format_fetch_start_time_to_timestamp(fetch_start_time)
    demisto.debug(f'{fetch_start_time=}, {formatted_fetch_start_time_timestamp=}')

    filters["date"] = {"gte": formatted_fetch_start_time_timestamp}
    demisto.debug(f'fetching alerts using filter {filters} with max results {max_results}')

    alerts_response_data = client.list_incidents(filters, limit=max_results)
    alerts = alerts_response_data.get('data')
    alerts = arrange_alerts_by_incident_type(alerts)
    alerts_to_incident = filter_incidents_by_duplicates_and_limit(
        incidents_res=alerts, last_run=last_run, fetch_limit=max_results, id_field='_id'
    )

    incidents = alerts_to_xsoar_incidents(alerts_to_incident)

    last_run = update_last_run_object(
        last_run=last_run,
        incidents=alerts_to_incident,
        fetch_limit=max_results,
        start_fetch_time=fetch_start_time,
        end_fetch_time=fetch_end_time,
        look_back=look_back,
        created_time_field='timestamp',
        id_field='_id',
        date_format=DATE_FORMAT,
        increase_last_run_time=True
    )

    if 'last_fetch_id' in last_run:  # no need to save last fetch id, remove support from older versions of fetch
        last_run.pop('last_fetch_id', None)
    demisto.debug(f'setting last run to: {last_run}')
    return last_run, incidents


def params_to_filter(severity: List[str], resolution_status: List[str]):
    filters: Dict[str, Any] = {}
    if len(severity) == 1:
        filters['severity'] = {'eq': SEVERITY_OPTIONS[severity[0]]}

    else:
        severities = [
            SEVERITY_OPTIONS[severity_option] for severity_option in severity
        ]
        filters['severity'] = {'eq': severities}

    if len(resolution_status) == 1:
        filters['resolutionStatus'] = {'eq': RESOLUTION_STATUS_OPTIONS[resolution_status[0]]}

    else:
        resolution_statuses = [
            RESOLUTION_STATUS_OPTIONS[resolution]
            for resolution in resolution_status
        ]
        filters['resolutionStatus'] = {'eq': resolution_statuses}
    return filters


def close_benign_command(client: Client, args: dict) -> CommandResults:
    """
    Closing alerts as benign.

    API: https://docs.microsoft.com/en-gb/cloud-app-security/api-alerts-close-benign
    """
    alert_ids = argToList(args.get('alert_ids'))
    custom_filter = args.get('custom_filter')
    comment = args.get('comment')
    reason = CLOSE_BENIGN_REASON_OPTIONS.get(args.get('reason', ''))
    send_feedback = argToBoolean(args.get('sendFeedback', 'false'))
    feedback_text = args.get('feedbackText')
    allow_contact = argToBoolean(args.get('allowContact', 'false'))
    contact_email = args.get('contactEmail')

    request_data = args_to_filter_close_alerts(
        alert_ids=alert_ids,
        custom_filter=custom_filter,
        comment=comment,
        send_feedback=send_feedback,
        feedback_text=feedback_text,
        allow_contact=allow_contact,
        contact_email=contact_email,
        reason=reason,
    )
    closed_benign_alerts = client.close_benign(request_data)

    if 'alertsNotFound' in closed_benign_alerts:
        not_found_alerts = '\n'.join(closed_benign_alerts['alertsNotFound'])
        raise DemistoException(f'Failed to close the following alerts:\n{not_found_alerts}')

    number_of_close_benign = closed_benign_alerts['closed_benign']
    return CommandResults(
        readable_output=f'{number_of_close_benign} alerts were closed as benign.',
        raw_response=closed_benign_alerts,
    )


def close_false_positive_command(client: Client, args: dict) -> CommandResults:
    """
    Closing alert as false-positive.

    API: https://docs.microsoft.com/en-gb/cloud-app-security/api-alerts-close-false-positive
    """
    alert_ids = argToList(args.get('alert_ids'))
    custom_filter = args.get('custom_filter')
    comment = args.get('comment')
    reason = CLOSE_FALSE_POSITIVE_REASON_OPTIONS.get(args.get('reason', ''))
    send_feedback = argToBoolean(args.get('sendFeedback')) if args.get('sendFeedback') else False
    feedback_text = args.get('feedbackText')
    allow_contact = argToBoolean(args.get('allowContact')) if args.get('allowContact') else False
    contact_email = args.get('contactEmail')

    request_data = args_to_filter_close_alerts(
        alert_ids=alert_ids,
        custom_filter=custom_filter,
        comment=comment,
        send_feedback=send_feedback,
        feedback_text=feedback_text,
        allow_contact=allow_contact,
        contact_email=contact_email,
        reason=reason,
    )
    closed_false_positive_alerts = client.close_false_positive(request_data)

    if 'alertsNotFound' in closed_false_positive_alerts:
        not_found_alerts = '\n'.join(closed_false_positive_alerts['alertsNotFound'])
        raise DemistoException(f'Failed to close the following alerts:\n{not_found_alerts}')

    number_of_closed_false_positive_alerts = closed_false_positive_alerts['closed_false_positive']
    return CommandResults(
        readable_output=f'{number_of_closed_false_positive_alerts} alerts were closed as false-positive.',
        raw_response=closed_false_positive_alerts,
    )


def close_true_positive_command(client: Client, args: dict) -> CommandResults:
    """
    Closing alerts as true-positive.

    API: https://docs.microsoft.com/en-gb/cloud-app-security/api-alerts-close-true-positive
    """
    alert_ids = argToList(args.get('alert_ids'))
    custom_filter = args.get('custom_filter')
    comment = args.get('comment')
    send_feedback = argToBoolean(args.get('sendFeedback')) if args.get('sendFeedback') else False
    feedback_text = args.get('feedbackText')
    allow_contact = argToBoolean(args.get('allowContact')) if args.get('allowContact') else False
    contact_email = args.get('contactEmail')

    request_data = args_to_filter_close_alerts(
        alert_ids=alert_ids,
        custom_filter=custom_filter,
        comment=comment,
        send_feedback=send_feedback,
        feedback_text=feedback_text,
        allow_contact=allow_contact,
        contact_email=contact_email,
    )
    closed_true_positive_alert = client.close_true_positive(request_data)

    if 'alertsNotFound' in closed_true_positive_alert:
        not_found_alerts = '\n'.join(closed_true_positive_alert['alertsNotFound'])
        raise DemistoException(f'Failed to close the following alerts:\n{not_found_alerts}')

    number_of_close_true_positive = closed_true_positive_alert['closed_true_positive']
    return CommandResults(
        readable_output=f'{number_of_close_true_positive} alerts were closed as true-positive.',
        raw_response=closed_true_positive_alert,
    )


def main():  # pragma: no cover
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params: dict = demisto.params()
    command = demisto.command()
    args = demisto.args()

    try:
        app_id = params.get('app_id')
        tenant_id = params.get('tenant_id')
        auth_mode = params.get('auth_mode', 'legacy')
        enc_key = params.get('client_id', {}).get('password')

        verify = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        endpoint_type_name = params.get('endpoint_type') or 'Worldwide'
        endpoint_type = MICROSOFT_DEFENDER_FOR_APPLICATION_TYPE[endpoint_type_name]
        azure_cloud = AZURE_CLOUDS[endpoint_type]  # The MDA endpoint type is a subset of the azure clouds.
        token = params.get('creds_token', {}).get('password', '') or params.get('token', '')
        base_url = f'{params.get("url")}/api/v1'
        client = Client(
            app_id=app_id,
            verify=verify,
            base_url=base_url,
            proxy=proxy,
            endpoint_type=endpoint_type,
            tenant_id=tenant_id,
            enc_key=enc_key,
            auth_mode=auth_mode,
            azure_cloud=azure_cloud,
            headers={'Authorization': f'Token {token}'}
        )

        demisto.debug(f'Command being called is {command}')

        if command == 'test-module':
            result = test_module(client, params.get('isFetch'), params.get('custom_filter'))
            return_results(result)

        elif command == 'fetch-incidents':
            first_fetch = params.get('first_fetch')
            max_results = params.get('max_fetch')
            severity = params.get('severity') or []
            look_back = arg_to_number(params.get('look_back')) or 0
            resolution_status = params.get('resolution_status') or []
            if params.get('custom_filter'):
                filters = json.loads(str(params.get('custom_filter')))
            else:
                filters = params_to_filter(severity, resolution_status)  # type: ignore
            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch=first_fetch,
                filters=filters,
                look_back=look_back)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == 'microsoft-cas-auth-reset':
            return_results(reset_auth())
        elif command == 'microsoft-cas-auth-test':
            return_results(test_connection(client))
        else:
            commands = {
                'microsoft-cas-auth-start': start_auth,
                'microsoft-cas-auth-complete': complete_auth,
                'microsoft-cas-alerts-list': list_alerts_command,
                'microsoft-cas-alert-dismiss-bulk': bulk_dismiss_alert_command,  # Deprecated.
                'microsoft-cas-alert-resolve-bulk': bulk_resolve_alert_command,  # Deprecated.
                'microsoft-cas-activities-list': list_activities_command,
                'microsoft-cas-files-list': list_files_command,
                'microsoft-cas-users-accounts-list': list_users_accounts_command,
                'microsoft-cas-alert-close-benign': close_benign_command,
                'microsoft-cas-alert-close-true-positive': close_true_positive_command,
                'microsoft-cas-alert-close-false-positive': close_false_positive_command,
            }
            command_callable = commands.get(command)
            if command_callable:
                return_results(command_callable(client, args))
            else:
                raise NotImplementedError(f'command {command} is not implemented.')

    # Log exceptions
    except Exception as exc:
        return_error(f'Failed to execute {command} command. Error: {str(exc)}', error=exc)


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

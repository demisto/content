import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
SAAS_SECURITY_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

SAAS_SECURITY_INCIDENT_TYPE_NAME = 'Saas Security Incident'

CLIENT_CREDS = 'client_credentials'

# Token life time is 119 minutes
TOKEN_LIFE_TIME = 117

# Actual value is 1000 but we don't want to allow it.
LIMIT_MAX = 200
LIMIT_MIN = 10
LIMIT_DEFAULT = 50

INC_HEADERS_SHORTEN = ['incident_id', 'app_id', 'app_name', 'asset_id', 'asset_name', 'exposure_level', 'severity',
                       'state', 'status', 'category', 'created_at', 'updated_at', 'policy_name']

REMEDIATION_MAP = {
    'Remove public sharing': 'remove_public_sharing',
    'Quarantine': 'system_quarantine',
    'Restore': 'system_restore',
}

STATUS_MAP = {
    'New': 'open-new',
    'Assigned': 'open-assigned',
    'In Progress': 'open-in progress',
    'Pending': 'open-pending',
    'No Reason': 'closed-no reason',
    'Business Justified': 'closed-business justified',
    'Misidentified': 'closed-misidentified',
    'In The Cloud': 'closed-in the cloud',
    'Dismiss': 'closed-dismiss',
    'All': '',
}

MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}

POSSIBLE_CATEGORIES_TO_MIRROR_OUT = ['no_reason', 'business_justified', 'misidentified']

OUTGOING_MIRRORED_FIELDS = ['state', 'category']
INCOMING_MIRRORED_FIELDS = ['state', 'category', 'status', 'assigned_to', 'resolved_by', 'asset_sha256']


class Scopes:
    api = 'api_access'
    incidents = 'incident_api'
    remediation = 'remediation_api'


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls to the Saas Security platform, and does not contain any XSOAR logic.
    Handles the token retrieval.

    :param base_url (str): Saas Security server url.
    :param client_id (str): client ID.
    :param client_secret (str): client secret.
    :param verify (bool): specifies whether to verify the SSL certificate or not.
    :param proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)

    def http_request(self, *args, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        :return: The http response
        """
        token = self.get_access_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }
        return super()._http_request(*args, headers=headers, **kwargs)  # type: ignore[misc]

    def get_access_token(self):
        """
       Obtains access and refresh token from server.
       Access token is used and stored in the integration context until expiration time.
       After expiration, new refresh token and access token are obtained and stored in the
       integration context.

       :return: Access token that will be added to authorization header.
       :rtype: str
       """
        now = datetime.now()
        integration_context = get_integration_context()
        access_token = integration_context.get('access_token')
        time_issued = integration_context.get('time_issued')

        if access_token and get_passed_mins(now, time_issued) < TOKEN_LIFE_TIME:
            return access_token

        # there's no token or it is expired
        access_token = self.get_token_request()
        integration_context = {'access_token': access_token, 'time_issued': date_to_timestamp(now) / 1000}
        set_integration_context(integration_context)
        return access_token

    def get_token_request(self):
        """
        Sends request to retrieve token.

       :return: Access token.
       :rtype: str
        """
        base64_encoded_creds = b64_encode(f'{self.client_id}:{self.client_secret}')
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded; charset=ISO-8859-1',
            'Authorization': f'Basic {base64_encoded_creds}',
        }
        data = {
            'grant_type': CLIENT_CREDS,
            'scope': f'{Scopes.api} {Scopes.incidents} {Scopes.remediation}',
        }
        token_response = self._http_request('POST', url_suffix='/oauth/token',
                                            data=data, headers=headers)
        return token_response.get('access_token')

    def get_incidents(self, limit: int = None, from_time: str = None, to_time: str = None, app_ids: str = None,
                      state: str = None, severity: str = None, status: str = None, next_page: str = None):
        """
        :param limit: The number of incidents to pull per page. Default is 50, max is 1000, min is 10.
        :param from_time: The start time of query, filter by the incident's “updated-at” field.
        :param to_time: The end time of query, filter by the incident's “updated-at” field.
        :param app_ids: List of application id. Comma-separated.
        :param state: The state of the incidents to pull. Default is open.
        :param severity: The severity of the incidents to pull.
        :param status: The status of the incidents to pull.
        :param next_page: For pagination purposes. If provided, params should be None.
        """
        url_suffix = next_page or '/incident/api/incidents/delta'
        state = state if state != 'All' else None

        params = {
            'limit': limit,
            'from': from_time,
            'to': to_time,
            'app_ids': app_ids,
            'state': state,
            'severity': severity,
            'status': status,
        } if not next_page else {}
        remove_nulls_from_dictionary(params)

        return self.http_request('GET', url_suffix=url_suffix, params=params)

    def get_incident_by_id(self, inc_id: str):
        """
        :param inc_id: The incident ID.
        """
        return self.http_request('GET', url_suffix=f'/incident/api/incidents/{inc_id}')

    def update_incident_state(self, inc_id: str, category: str):
        """
        :param inc_id: The incident ID.
        :param category: Closing category.
        """
        body = {
            'state': 'closed',
            'category': category,
        }
        return self.http_request('POST', url_suffix=f'/incident/api/incidents/{inc_id}/state', json_data=body)

    def get_apps(self):
        return self.http_request('GET', url_suffix='/incident/api/apps')

    def remediate_asset(self, asset_id: str, remediation_type: str, remove_inherited_sharing: bool):
        """
        :param asset_id: The asset ID.
        :param remediation_type: The remediation action to take.
        :param remove_inherited_sharing: Used when remediation type is “remove_public_sharing”,
            when set to true, all the parent folder sharing url will be removed.
        """
        body = assign_params(
            remediation_type=remediation_type,
            remove_inherited_sharing=remove_inherited_sharing,
            asset_id=asset_id,
        )

        self.http_request('POST', url_suffix='/remediation/api/assets', json_data=body, resp_type='response')

    def asset_remediation_status(self, asset_id: str, remediation_type: str):
        """
        :param asset_id: The asset ID.
        :param remediation_type: The remediation action that was taken.
        """

        params = assign_params(
            remediation_type=remediation_type,
            asset_id=asset_id,
        )

        return self.http_request('GET', url_suffix='/remediation/api/assets', params=params)


''' HELPER FUNCTIONS '''


def validate_limit(limit: Optional[int]) -> int:
    """
    Validate the limit according to the following rules:

    1. if the limit is negative, raise an exception.
    2. if the limit is less than 10, the limit will be equal to 10.
    3. if the limit is not dividable by 10, make sure it gets rounded down to a number that is dividable by 10.
    4. if limit > MAX_LIMIT (200) - make sure it will always be MAX_LIMIT (200).
    5. if a limit is not provided, set it up for the default limit which is 50.
    """
    demisto.debug(f'limit before validate: {limit}')
    if limit:
        if limit <= 0:
            raise DemistoException('The limit parameter cannot be negative number or zero')
        if limit < LIMIT_MIN:
            limit = LIMIT_MIN
        if limit > LIMIT_MAX:  # do not allow a limit of more than 200 to avoid timeouts
            limit = LIMIT_MAX
        if limit % 10 != 0:  # max limit must be a multiplier of 10 (SaaS API limit)
            # round down the limit
            limit = int(limit // 10) * 10
    else:
        limit = LIMIT_DEFAULT

    demisto.debug(f'limit after validate: {limit}')
    return limit


def get_passed_mins(start_time, end_time_str, tz=None):
    """
    Calculates the amount of minutes passed between 2 dates.
    :param start_time: Start time in datetime
    :param end_time_str: End time in str

    :return: The passed minutes.
    :rtype: int
    """
    time_delta = start_time - datetime.fromtimestamp(end_time_str, tz)
    return time_delta.seconds / 60


def convert_to_xsoar_incident(inc) -> dict:
    occurred = inc.get('created_at')
    return {
        'name': f'Saas Security: {inc.get("asset_name", "No asset name")}',
        'occurred': datetime.strptime(occurred, SAAS_SECURITY_DATE_FORMAT).strftime(
            DATE_FORMAT) if occurred else None,
        'rawJSON': json.dumps(inc)
    }


''' COMMAND FUNCTIONS '''


def test_module(client: Client, is_fetch: bool = False, first_fetch_time: str = None, state: str = None,
                severity: str = None, status: str = None, app_ids: str = None) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    When an instance was configured to fetch incident, the fetch params are tested as well.
    """
    # test with fetch parameters
    if is_fetch:
        last_fetch = dateparser.parse(first_fetch_time, settings={'TIMEZONE': 'UTC'})  # type: ignore
        assert last_fetch is not None
        last_fetch = last_fetch.strftime(SAAS_SECURITY_DATE_FORMAT)[:-4] + 'Z'
        assert last_fetch is not None
        client.get_incidents(from_time=last_fetch, state=state, severity=severity, status=status, app_ids=app_ids)
    else:
        client.get_incidents()
    return 'ok'


def get_incidents_command(client: Client, args: dict) -> CommandResults:
    """
    List incidents with query.
    """
    limit = validate_limit(arg_to_number(args.get('limit')))
    from_time = args.get('from')
    to_time = args.get('to')
    app_ids = ','.join(argToList(args.get('app_ids', [])))
    state = args.get('state', 'open')
    severity = ','.join(argToList(args.get('severity', [])))
    status = ','.join(STATUS_MAP.get(x) for x in argToList(args.get('status', [])))  # type: ignore[misc]
    next_page = args.get('next_page')

    raw_res = client.get_incidents(limit, from_time, to_time, app_ids, state, severity, status, next_page)
    incidents = raw_res.get('resources', [])

    # The API always returns the nextPage field with value in it even if there are no more incidents to retrieve.
    next_page = raw_res.get('nextPath') if len(incidents) == limit else None
    metadata = 'Run the following command to retrieve the next batch of incidents:\n' \
               f'!saas-security-incidents-get next_page={next_page}' if next_page else None

    outputs = {
        'SaasSecurity.Incident(val.incident_id && val.incident_id == obj.incident_id)': incidents,
    }
    if next_page:
        outputs['SaasSecurity.NextResultsPage'] = next_page

    human_readable = tableToMarkdown('Incidents', incidents, headers=INC_HEADERS_SHORTEN,
                                     headerTransform=string_to_table_header, removeNull=True,
                                     metadata=metadata)

    return CommandResults(
        readable_output=human_readable,
        outputs=outputs,
        raw_response=raw_res)


def get_incident_by_id_command(client: Client, args: dict) -> CommandResults:
    """
    Get incident by ID.
    """
    inc_id = args['id']
    incident = client.get_incident_by_id(inc_id)
    human_readable = tableToMarkdown(f'Incident {inc_id} details', incident, headers=INC_HEADERS_SHORTEN,
                                     headerTransform=string_to_table_header, removeNull=True)

    return CommandResults(
        outputs_prefix='SaasSecurity.Incident',
        outputs_key_field='incident_id',
        readable_output=human_readable,
        outputs=incident,
        raw_response=incident)


def update_incident_state_command(client: Client, args: dict) -> CommandResults:
    """
    Changes an Incident status, can only closing due to an API limitation.
    Category can be changed multiple times.
    """
    inc_id = args['id']
    category = args.get('category', '').replace(' ', '_').lower()

    raw_res = client.update_incident_state(inc_id, category)
    raw_res['incident_id'] = inc_id
    human_readable = tableToMarkdown(f'Incident {inc_id} status details', raw_res, removeNull=True,
                                     headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix='SaasSecurity.IncidentState',
        outputs_key_field='incident_id',
        readable_output=human_readable,
        outputs=raw_res,
        raw_response=raw_res)


def get_apps_command(client: Client, _) -> CommandResults:
    """
    Gets Apps info.
    """
    raw_res = client.get_apps()
    human_readable = tableToMarkdown('Apps Info', raw_res, removeNull=True,
                                     headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix='SaasSecurity.App',
        outputs_key_field='app_id',
        readable_output=human_readable,
        outputs=raw_res,
        raw_response=raw_res)


def remediate_asset_command(client: Client, args: dict) -> CommandResults:
    """
    Remediate as asset.
    """
    asset_id = args['asset_id']
    remediation_type = REMEDIATION_MAP.get(args.get('remediation_type'))  # type: ignore

    if not remediation_type:
        raise DemistoException(f'Invalid remediation type: {args.get("remediation_type")}.\n'
                               f'Must be one of the following: Remove public sharing, Quarantine, Restore')

    remove_inherited_sharing = argToBoolean(
        args.get('remove_inherited_sharing', False)) if remediation_type == 'remove_public_sharing' else None

    client.remediate_asset(asset_id, remediation_type, remove_inherited_sharing)  # type: ignore[arg-type]
    outputs = {
        'asset_id': asset_id,
        'remediation_type': remediation_type,
        'status': 'pending',
    }
    return CommandResults(
        outputs_prefix='SaasSecurity.Remediation',
        outputs_key_field='asset_id',
        readable_output=tableToMarkdown(f'Remediation details for asset: {asset_id}', outputs, removeNull=True,
                                        headerTransform=string_to_table_header),
        outputs=outputs)


def get_remediation_status_command(client: Client, args: dict) -> CommandResults:
    """
    Get Remediation Status for a given asset ID.
    """
    asset_id = args['asset_id']
    remediation_type = REMEDIATION_MAP.get(args.get('remediation_type'))  # type: ignore

    if not remediation_type:
        raise DemistoException(f'Invalid remediation type: {remediation_type}.\n'
                               f'Must be one of the following: Remove public sharing, Quarantine, Restore')

    raw_res = client.asset_remediation_status(asset_id, remediation_type)
    human_readable = tableToMarkdown(f'Asset {asset_id} remediation details', raw_res, removeNull=True,
                                     headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix='SaasSecurity.Remediation',
        outputs_key_field='asset_id',
        readable_output=human_readable,
        outputs=raw_res,
        raw_response=raw_res)


def fetch_incidents(client: Client, first_fetch_time, fetch_limit, fetch_state, fetch_severity, fetch_status,
                    fetch_app_ids, mirror_direction=None, integration_instance=''):
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('last_run_time')

    if last_fetch is None:
        last_fetch = dateparser.parse(first_fetch_time, settings={'TIMEZONE': 'UTC'})
        last_fetch = last_fetch.strftime(SAAS_SECURITY_DATE_FORMAT)[:-4] + 'Z'  # format ex: 2021-08-23T09:26:25.872Z

    current_fetch = last_fetch
    results = client.get_incidents(limit=fetch_limit, from_time=last_fetch, state=fetch_state, severity=fetch_severity,
                                   status=fetch_status, app_ids=fetch_app_ids).get('resources', [])

    last_fetch_datetime = datetime.strptime(last_fetch, SAAS_SECURITY_DATE_FORMAT)
    incidents = list()
    for inc in results:

        date_updated = inc.get('updated_at')
        date_updated_dt = datetime.strptime(date_updated, SAAS_SECURITY_DATE_FORMAT) + timedelta(milliseconds=1)
        if date_updated_dt > datetime.strptime(current_fetch, SAAS_SECURITY_DATE_FORMAT):
            current_fetch = date_updated_dt.strftime(SAAS_SECURITY_DATE_FORMAT)[:-4] + 'Z'

        # We fetch the incidents by the "updated-at" field,
        # So we need to filter the incidents created before the last_fetch
        date_created = inc.get('created_at')
        if datetime.strptime(date_created, SAAS_SECURITY_DATE_FORMAT) < last_fetch_datetime:
            continue

        inc['mirror_direction'] = mirror_direction
        inc['mirror_instance'] = integration_instance
        inc['last_mirrored_in'] = int(datetime.now().timestamp() * 1000)

        incident = convert_to_xsoar_incident(inc)
        incidents.append(incident)

    demisto.setLastRun({'last_run_time': current_fetch})
    demisto.incidents(incidents)


def get_remote_data_command(client, args):
    """
    get-remote-data command: Returns an updated remote incident.
    Args:
        client: The client object.
        args:
            id: incident id to retrieve.
            lastUpdate: when was the last time we retrieved data.

    Returns:
        GetRemoteDataResponse object, which contain the incident data to update.
    """
    remote_args = GetRemoteDataArgs(args)
    demisto.debug('Performing get-remote-data command with incident id: {} and last_update: {}'
                  .format(remote_args.remote_incident_id, remote_args.last_update))

    incident_data = {}
    try:
        incident_data = client.get_incident_by_id(remote_args.remote_incident_id)
        delta = {field: incident_data.get(field) for field in INCOMING_MIRRORED_FIELDS if incident_data.get(field)}

        last_update_date = dateparser.parse(remote_args.last_update, settings={'TIMEZONE': 'UTC'})
        assert last_update_date is not None, f'could not parse {remote_args.last_update}'
        if not delta or date_to_timestamp(incident_data.get('updated_at'), '%Y-%m-%dT%H:%M:%S.%fZ') \
                <= int(last_update_date.timestamp()):
            demisto.debug("Nothing new in the incident.")
            delta = {
                'id': remote_args.remote_incident_id,
                'in_mirror_error': ""
            }

            return GetRemoteDataResponse(
                mirrored_object=delta,
                entries=[]
            )

        entries = []

        state = delta and delta.get('state')
        if state and state.lower() == 'closed':
            if demisto.params().get('close_incident'):

                demisto.debug(f'Incident is closed: {remote_args.remote_incident_id}')
                entries.append({
                    'Type': EntryType.NOTE,
                    'Contents': {
                        'dbotIncidentClose': True,
                        'closeReason': f'From SaasSecurity: {delta.get("category")}'
                    },
                    'ContentsFormat': EntryFormat.JSON
                })

        demisto.debug(f"Update incident {remote_args.remote_incident_id} with fields: {delta}")
        return GetRemoteDataResponse(
            mirrored_object=delta,
            entries=entries
        )

    except Exception as e:
        demisto.debug(f"Error in Saas Security incoming mirror for incident {remote_args.remote_incident_id} \n"
                      f"Error message: {str(e)}")

        if incident_data:
            incident_data['in_mirror_error'] = str(e)

        else:
            incident_data = {
                'id': remote_args.remote_incident_id,
                'in_mirror_error': str(e)
            }

        return GetRemoteDataResponse(
            mirrored_object=incident_data,
            entries=[]
        )


def get_modified_remote_data_command(client, args):
    """
    Gets the modified remote incident IDs.
    Args:
        client: The client object.
        args:
            last_update: the last time we retrieved modified incidents.

    Returns:
        GetModifiedRemoteDataResponse object, which contains a list of the retrieved incident IDs.
    """
    remote_args = GetModifiedRemoteDataArgs(args)

    last_update_utc = dateparser.parse(remote_args.last_update, settings={'TIMEZONE': 'UTC'})  # convert to utc format
    assert last_update_utc is not None, f'could not parse {remote_args.last_update}'
    last_update_utc = last_update_utc.strftime(SAAS_SECURITY_DATE_FORMAT)[:-4] + 'Z'  # format ex: 2021-08-23T09:26:25.872Z
    demisto.debug(f'last_update in UTC is {last_update_utc}')

    raw_incidents = client.get_incidents(from_time=last_update_utc, limit=100).get('resources', [])

    modified_incident_ids = list()
    for raw_incident in raw_incidents:
        incident_id = raw_incident.get('incident_id')
        modified_incident_ids.append(str(incident_id))

    return GetModifiedRemoteDataResponse(modified_incident_ids)


def get_mapping_fields_command():
    """
    Gets a list of fields for an incident type.

    Returns: GetMappingFieldsResponse object which contain the field names.
    """
    saas_security_incident_type_scheme = SchemeTypeMapping(type_name=SAAS_SECURITY_INCIDENT_TYPE_NAME)

    for field in OUTGOING_MIRRORED_FIELDS:
        saas_security_incident_type_scheme.add_field(field)

    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(saas_security_incident_type_scheme)

    return mapping_response


def update_remote_system_command(client: Client, args: Dict[str, Any]) -> str:
    """
    update-remote-system command: pushes local changes to the remote system.
    Since the API limitation doesn't allow to update the category when the incident state is open,
    The only use cases the update-remote-system can update are:
     1. When the incident were closed in XSOAR, so this command will close the mirror remote incident as well.
     2. If the category of an incident which was already closed in the remote and fetched was changed.

    :type client: ``Client``
    :param client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['data']`` the data to send to the remote system
        ``args['entries']`` the entries to send to the remote system
        ``args['incidentChanged']`` boolean telling us if the local incident indeed changed or not
        ``args['remoteId']`` the remote incident id

    :return:
        ``str`` containing the remote incident id - really important if the incident is newly created remotely
    :rtype: ``str``
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    if parsed_args.delta:
        demisto.debug(f'Got the following delta keys {str(list(parsed_args.delta.keys()))}')

    if parsed_args.incident_changed:
        # Check if the incident were closed in XSOAR,
        # or the category of an incident which was already closed in the remote was changed,
        # since these are the only use cases we wanna mirror out.
        if parsed_args.inc_status == IncidentStatus.DONE or (parsed_args.data.get('state') == 'closed'
                                                             and 'category' in parsed_args.data):

            category = parsed_args.data.get('category').replace(' ', '_').lower() \
                if 'category' in parsed_args.data else None
            if category in POSSIBLE_CATEGORIES_TO_MIRROR_OUT:

                try:
                    demisto.debug(f'Sending incident with remote ID {parsed_args.remote_incident_id} to remote system.')
                    result = client.update_incident_state(inc_id=parsed_args.remote_incident_id,
                                                          category=category)
                    demisto.debug(f'Incident updated successfully. Result: {result}')

                except Exception as e:
                    demisto.error(
                        f"Error in Saas Security outgoing mirror for incident {parsed_args.remote_incident_id} \n"
                        f"Error message: {str(e)}")
            else:
                demisto.debug(f'The value of category {parsed_args.data.get("category")} is invalid.'
                              f' The category can be one of the following {POSSIBLE_CATEGORIES_TO_MIRROR_OUT}.')
        else:
            demisto.debug('Skipping updating the remote incident since the incident is not closed. '
                          'Could not update the category for open incident due to an API limitation.')
    else:
        demisto.debug(f'Skipping updating remote incident fields [{parsed_args.remote_incident_id}] '
                      f'as it is not new nor changed.')

    return parsed_args.remote_incident_id


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    client_id: str = params['credentials']['identifier']
    client_secret: str = params['credentials']['password']
    base_url: str = params['url'].rstrip('/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    # Fetch incident related params:
    first_fetch_time = params.get('first_fetch', '3 days')
    fetch_limit = validate_limit(arg_to_number(params.get('max_fetch')))
    fetch_state = params.get('state')
    fetch_severity = params.get('severity')
    fetch_status = ','.join(STATUS_MAP.get(x) for x in argToList(params.get('status', [])))  # type: ignore[misc]
    fetch_app_ids = ','.join(argToList(params.get('app_ids', [])))

    mirror_direction = MIRROR_DIRECTION.get(params.get('mirror_direction', 'None'), None)
    instance = demisto.integrationInstance()

    commands = {
        'saas-security-incidents-get': get_incidents_command,
        'saas-security-incident-get-by-id': get_incident_by_id_command,
        'saas-security-incident-state-update': update_incident_state_command,
        'saas-security-get-apps': get_apps_command,
        'saas-security-asset-remediate': remediate_asset_command,
        'saas-security-remediation-status-get': get_remediation_status_command,
        'get-remote-data': get_remote_data_command,
        'get-modified-remote-data': get_modified_remote_data_command,
        'update-remote-system': update_remote_system_command,
    }
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == 'test-module':
            return_results(test_module(client, params.get('isFetch'), first_fetch_time, fetch_state, fetch_severity,
                                       fetch_status, fetch_app_ids))
        elif command == 'fetch-incidents':
            fetch_incidents(client, first_fetch_time, fetch_limit, fetch_state, fetch_severity, fetch_status,
                            fetch_app_ids, mirror_direction, instance)
        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command())

        elif command in commands:
            return_results(commands[command](client, demisto.args()))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

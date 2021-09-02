import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
SAAS_SECURITY_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

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
        params = {
            'grant_type': CLIENT_CREDS,
            'scope': f'{Scopes.api} {Scopes.incidents} {Scopes.remediation}',
        }
        token_response = self._http_request('POST', url_suffix='/oauth/token',
                                            params=params, headers=headers)
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
        last_fetch = dateparser.parse(first_fetch_time, settings={'TIMEZONE': 'UTC'})
        last_fetch = last_fetch.strftime(SAAS_SECURITY_DATE_FORMAT)[:-4] + 'Z'
        client.get_incidents(from_time=last_fetch, state=state, severity=severity, status=status, app_ids=app_ids)
    else:
        client.get_incidents()
    return 'ok'


def get_incidents_command(client: Client, args: dict) -> CommandResults:
    """
    List incidents with query.
    """
    limit = arg_to_number(args.get('limit')) or LIMIT_DEFAULT
    from_time = args.get('from')
    to_time = args.get('to')
    app_ids = ','.join(argToList(args.get('app_ids', [])))
    state = args.get('state', 'open')
    severity = ','.join(argToList(args.get('severity', [])))
    status = ','.join(STATUS_MAP.get(x) for x in argToList(args.get('status', [])))  # type: ignore[misc]
    next_page = args.get('next_page')

    if limit > LIMIT_MAX or limit < LIMIT_MIN:
        demisto.debug('SaaSSecurity: limit must be between 10 to 500. Setting limit to the default value of 50.')
        limit = LIMIT_MIN

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

    client.remediate_asset(asset_id, remediation_type, remove_inherited_sharing)
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
                    fetch_app_ids):
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('last_run_time')

    if last_fetch is None:
        last_fetch = dateparser.parse(first_fetch_time, settings={'TIMEZONE': 'UTC'})
        last_fetch = last_fetch.strftime(SAAS_SECURITY_DATE_FORMAT)[:-4] + 'Z'  # format ex: 2021-08-23T09:26:25.872Z

    current_fetch = last_fetch
    results = client.get_incidents(limit=fetch_limit, from_time=last_fetch, state=fetch_state, severity=fetch_severity,
                                   status=fetch_status, app_ids=fetch_app_ids).get('resources', [])
    incidents = list()
    for inc in results:
        incident = convert_to_xsoar_incident(inc)
        incidents.append(incident)

        date_updated = inc.get('updated_at')
        date_updated_dt = datetime.strptime(date_updated, SAAS_SECURITY_DATE_FORMAT)

        if date_updated_dt > datetime.strptime(current_fetch, SAAS_SECURITY_DATE_FORMAT):
            current_fetch = date_updated

    demisto.setLastRun({'last_run_time': current_fetch})
    demisto.incidents(incidents)


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
    fetch_limit = arg_to_number(params.get('max_fetch', LIMIT_DEFAULT))
    fetch_state = params.get('state')
    fetch_severity = params.get('severity')
    fetch_status = ','.join(STATUS_MAP.get(x) for x in argToList(params.get('status', [])))  # type: ignore[misc]
    fetch_app_ids = ','.join(argToList(params.get('app_ids', [])))

    commands = {
        'saas-security-incidents-get': get_incidents_command,
        'saas-security-incident-get-by-id': get_incident_by_id_command,
        'saas-security-incident-state-update': update_incident_state_command,
        'saas-security-get-apps': get_apps_command,
        'saas-security-asset-remediate': remediate_asset_command,
        'saas-security-remediation-status-get': get_remediation_status_command,
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
                            fetch_app_ids)
        elif command in commands:
            return_results(commands[command](client, demisto.args()))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

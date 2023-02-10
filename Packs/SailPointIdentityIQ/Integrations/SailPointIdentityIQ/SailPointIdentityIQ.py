import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

import base64
import datetime as dt
import json
import traceback

import dateparser
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

# IdentityIQ OAuth token endpoint
IIQ_OAUTH_EXT = '/oauth2/token'
IIQ_SCIM_PREFIX = '/scim/v2'

# SCIM core endpoints
IIQ_SCIM_SERVICE_PROVIDER_CONFIG_EXT = f'{IIQ_SCIM_PREFIX}/ServiceProviderConfig'
IIQ_SCIM_RESOURCE_TYPES_EXT = f'{IIQ_SCIM_PREFIX}/ResourceTypes'
IIQ_SCIM_SCHEMAS_EXT = f'{IIQ_SCIM_PREFIX}/Schemas'

# SCIM resource endpoints
IIQ_SCIM_USERS_EXT = f'{IIQ_SCIM_PREFIX}/Users'
IIQ_SCIM_ACCOUNTS_EXT = f'{IIQ_SCIM_PREFIX}/Accounts'
IIQ_SCIM_ENTITLEMENTS_EXT = f'{IIQ_SCIM_PREFIX}/Entitlements'
IIQ_SCIM_ROLES_EXT = f'{IIQ_SCIM_PREFIX}/Roles'
IIQ_SCIM_POLICY_VIOLATIONS_EXT = f'{IIQ_SCIM_PREFIX}/PolicyViolations'
IIQ_SCIM_LAUNCHED_WORKFLOWS_EXT = f'{IIQ_SCIM_PREFIX}/LaunchedWorkflows'
IIQ_SCIM_TASK_RESULTS_EXT = f'{IIQ_SCIM_PREFIX}/TaskResults'
IIQ_SCIM_ALERTS_EXT = f'{IIQ_SCIM_PREFIX}/Alerts'

# From ServiceProviderConfig (filter.maxResults) for IdentityIQ SCIM API
MAX_INCIDENTS_TO_FETCH = 1000
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with API request.
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, headers: dict, max_results: int, request_timeout: int):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)
        self.max_results = max_results
        self.request_timeout = request_timeout

    def send_request(self, url_suffix: str, method: str, params=None, json_data=None):
        """
        Perform a HTTP request to IdentityIQ SCIM API.

        :type url_suffix: ``str``
        :param url_suffix: IdentityIQ SCIM API endpoint ext suffix.

        :type method: ``str``
        :param method: HTTP method, e.g. 'GET', 'POST', 'PUT', 'DELETE'.

        :type params: ``JSON``
        :param params: URL parameters to specify the query.

        :type json_data: ``JSON``
        :param json_data: Data to be sent as part of 'POST' or 'PUT' request.

        :return: Response after fulfilling the request successfully, else None.
        """
        if url_suffix is None or method is None:
            return None
        return self._http_request(url_suffix=url_suffix, method=method, json_data=json_data, params=params,
                                  timeout=self.request_timeout, resp_type='response',
                                  ok_codes=(200, 201, 202, 204, 400, 401, 404, 409, 500), proxies=handle_proxy())


''' HELPER/UTILITY FUNCTIONS '''


def get_headers(base_url: str, client_id: str, client_secret: str, grant_type: str, verify: bool):
    """
    Create header with OAuth 2.0 authentication information.

    :type base_url: ``str``
    :param base_url: Base URL of the IdentityIQ tenant.

    :type client_id: ``str``
    :param client_id: Client Id for OAuth 2.0.

    :type client_secret: ``str``
    :param client_secret: Client Secret for OAuth 2.0.

    :type grant_type: ``str``
    :param grant_type: Grant Type for OAuth 2.0. Defaulted to 'client_credentials' if not provided.

    :return: Header with OAuth 2.0 information if client_id & client_secret are provided, else None.
    This will return None if the client_id & client_secret were not valid (authorized).
    """
    if base_url is None or client_id is None or client_secret is None:
        return None

    if grant_type is None:
        grant_type = 'client_credentials'

    auth_cred = client_id + ':' + client_secret
    iiq_oauth_body = f'grant_type={grant_type}'
    iiq_oauth_headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic %s' % base64.b64encode(auth_cred.encode()).decode()
    }
    oauth_response = requests.request("POST", url=f'{base_url}{IIQ_OAUTH_EXT}', data=iiq_oauth_body,
                                      headers=iiq_oauth_headers, verify=verify)
    if oauth_response is not None and 200 <= oauth_response.status_code < 300:
        return {
            'Authorization': 'Bearer %s' % oauth_response.json().get('access_token', None),
            'Content-Type': 'application/json'
        }
    else:
        err_msg = 'Failed to get response'
        if oauth_response is not None:
            err_msg += f' {oauth_response.status_code}'
        raise DemistoException(err_msg)


def transform_object_list(object_type: str, object_list=None):
    """
    Transform list objects, i.e. - replace the scim uri to a compressed object name.
    This is done as PAN XSOAR is unable to process json keys with symbols like - '.' or ':'.

    :type object_type: ``str``
    :param object_type: Type of IdentityIQ object.

    :type object_list: ``list``
    :param object_list: List of Identity resources objects.

    :return: Transformed list object.
    """
    if not isinstance(object_list, list):
        return None

    transformed_list = []
    for object in object_list:
        transformed_list.append(transform_object(object_type, object))
    return transformed_list


def transform_object(object_type: str, object=None):
    """
    Transform objects, i.e. - replace the scim uri to a compressed object name.
    This is done as PAN XSOAR is unable to process json keys with symbols like - '.' or ':'.

    :type object_type: ``str``
    :param object_type: Type of IdentityIQ object.

    :type object: ``JSON``
    :param object: Identity resources object.

    :return: Transformed object.
    """
    if not isinstance(object, dict):
        return None

    if object_type == 'IdentityIQ.Identity':
        if 'urn:ietf:params:scim:schemas:sailpoint:1.0:User' in object:
            object['sailpointUser'] = object.pop('urn:ietf:params:scim:schemas:sailpoint:1.0:User')
        if 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User' in object:
            object['extendedUser'] = object.pop('urn:ietf:params:scim:schemas:extension:enterprise:2.0:User')
    elif object_type == 'IdentityIQ.Workflow':
        if 'urn:ietf:params:scim:schemas:sailpoint:1.0:LaunchedWorkflow' in object:
            object['launchedWorkflow'] = object.pop('urn:ietf:params:scim:schemas:sailpoint:1.0:LaunchedWorkflow')
    elif object_type == 'IdentityIQ.Alert':
        if 'urn:ietf:params:scim:schemas:sailpoint:1.0:AlertInput' in object:
            object['alertInput'] = object.pop('urn:ietf:params:scim:schemas:sailpoint:1.0:AlertInput')
    return object


def get_markdown(object_type: str, objects=None):
    """
    Getting markdown for object type to display the results in human readable format.

    :type object_type: ``str``
    :param object_type: Type of IdentityIQ object.

    :type objects: ``dict`` or ``list``
    :param objects: Single or list of Identity resources object/s.

    :return: Markdown for each object type.
    """
    markdown = ''
    if object_type == 'IdentityIQ.Identity':
        headers = ['id', 'userName', 'displayName', 'name', 'emails', 'sailpointUser', 'extendedUser', 'entitlements',
                   'roles', 'capabilities', 'active']
        markdown = tableToMarkdown('Identity(Identities)', objects, headers=headers)
    elif object_type == 'IdentityIQ.PolicyViolation':
        headers = ['id', 'policyName', 'constraintName', 'status', 'description', 'identity', 'owner']
        markdown = tableToMarkdown('PolicyViolation(s)', objects, headers=headers)
    elif object_type == 'IdentityIQ.TaskResult':
        headers = ['id', 'name', 'type', 'host', 'progress', 'completionStatus', 'launched', 'taskDefinition',
                   'pendingSignoffs', 'launcher', 'completed', 'taskSchedule', 'partitioned', 'terminated', 'messages',
                   'attributes']
        markdown = tableToMarkdown('TaskResult(s)', objects, headers=headers)
    elif object_type == 'IdentityIQ.Account':
        headers = ['id', 'displayName', 'identity', 'hasEntitlements', 'application', 'nativeIdentity', 'active',
                   'lastRefresh', 'manuallyCorrelated', 'application', 'locked']
        markdown = tableToMarkdown('Account(s)', objects, headers=headers)
    elif object_type == 'IdentityIQ.Workflow':
        headers = ['id', 'name', 'workflowName', 'identityRequestId', 'workflowCaseId', 'launched', 'targetClass',
                   'targetName', 'type', 'completionStatus', 'launcher', 'terminated', 'attributes', 'partitioned',
                   'completed', 'pendingSignoffs', 'taskDefinition', 'launchedWorkflow']
        markdown = tableToMarkdown('Workflow(s)', objects, headers=headers)
    elif object_type == 'IdentityIQ.Role':
        headers = ['id', 'name', 'owner', 'active', 'displayableName', 'permits', 'type', 'descriptions',
                   'requirements']
        markdown = tableToMarkdown('Role(s)', objects, headers=headers)
    elif object_type == 'IdentityIQ.Entitlement':
        headers = ['id', 'displayableName', 'type', 'attribute', 'value', 'owner', 'application', 'descriptions',
                   'requestable', 'aggregated', 'created']
        markdown = tableToMarkdown('Entitlement(s)', objects, headers=headers)
    elif object_type == 'IdentityIQ.Alert':
        headers = ['id', 'name', 'displayName', 'type', 'targetId', 'targetDisplayName', 'targetType', 'alertInput',
                   'actions', 'application', 'attributes', 'lastProcessed']
        markdown = tableToMarkdown('Alert(s)', objects, headers=headers)
    return markdown


def build_results(prefix: str, key_field: str, response=None):
    """
    Build results.

    :type prefix: ``str``
    :param prefix: Prefix for CommandResults as part of the results.

    :type key_field: ``str``
    :param key_field: Key field for CommandResults as part of the results.

    :type response: ``response``
    :param response: Response object from IdentityIQ API call.

    :return: CommandResults in case of a successful response else message describing the error status.
    """
    if response is not None and 200 <= response.status_code < 300:
        data = response.json()
        if 'Resources' in data:
            outputs = transform_object_list(prefix, data.get('Resources'))
            markdown = '### Results:\nTotal: ' + str(data.get('totalResults')) + '\n'
        else:
            outputs = transform_object(prefix, data)
            markdown = '### Results:\n'
        markdown += get_markdown(prefix, outputs)

        return CommandResults(
            readable_output=markdown,
            outputs_prefix=prefix,
            outputs_key_field=key_field,
            outputs=outputs
        )
    else:
        if 'status' in response.json() and 'detail' in response.json():
            return ''.join((response.json().get('status'), ' : ', response.json().get('detail')))
        elif 'status' in response.json():
            return response.json().get('status')
    return None


''' COMMAND FUNCTIONS '''


def test_connection(client: Client):
    """
    Test connectivity to IdentityIQ (pings SCIM's ResourceTypes API).

    :type client: ``Client``
    :param client: SailPoint client

    :return: HTTP connectivity status for test connection.
    """
    # Service provider config url may not be behind any auth, hence test resource types URL
    response = client.send_request(IIQ_SCIM_RESOURCE_TYPES_EXT, "GET", None)
    if response is not None and 200 <= response.status_code < 300:
        return 'ok'
    else:
        return 'Unable to connect to IdentityIQ!'


def fetch_incidents(client: Client, last_run, first_fetch_str):
    """
    Fetch incidents [IdentityIQ Alerts]

    :type client: ``Client``
    :param client: SailPoint client

    :type last_run: ``[Dict[str, str]]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch.

    :type first_fetch_str: ``str``
    :param first_fetch_str: First fetch time ("3 days", "1 month", etc).

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR
    """
    first_fetch_date = dateparser.parse(first_fetch_str)
    assert first_fetch_date is not None, f'could not parse {first_fetch_str}'
    first_fetch = first_fetch_date.strftime(DATE_FORMAT)
    last_processed = last_run.get('last_fetch', first_fetch)
    now = dt.datetime.now().strftime(DATE_FORMAT)

    incidents = []
    filter_string = ''.join(
        ('(lastProcessed gt "', last_processed, '" and lastProcessed le "', now, '")'))
    params = {'filter': filter_string}
    response = client.send_request(IIQ_SCIM_ALERTS_EXT, "GET", params, None)
    if response is not None and 200 <= response.status_code < 300:
        alerts = transform_object_list('IdentityIQ.Alert', response.json().get('Resources'))
        for alert in alerts:
            if 'displayName' in alert:
                incident_name = alert.get('displayName', None)
            else:
                incident_name = alert.get('name', None)
            incident = {
                'name': incident_name,
                'details': alert.get('name', None),
                'occurred': alert.get('meta', {}).get('created', None),
                'rawJSON': json.dumps(alert)
            }
            incidents.append(incident)
    next_run = {'last_fetch': now}
    return next_run, incidents


def search_identities(client: Client, id: str, email: str, risk: int, active: bool, filter: str):
    """
    Search identities by search/filter parameters (id, email, risk & active) using IdentityIQ SCIM API's.
    Command: identityiq-search-identities

    :type client: ``Client``
    :param client: SailPoint client

    :type id: ``str``
    :param id:  Internal Id of the user being requested.

    :type email: ``str``
    :param email: Email address of the user being requested.

    :type risk: ``int``
    :param risk: Numeric value of baseline risk score, users above this will be returned.

    :type active: ``bool``
    :param active: Determines whether search will return only active users.

    :return: Identity object (JSON) corresponding to the id or list of identity objects matching search/filter
    parameters. All Identities if the search parameters are None. Empty JSON if the identity was not found in
    IdentityIQ.
    """
    params = None
    if id is not None:
        url = ''.join((IIQ_SCIM_USERS_EXT, '/', id))
    else:
        url = IIQ_SCIM_USERS_EXT
        filter_list = []

        # use custom filter
        if filter is not None:
            filter_list.append(filter)
        else:
            if email is not None:
                filter_list.append(''.join(('emails.value eq "', email, '"')))
            if risk is not None:
                filter_list.append(''.join(('urn:ietf:params:scim:schemas:sailpoint:1.0:User:riskScore ge ', str(risk))))
            if active is not None:
                filter_list.append(''.join(('active eq ', str(active).lower())))
        # Combine the filters
        if filter_list is not None and len(filter_list) > 0:
            filter_string = ' and '.join(filter_list)
            params = {'filter': filter_string}
    return client.send_request(url, "GET", params, None)


def get_policy_violations(client: Client, id: str):
    """
    Get policy violation by id or all policy violations using IdentityIQ SCIM API's.
    Command: identityiq-get-policyviolations

    :type client: ``Client``
    :param client: SailPoint client

    :type id: ``str``
    :param id: Internal Id of the policy violation being requested.

    :return: Policy violation object (JSON) corresponding to the id or list of policy violation objects if id was None.
    """
    if id is not None:
        url = ''.join((IIQ_SCIM_POLICY_VIOLATIONS_EXT, '/', id))
    else:
        url = IIQ_SCIM_POLICY_VIOLATIONS_EXT
    return client.send_request(url, "GET", None, None)


def get_task_results(client: Client, id: str):
    """
    Get task result by id or all task results using IdentityIQ SCIM API's.
    Command: identityiq-get-taskresults

    :type client: ``Client``
    :param client: SailPoint client

    :type id: ``str``
    :param id: Internal Id of the task result being requested.

    :return: Task result object (JSON) corresponding to the id or list of task result objects if id was None.
    """
    if id is not None:
        url = ''.join((IIQ_SCIM_TASK_RESULTS_EXT, '/', id))
    else:
        url = IIQ_SCIM_TASK_RESULTS_EXT
    return client.send_request(url, "GET", None, None)


def get_accounts(client: Client, id: str, display_name: str, last_refresh: str, native_identity: str,
                 last_target_agg: str,
                 identity_name: str, application_name: str):
    """
    Get accounts by search/filter parameters (id, display_name, last_refresh, native_identity,
    last_target_agg, identity_name & application_name) using IdentityIQ SCIM API's.
    Command: identityiq-get-accounts

    :type client: ``Client``
    :param client: SailPoint client

    :type id: ``str``
    :param id: Internal Id of the account to be returned.

    :type display_name: ``str``
    :param display_name: Display name of the account to be returned.

    :type last_refresh: ``str``
    :param last_refresh: Timestamp of the last time the account(s) were refreshed from the target system.

    :type native_identity: ``str``
    :param native_identity: Unique identifier of the account on the target system.

    :type last_target_agg: ``str``
    :param last_target_agg: Timestamp of the last targeted aggregation of the account from the target system.

    :type identity_name: ``str``
    :param identity_name: Unique name of the identity for which all accounts will be returned.

    :type application_name: ``str``
    :param application_name: Unique name of the application for which all accounts will be returned.

    :return: Account object (JSON) corresponding to the id or list of identity objects matching search/filter
    parameters. All account if the search parameters are None. Empty JSON if the account was not found in IdentityIQ.
    """
    params = None
    if id is not None:
        url = ''.join((IIQ_SCIM_ACCOUNTS_EXT, '/', id))
    else:
        url = IIQ_SCIM_ACCOUNTS_EXT
        filter_list = []
        if display_name is not None:
            filter_list.append(''.join(('displayName eq "', display_name, '"')))
        if last_refresh is not None:
            filter_list.append(''.join(('lastRefresh ge "', last_refresh, '"')))
        if native_identity is not None:
            filter_list.append(''.join(('nativeIdentity eq "', native_identity, '"')))
        if last_target_agg is not None:
            filter_list.append(''.join(('lastTargetAggregation ge "', last_target_agg, '"')))
        if identity_name is not None:
            filter_list.append(''.join(
                ('(identity.userName eq "', identity_name, '"', ' or identity.displayName eq "', identity_name, '")')))
        if application_name is not None:
            filter_list.append(''.join(('application.displayName eq "', application_name, '"')))
        # Combine the filters
        if filter_list is not None and len(filter_list) > 0:
            filter_string = ' and '.join(filter_list)
            params = {'filter': filter_string}
    return client.send_request(url, "GET", params, None)


def change_account_status(client: Client, id: str, status: bool):
    """
    Enable/disable account's active status by id using IdentityIQ SCIM API's.
    Command: identityiq-disable-account, identityiq-enable-account

    :type client: ``Client``
    :param client: SailPoint client

    :type id: ``str``
    :param id: (str) Internal Id of the specific account to be enabled/disabled.

    :type status: ``bool``
    :param status: True (enable) or False (disable).

    :return: Account object with active flag changed (JSON). None if the request was unsuccessful.
    """
    if id is None or status is None or type(status) is not bool:
        return None

    # Get the user account (we need several fields to update as this is not a PATCH HTTP call).
    url = ''.join((IIQ_SCIM_ACCOUNTS_EXT, '/', id))
    response = client.send_request(url, "GET", None)
    if response is not None and 200 <= response.status_code < 300:
        data = response.json()
        data['active'] = str(status).lower()
        return client.send_request(url, "PUT", None, data)
    else:
        return response.json()


def delete_account(client: Client, id: str):
    """
    Delete account by id using IdentityIQ SCIM API's.
    Command: identityiq-delete-account

    :type client: ``Client``
    :param client: SailPoint client

    :type id: ``str``
    :param id: Internal Id of the specific account to be deleted.

    :return: Empty HTTP 204 response. None if the request was unsuccessful.
    """
    if id is None:
        return None
    url = ''.join((IIQ_SCIM_ACCOUNTS_EXT, '/', id))
    response = client.send_request(url, "DELETE", None, None)
    if response is not None and 200 <= response.status_code < 300:
        return 'Account deleted successfully!'
    else:
        if 'status' in response.json() and 'detail' in response.json():
            return ''.join((response.json().get('status'), ' : ', response.json().get('detail')))
        elif 'status' in response.json():
            return response.json().get('status')
    return None


def get_launched_workflows(client: Client, id: str):
    """
    Get launched workflow by id or all launched workflows using IdentityIQ SCIM API's.
    Command: identitytiq-get-launched-workflows

    :type client: ``Client``
    :param client: SailPoint client

    :type id: ``str``
    :param id: Internal Id of the specific launched workflow being requested.

    :return: Launched workflow object (JSON) corresponding to the id or list of launched workflows objects if id was None.
    """
    if id is not None:
        url = ''.join((IIQ_SCIM_LAUNCHED_WORKFLOWS_EXT, '/', id))
    else:
        url = IIQ_SCIM_LAUNCHED_WORKFLOWS_EXT
    return client.send_request(url, "GET", None, None)


def get_roles(client: Client, id: str):
    """
    Get role by id or all roles using IdentityIQ SCIM API's.
    Command: identityiq-get-roles

    :type client: ``Client``
    :param client: SailPoint client

    :type id: ``str``
    :param id: Internal Id of the specific role being requested.

    :return: Role object (JSON) corresponding to the id or list of role objects if id was None.
    """
    if id is not None:
        url = ''.join((IIQ_SCIM_ROLES_EXT, '/', id))
    else:
        url = IIQ_SCIM_ROLES_EXT
    return client.send_request(url, "GET", None, None)


def get_entitlements(client: Client, id: str):
    """
    Get entitlement by id or all entitlements using IdentityIQ SCIM API's.
    Command: identityiq-get-entitlements

    :type client: ``Client``
    :param client: SailPoint client

    :type id: ``str``
    :param id: Internal Id of the specific entitlement being requested.

    :return: Entitlement object (JSON) corresponding to the id or list of entitlement objects if id was None.
    """
    if id is not None:
        url = ''.join((IIQ_SCIM_ENTITLEMENTS_EXT, '/', id))
    else:
        url = IIQ_SCIM_ENTITLEMENTS_EXT
    return client.send_request(url, "GET", None, None)


def get_alerts(client: Client, id: str):
    """
    Get alert by id or all alerts using IdentityIQ SCIM API's.
    Command: identityiq-get-alerts

    :type client: ``Client``
    :param client: SailPoint client

    :type id: ``str``
    :param id: Internal Id of the specific alert being requested.

    :return: Alert object (JSON) corresponding to the id or list of alert objects if id was None.
    """
    if id is not None:
        url = ''.join((IIQ_SCIM_ALERTS_EXT, '/', id))
    else:
        url = IIQ_SCIM_ALERTS_EXT
    return client.send_request(url, "GET", None, None)


def create_alert(client: Client, display_name: str, attributes=None):
    """
    Create an alert using IdentityIQ SCIM API's.
    Command: identityiq-create-alert

    :type client: ``Client``
    :param client: SailPoint client

    :type display_name: ``str``
    :param display_name: Display name of the alert.

    :type attributes: ``list``
    :param attributes: List of JSON objects with the following structure.
        [
            {
                'key': '',
                'value': '',
                'type': ''
            }
        ]

    :return: Newly created alert object (JSON).
    """
    if display_name is None:
        return None

    if attributes is None:
        attributes = []

    data = {
        'displayName': display_name,
        'type': 'PAN XSOAR',
        'attributes': attributes
    }
    return client.send_request(IIQ_SCIM_ALERTS_EXT, "POST", None, data)


''' MAIN FUNCTION '''


def main():
    """
    Intercept and execute commands.
    """

    # IdentityIQ Base URL (https://identityiq-server.com/identityiq)
    base_url = demisto.params().get('identityiq_url')

    # OAuth 2.0 Credentials
    client_id = demisto.params().get('client_id')
    client_secret = demisto.params().get('client_secret')
    grant_type = 'client_credentials'

    # Convert the argument to an int or set to MAX_INCIDENTS_TO_FETCH
    max_results = int(demisto.params().get('max_fetch'))
    if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
        max_results = MAX_INCIDENTS_TO_FETCH

    first_fetch_str = demisto.params().get('first_fetch', '3 days')

    # Other configs
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = handle_proxy()
    request_timeout = 10

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = get_headers(base_url, client_id, client_secret, grant_type, verify_certificate)
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers,
            max_results=max_results,
            request_timeout=request_timeout)
        results = None
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            results = test_connection(client)

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(client, demisto.getLastRun(), first_fetch_str)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'identityiq-search-identities':
            id = demisto.args().get('id', None)
            email = demisto.args().get('email', None)
            risk = demisto.args().get('risk', 0)
            active = demisto.args().get('active', True)
            filter = demisto.args().get('filter', None)
            response = search_identities(client, id, email, risk, active, filter)
            results = build_results('IdentityIQ.Identity', 'id', response)

        elif demisto.command() == 'identityiq-get-policyviolations':
            id = demisto.args().get('id', None)
            response = get_policy_violations(client, id)
            results = build_results('IdentityIQ.PolicyViolation', 'policyName', response)

        elif demisto.command() == 'identityiq-get-taskresults':
            id = demisto.args().get('id', None)
            response = get_task_results(client, id)
            results = build_results('IdentityIQ.TaskResult', 'id', response)

        elif demisto.command() == 'identityiq-get-accounts':
            id = demisto.args().get('id', None)
            display_name = demisto.args().get('display_name', None)
            last_refresh = demisto.args().get('last_refresh', None)
            native_identity = demisto.args().get('native_identity', None)
            last_target_agg = demisto.args().get('last_target_agg')
            identity_name = demisto.args().get('identity_name', None)
            application_name = demisto.args().get('application_name', None)
            response = get_accounts(client, id, display_name, last_refresh, native_identity, last_target_agg,
                                    identity_name,
                                    application_name)
            results = build_results('IdentityIQ.Account', 'id', response)

        elif demisto.command() == 'identityiq-disable-account':
            id = demisto.args().get('id', None)
            response = change_account_status(client, id, False)
            results = build_results('IdentityIQ.Account', 'id', response)

        elif demisto.command() == 'identityiq-enable-account':
            id = demisto.args().get('id', None)
            response = change_account_status(client, id, True)
            results = build_results('IdentityIQ.Account', 'id', response)

        elif demisto.command() == 'identityiq-delete-account':
            id = demisto.args().get('id', None)
            results = delete_account(client, id)

        elif demisto.command() == 'identitytiq-get-launched-workflows':
            id = demisto.args().get('id', None)
            response = get_launched_workflows(client, id)
            results = build_results('IdentityIQ.Workflow', 'id', response)

        elif demisto.command() == 'identityiq-get-roles':
            id = demisto.args().get('id', None)
            response = get_roles(client, id)
            results = build_results('IdentityIQ.Role', 'name', response)

        elif demisto.command() == 'identityiq-get-entitlements':
            id = demisto.args().get('id', None)
            response = get_entitlements(client, id)
            results = build_results('IdentityIQ.Entitlement', 'id', response)

        elif demisto.command() == 'identityiq-get-alerts':
            id = demisto.args().get('id', None)
            response = get_alerts(client, id)
            results = build_results('IdentityIQ.Alert', 'id', response)

        elif demisto.command() == 'identityiq-create-alert':
            display_name = demisto.args().get('display_name', None)
            attribute = demisto.args().get('attribute', None)
            response = create_alert(client, display_name, attribute)
            results = build_results('IdentityIQ.Alert', 'id', response)

        return_results(results)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

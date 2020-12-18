from CommonServerPython import *

''' IMPORTS '''

import base64
import json
import traceback

import requests
import urllib3
import datetime as dt

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

# IdentityIQ Base URL (https://identityiq-server.com/identityiq)
IIQ_BASE_URL = demisto.params().get('identityiq_url')

# Authentication Type ('BASIC' or 'OAUTH')
AUTH_TYPE = demisto.params().get('auth_type')

# Auth Type Constants
AUTH_TYPE_OAUTH = 'OAUTH'
AUTH_TYPE_BASIC = 'BASIC'

# OAuth 2.0 Credentials
CLIENT_ID = demisto.params().get('client_id')
CLIENT_SECRET = demisto.params().get('client_secret')
GRANT_TYPE = 'client_credentials'

# Basic Auth Credentials
USERNAME = demisto.params().get('username')
PASSWORD = demisto.params().get('password')

# IdentityIQ OAuth token endpoint
IIQ_OAUTH_EXT = 'oauth2/token'

# SCIM base endpoint
IIQ_SCIM_BASE_EXT = 'scim/v2'

# SCIM core endpoints
IIQ_SCIM_SERVICE_PROVIDER_CONFIG_EXT = 'ServiceProviderConfig'
IIQ_SCIM_RESOURCE_TYPES_EXT = 'ResourceTypes'
IIQ_SCIM_SCHEMAS_EXT = 'Schemas'

# SCIM resource endpoints
IIQ_SCIM_USERS_EXT = 'Users'
IIQ_SCIM_ACCOUNTS_EXT = 'Accounts'
IIQ_SCIM_ENTITLEMENTS_EXT = 'Entitlements'
IIQ_SCIM_ROLES_EXT = 'Roles'
IIQ_SCIM_POLICY_VIOLATIONS_EXT = 'PolicyViolations'
IIQ_SCIM_LAUNCHED_WORKFLOWS_EXT = 'LaunchedWorkflows'
IIQ_SCIM_TASK_RESULTS_EXT = 'TaskResults'
IIQ_SCIM_ALERTS_EXT = 'Alerts'

# IdentityIQ OAuth URL
IIQ_OAUTH_URL = f'{IIQ_BASE_URL}/{IIQ_OAUTH_EXT}'
# IdentityIQ OAuth URL
IIQ_SCIM_URL = f'{IIQ_BASE_URL}/{IIQ_SCIM_BASE_EXT}'
# Service provider config url may not be behind any auth, hence test resource types URL
IIQ_TEST_URL = f'{IIQ_SCIM_URL}/{IIQ_SCIM_RESOURCE_TYPES_EXT}'
# IdentityIQ SCIM users/identities URL
IIQ_SCIM_USERS_URL = f'{IIQ_SCIM_URL}/{IIQ_SCIM_USERS_EXT}'
# IdentityIQ SCIM accounts URL
IIQ_SCIM_ACCOUNTS_URL = f'{IIQ_SCIM_URL}/{IIQ_SCIM_ACCOUNTS_EXT}'
# IdentityIQ SCIM entitlements URL
IIQ_SCIM_ENTITLEMENTS_URL = f'{IIQ_SCIM_URL}/{IIQ_SCIM_ENTITLEMENTS_EXT}'
# IdentityIQ SCIM roles URL
IIQ_SCIM_ROLES_URL = f'{IIQ_SCIM_URL}/{IIQ_SCIM_ROLES_EXT}'
# IdentityIQ SCIM policy violations URL
IIQ_SCIM_POLICY_VIOLATIONS_URL = f'{IIQ_SCIM_URL}/{IIQ_SCIM_POLICY_VIOLATIONS_EXT}'
# IdentityIQ SCIM workflows URL
IIQ_SCIM_LAUNCHED_WORKFLOWS_URL = f'{IIQ_SCIM_URL}/{IIQ_SCIM_LAUNCHED_WORKFLOWS_EXT}'
# IdentityIQ SCIM task results URL
IIQ_SCIM_TASK_RESULTS_URL = f'{IIQ_SCIM_URL}/{IIQ_SCIM_TASK_RESULTS_EXT}'
# IdentityIQ SCIM users/identities alerts URL
IIQ_SCIM_ALERTS_URL = f'{IIQ_SCIM_URL}/{IIQ_SCIM_ALERTS_EXT}'

# Fetch incident (alerts)
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
MAX_ALERT_WINDOW = 72

''' HELPER/UTILITY FUNCTIONS '''


def get_oauth_headers(client_id: str, client_secret: str, grant_type: str):
    """
    Create header with OAuth 2.0 authentication information.

    :type client_id: ``str``
    :param client_id: Client Id for OAuth 2.0.

    :type client_secret: ``str``
    :param client_secret: Client Secret for OAuth 2.0.

    :type grant_type: ``str``
    :param grant_type: Grant Type for OAuth 2.0. Defaulted to 'client_credentials' if not provided.

    :return: Header with OAuth 2.0 information if client_id & client_secret are provided, else None.
    This will return None if the client_id & client_secret were not valid (authorized).
    """
    if client_id is None or client_secret is None:
        return None

    if grant_type is None:
        grant_type = 'client_credentials'

    auth_cred = client_id + ':' + client_secret
    iiq_oauth_body = f'grant_type={grant_type}'
    iiq_oauth_headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic %s' % base64.b64encode(auth_cred.encode()).decode()
    }
    oauth_response = requests.request("POST", url=IIQ_OAUTH_URL, data=iiq_oauth_body, headers=iiq_oauth_headers)
    if oauth_response is not None and 200 <= oauth_response.status_code < 300:
        return {
            'Authorization': 'Bearer %s' % oauth_response.json()['access_token'],
            'Content-Type': 'application/json'
        }
    else:
        return None


def get_basic_auth_headers(username: str, password: str):
    """
    Create header with basic authentication information.

    :type username: ``str``
    :param username: Username for Basic Auth.

    :type password: ``str``
    :param password: Password for Basic Auth.

    :return: Header with Basic Auth information if username & password are provided, else None.
    """
    if username is None or password is None:
        return None

    auth_cred = username + ':' + password
    return {
        'Authorization': 'Basic %s' % base64.b64encode(auth_cred.encode()).decode(),
        'Content-Type': 'application/json'
    }


def get_headers(auth_type: str):
    """
    Create header for IdentityIQ SCIM API requests.

    :type auth_type: ``str``
    :param auth_type: Authentication type for connectivity with IdentityIQ, e.g. 'OAUTH' or 'BASIC'.

    :return: Header with either OAuth 2.0 or Basic information based on the auth_type provided. If the auth_type neither
    'OAUTH' nor 'BASIC', then the header is returned as None.
    """
    headers = None
    if auth_type == AUTH_TYPE_OAUTH:
        headers = get_oauth_headers(CLIENT_ID, CLIENT_SECRET, GRANT_TYPE)
    elif auth_type == AUTH_TYPE_BASIC:
        headers = get_basic_auth_headers(USERNAME, PASSWORD)
    return headers


def send_request(url: str, method: str, data=None):
    """
    Perform a HTTP request to IdentityIQ SCIM API.

    :type url: ``str``
    :param url: IdentityIQ SCIM API endpoint.

    :type method: ``str``
    :param method: HTTP method, e.g. 'GET', 'POST', 'PUT', 'DELETE'.

    :type data: ``JSON``
    :param data: Data to be sent as part of 'POST' or 'PUT' request.

    :return: Response after fulfilling the request successfully, else None.
    """
    headers = get_headers(AUTH_TYPE)
    if headers is None:
        return None
    if url is None or method is None:
        return None

    return requests.request(method, url=url, data=data, headers=headers)


def transform_object_list(object_type: str, object_list=None):
    """
    Transform list objects, i.e. - replace the scim uri to a compressed object name.
    This is done as PAN XSOAR is unable to process json keys with symbols like - '.' or ':'.

    :type object_type: ``str``
    :param object_type: Type of IdentityIQ object.

    :type object_list: ``JSON``
    :param object_list: List of Identity resources objects.

    :return: Transformed list object.
    """
    if object_list is None:
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
    if object is None:
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

    :type objects: ``JSON``
    :param objects: Single or list of Identity resources object/s.

    :return: Markdown for each object type.
    """
    markdown = ''
    if object_type == 'IdentityIQ.Identity':
        headers = ['id', 'userName', 'displayName', 'name', 'emails', 'sailpointUser', 'extendedUser', 'entitlements',
                   'roles', 'capabilities', 'active']
        markdown = tableToMarkdown('Identity', objects, headers=headers)
    elif object_type == 'IdentityIQ.PolicyViolation':
        headers = ['id', 'policyName', 'constraintName', 'status', 'description', 'identity', 'owner']
        markdown = tableToMarkdown('PolicyViolation', objects, headers=headers)
    elif object_type == 'IdentityIQ.TaskResult':
        headers = ['id', 'name', 'type', 'host', 'progress', 'completionStatus', 'launched', 'taskDefinition',
                   'pendingSignoffs', 'launcher', 'completed', 'taskSchedule', 'partitioned', 'terminated', 'messages',
                   'attributes']
        markdown = tableToMarkdown('TaskResult', objects, headers=headers)
    elif object_type == 'IdentityIQ.Account':
        headers = ['id', 'displayName', 'identity', 'hasEntitlements', 'application', 'nativeIdentity', 'active',
                   'lastRefresh', 'manuallyCorrelated', 'application', 'locked']
        markdown = tableToMarkdown('Account', objects, headers=headers)
    elif object_type == 'IdentityIQ.Workflow':
        headers = ['id', 'name', 'workflowName', 'identityRequestId', 'workflowCaseId', 'launched', 'targetClass',
                   'targetName', 'type', 'completionStatus', 'launcher', 'terminated', 'attributes', 'partitioned',
                   'completed', 'pendingSignoffs', 'taskDefinition', 'launchedWorkflow']
        markdown = tableToMarkdown('Workflow', objects, headers=headers)
    elif object_type == 'IdentityIQ.Role':
        headers = ['id', 'name', 'owner', 'active', 'displayableName', 'permits', 'type', 'descriptions',
                   'requirements']
        markdown = tableToMarkdown('Role', objects, headers=headers)
    elif object_type == 'IdentityIQ.Entitlement':
        headers = ['id', 'displayableName', 'type', 'attribute', 'value', 'owner', 'application', 'descriptions',
                   'requestable', 'aggregated', 'created']
        markdown = tableToMarkdown('Entitlement', objects, headers=headers)
    elif object_type == 'IdentityIQ.Alert':
        headers = ['id', 'name', 'displayName', 'type', 'targetId', 'targetDisplayName', 'targetType', 'alertInput',
                   'actions', 'application', 'attributes', 'lastProcessed']
        markdown = tableToMarkdown('Alert', objects, headers=headers)
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
            outputs = transform_object_list(prefix, data['Resources'])
            markdown = '### Results:\nTotal: ' + str(data['totalResults']) + '\n'
            demisto.results('Total: %s' % str(data['totalResults']))
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
            return ''.join((response.json()['status'], ' : ', response.json()['detail']))
        elif 'status' in response.json():
            return response.json()['status']


''' COMMAND FUNCTIONS '''


def test_connection():
    """
    Test connectivity to IdentityIQ (pings SCIM's ResourceTypes API).
    Command: identityiq-search-identities

    :return: HTTP connectivity status for test connection.
    """
    response = send_request(IIQ_TEST_URL, "GET", None)
    if response is not None and 200 <= response.status_code < 300:
        return 'ok'
    else:
        return 'Unable to connect to IdentityIQ!'


def fetch_incidents(last_run):
    """
    Fetch incidents [IdentityIQ Alerts]

    :type last_run: ``[Dict[str, str]]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR
    """
    now = dt.datetime.now().replace(microsecond=0).isoformat()
    last_processed = last_run.get('last_fetch', None)

    # Compute the time frame for which the alerts will be requested.
    if last_processed is None:
        # Never processed, hence time filter window is MAX_ALERT_WINDOW (72 hrs) past from now
        last_processed_past = (dt.datetime.strptime(now, DATE_FORMAT) + dt.timedelta(hours=-MAX_ALERT_WINDOW,
                                                                                     minutes=0)).isoformat()
        last_processed = now
    else:
        now_formatted = dt.datetime.strptime(now, DATE_FORMAT)
        last_processed_formatted = dt.datetime.strptime(last_processed, DATE_FORMAT)
        diff = (now_formatted - last_processed_formatted).total_seconds() / 3600
        if diff > MAX_ALERT_WINDOW:
            # If the difference between the last run and this run is more than MAX_ALERT_WINDOW (72 hrs),
            # then make it only run for past MAX_ALERT_WINDOW (72 hrs)
            last_processed_past = (dt.datetime.strptime(now, DATE_FORMAT) + dt.timedelta(hours=-MAX_ALERT_WINDOW,
                                                                                         minutes=0)).isoformat()
            last_processed = now
        else:
            # Else, run for only the delta time (1 min in case of normal execution)
            last_processed_past = last_processed
            last_processed = now

    incidents = []
    url = ''.join(
        (IIQ_SCIM_ALERTS_URL, '?filter=(lastProcessed gt "', last_processed_past, '" and lastProcessed le "',
         last_processed, '")'))
    response = send_request(url, "GET", None)
    if response is not None and 200 <= response.status_code < 300:
        alerts = transform_object_list('IdentityIQ.Alert', response.json()['Resources'])
        for alert in alerts:
            if 'displayName' in alert:
                incident_name = alert['displayName']
            else:
                incident_name = alert['name']

            incident = {
                'name': incident_name,
                'details': alert['name'],
                'occurred': alert['meta']['created'],
                'rawJSON': json.dumps(alert)
            }
            incidents.append(incident)
    next_run = {'last_fetch': now}
    return next_run, incidents


def search_identities(id: str, email: str, risk: int, active: bool):
    """
    Search identities by search/filter parameters (id, email, risk & active) using IdentityIQ SCIM API's.
    Command: identityiq-search-identities

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
    if id is not None:
        url = ''.join((IIQ_SCIM_USERS_URL, '/', id))
    else:
        filter_string_prefix = '?filter='
        filter_list = []
        if email is not None:
            filter_list.append(''.join(('emails.value eq "', email, '"')))
        if risk is not None:
            filter_list.append(''.join(('urn:ietf:params:scim:schemas:sailpoint:1.0:User:riskScore ge ', str(risk))))
        if active is not None:
            filter_list.append(''.join(('active eq ', str(active).lower())))
        if filter_list is not None and len(filter_list) > 0:
            filter_string_suffix = ' and '.join(filter_list)
            filter_string = filter_string_prefix + filter_string_suffix
            url = ''.join((IIQ_SCIM_USERS_URL, filter_string))
        else:
            url = IIQ_SCIM_USERS_URL
    return send_request(url, "GET", None)


def get_policy_violations(id: str):
    """
    Get policy violation by id or all policy violations using IdentityIQ SCIM API's.
    Command: identityiq-get-policyviolations

    :type id: ``str``
    :param id: Internal Id of the policy violation being requested.

    :return: Policy violation object (JSON) corresponding to the id or list of policy violation objects if id was None.
    """
    if id is not None:
        url = ''.join((IIQ_SCIM_POLICY_VIOLATIONS_URL, '/', id))
    else:
        url = IIQ_SCIM_POLICY_VIOLATIONS_URL
    return send_request(url, "GET", None)


def get_task_results(id: str):
    """
    Get task result by id or all task results using IdentityIQ SCIM API's.
    Command: identityiq-get-taskresults

    :type id: ``str``
    :param id: Internal Id of the task result being requested.

    :return: Task result object (JSON) corresponding to the id or list of task result objects if id was None.
    """
    if id is not None:
        url = ''.join((IIQ_SCIM_TASK_RESULTS_URL, '/', id))
    else:
        url = IIQ_SCIM_TASK_RESULTS_URL
    return send_request(url, "GET", None)


def get_accounts(id: str, display_name: str, last_refresh: str, native_identity: str, last_target_agg: str,
                 identity_name: str, application_name: str):
    """
    Get accounts by search/filter parameters (id, display_name, last_refresh, native_identity,
    last_target_agg, identity_name & application_name) using IdentityIQ SCIM API's.
    Command: identityiq-get-accounts

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
    if id is not None:
        url = ''.join((IIQ_SCIM_ACCOUNTS_URL, '/', id))
    else:
        filter_string_prefix = '?filter='
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

        if filter_list is not None and len(filter_list) > 0:
            filter_string_suffix = ' and '.join(filter_list)
            filter_string = filter_string_prefix + filter_string_suffix
            url = ''.join((IIQ_SCIM_ACCOUNTS_URL, filter_string))
        else:
            url = IIQ_SCIM_ACCOUNTS_URL
    return send_request(url, "GET", None)


def change_account_status(id: str, status: bool):
    """
    Enable/disable account's active status by id using IdentityIQ SCIM API's.
    Command: identityiq-disable-account, identityiq-enable-account

    :type id: ``str``
    :param id: (str) Internal Id of the specific account to be enabled/disabled.

    :type status: ``bool``
    :param status: True (enable) or False (disable).

    :return: Account object with active flag changed (JSON). None if the request was unsuccessful.
    """
    if id is None or status is None or type(status) is not bool:
        return None

    # Get the user account (we need several fields to update as this is not a PATCH HTTP call).
    url = ''.join((IIQ_SCIM_ACCOUNTS_URL, '/', id))
    response = send_request(url, "GET", None)
    if response is not None and 200 <= response.status_code < 300:
        data = response.json()
        data['active'] = str(status).lower()
        return send_request(url, "PUT", json.dumps(data))
    else:
        return response.json()


def delete_account(id: str):
    """
    Delete account by id using IdentityIQ SCIM API's.
    Command: identityiq-delete-account

    :type id: ``str``
    :param id: Internal Id of the specific account to be deleted.

    :return: Empty HTTP 204 response. None if the request was unsuccessful.
    """
    if id is None:
        return None
    url = ''.join((IIQ_SCIM_ACCOUNTS_URL, '/', id))
    response = send_request(url, "DELETE", None)
    if response is not None and 200 <= response.status_code < 300:
        return 'Account deleted successfully!'
    else:
        if 'status' in response.json() and 'detail' in response.json():
            return ''.join((response.json()['status'], ' : ', response.json()['detail']))
        elif 'status' in response.json():
            return response.json()['status']


def get_launched_workflows(id: str):
    """
    Get launched workflow by id or all launched workflows using IdentityIQ SCIM API's.
    Command: identitytiq-get-launched-workflows

    :type id: ``str``
    :param id: Internal Id of the specific launched workflow being requested.

    :return: Launched workflow object (JSON) corresponding to the id or list of launched workflows objects if id was None.
    """
    if id is not None:
        url = ''.join((IIQ_SCIM_LAUNCHED_WORKFLOWS_URL, '/', id))
    else:
        url = IIQ_SCIM_LAUNCHED_WORKFLOWS_URL
    return send_request(url, "GET", None)


def get_roles(id: str):
    """
    Get role by id or all roles using IdentityIQ SCIM API's.
    Command: identityiq-get-roles

    :type id: ``str``
    :param id: Internal Id of the specific role being requested.

    :return: Role object (JSON) corresponding to the id or list of role objects if id was None.
    """
    if id is not None:
        url = ''.join((IIQ_SCIM_ROLES_URL, '/', id))
    else:
        url = IIQ_SCIM_ROLES_URL
    return send_request(url, "GET", None)


def get_entitlements(id: str):
    """
    Get entitlement by id or all entitlements using IdentityIQ SCIM API's.
    Command: identityiq-get-entitlements

    :type id: ``str``
    :param id: Internal Id of the specific entitlement being requested.

    :return: Entitlement object (JSON) corresponding to the id or list of entitlement objects if id was None.
    """
    if id is not None:
        url = ''.join((IIQ_SCIM_ENTITLEMENTS_URL, '/', id))
    else:
        url = IIQ_SCIM_ENTITLEMENTS_URL
    return send_request(url, "GET", None)


def get_alerts(id: str):
    """
    Get alert by id or all alerts using IdentityIQ SCIM API's.
    Command: identityiq-get-alerts

    :type id: ``str``
    :param id: Internal Id of the specific alert being requested.

    :return: Alert object (JSON) corresponding to the id or list of alert objects if id was None.
    """
    if id is not None:
        url = ''.join((IIQ_SCIM_ALERTS_URL, '/', id))
    else:
        url = IIQ_SCIM_ALERTS_URL
    return send_request(url, "GET", None)


def create_alert(display_name: str, attributes=None):
    """
    Create an alert using IdentityIQ SCIM API's.
    Command: identityiq-create-alert

    :type display_name: ``str``
    :param display_name: Display name of the alert.

    :type attributes: ``JSON``
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

    data = {
        'displayName': display_name,
        'type': 'PAN XSOAR',
        'attributes': attributes
    }
    return send_request(IIQ_SCIM_ALERTS_URL, "POST", json.dumps(data))


''' MAIN FUNCTION '''


def main():
    """
    Intercept and execute commands.
    """

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        results = None
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            results = test_connection()

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(demisto.getLastRun())
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'identityiq-search-identities':
            id = demisto.args().get('id', None)
            email = demisto.args().get('email', None)
            risk = demisto.args().get('risk', 0)
            active = demisto.args().get('active', True)
            response = search_identities(id, email, risk, active)
            results = build_results('IdentityIQ.Identity', 'id', response)

        elif demisto.command() == 'identityiq-get-policyviolations':
            id = demisto.args().get('id', None)
            response = get_policy_violations(id)
            results = build_results('IdentityIQ.PolicyViolation', 'policyName', response)

        elif demisto.command() == 'identityiq-get-taskresults':
            id = demisto.args().get('id', None)
            response = get_task_results(id)
            results = build_results('IdentityIQ.TaskResult', 'id', response)

        elif demisto.command() == 'identityiq-get-accounts':
            id = demisto.args().get('id', None)
            display_name = demisto.args().get('display_name', None)
            last_refresh = demisto.args().get('last_refresh', None)
            native_identity = demisto.args().get('native_identity', None)
            last_target_agg = demisto.args().get('last_target_agg')
            identity_name = demisto.args().get('identity_name', None)
            application_name = demisto.args().get('application_name', None)
            response = get_accounts(id, display_name, last_refresh, native_identity, last_target_agg, identity_name,
                                    application_name)
            results = build_results('IdentityIQ.Account', 'id', response)

        elif demisto.command() == 'identityiq-disable-account':
            id = demisto.args().get('id', None)
            response = change_account_status(id, False)
            results = build_results('IdentityIQ.Account', 'id', response)

        elif demisto.command() == 'identityiq-enable-account':
            id = demisto.args().get('id', None)
            response = change_account_status(id, True)
            results = build_results('IdentityIQ.Account', 'id', response)

        elif demisto.command() == 'identityiq-delete-account':
            id = demisto.args().get('id', None)
            results = delete_account(id)

        elif demisto.command() == 'identitytiq-get-launched-workflows':
            id = demisto.args().get('id', None)
            response = get_launched_workflows(id)
            results = build_results('IdentityIQ.Workflow', 'id', response)

        elif demisto.command() == 'identityiq-get-roles':
            id = demisto.args().get('id', None)
            response = get_roles(id)
            results = build_results('IdentityIQ.Role', 'name', response)

        elif demisto.command() == 'identityiq-get-entitlements':
            id = demisto.args().get('id', None)
            response = get_entitlements(id)
            results = build_results('IdentityIQ.Entitlement', 'id', response)

        elif demisto.command() == 'identityiq-get-alerts':
            id = demisto.args().get('id', None)
            response = get_alerts(id)
            results = build_results('IdentityIQ.Alert', 'id', response)

        elif demisto.command() == 'identityiq-create-alert':
            display_name = demisto.args().get('display_name', None)
            attribute = demisto.args().get('attribute', None)
            response = create_alert(display_name, attribute)
            results = build_results('IdentityIQ.Alert', 'id', response)

        return_results(results)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

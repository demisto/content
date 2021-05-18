from CommonServerPython import *

''' IMPORTS '''

import traceback

import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

# IdentityNow OAuth token endpoint
IDN_OAUTH_EXT = '/oauth/token'
IDN_SEARCH_PREFIX = '/beta/search'

# Resource endpoints
IDN_SEARCH_IDENTITIES_EXT = f'{IDN_SEARCH_PREFIX}/identities'
IDN_BETA_ACCOUNTS_EXT = '/beta/accounts'
IDN_SEARCH_ACCESS_PROFILES_EXT = f'{IDN_SEARCH_PREFIX}/accessprofiles'
IDN_SEARCH_ROLES_EXT = f'{IDN_SEARCH_PREFIX}/roles'
IDN_SEARCH_ENTITLEMENTS_EXT = f'{IDN_SEARCH_PREFIX}/entitlements'
IDN_SEARCH_EVENTS_EXT = f'{IDN_SEARCH_PREFIX}/events'
IDN_BETA_ACCOUNT_ACTIVITIES_EXT = '/beta/account-activities'
IDN_BETA_ACCESS_REQUEST_EXT = '/beta/access-requests'

# Other constants
# Using beta account API for accounts
SEARCHABLE_TYPE_LIST = ['identities', 'accessprofiles', 'roles', 'entitlements', 'events']
MAX_INCIDENTS_TO_FETCH = 250
MAX_LIMIT = 250
OFFSET_DEFAULT = '0'
LIMIT_DEFAULT = '250'
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
        Perform a HTTP request to IdentityNow API.

        :type url_suffix: ``str``
        :param url_suffix: IdentityNow API endpoint ext suffix.

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
                                  timeout=self.request_timeout, resp_type='response')


''' HELPER/UTILITY FUNCTIONS '''


def get_headers(base_url: str, client_id: str, client_secret: str, grant_type: str):
    """
    Create header with OAuth 2.0 authentication information.

    :type base_url: ``str``
    :param base_url: Base URL of the IdentityNow tenant.

    :type client_id: ``str``
    :param client_id: Client Id for OAuth 2.0.

    :type client_secret: ``str``
    :param client_secret: Client Secret for OAuth 2.0.

    :type grant_type: ``str``
    :param grant_type: Grant Type for OAuth 2.0. Defaulted to 'client_credentials' if not provided.

    :return: Header with OAuth 2.0 information if client_id & client_secret are provided, else ConnectionError(message).
    This will return ConnectionError(message) if the client_id & client_secret were not valid (authorized).
    """
    if base_url is None or client_id is None or client_secret is None:
        return None

    if grant_type is None:
        grant_type = 'client_credentials'

    params = {
        'grant_type': grant_type,
        'client_id': client_id,
        'client_secret': client_secret
    }
    oauth_response = requests.request("POST", url=f'{base_url}{IDN_OAUTH_EXT}', params=params)
    if oauth_response is not None and 200 <= oauth_response.status_code < 300:
        return {
            'Authorization': 'Bearer %s' % oauth_response.json().get('access_token', None),
            'Content-Type': 'application/json'
        }
    elif oauth_response.json().get('error_description') is not None:
        raise ConnectionError(oauth_response.json().get('error_description'))
    else:
        raise ConnectionError('Unable to fetch headers from IdentityNow!')


def build_query_object(object_type: str, query: str):
    """
    Build query object for IdentityNow Search Engine.

    :type object_type: ``str``
    :param object_type: Type of object (Identity, AccessProfile, Account, Role, Entitlement, Event)

    :type query: ``str``
    :param query: Elastic search query for the IdentityNow Search Engine.

    :return: JSON object that contains the elastic search query.
    """
    if object_type is None or object_type not in SEARCHABLE_TYPE_LIST:
        return None

    if query is None:
        return None

    return {
        "indices": [object_type],
        "query": {
            "query": query
        }
    }


def get_markdown(object_type: str, objects=None):
    """
    Getting markdown for object type to display the results in human readable format.

    :type object_type: ``str``
    :param object_type: Type of IdentityNow object.

    :type objects: ``dict`` or ``list``
    :param objects: Single or list of Identity resources object/s.

    :return: Markdown for each object type.
    """
    markdown = ''
    if object_type == 'IdentityNow.Identity':
        headers = ['id', 'name', 'displayName', 'firstName', 'lastName', 'email', 'created', 'modified', 'inactive',
                   'protected', 'status', 'isManager', 'identityProfile', 'source', 'attributes', 'accounts',
                   'accountCount', 'appCount', 'accessCount', 'entitlementCount', 'roleCount', 'accessProfileCount',
                   'pod', 'org', 'type']
        markdown = tableToMarkdown('Identity(Identities)', objects, headers=headers, removeNull=True)
    elif object_type == 'IdentityNow.Account':
        headers = ['id', 'name', 'identityId', 'nativeIdentity', 'sourceId', 'created', 'modified',
                   'attributes', 'authoritative', 'disabled', 'locked', 'systemAccount', 'uncorrelated',
                   'manuallyCorrelated', 'hasEntitlements']
        markdown = tableToMarkdown('Account(s)', objects, headers=headers, removeNull=True)
    elif object_type == 'IdentityNow.AccountActivity':
        headers = ['id', 'name', 'created', 'modified', 'completed', 'completionStatus', 'type',
                   'requesterIdentitySummary', 'targetIdentitySummary', 'items', 'executionStatus', 'cancelable',
                   'cancelComment']
        markdown = tableToMarkdown('Account Activity(Account Activities)', objects, headers=headers, removeNull=True)
    elif object_type == 'IdentityNow.AccessProfile':
        headers = ['id', 'name', 'description', 'source', 'entitlements', 'entitlementCount', 'created', 'modified',
                   'synced', 'enabled', 'requestable', 'requestCommentsRequired', 'owner', 'pod', 'org', 'type']
        markdown = tableToMarkdown('Access Profile(s)', objects, headers=headers, removeNull=True)
    elif object_type == 'IdentityNow.Role':
        headers = ['id', 'name', 'description', 'accessProfiles', 'accessProfileCount', 'created', 'modified', 'synced',
                   'enabled', 'requestable', 'requestCommentsRequired', 'owner', 'pod', 'org', 'type']
        markdown = tableToMarkdown('Role(s)', objects, headers=headers, removeNull=True)
    elif object_type == 'IdentityNow.Entitlement':
        headers = ['id', 'name', 'displayName', 'description', 'modified', 'synced', 'source', 'privileged',
                   'identityCount', 'attribute', 'value', 'schema', 'pod', 'org', 'type']
        markdown = tableToMarkdown('Entitlement(s)', objects, headers=headers, removeNull=True)
    elif object_type == 'IdentityNow.Event':
        headers = ['id', 'name', 'stack', 'created', 'synced', 'objects', 'ipAddress', 'technicalName', 'target',
                   'actor', 'action', 'attributes', 'operation', 'status', 'pod', 'org', 'type']
        markdown = tableToMarkdown('Event(s)', objects, headers=headers, removeNull=True)
    return markdown


def build_results(prefix: str, key_field: str, response=None):
    """
    Build results.

    :type prefix: ``str``
    :param prefix: Prefix for CommandResults as part of the results.

    :type key_field: ``str``
    :param key_field: Key field for CommandResults as part of the results.

    :type response: ``response``
    :param response: Response object from IdentityNow API call.

    :return: CommandResults in case of a successful response else message describing the error status.
    """
    if response is not None and 200 <= response.status_code < 300:
        if isinstance(response.json(), list):
            markdown = '### Results:\nTotal: ' + str(len(response.json())) + '\n'
        else:
            markdown = '### Results:\n'
        markdown += get_markdown(prefix, response.json())
        return CommandResults(
            readable_output=markdown,
            outputs_prefix=prefix,
            outputs_key_field=key_field,
            outputs=response.json()
        )
    else:
        return None


''' COMMAND FUNCTIONS '''


def test_connection(base_url: str, client_id: str, client_secret: str, grant_type: str):
    """
    Test connectivity to IdentityNow

    :type base_url: ``str``
    :param base_url: Base URL of the IdentityNow tenant.

    :type client_id: ``str``
    :param client_id: Client Id for OAuth 2.0.

    :type client_secret: ``str``
    :param client_secret: Client Secret for OAuth 2.0.

    :type grant_type: ``str``
    :param grant_type: Grant Type for OAuth 2.0. Defaulted to 'client_credentials' if not provided.

    :return: HTTP connectivity status for test connection.
    """
    try:
        get_headers(base_url, client_id, client_secret, grant_type)
        return 'ok'
    except ConnectionError as error:
        return f'Error Connecting : {error}'


def search(client: Client, object_type: str, query: str, offset: int, limit: int):
    """
    Search object type using elastic search query for IdentityNow Search Engine.
    Command(s): identitynow-search-identities, identitynow-search-accessprofiles, identitynow-search-roles,
    identitynow-search-entitlements, identitynow-search-events

    :type client: ``Client``
    :param client: SailPoint client

    :type object_type: ``str``
    :param object_type: Type of object(Identity, AccessProfile, Role, Entitlement, Event)

    :type query: ``str``
    :param query: The query using the Elasticsearch Query (String Query) syntax from the Query DSL extended by SailPoint
    to support Nested queries.

    :type offset: ``int``
    :param offset: Offset into the full result set. Usually specified with limit to paginate through the results.

    :type limit: ``int``
    :param limit: Max number of results to return. Maximum of 250.

    :return: IdentityNow object (JSON) corresponding to the elastic search query. Empty JSON if the event was not found
    in IdentityNow.
    """
    if object_type is None or object_type not in SEARCHABLE_TYPE_LIST:
        return None

    if query is None:
        return None

    if not offset or offset < 0:
        offset = 0

    if not limit or limit > MAX_LIMIT:
        limit = MAX_LIMIT

    params = {'offset': offset, 'limit': limit}
    url = IDN_SEARCH_PREFIX
    if object_type == 'IdentityNow.Identity':
        url = IDN_SEARCH_IDENTITIES_EXT
    elif object_type == 'IdentityNow.AccessProfile':
        url = IDN_SEARCH_ACCESS_PROFILES_EXT
    elif object_type == 'IdentityNow.Role':
        url = IDN_SEARCH_ROLES_EXT
    elif object_type == 'IdentityNow.Entitlement':
        url = IDN_SEARCH_ENTITLEMENTS_EXT
    elif object_type == 'IdentityNow.Event':
        url = IDN_SEARCH_EVENTS_EXT
    return client.send_request(url, "POST", params, build_query_object(object_type, query))


def get_accounts(client: Client, id: str, name: str, native_identity: int, offset: int, limit: int):
    """
    Get accounts by search/filter parameters (id, name, native_identity).
    Command(s): identitynow-get-accounts

    :type client: ``Client``
    :param client: SailPoint client

    :type id: ``str``
    :param id: Account Id of the user/identity.

    :type name: ``str``
    :param name: Name of the user/identity on the account.

    :type native_identity: ``str``
    :param native_identity: Native identity for the user account.

    :type offset: ``int``
    :param offset: Offset into the full result set. Usually specified with limit to paginate through the results.

    :type limit: ``int``
    :param limit: Max number of results to return. Maximum of 250.

    :return: Account object (JSON) corresponding to the filter parameters. Empty JSON if the event was not found in
    IdentityNow.
    """
    if not offset or offset < 0:
        offset = 0

    if not limit or limit > MAX_LIMIT:
        limit = MAX_LIMIT

    params = {'offset': offset, 'limit': limit}
    if id is not None:
        url = ''.join((IDN_BETA_ACCOUNTS_EXT, '/', id))
    else:
        url = IDN_BETA_ACCOUNTS_EXT
        filter_list = []
        if name is not None:
            filter_list.append(''.join(('name eq "', name, '"')))
        if native_identity is not None:
            filter_list.append(''.join(('nativeIdentity eq "', native_identity, '"')))
        # Combine the filters
        if filter_list is not None and len(filter_list) > 0:
            filter_string = ' and '.join(filter_list)
            params.update({'filters': filter_string})
    return client.send_request(url, "GET", params, None)


def get_account_activities(client: Client, id: str, requested_for: str, requested_by: str, regarding_identity: str,
                           type: str, offset: int, limit: int):
    """
    Get account activities by search/filter parameters (requested_for, requested_by, regarding_identity, type).
    Command(s): identitynow-get-accountactivities

    :type client: ``Client``
    :param client: SailPoint client

    :type id: ``str``
    :param id: Account activity Id.

    :type requested_for: ``str``
    :param requested_for: The identity that the activity was requested for (me indicates current user).

    :type requested_by: ``str``
    :param requested_by: The identity that requested the activity (me indicates current user).

    :type regarding_identity: ``str``
    :param regarding_identity: The specified identity will be either requester or target of account activity (me
    indicates current user).

    :type type: ``str``
    :param type: Type of account activity.

    :type offset: ``int``
    :param offset: Offset into the full result set. Usually specified with limit to paginate through the results.

    :type limit: ``int``
    :param limit: Max number of results to return. Maximum of 250.

    :return: Account object (JSON) corresponding to the filter parameters. Empty JSON if the event was not found in
    IdentityNow.
    """
    if not offset or offset < 0:
        offset = 0

    if not limit or limit > MAX_LIMIT:
        limit = MAX_LIMIT

    params = {'offset': offset, 'limit': limit}
    if id is not None:
        url = ''.join((IDN_BETA_ACCOUNT_ACTIVITIES_EXT, '/', id))
    else:
        url = IDN_BETA_ACCOUNT_ACTIVITIES_EXT
        if requested_for is not None:
            params.update({'requested-for': requested_for})
        if requested_by is not None:
            params.update({'requested-by': requested_by})
        if regarding_identity is not None:
            params.update({'regarding-identity': regarding_identity})
        if type is not None:
            params.update({'filters': ''.join(('type eq "', type, '"'))})
    return client.send_request(url, "GET", params, None)


def access_request_bulk(client: Client, request_type: str, requested_for=None, requested_items=None):
    """
    Grant or revoke access request for a list of objects(access profiles or roles) for a list of users.
    Command(s): identitynow-request-grant, identitynow-request-revoke

    :type client: ``Client``
    :param client: SailPoint client

    :type request_type: ``str``
    :param request_type: Type of access request(GRANT_ACCESS or REVOKE_ACCESS).

    :type requested_for: ``list``
    :param requested_for: List of Identity Id's.

    :type requested_items: ``list``
    :param requested_items: List of objects(access profiles or roles).

    :return: Success or failure status.
    """
    if request_type is None or requested_for is None or requested_items is None:
        return None

    json_data = {
        "requestedFor": requested_for,
        "requestType": request_type,
        "requestedItems": requested_items,
        "clientMetadata": {}
    }
    response = client.send_request(IDN_BETA_ACCESS_REQUEST_EXT, "POST", None, json_data)
    if response is not None and 200 <= response.status_code < 300:
        return 'Access request was successful!'
    elif 'detailCode' in response.json():
        return response.json()
    return None


def access_request(client: Client, request_type: str, requested_for: str, requested_item: str, requested_item_type: str,
                   comment: str):
    """
    Grant or revoke access request for a single object(access profile or role) for a single user.
    Command(s): identitynow-request-grant, identitynow-request-revoke

    :type client: ``Client``
    :param client: SailPoint client

    :type request_type: ``str``
    :param request_type: Type of access request(GRANT_ACCESS or REVOKE_ACCESS).

    :type requested_for: ``str``
    :param requested_for: Identity Id for whom the access request is being made.

    :type requested_item: ``str``
    :param requested_item: Id of the object(access profile or role).

    :type requested_item_type: ``str``
    :param requested_item_type: Type of object(ACCESS_PROFILE or ROLE).

    :type comment: ``str``
    :param comment: Comments to attach to the item request.

    :return: Success or failure status.
    """
    if request_type is None or requested_for is None or requested_item is None or requested_item_type is None:
        return None

    json_data = {
        "requestedFor": [requested_for],
        "requestType": request_type,
        "requestedItems": [
            {
                "type": requested_item_type,
                "id": requested_item,
                "comment": comment
            }
        ],
        "clientMetadata": {}
    }
    response = client.send_request(IDN_BETA_ACCESS_REQUEST_EXT, "POST", None, json_data)
    if response is not None and 200 <= response.status_code < 300:
        return 'Access request was successful!'
    elif 'detailCode' in response.json():
        return response.json()
    return None


''' MAIN FUNCTION '''


def main():
    """
    Intercept and execute commands.
    """

    params = demisto.params()
    # IdentityNow API Base URL (https://org.api.identitynow.com)
    base_url = params.get('identitynow_url')

    # OAuth 2.0 Credentials
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')
    grant_type = 'client_credentials'

    # Other configs
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    request_timeout = 10

    headers = {}
    try:
        headers = get_headers(base_url, client_id, client_secret, grant_type)
    except ConnectionError as error:
        demisto.error(f'Error getting header : {error}')
        return_error(f'Error getting header : {error}')

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
        max_results=MAX_INCIDENTS_TO_FETCH,
        request_timeout=request_timeout)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        args = demisto.args()
        results = None
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            results = test_connection(base_url, client_id, client_secret, grant_type)

        elif command == 'identitynow-search-identities':
            query = args.get('query', None)
            offset = int(args.get('offset', OFFSET_DEFAULT))
            limit = int(args.get('limit', LIMIT_DEFAULT))
            response = search(client, 'identities', query, offset, limit)
            results = build_results('IdentityNow.Identity', 'id', response)

        elif command == 'identitynow-get-accounts':
            id = args.get('id', None)
            name = args.get('name', None)
            native_identity = args.get('native_identity', None)
            offset = int(args.get('offset', OFFSET_DEFAULT))
            limit = int(args.get('limit', LIMIT_DEFAULT))
            response = get_accounts(client, id, name, native_identity, offset, limit)
            results = build_results('IdentityNow.Account', 'id', response)

        elif command == 'identitynow-get-accountactivities':
            id = args.get('id', None)
            requested_for = args.get('requested_for', None)
            requested_by = args.get('requested_by', None)
            regarding_identity = args.get('regarding_identity', None)
            type = args.get('type', None)
            offset = int(args.get('offset', OFFSET_DEFAULT))
            limit = int(args.get('limit', LIMIT_DEFAULT))
            response = get_account_activities(client, id, requested_for, requested_by, regarding_identity, type, offset,
                                              limit)
            results = build_results('IdentityNow.AccountActivity', 'id', response)

        elif command == 'identitynow-search-accessprofiles':
            query = args.get('query', None)
            offset = int(args.get('offset', OFFSET_DEFAULT))
            limit = int(args.get('limit', LIMIT_DEFAULT))
            response = search(client, 'accessprofiles', query, offset, limit)
            results = build_results('IdentityNow.AccessProfile', 'id', response)

        elif command == 'identitynow-search-roles':
            query = args.get('query', None)
            offset = int(args.get('offset', OFFSET_DEFAULT))
            limit = int(args.get('limit', LIMIT_DEFAULT))
            response = search(client, 'roles', query, offset, limit)
            results = build_results('IdentityNow.Role', 'id', response)

        elif command == 'identitynow-search-entitlements':
            query = args.get('query', None)
            offset = int(args.get('offset', OFFSET_DEFAULT))
            limit = int(args.get('limit', LIMIT_DEFAULT))
            response = search(client, 'entitlements', query, offset, limit)
            results = build_results('IdentityNow.Entitlement', 'id', response)

        elif command == 'identitynow-search-events':
            query = args.get('query', None)
            offset = int(args.get('offset', OFFSET_DEFAULT))
            limit = int(args.get('limit', LIMIT_DEFAULT))
            response = search(client, 'events', query, offset, limit)
            results = build_results('IdentityNow.Event', 'id', response)

        elif command == 'identitynow-request-grant':
            requested_for = args.get('requested_for', None)
            requested_item = args.get('requested_item', None)
            requested_item_type = args.get('requested_item_type', None)
            comment = args.get('comment', None)
            results = access_request(client, "GRANT_ACCESS", requested_for, requested_item, requested_item_type,
                                     comment)

        elif command == 'identitynow-request-revoke':
            requested_for = args.get('requested_for', None)
            requested_item = args.get('requested_item', None)
            requested_item_type = args.get('requested_item_type', None)
            comment = args.get('comment', None)
            results = access_request(client, "REVOKE_ACCESS", requested_for, requested_item, requested_item_type,
                                     comment)

        return_results(results)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

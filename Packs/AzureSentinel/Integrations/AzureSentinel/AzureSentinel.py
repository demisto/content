import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
# IMPORTS

import json
import requests
import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''

APP_NAME = 'ms-azure-sentinel'

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

API_VERSION = '2019-01-01-preview'

NEXTLINK_DESCRIPTION = 'NextLink for listing commands'

AUTHORIZATION_ERROR_MSG = 'There was a problem in retrieving an updated access token.\n'\
                          'The response from the server did not contain the expected content.'

INCIDENT_HEADERS = ['ID', 'IncidentNumber', 'Title', 'Description', 'Severity', 'Status', 'AssigneeName',
                    'AssigneeEmail', 'Labels', 'FirstActivityTimeUTC', 'LastActivityTimeUTC', 'LastModifiedTimeUTC',
                    'CreatedTimeUTC', 'AlertsCount', 'BookmarksCount', 'CommentsCount', 'AlertProductNames',
                    'Tactics', 'FirstActivityTimeGenerated', 'LastActivityTimeGenerated', 'Etag']

COMMENT_HEADERS = ['ID', 'IncidentID', 'Message', 'AuthorName', 'AuthorEmail', 'CreatedTimeUTC']

ENTITIES_RETENTION_PERIOD_MESSAGE = '\nNotice that in the current Azure Sentinel API version, the retention period ' \
                                    'for GetEntityByID is 30 days.'


class Client:
    def __init__(self, self_deployed, refresh_token, auth_and_token_url, enc_key, redirect_uri, auth_code,
                 subscription_id, resource_group_name, workspace_name, verify, proxy):

        tenant_id = refresh_token if self_deployed else ''
        refresh_token = (demisto.getIntegrationContext().get('current_refresh_token') or refresh_token)
        base_url = f'https://management.azure.com/subscriptions/{subscription_id}/' \
            f'resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/' \
            f'{workspace_name}/providers/Microsoft.SecurityInsights'
        self.ms_client = MicrosoftClient(
            self_deployed=self_deployed,
            auth_id=auth_and_token_url,
            refresh_token=refresh_token,
            enc_key=enc_key,
            redirect_uri=redirect_uri,
            token_retrieval_url='https://login.microsoftonline.com/{tenant_id}/oauth2/token',
            grant_type=AUTHORIZATION_CODE,  # disable-secrets-detection
            app_name=APP_NAME,
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            resource='https://management.core.windows.net',
            scope='',
            tenant_id=tenant_id,
            auth_code=auth_code,
            ok_codes=(200, 201, 202, 204, 400, 401, 403, 404)
        )

    def http_request(self, method, url_suffix=None, full_url=None, params=None, data=None, is_get_entity_cmd=False):
        if not params:
            params = {}
        if not full_url:
            params['api-version'] = API_VERSION

        res = self.ms_client.http_request(method=method,  # disable-secrets-detection
                                          url_suffix=url_suffix,
                                          full_url=full_url,
                                          json_data=data,
                                          params=params,
                                          resp_type='response')
        res_json = res.json()

        if res.status_code in (400, 401, 403, 404):
            code = res_json.get('error', {}).get('code', 'Error')
            error_msg = res_json.get('error', {}).get('message', res_json)
            if res.status_code == 404 and is_get_entity_cmd:
                error_msg += ENTITIES_RETENTION_PERIOD_MESSAGE
            raise ValueError(
                f'[{code} {res.status_code}] {error_msg}'
            )

        return res_json


''' INTEGRATION HELPER METHODS '''


def format_date(date):
    if not date:
        return None
    return dateparser.parse(date).strftime(DATE_FORMAT)


def incident_data_to_demisto_format(inc_data):
    properties = inc_data.get('properties', {})

    formatted_data = {
        'ID': inc_data.get('name'),
        'IncidentNumber': properties.get('incidentNumber'),
        'Title': properties.get('title'),
        'Description': properties.get('description'),
        'Severity': properties.get('severity'),
        'Status': properties.get('status'),
        'AssigneeName': properties.get('owner', {}).get('assignedTo'),
        'AssigneeEmail': properties.get('owner', {}).get('email'),
        'Label': [{
            'Name': label.get('name'),
            'Type': label.get('type')
        } for label in properties.get('labels', [])],
        'FirstActivityTimeUTC': format_date(properties.get('firstActivityTimeUtc')),
        'LastActivityTimeUTC': format_date(properties.get('lastActivityTimeUtc')),
        'LastModifiedTimeUTC': format_date(properties.get('lastModifiedTimeUtc')),
        'CreatedTimeUTC': format_date(properties.get('createdTimeUtc')),
        'AlertsCount': properties.get('additionalData', {}).get('alertsCount'),
        'BookmarksCount': properties.get('additionalData', {}).get('bookmarksCount'),
        'CommentsCount': properties.get('additionalData', {}).get('commentsCount'),
        'AlertProductNames': properties.get('additionalData', {}).get('alertProductNames'),
        'Tactics': properties.get('tactics'),
        'FirstActivityTimeGenerated': format_date(properties.get('firstActivityTimeGenerated')),
        'LastActivityTimeGenerated': format_date(properties.get('lastActivityTimeGenerated')),
        'Etag': inc_data.get('etag'),
        'Deleted': False
    }
    return formatted_data


def get_update_incident_request_data(client, args):
    # Get Etag and other mandatory properties (title, severity, status) for update_incident command
    _, _, result = get_incident_by_id_command(client, args)

    title = args.get('title')
    description = args.get('description')
    severity = args.get('severity')
    status = args.get('status')

    if not title:
        title = result.get('properties', {}).get('title')
    if not description:
        description = result.get('properties', {}).get('description')
    if not severity:
        severity = result.get('properties', {}).get('severity')
    if not status:
        status = result.get('properties', {}).get('status')

    inc_data = {
        'etag': result.get('etag'),
        'properties': {
            'title': title,
            'description': description,
            'severity': severity,
            'status': status
        }
    }
    remove_nulls_from_dictionary(inc_data['properties'])

    return inc_data


def comment_data_to_demisto_format(comment_data, inc_id):
    properties = comment_data.get('properties', {})

    formatted_data = {
        'ID': comment_data.get('name'),
        'IncidentID': inc_id,
        'Message': properties.get('message'),
        'AuthorName': properties.get('author', {}).get('assignedTo'),
        'AuthorEmail': properties.get('author', {}).get('email'),
        'CreatedTimeUTC': format_date(properties.get('createdTimeUtc'))
    }
    return formatted_data


def incident_related_resource_data_to_demisto_format(resource_data, incident_id):
    properties = resource_data.get('properties', {})

    formatted_data = {
        'ID': properties.get('relatedResourceName'),
        'Kind': properties.get('relatedResourceKind'),
        'IncidentID': incident_id
    }
    return formatted_data


def entity_related_resource_data_to_demisto_format(resource_data, entity_id):
    properties = resource_data.get('properties', {})

    formatted_data = {
        'ID': properties.get('relatedResourceName'),
        'Kind': properties.get('relatedResourceKind'),
        'EntityID': entity_id
    }
    return formatted_data


def flatten_entity_attributes(attributes):
    # This method flattens a GET entity response json.
    flattened_results = attributes.get('properties', {})
    flattened_results['ID'] = attributes.get('name')
    flattened_results['Kind'] = attributes.get('kind')
    return flattened_results


def severity_to_level(severity):
    if severity == 'Informational':
        return 0.5
    elif severity == 'Low':
        return 1
    elif severity == 'Medium':
        return 2
    elif severity == 'High':
        return 3
    return 0


''' INTEGRATION COMMANDS '''


def test_connection(client, params):
    if params.get('self_deployed', False) and not params.get('auth_code'):
        return_error('You must enter an authorization code in a self-deployed configuration.')
    client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    return_outputs('```✅ Success!```')


def get_incident_by_id_command(client, args):
    inc_id = args.get('incident_id')
    url_suffix = f'incidents/{inc_id}'

    result = client.http_request('GET', url_suffix)
    incident = incident_data_to_demisto_format(result)

    outputs = {'AzureSentinel.Incident(val.ID === obj.ID)': incident}

    readable_output = tableToMarkdown(f'Incident {inc_id} details', incident,
                                      headers=INCIDENT_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def list_incidents_command(client, args, is_fetch_incidents=False):
    filter_expression = args.get('filter')
    limit = None if is_fetch_incidents else min(50, int(args.get('limit')))
    next_link = args.get('next_link', '')

    if next_link:
        next_link = next_link.replace('%20', ' ')  # OData syntax can't handle '%' character
        result = client.http_request('GET', full_url=next_link)
    else:
        url_suffix = 'incidents'
        params = {
            '$top': limit,
            '$filter': filter_expression,
            '$orderby': 'properties/createdTimeUtc asc'
        }
        remove_nulls_from_dictionary(params)

        result = client.http_request('GET', url_suffix, params=params)

    incidents = [incident_data_to_demisto_format(inc) for inc in result.get('value')]

    if is_fetch_incidents:
        return None, incidents, {}

    outputs = {'AzureSentinel.Incident(val.ID === obj.ID)': incidents}

    # we don't want whitespaces in this value, so it won't be considered as two arguments in the CLI by mistake
    next_link = result.get('nextLink', '').replace(' ', '%20')
    if next_link:
        next_link_item = {
            'Description': NEXTLINK_DESCRIPTION,
            'URL': next_link
        }
        outputs[f'AzureSentinel.NextLink(val.Description == "{NEXTLINK_DESCRIPTION}")'] = next_link_item  # type: ignore

    readable_output = tableToMarkdown(f'Incidents List ({len(incidents)} results)', incidents,
                                      headers=INCIDENT_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def update_incident_command(client, args):
    inc_id = args.get('incident_id')

    inc_data = get_update_incident_request_data(client, args)

    url_suffix = f'incidents/{inc_id}'
    result = client.http_request('PUT', url_suffix, data=inc_data)
    incident = incident_data_to_demisto_format(result)

    outputs = {'AzureSentinel.Incident(val.ID === obj.ID)': incident}

    readable_output = tableToMarkdown(f'Updated incidents {inc_id} details', incident,
                                      headers=INCIDENT_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def delete_incident_command(client, args):
    inc_id = args.get('incident_id')
    url_suffix = f'incidents/{inc_id}'

    client.http_request('DELETE', url_suffix)

    context = {
        'ID': inc_id,
        'Deleted': True
    }
    outputs = {'AzureSentinel.Incident(val.ID === obj.ID)': context}
    return f'Incident {inc_id} was deleted successfully.', outputs, {}


def list_incident_comments_command(client, args):
    inc_id = args.get('incident_id')
    limit = min(50, int(args.get('limit')))
    next_link = args.get('next_link', '')

    if next_link:
        next_link = next_link.replace('%20', ' ')  # OData syntax can't handle '%' character
        result = client.http_request('GET', full_url=next_link)
    else:
        url_suffix = f'incidents/{inc_id}/comments'
        params = {'$top': limit}
        remove_nulls_from_dictionary(params)

        result = client.http_request('GET', url_suffix, params=params)

    comments = [comment_data_to_demisto_format(inc, inc_id) for inc in result.get('value')]

    outputs = {f'AzureSentinel.IncidentComment(val.ID === obj.ID && val.IncidentID === {inc_id})': comments}

    # we don't want whitespaces in this value, so it won't be considered as two arguments in the CLI by mistake
    next_link = result.get('nextLink', '').replace(' ', '%20')
    if next_link:
        next_link_item = {
            'Description': NEXTLINK_DESCRIPTION,
            'URL': next_link
        }
        outputs[f'AzureSentinel.NextLink(val.Description == "{NEXTLINK_DESCRIPTION}")'] = next_link_item  # type: ignore

    readable_output = tableToMarkdown(f'Incident {inc_id} Comments ({len(comments)} results)', comments,
                                      headers=COMMENT_HEADERS,  # disable-secrets-detection
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def incident_add_comment_command(client, args):
    import random

    inc_id = args.get('incident_id')
    url_suffix = f'incidents/{inc_id}/comments/{str(random.getrandbits(128))}'
    comment_data = {
        'properties': {
            'message': args.get('message')
        }
    }

    result = client.http_request('PUT', url_suffix, data=comment_data)
    comment = comment_data_to_demisto_format(result, inc_id)

    outputs = {
        f'AzureSentinel.IncidentComment(val.ID === obj.ID && val.IncidentID === {inc_id})': comment
    }

    readable_output = tableToMarkdown(f'Incident {inc_id} new comment details', comment,
                                      headers=COMMENT_HEADERS,  # disable-secrets-detection
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def get_entity_by_id_command(client, args):
    entity_id = args.get('entity_id')
    url_suffix = f'entities/{entity_id}'

    result = client.http_request('GET', url_suffix, is_get_entity_cmd=True)

    flattened_result = flatten_entity_attributes(result)

    readable_output = tableToMarkdown(f'Entity {entity_id} details',
                                      flattened_result,
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    outputs = {
        'AzureSentinel.Entity(val.ID === obj.ID)': flattened_result
    }

    return (
        readable_output,
        outputs,
        result
    )


def list_entity_relations_command(client, args):
    entity_id = args.get('entity_id')
    limit = min(50, int(args.get('limit')))
    next_link = args.get('next_link', '')
    entity_kinds = args.get('entity_kinds')
    filter_expression = args.get('filter', '')

    if next_link:
        next_link = next_link.replace('%20', ' ')  # OData syntax can't handle '%' character
        result = client.http_request('GET', full_url=next_link)
    else:
        # Handle entity kinds to filter by
        if entity_kinds:
            if filter_expression:
                filter_expression += ' and '
            filter_expression += f"search.in(properties/relatedResourceKind, '{entity_kinds}', ',')"

        url_suffix = f'entities/{entity_id}/relations'
        params = {
            '$top': limit,
            '$filter': filter_expression
        }
        remove_nulls_from_dictionary(params)

        result = client.http_request('GET', url_suffix, params=params)

    relations = [
        entity_related_resource_data_to_demisto_format(resource, entity_id) for resource in result.get('value')
    ]

    outputs = {f'AzureSentinel.EntityRelatedResource(val.ID === obj.ID && val.EntityID == {entity_id})': relations}

    # we don't want whitespaces in this value, so it won't be considered as two arguments in the CLI by mistake
    next_link = result.get('nextLink', '').replace(' ', '%20')
    if next_link:
        next_link_item = {
            'Description': NEXTLINK_DESCRIPTION,
            'URL': next_link
        }
        outputs[f'AzureSentinel.NextLink(val.Description == "{NEXTLINK_DESCRIPTION}")'] = next_link_item  # type: ignore

    readable_output = tableToMarkdown(f'Entity {entity_id} Relations ({len(relations)} results)', relations,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def list_incident_relations_command(client, args):
    inc_id = args.get('incident_id')
    limit = min(50, int(args.get('limit')))
    next_link = args.get('next_link', '')
    entity_kinds = args.get('entity_kinds')
    filter_expression = args.get('filter', '')

    if next_link:
        next_link = next_link.replace('%20', ' ')  # OData syntax can't handle '%' character
        result = client.http_request('GET', full_url=next_link)
    else:
        # Handle entity kinds to filter by
        if entity_kinds:
            if filter_expression:
                filter_expression += ' and '
            filter_expression += f"search.in(properties/relatedResourceKind, '{entity_kinds}', ',')"

        url_suffix = f'incidents/{inc_id}/relations'
        params = {
            '$top': limit,
            '$filter': filter_expression
        }
        remove_nulls_from_dictionary(params)

        result = client.http_request('GET', url_suffix, params=params)

    relations = [
        incident_related_resource_data_to_demisto_format(resource, inc_id) for resource in result.get('value')
    ]

    outputs = {f'AzureSentinel.IncidentRelatedResource(val.ID === obj.ID && val.IncidentID == {inc_id})': relations}

    # we don't want whitespaces in this value, so it won't be considered as two arguments in the CLI by mistake
    next_link = result.get('nextLink', '').replace(' ', '%20')
    if next_link:
        next_link_item = {
            'Description': NEXTLINK_DESCRIPTION,
            'URL': next_link
        }
        outputs[f'AzureSentinel.NextLink(val.Description == "{NEXTLINK_DESCRIPTION}")'] = next_link_item  # type: ignore

    readable_output = tableToMarkdown(f'Incident {inc_id} Relations ({len(relations)} results)', relations,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def fetch_incidents(client, last_run, first_fetch_time, min_severity):
    # Get the last fetch details, if exist
    last_fetch_time = last_run.get('last_fetch_time')
    last_fetch_ids = last_run.get('last_fetch_ids', [])

    # Handle first time fetch
    if last_fetch_time is None:
        last_fetch_time_str, _ = parse_date_range(first_fetch_time, DATE_FORMAT)
        last_fetch_time = dateparser.parse(last_fetch_time_str)
    else:
        last_fetch_time = dateparser.parse(last_fetch_time)

    latest_created_time = last_fetch_time
    latest_created_time_str = latest_created_time.strftime(DATE_FORMAT)
    command_args = {'filter': f'properties/createdTimeUtc ge {latest_created_time_str}'}
    _, items, _ = list_incidents_command(client, command_args, is_fetch_incidents=True)
    incidents = []
    current_fetch_ids = []

    for incident in items:
        incident_severity = severity_to_level(incident.get('Severity'))

        # fetch only incidents that weren't fetched in the last run and their severity is at least min_severity
        if incident.get('ID') not in last_fetch_ids and incident_severity >= min_severity:
            incident_created_time = dateparser.parse(incident.get('CreatedTimeUTC'))
            incident = {
                'name': '[Azure Sentinel] ' + incident.get('Title'),
                'occurred': incident.get('CreatedTimeUTC'),
                'severity': incident_severity,
                'rawJSON': json.dumps(incident)
            }

            incidents.append(incident)
            current_fetch_ids.append(incident.get('ID'))

            # Update last run to the latest fetch time
            if incident_created_time > latest_created_time:
                latest_created_time = incident_created_time

    next_run = {
        'last_fetch_time': latest_created_time.strftime(DATE_FORMAT),
        'last_fetch_ids': current_fetch_ids
    }
    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            self_deployed=params.get('self_deployed', False),
            auth_and_token_url=params.get('auth_id', ''),
            refresh_token=params.get('refresh_token', ''),
            enc_key=params.get('enc_key', ''),
            redirect_uri=params.get('redirect_uri', ''),
            auth_code=params.get('auth_code', ''),
            subscription_id=params.get('subscriptionID', ''),
            resource_group_name=params.get('resourceGroupName', ''),
            workspace_name=params.get('workspaceName', ''),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False)
        )

        commands = {
            'azure-sentinel-get-incident-by-id': get_incident_by_id_command,
            'azure-sentinel-list-incidents': list_incidents_command,
            'azure-sentinel-update-incident': update_incident_command,
            'azure-sentinel-delete-incident': delete_incident_command,
            'azure-sentinel-list-incident-comments': list_incident_comments_command,
            'azure-sentinel-incident-add-comment': incident_add_comment_command,
            'azure-sentinel-list-incident-relations': list_incident_relations_command,
            'azure-sentinel-get-entity-by-id': get_entity_by_id_command,
            'azure-sentinel-list-entity-relations': list_entity_relations_command
        }

        if demisto.command() == 'test-module':
            # cannot use test module due to the lack of ability to set refresh token to integration context
            raise Exception("Please use !azure-sentinel-test instead")

        elif demisto.command() == 'azure-sentinel-test':
            test_connection(client, params)

        elif demisto.command() == 'fetch-incidents':
            # How much time before the first fetch to retrieve incidents
            first_fetch_time = params.get('fetch_time', '3 days').strip()

            min_severity = severity_to_level(params.get('min_severity', 'Informational'))

            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                min_severity=min_severity
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() in commands:
            return_outputs(*commands[demisto.command()](client, demisto.args()))  # type: ignore

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


class MicrosoftClient(BaseClient):
    def __init__(self, tenant_id: str = '',
                 auth_id: str = '',
                 enc_key: str = '',
                 token_retrieval_url: str = 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
                 app_name: str = '',
                 refresh_token: str = '',
                 auth_code: str = '',
                 scope: str = 'https://graph.microsoft.com/.default',
                 grant_type: str = CLIENT_CREDENTIALS,
                 redirect_uri: str = 'https://localhost/myapp',
                 resource: Optional[str] = '',
                 multi_resource: bool = False,
                 resources: List[str] = None,
                 verify: bool = True,
                 self_deployed: bool = False,
                 *args, **kwargs):
        """
        Microsoft Client class that implements logic to authenticate with oproxy or self deployed applications.
        It also provides common logic to handle responses from Microsoft.
        Args:
            tenant_id: If self deployed it's the tenant for the app url, otherwise (oproxy) it's the token
            auth_id: If self deployed it's the client id, otherwise (oproxy) it's the auth id and may also
            contain the token url
            enc_key: If self deployed it's the client secret, otherwise (oproxy) it's the encryption key
            scope: The scope of the application (only if self deployed)
            resource: The resource of the application (only if self deployed)
            multi_resource: Where or not module uses a multiple resources (self-deployed, auth_code grant type only)
            resources: Resources of the application (for multi-resource mode)
            verify: Demisto insecure parameter
            self_deployed: Indicates whether the integration mode is self deployed or oproxy
        """
        super().__init__(verify=verify, *args, **kwargs)  # type: ignore[misc]
        if not self_deployed:
            auth_id_and_token_retrieval_url = auth_id.split('@')
            auth_id = auth_id_and_token_retrieval_url[0]
            if len(auth_id_and_token_retrieval_url) != 2:
                self.token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token'  # guardrails-disable-line
            else:
                self.token_retrieval_url = auth_id_and_token_retrieval_url[1]

            self.app_name = app_name
            self.auth_id = auth_id
            self.enc_key = enc_key
            self.tenant_id = tenant_id
            self.refresh_token = refresh_token

        else:
            self.token_retrieval_url = token_retrieval_url.format(tenant_id=tenant_id)
            self.client_id = auth_id
            self.client_secret = enc_key
            self.tenant_id = tenant_id
            self.auth_code = auth_code
            self.grant_type = grant_type
            self.resource = resource
            self.scope = scope
            self.redirect_uri = redirect_uri

        self.auth_type = SELF_DEPLOYED_AUTH_TYPE if self_deployed else OPROXY_AUTH_TYPE
        self.verify = verify

        self.multi_resource = multi_resource
        if self.multi_resource:
            self.resources = resources if resources else []
            self.resource_to_access_token: Dict[str, str] = {}

    def http_request(
            self, *args, resp_type='json', headers=None,
            return_empty_response=False, scope: Optional[str] = None,
            resource: str = '', **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Args:
            resp_type: Type of response to return. will be ignored if `return_empty_response` is True.
            headers: Headers to add to the request.
            return_empty_response: Return the response itself if the return_code is 206.
            scope: A scope to request. Currently will work only with self-deployed app.
        Returns:
            Response from api according to resp_type. The default is `json` (dict or list).
        """
        token = self.get_access_token(resource=resource, scope=scope)
        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if headers:
            default_headers.update(headers)
        response = super()._http_request(   # type: ignore[misc]
            *args, resp_type="response", headers=default_headers, **kwargs)

        # 206 indicates Partial Content, reason will be in the warning header.
        # In that case, logs with the warning header will be written.
        if response.status_code == 206:
            demisto.debug(str(response.headers))
        is_response_empty_and_successful = (response.status_code == 204)
        if is_response_empty_and_successful and return_empty_response:
            return response

        try:
            if resp_type == 'json':
                return response.json()
            if resp_type == 'text':
                return response.text
            if resp_type == 'content':
                return response.content
            if resp_type == 'xml':
                ET.parse(response.text)
            return response
        except ValueError as exception:
            raise DemistoException('Failed to parse json object from response: {}'.format(response.content), exception)

    def get_access_token(self, resource: str = '', scope: Optional[str] = None):
        """
        Obtains access and refresh token from oproxy server or just a token from a self deployed app.
        Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.

        Args:
            scope: A scope to get instead of the default on the API.

        Returns:
            str: Access token that will be added to authorization header.
        """
        integration_context = demisto.getIntegrationContext()
        refresh_token = integration_context.get('current_refresh_token', '')
        # Set keywords. Default without the scope prefix.
        access_token_keyword = f'{scope}_access_token' if scope else 'access_token'
        valid_until_keyword = f'{scope}_valid_until' if scope else 'valid_until'

        if self.multi_resource:
            access_token = integration_context.get(resource)
        else:
            access_token = integration_context.get(access_token_keyword)

        valid_until = integration_context.get(valid_until_keyword)

        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        auth_type = self.auth_type
        if auth_type == OPROXY_AUTH_TYPE:
            if self.multi_resource:
                for resource_str in self.resources:
                    access_token, expires_in, refresh_token = self._oproxy_authorize(resource_str)
                    self.resource_to_access_token[resource_str] = access_token
                    self.refresh_token = refresh_token
            else:
                access_token, expires_in, refresh_token = self._oproxy_authorize(scope=scope)

        else:
            access_token, expires_in, refresh_token = self._get_self_deployed_token(refresh_token, scope=scope)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer
        valid_until = time_now + expires_in
        integration_context.update({
            access_token_keyword: access_token,
            valid_until_keyword: valid_until,
            'current_refresh_token': refresh_token
        })

        # Add resource access token mapping
        if self.multi_resource:
            integration_context.update(self.resource_to_access_token)

        demisto.setIntegrationContext(integration_context)

        if self.multi_resource:
            return self.resource_to_access_token[resource]

        return access_token

    def _oproxy_authorize(self, resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing with oproxy.
        Args:
            scope: A scope to add to the request. Do not use it.
            resource: Resource to get.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        content = self.refresh_token or self.tenant_id
        headers = self._add_info_headers()
        oproxy_response = requests.post(
            self.token_retrieval_url,
            headers=headers,
            json={
                'app_name': self.app_name,
                'registration_id': self.auth_id,
                'encrypted_token': self.get_encrypted(content, self.enc_key),
                'scope': scope
            },
            verify=self.verify
        )

        if not oproxy_response.ok:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    oproxy_response.status_code, oproxy_response.reason, oproxy_response.text))
                err_response = oproxy_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                    elif detail:
                        server_msg = detail
                if server_msg:
                    msg += ' Server message: {}'.format(server_msg)
            except Exception as ex:
                demisto.error('Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)
        try:
            gcloud_function_exec_id = oproxy_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = oproxy_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Oproxy server did not contain the expected content.'
            )

        return (parsed_response.get('access_token', ''), parsed_response.get('expires_in', 3595),
                parsed_response.get('refresh_token', ''))

    def _get_self_deployed_token(self, refresh_token: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        if self.grant_type == AUTHORIZATION_CODE:
            if not self.multi_resource:
                return self._get_self_deployed_token_auth_code(refresh_token, scope=scope)
            else:
                expires_in = -1  # init variable as an int
                for resource in self.resources:
                    access_token, expires_in, refresh_token = self._get_self_deployed_token_auth_code(refresh_token,
                                                                                                      resource)
                    self.resource_to_access_token[resource] = access_token

                return '', expires_in, refresh_token
        else:
            # by default, grant_type is CLIENT_CREDENTIALS
            return self._get_self_deployed_token_client_credentials(scope=scope)

    def _get_self_deployed_token_client_credentials(self, scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application in client credentials grant type.

        Args:
            scope; A scope to add to the headers. Else will get self.scope.

        Returns:
            tuple: An access token and its expiry.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': CLIENT_CREDENTIALS
        }

        # Set scope.
        if self.scope or scope:
            data['scope'] = scope if scope else self.scope

        if self.resource:
            data['resource'] = self.resource

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))

        return access_token, expires_in, ''

    def _get_self_deployed_token_auth_code(
            self, refresh_token: str = '', resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.
        TODO: SCOPE@!##@!@#!@#
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'resource': self.resource if not resource else resource,
            'redirect_uri': self.redirect_uri
        }

        if scope:
            data['scope'] = scope

        refresh_token = refresh_token or self._get_refresh_token_from_auth_code_param()
        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            data['grant_type'] = AUTHORIZATION_CODE
            data['code'] = self.auth_code

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_refresh_token_from_auth_code_param(self) -> str:
        refresh_prefix = "refresh_token:"
        if self.auth_code.startswith(refresh_prefix):  # for testing we allow setting the refresh token directly
            demisto.debug("Using refresh token set as auth_code")
            return self.auth_code[len(refresh_prefix):]
        return ''

    @staticmethod
    def error_parser(error: requests.Response) -> str:
        """

        Args:
            error (requests.Response): response with error

        Returns:
            str: string of error

        """
        try:
            response = error.json()
            inner_error = response.get('error', {})
            if isinstance(inner_error, dict):
                err_str = f"{inner_error.get('code')}: {inner_error.get('message')}"
            else:
                err_str = inner_error
            if err_str:
                return err_str
            # If no error message
            raise ValueError
        except ValueError:
            return error.text

    @staticmethod
    def epoch_seconds(d: datetime = None) -> int:
        """
        Return the number of seconds for given date. If no date, return current.

        Args:
            d (datetime): timestamp
        Returns:
             int: timestamp in epoch
        """
        if not d:
            d = MicrosoftClient._get_utcnow()
        return int((d - MicrosoftClient._get_utcfromtimestamp(0)).total_seconds())

    @staticmethod
    def _get_utcnow() -> datetime:
        return datetime.utcnow()

    @staticmethod
    def _get_utcfromtimestamp(_time) -> datetime:
        return datetime.utcfromtimestamp(_time)

    @staticmethod
    def get_encrypted(content: str, key: str) -> str:
        """
        Encrypts content with encryption key.
        Args:
            content: Content to encrypt
            key: encryption key from oproxy

        Returns:
            timestamp: Encrypted content
        """

        def create_nonce():
            return os.urandom(12)

        def encrypt(string, enc_key):
            """
            Encrypts string input with encryption key.
            Args:
                string: String to encrypt
                enc_key: Encryption key

            Returns:
                bytes: Encrypted value
            """
            # String to bytes
            try:
                enc_key = base64.b64decode(enc_key)
            except Exception as err:
                return_error(f"Error in Microsoft authorization: {str(err)}"
                             f" Please check authentication related parameters.", error=traceback.format_exc())

            # Create key
            aes_gcm = AESGCM(enc_key)
            # Create nonce
            nonce = create_nonce()
            # Create ciphered data
            data = string.encode()
            ct = aes_gcm.encrypt(nonce, data, None)
            return base64.b64encode(nonce + ct)

        now = MicrosoftClient.epoch_seconds()
        encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
        return encrypted

    @staticmethod
    def _add_info_headers() -> Dict[str, str]:
        # pylint: disable=no-member
        headers = {}
        try:
            headers = get_x_content_info_headers()
        except Exception as e:
            demisto.error('Failed getting integration info: {}'.format(str(e)))

        return headers


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

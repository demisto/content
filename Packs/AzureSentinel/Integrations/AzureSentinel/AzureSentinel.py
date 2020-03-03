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

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

API_VERSION = '2019-01-01-preview'

AUTHORIZATION_ERROR_MSG = 'There was a problem in retrieving an updated access token.\n'\
                          'The response from the server did not contain the expected content.'

INCIDENT_HEADERS = ['ID', 'IncidentNumber', 'Title', 'Description', 'Severity', 'Status', 'AssigneeName',
                    'AssigneeEmail', 'Labels', 'FirstActivityTimeUTC', 'LastActivityTimeUTC', 'LastModifiedTimeUTC',
                    'CreatedTimeUTC', 'AlertsCount', 'BookmarksCount', 'CommentsCount', 'AlertProductNames',
                    'Tactics', 'FirstActivityTimeGenerated', 'LastActivityTimeGenerated', 'Etag']

COMMENT_HEADERS = ['ID', 'IncidentID', 'Message', 'AuthorName', 'AuthorEmail', 'CreatedTimeUTC']


class Client(BaseClient):
    def __init__(self, url, tenant_id, client_id, client_secret, auth_code,
                 subscription_id, resource_group_name, workspace_name, **kwargs):
        self.base_url = f'{url}/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/' \
            f'Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights'
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_code = auth_code
        self.access_token = self.get_access_token()
        super(Client, self).__init__(self.base_url, **kwargs)

    def get_access_token(self):
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get('access_token')
        refresh_token = integration_context.get('refresh_token')
        access_token_expiration_time = dateparser.parse(integration_context.get('access_token_expiration_time', '0'))

        if not access_token or datetime.now() - access_token_expiration_time > timedelta(seconds=-5):
            access_token = self.make_access_token_request(refresh_token)

        return access_token

    def make_access_token_request(self, refresh_token=None, retry=False):
        data = self.get_access_token_request_data(refresh_token)
        res = requests.post(f'https://login.microsoftonline.com/{self.tenant_id}/oauth2/token',
                            headers={'Content-Type': 'application/x-www-form-urlencoded'},
                            data=data)

        if res.status_code != 200:  # Refresh token has expired
            if not retry:  # Try again using auth_code
                return self.make_access_token_request(refresh_token=None, retry=True)
            else:
                raise Exception(AUTHORIZATION_ERROR_MSG)

        try:
            res_json = res.json()
            self.update_tokens_in_context(res_json)
            return res_json.get('access_token')
        except ValueError:
            raise Exception(AUTHORIZATION_ERROR_MSG)

    def get_access_token_request_data(self, refresh_token=None):
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': 'https://localhost/myapp',
            'resource': 'https://management.core.windows.net'
        }

        if refresh_token:
            data['grant_type'] = 'refresh_token'
            data['refresh_token'] = refresh_token
        else:
            data['grant_type'] = 'authorization_code'
            data['code'] = self.auth_code

        return data

    def update_tokens_in_context(self, res):
        integration_context = {
            'access_token': res.get('access_token'),
            'refresh_token': res.get('refresh_token'),
            'access_token_expiration_time': res.get('expires_on', '0')
        }
        demisto.setIntegrationContext(integration_context)

    def http_request(self, method, url_suffix=None, full_url=None, params=None, data=None):
        if not params:
            params = {}
        if not full_url:
            params['api-version'] = API_VERSION

        res = self._http_request(method=method,
                                 url_suffix=url_suffix,
                                 full_url=full_url,
                                 headers={'Authorization': 'Bearer ' + self.access_token},
                                 json_data=data,
                                 params=params,
                                 resp_type='response',
                                 ok_codes=(200, 201, 202, 204, 400, 401, 403, 404))
        res_json = res.json()

        if res.status_code in (400, 401, 403, 404):
            code = res_json.get('error', {}).get('code', 'Error')
            error_msg = res_json.get('error', {}).get('message', res_json)
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
        'Etag': inc_data.get('etag')
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


def related_resource_data_to_demisto_format(resource_data, inc_id):
    properties = resource_data.get('properties', {})

    formatted_data = {
        'ID': properties.get('relatedResourceName'),
        'Kind': properties.get('relatedResourceKind'),
        'IncidentID': inc_id
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


def test_module(client):
    # todo: in the current method of authorization we can't test the instance - can't use the auth_code twice
    list_incidents_command(client, {'top': '1'})
    return 'ok'


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
    top = None if is_fetch_incidents else min(50, int(args.get('top')))
    next_link = args.get('next_link')

    if next_link:
        result = client.http_request('GET', full_url=next_link)
    else:
        url_suffix = 'incidents'
        params = {
            '$top': top,
            '$filter': filter_expression
        }
        remove_nulls_from_dictionary(params)

        result = client.http_request('GET', url_suffix, params=params)

    incidents = [incident_data_to_demisto_format(inc) for inc in result.get('value')]

    if is_fetch_incidents:
        return None, incidents, {}

    outputs = {'AzureSentinel.Incident(val.ID === obj.ID)': incidents}

    next_link = result.get('nextLink')
    if next_link:
        outputs['AzureSentinel.NextLink'] = next_link

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

    return (
        f'Incident {inc_id} was deleted successfully.', {}, {}
    )


def list_incident_comments_command(client, args):
    inc_id = args.get('incident_id')
    top = min(50, int(args.get('top')))
    next_link = args.get('next_link')

    if next_link:
        result = client.http_request('GET', full_url=next_link)
    else:
        url_suffix = f'incidents/{inc_id}/comments'
        params = {'$top': top}
        remove_nulls_from_dictionary(params)

        result = client.http_request('GET', url_suffix, params=params)

    comments = [comment_data_to_demisto_format(inc, inc_id) for inc in result.get('value')]

    outputs = {f'AzureSentinel.IncidentComment(val.ID === obj.ID && val.IncidentID === {inc_id})': comments}

    next_link = result.get('nextLink')
    if next_link:
        outputs['AzureSentinel.NextToken'] = next_link

    readable_output = tableToMarkdown(f'Incident {inc_id} Comments ({len(comments)} results)', comments,
                                      headers=COMMENT_HEADERS,
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
                                      headers=COMMENT_HEADERS,
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

    result = client.http_request('GET', url_suffix)

    flattened_result = flatten_entity_attributes(result)

    readable_output = tableToMarkdown(f'Entity {entity_id} details', flattened_result, removeNull=True)

    outputs = {
        'AzureSentinel.Entity(val.ID === obj.ID)': flattened_result
    }

    return (
        readable_output,
        outputs,
        result
    )


def list_entities_command(client, args):
    # todo: only 20 elements are returned, no skipToken, while there are more (can be found by id).
    # limit = int(args.get('limit'))
    # offset = int(args.get('offset'))
    url_suffix = 'entities'

    result = client.http_request('GET', url_suffix)

    flattened_results = [flatten_entity_attributes(entity) for entity in result.get('value', [])]

    outputs = {
        'AzureSentinel.Entity(val.ID === obj.ID)': flattened_results
    }

    # todo: if we don't have $top param, I will do a manual pagination (currently waiting for a session w microsoft guy)
    readable_output = tableToMarkdown(f'Entities details', flattened_results, removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def list_incident_relations_command(client, args):
    inc_id = args.get('incident_id')
    top = min(50, int(args.get('top')))
    next_link = args.get('next_link')
    entity_kinds = args.get('entity_kinds')
    filter_expression = args.get('filter', '')

    if next_link:
        result = client.http_request('GET', full_url=next_link)
    else:
        # Handle entity kinds to filter by
        if entity_kinds:
            if filter_expression:
                filter_expression += ' and '
            filter_expression += f"search.in(properties/relatedResourceKind, '{entity_kinds}', ',')"

        url_suffix = f'incidents/{inc_id}/relations'
        params = {
            '$top': top,
            '$filter': filter_expression
        }
        remove_nulls_from_dictionary(params)

        result = client.http_request('GET', url_suffix, params=params)

    relations = [related_resource_data_to_demisto_format(resource, inc_id) for resource in result.get('value')]

    outputs = {f'AzureSentinel.IncidentRelatedResource(val.ID === obj.ID && val.IncidentID == {inc_id})': relations}

    next_link = result.get('nextLink')
    if next_link:
        outputs['AzureSentinel.NextLink'] = next_link

    readable_output = tableToMarkdown(f'Incident {inc_id} Relations ({len(relations)} results)', relations,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def fetch_incidents(client, last_run, first_fetch_time):
    # Get the last fetch details, if exist
    last_fetch_time = last_run.get('last_fetch_time')
    last_fetch_ids = last_run.get('last_fetch_ids', [])

    # Handle first time fetch
    if last_fetch_time is None:
        last_fetch_time_str, _ = parse_date_range(first_fetch_time, DATE_FORMAT)
        last_fetch_time = datetime.strptime(last_fetch_time_str, DATE_FORMAT)
    else:
        last_fetch_time = datetime.strptime(last_fetch_time, DATE_FORMAT)

    latest_created_time = last_fetch_time
    latest_created_time_str = latest_created_time.strftime(DATE_FORMAT)
    command_args = {'filter': f'properties/createdTimeUtc ge {latest_created_time_str}'}
    _, items, _ = list_incidents_command(client, command_args, is_fetch_incidents=True)
    incidents = []
    current_fetch_ids = []

    for incident in items:
        # fetch only incidents that weren't fetched in the last run
        if incident.get('ID') not in last_fetch_ids:
            incident_created_time = datetime.strptime(incident.get('CreatedTimeUTC'), DATE_FORMAT)
            incident = {
                'name': '[Azure Sentinel] ' + incident.get('Title'),
                'occurred': incident.get('CreatedTimeUTC'),
                'severity': severity_to_level(incident.get('Severity')),
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

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = params.get('fetch_time', '3 days').strip()

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            url=params['url'],
            tenant_id=params['tenant_id'],
            client_id=params['client_id'],
            client_secret=params['client_secret'],
            auth_code=params['auth_code'],
            subscription_id=params['subscriptionID'],
            resource_group_name=params['resourceGroupName'],
            workspace_name=params['workspaceName'],
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
            'azure-sentinel-get-entity-by-id': get_entity_by_id_command,
            'azure-sentinel-list-entities': list_entities_command,
            'azure-sentinel-list-incident-relations': list_incident_relations_command
        }

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() in commands:
            return_outputs(*commands[demisto.command()](client, demisto.args()))  # type: ignore

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

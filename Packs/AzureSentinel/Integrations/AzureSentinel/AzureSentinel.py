import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
# IMPORTS

import json
import requests
import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_VERSION = '2019-01-01-preview'

INCIDENT_HEADERS = ['ID', 'Title', 'Description', 'Severity', 'Status', 'AssigneeName', 'AssigneeEmail', 'Labels',
                    'FirstActivityTimeUTC', 'LastActivityTimeUTC', 'LastModifiedTimeUTC', 'CreatedTimeUTC',
                    'IncidentNumber', 'AlertsCount', 'BookmarksCount', 'CommentsCount', 'AlertProductNames',
                    'Tactics', 'FirstActivityTimeGenerated', 'LastActivityTimeGenerated']

COMMENT_HEADERS = ['ID', 'Message', 'AuthorName', 'AuthorEmail', 'CreatedTimeUTC']


class Client(BaseClient):
    def __init__(self, tenant_id, client_id, client_secret, auth_code,
                 subscription_id, resource_group_name, workspace_name, **kwargs):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_code = auth_code
        # self.access_token = self.get_access_token()
        self.access_token = ''
        self.base_url = f'https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/' \
            f'{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/' \
            f'providers/Microsoft.SecurityInsights'
        super(Client, self).__init__(self.base_url, **kwargs)

    def get_access_token(self):
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get('access_token')
        refresh_token = integration_context.get('refresh_token')
        access_token_expiration_time = integration_context.get('access_token_expiration_time')

        if access_token is None or datetime.now() - access_token_expiration_time > timedelta(seconds=-5):
            access_token = self.make_access_token_request(refresh_token)

        return access_token

    def make_access_token_request(self, refresh_token=None):
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': 'https://localhost/myapp',
            'resource': 'https://management.core.windows.net'
        }

        if refresh_token:
            params['grant_type'] = 'refresh_token'
            params['refresh_token'] = refresh_token
        else:
            params['grant_type'] = 'authorization_code'
            params['code'] = self.auth_code

        res = requests.post(f'https://login.microsoftonline.com/{self.tenant_id}/oauth2/token',
                            headers={'Content-Type': 'application/x-www-form-urlencoded'},
                            params=params)

        if res.status_code != 200:
            # Refresh token has expired, try again using auth_code
            return self.make_access_token_request(refresh_token=None)

        try:
            res_json = res.json()
            self.update_tokens_in_context(res_json)
            return res_json['access_token']

        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the server did not contain the expected content.'
            )

    def update_tokens_in_context(self, res):
        integration_context = {
            'access_token': res['access_token'],
            'refresh_token': res['refresh_token'],
            'access_token_expiration_time': datetime.fromtimestamp(res['expires_on'])
        }

        demisto.setIntegrationContext(integration_context)

    def http_request(self, method, url_suffix, params=None, data=None, resp_type='response'):
        self.update_access_token()

        if not params:
            params = {}
        params['api-version'] = API_VERSION

        res = self._http_request(method=method,
                                 url_suffix=url_suffix,
                                 headers={'Authorization': 'Bearer ' + self.access_token},
                                 json_data=data,
                                 params=params,
                                 resp_type=resp_type,
                                 ok_codes=(200, 201, 202, 204, 400, 403, 404))
        return res

    def update_access_token(self):
        self.access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkhsQzBSMTJza3hOWjFXUXdtak9GXzZ0X3RERSIsImtpZCI6IkhsQzBSMTJza3hOWjFXUXdtak9GXzZ0X3RERSJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2ViYWMxYTE2LTgxYmYtNDQ5Yi04ZDQzLTU3MzJjM2MxZDk5OS8iLCJpYXQiOjE1ODI2NTkyNDAsIm5iZiI6MTU4MjY1OTI0MCwiZXhwIjoxNTgyNjYzMTQwLCJhY3IiOiIxIiwiYWlvIjoiQVNRQTIvOE9BQUFBcDlDcWJjdnlZT3Q4bE1GQXU0aCtPRWhQSmZEcG80cnJmMWtoTStsbHZNZz0iLCJhbXIiOlsicHdkIl0sImFwcGlkIjoiOTRiNDUyMjUtYjZhNS00NTNlLTljYmMtMmU3MjJkYmMyZmQzIiwiYXBwaWRhY3IiOiIxIiwiZmFtaWx5X25hbWUiOiJCcmFuZGVpcyIsImdpdmVuX25hbWUiOiJBdmlzaGFpIiwiZ3JvdXBzIjpbIjJhZGYxNGM2LWMyMGUtNDNlOC05OTgwLWU2NzEyNWZmNGM2MiIsImM2NTY3YWU0LWVkZjUtNDZiNS05ZDNlLWVhNjYwY2VhZDYxMCIsIjg0YTE5OTkwLTE1ZmYtNGVhNy1iMzM5LTZmMmM3NjE5MjgxOSJdLCJpcGFkZHIiOiIzNC45OS4yMzEuMjQxIiwibmFtZSI6IkF2aXNoYWkgQnJhbmRlaXMiLCJvaWQiOiIzZmE5ZjI4Yi1lYjBlLTQ2M2EtYmE3Yi04MDg5ZmU5OTkxZTIiLCJwdWlkIjoiMTAwMzAwMDA5QUJDMjg3OCIsInNjcCI6InVzZXJfaW1wZXJzb25hdGlvbiIsInN1YiI6InJTdWlVUnV4NkctSWtpLXZyNUticHU4QmtkZk15aUpmVmgtNndqaFdYNXMiLCJ0aWQiOiJlYmFjMWExNi04MWJmLTQ0OWItOGQ0My01NzMyYzNjMWQ5OTkiLCJ1bmlxdWVfbmFtZSI6ImF2aXNoYWlAZGVtaXN0b2Rldi5vbm1pY3Jvc29mdC5jb20iLCJ1cG4iOiJhdmlzaGFpQGRlbWlzdG9kZXYub25taWNyb3NvZnQuY29tIiwidXRpIjoiamRDOUtXZjR0MHltdWlxN3NBc0RBQSIsInZlciI6IjEuMCIsIndpZHMiOlsiM2EyYzYyZGItNTMxOC00MjBkLThkNzQtMjNhZmZlZTVkOWQ1IiwiNjJlOTAzOTQtNjlmNS00MjM3LTkxOTAtMDEyMTc3MTQ1ZTEwIl19.SXmeO_SLSkkIJJC8k_NSZdSR6SWTr2BZMKx7A8g7EkgWihsI51bCIyIG_l96bhuWj4qr4kjWBJw1ZFKV8pFZgW9T2qYtIuJXr0x0OoYCit7zMbLMuNBFwnr60PXqVDctFsVqtp1RpkRPAot80i6dZN-d3pgy8QXzy6BwVwPXNNhTliqkBc11YeZSuU8iluvf5cLq3w5y7e1JULMJfIR5Y-ij8MbDxTzo9U6k99U0AAlVYBEm2u9CelVEoX6nJuKCx7HUBXbr_o30QMi1ZRr6fTX3ZaYPfRfW5d1XC4yHQb76-Y6L5EQw-RudIWphQk9mCWWMxARJHS-3cw0_fuZA7Q"


def get_response_next_token(next_link):
    match = re.search(r'\$skipToken=([^&]*)', next_link)
    if match:
        return match.group(1)
    return None


def incident_data_to_demisto_format(inc_data):
    inc_properties = inc_data.get('properties', {})

    formatted_data = {
        'ID': inc_data.get('name'),
        'Title': inc_properties.get('title'),
        'Description': inc_properties.get('description'),
        'Severity': inc_properties.get('severity'),
        'Status': inc_properties.get('status'),
        'AssigneeName': inc_properties.get('owner', {}).get('assignedTo'),
        'AssigneeEmail': inc_properties.get('owner', {}).get('email'),
        'Labels': [{
            'Name': label.get('name'),
            'Type': label.get('type')
            } for label in inc_properties.get('labels', [])
        ],
        'FirstActivityTimeUTC': inc_properties.get('firstActivityTimeUtc'),
        'LastActivityTimeUTC': inc_properties.get('lastActivityTimeUtc'),
        'LastModifiedTimeUTC': inc_properties.get('lastModifiedTimeUtc'),
        'CreatedTimeUTC': inc_properties.get('createdTimeUtc'),
        'IncidentNumber': inc_properties.get('incidentNumber'),
        'AlertsCount': inc_properties.get('additionalData', {}).get('alertsCount'),
        'BookmarksCount': inc_properties.get('additionalData', {}).get('bookmarksCount'),
        'CommentsCount': inc_properties.get('additionalData', {}).get('commentsCount'),
        'AlertProductNames': inc_properties.get('additionalData', {}).get('alertProductNames'),
        'Tactics': inc_properties.get('tactics'),
        'FirstActivityTimeGenerated': inc_properties.get('firstActivityTimeGenerated'),
        'LastActivityTimeGenerated': inc_properties.get('lastActivityTimeGenerated')
    }
    return formatted_data


def comment_data_to_demisto_format(comment_data):
    inc_properties = comment_data.get('properties', {})

    formatted_data = {
        'ID': comment_data.get('name'),
        'Message': inc_properties.get('message'),
        'AuthorName': inc_properties.get('author', {}).get('assignedTo'),
        'AuthorEmail': inc_properties.get('author', {}).get('email'),
        'CreatedTimeUTC': inc_properties.get('createdTimeUtc')
    }
    return formatted_data


def test_module(client):
    return 'ok'


def update_incident_command(client, args):
    # todo: request is broken
    inc_id = args.get('incident_id')
    inc_data = {
        'properties': {
            'title': args.get('title'),
            'description': args.get('description'),
            'severity': args.get('severity'),
            'status': args.get('status'),
            # 'enum': args.get('classification'),  # todo: enum not in preview api version
            'owner': {
                'email': args.get('owner_email')  # todo: I don't think this will work
            }
        }
    }

    # todo: beautify when possible
    remove_nulls_from_dictionary(inc_data['properties']['owner'])
    remove_nulls_from_dictionary(inc_data['properties'])

    url_suffix = f'incidents/{inc_id}'

    result = client.http_request('PUT', url_suffix, data=inc_data, resp_type='json')
    outputs = incident_data_to_demisto_format(result)

    readable_output = tableToMarkdown(f'Updated incidents {inc_id} details', outputs)

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


def get_incident_by_id_command(client, args):
    inc_id = args.get('incident_id')
    url_suffix = f'incidents/{inc_id}'

    result = client.http_request('GET', url_suffix, resp_type='json')
    outputs = incident_data_to_demisto_format(result)

    readable_output = tableToMarkdown(f'Incident {inc_id} details', outputs,
                                      headers=COMMENT_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def list_incidents_command(client, args):
    top = int(args.get('top'))
    next_token = args.get('next_token')
    url_suffix = 'incidents'

    params = {}
    if top:
        params['$top'] = top
    if next_token:
        params['$skipToken'] = next_token

    result = client.http_request('GET', url_suffix, params, resp_type='json')

    incidents = [incident_data_to_demisto_format(inc) for inc in result.get('value')]
    next_token = get_response_next_token(result.get('nextLink'))

    outputs = {
        'Incident(val.ID === obj.ID)': incidents,
        'NextToken': next_token
    }

    readable_output = tableToMarkdown(f'Incidents List ({len(incidents)} results)', incidents,
                                      metadata=f'Next Token: {next_token}',
                                      headers=INCIDENT_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def get_incident_comment_by_id_command(client, args):
    inc_id = args.get('incident_id')
    comment_id = args.get('comment_id')
    url_suffix = f'incidents/{inc_id}/comments/{comment_id}'

    result = client.http_request('GET', url_suffix, resp_type='json')
    outputs = comment_data_to_demisto_format(result)

    readable_output = tableToMarkdown(f'Incident {inc_id} details', outputs,
                                      headers=COMMENT_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def list_incident_comments_command(client, args):
    inc_id = args.get('incident_id')
    top = int(args.get('top'))
    next_token = args.get('next_token')
    url_suffix = f'incidents/{inc_id}/comments'

    params = {}
    if top:
        params['$top'] = top
    if next_token:
        params['$skipToken'] = next_token

    result = client.http_request('GET', url_suffix, params, resp_type='json')

    comments = [comment_data_to_demisto_format(inc) for inc in result.get('value')]
    next_token = get_response_next_token(result.get('nextLink'))

    outputs = {
        f'Incident(ID === {inc_id}).Comment': comments,
        'NextToken': next_token
    }

    readable_output = tableToMarkdown(f'Incident {inc_id} Comments ({len(comments)} results)', comments,
                                      metadata=f'Next Token: {next_token}',
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
        'properties': {  # todo: can't define author - depends on user (token)
            'message': args.get('message')
        }
    }

    result = client.http_request('PUT', url_suffix, data=comment_data)
    outputs = comment_data_to_demisto_format(result)

    readable_output = tableToMarkdown(f'Incident {inc_id} details', outputs,
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

    readable_output = tableToMarkdown(f'Entity {entity_id} details', result,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        result,
        result
    )


def list_entities_command(client, args):
    top = int(args.get('top'))
    next_token = args.get('next_token')
    url_suffix = 'entities'

    params = {}
    if top:
        params['$top'] = top
    if next_token:
        params['$skipToken'] = next_token

    result = client.http_request('GET', url_suffix, params, resp_type='json')
    next_token = get_response_next_token(result.get('nextLink'))
    outputs = {
        'RawResponse': result,
        'NextToken': next_token
    }

    readable_output = tableToMarkdown(f'Entities List ({len(result)} results)', result,
                                      metadata=f'Next Token: {next_token}',
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def list_incident_relations_command(client, args):
    inc_id = args.get('incident_id')
    top = int(args.get('top'))
    next_token = args.get('next_token')
    url_suffix = f'incidents/{inc_id}/relations'

    params = {}
    if top:
        params['$top'] = top
    if next_token:
        params['$skipToken'] = next_token

    result = client.http_request('GET', url_suffix, params, resp_type='json')

    relations = [comment_data_to_demisto_format(inc) for inc in result.get('value')]
    next_token = get_response_next_token(result.get('nextLink'))

    outputs = {
        f'Incident(ID === {inc_id}).Relation': relations,
        'NextToken': next_token
    }

    readable_output = tableToMarkdown(f'Incident {inc_id} Relations ({len(relations)} results)', relations,
                                      metadata=f'Next Token: {next_token}',
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return (
        readable_output,
        outputs,
        result
    )


def fetch_incidents(client, last_run, first_fetch_time):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): HelloWorld client
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto

    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch, _ = dateparser.parse(first_fetch_time)
    else:
        last_fetch = dateparser.parse(last_fetch)

    latest_created_time = last_fetch
    incidents = []
    items = client.list_incidents()
    for item in items:
        incident_created_time = dateparser.parse(item['created_time'])
        incident = {
            'name': item['description'],
            'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(item)
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
    return next_run, incidents
    """
    pass


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
            'azure-sentinel-get-incident-comment-by-id': get_incident_comment_by_id_command,
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
            return_outputs(*commands[demisto.command()](client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

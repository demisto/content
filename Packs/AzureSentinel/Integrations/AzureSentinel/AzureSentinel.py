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


def str_to_bool(str_bool):
    return str_bool.lower() == 'true'


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
    classification = args.get('classification')
    classification_reason = args.get('classification_reason')

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
            'status': status,
            'classification': classification,
            'classificationReason': classification_reason
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
    expand_entity_information = str_to_bool(args.get('expand_entity_information'))

    if not expand_entity_information:
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
    else:
        # This expansion_id is written according to -
        # https://techcommunity.microsoft.com/t5/azure-sentinel/get-entities-for-a-sentinel-incidient-by-api/m-p/1422643

        expansion_id = "98b974fd-cc64-48b8-9bd0-3a209f5b944b"
        url_suffix = f'entities/{entity_id}/expand'
        data = {
            "expansionId": expansion_id
        }

        result = client.http_request('POST', url_suffix, is_get_entity_cmd=True, data=data)

        result_value = result.get('value', {})
        result_entities = result_value.get('entities', [])
        readable_output = tableToMarkdown(f'Entity {entity_id} details',
                                          result_entities,
                                          removeNull=True,
                                          headerTransform=pascalToSpace)

        outputs = {
            'AzureSentinel.Entity(val.id === obj.id)': result_entities
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


from MicrosoftApiModule import *  # noqa: E402


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
# IMPORTS

import json
import requests
import dateparser
import uuid

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''

APP_NAME = 'ms-azure-sentinel'

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

API_VERSION = '2021-04-01'

DEFAULT_AZURE_SERVER_URL = 'https://management.azure.com'

NEXTLINK_DESCRIPTION = 'NextLink for listing commands'

XSOAR_USER_AGENT = 'SentinelPartner-PaloAltoNetworks-CortexXsoar/1.0.0'

AUTHORIZATION_ERROR_MSG = 'There was a problem in retrieving an updated access token.\n' \
                          'The response from the server did not contain the expected content.'

INCIDENT_HEADERS = ['ID', 'IncidentNumber', 'Title', 'Description', 'Severity', 'Status', 'IncidentUrl', 'AssigneeName',
                    'AssigneeEmail', 'Label', 'FirstActivityTimeUTC', 'LastActivityTimeUTC', 'LastModifiedTimeUTC',
                    'CreatedTimeUTC', 'AlertsCount', 'BookmarksCount', 'CommentsCount', 'AlertProductNames',
                    'Tactics', 'FirstActivityTimeGenerated', 'LastActivityTimeGenerated']

COMMENT_HEADERS = ['ID', 'IncidentID', 'Message', 'AuthorName', 'AuthorEmail', 'CreatedTimeUTC']

ENTITIES_RETENTION_PERIOD_MESSAGE = '\nNotice that in the current Azure Sentinel API version, the retention period ' \
                                    'for GetEntityByID is 30 days.'

DEFAULT_LIMIT = 50

DEFAULT_SOURCE = 'Azure Sentinel'

THREAT_INDICATORS_HEADERS = ['Name', 'DisplayName', 'Values', 'Types', 'Source', 'Confidence', 'Tags']


class AzureSentinelClient:
    def __init__(self, server_url: str, tenant_id: str, client_id: str,
                 client_secret: str, subscription_id: str,
                 resource_group_name: str, workspace_name: str,
                 verify: bool = True, proxy: bool = False):
        """
        AzureSentinelClient class that make use client credentials for authorization with Azure.

        :type server_url: ``str``
        :param server_url: The server url.

        :type tenant_id: ``str``
        :param tenant_id: The tenant id.

        :type client_id: ``str``
        :param client_id: The client id.

        :type client_secret: ``str``
        :param client_secret: The client secret from Azure registered application.

        :type subscription_id: ``str``
        :param subscription_id: The subscription id.

        :type resource_group_name: ``str``
        :param resource_group_name: The resource group name.

        :type workspace_name: ``str``
        :param workspace_name: The workspace name.

        :type verify: ``bool``
        :param verify: Whether the request should verify the SSL certificate.

        :type proxy: ``bool``
        :param proxy: Whether to run the integration using the system proxy.
        """
        server_url = f'{server_url}/subscriptions/{subscription_id}/' \
                     f'resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/' \
                     f'{workspace_name}/providers/Microsoft.SecurityInsights'
        self._client = MicrosoftClient(
            tenant_id=tenant_id,
            auth_id=client_id,
            enc_key=client_secret,
            self_deployed=True,
            grant_type=CLIENT_CREDENTIALS,
            base_url=server_url,
            scope=Scopes.management_azure,
            ok_codes=(200, 201, 202, 204),
            verify=verify,
            proxy=proxy
        )

    def http_request(self, method, url_suffix=None, full_url=None, params=None, data=None):
        """
        Wrapped the client's `http_request` for adding some required params and headers
        """
        if not full_url:
            params = params or {}
            params['api-version'] = API_VERSION

        res = self._client.http_request(
            method=method,  # disable-secrets-detection
            url_suffix=url_suffix,
            full_url=full_url,
            headers={'User-Agent': XSOAR_USER_AGENT},
            json_data=data,
            params=params,
            error_handler=error_handler,
            resp_type='response',
        )

        if res.content:
            return res.json()

        return res


''' INTEGRATION HELPER METHODS '''


def error_handler(response: requests.Response):
    """
    raise informative exception in case of error response
    """
    if response.status_code in (400, 401, 403, 404):
        res_json = response.json()
        error_kind = res_json.get('error', {}).get('code', 'BadRequest')
        error_msg = res_json.get('error', {}).get('message', res_json)
        raise ValueError(
            f'[{error_kind} {response.status_code}] {error_msg}'
        )


def format_date(date):
    if not date:
        return None
    return dateparser.parse(date).strftime(DATE_FORMAT)  # type:ignore


def incident_data_to_xsoar_format(inc_data):
    """
    Convert the incident data from the raw to XSOAR format.

    :param inc_data: (dict) The incident raw data.
    """
    properties = inc_data.get('properties', {})

    formatted_data = {
        'ID': inc_data.get('name'),
        'IncidentNumber': properties.get('incidentNumber'),
        'IncidentUrl': properties.get('incidentUrl'),
        'Title': properties.get('title'),
        'Description': properties.get('description'),
        'Severity': properties.get('severity'),
        'Status': properties.get('status'),
        'AssigneeName': properties.get('owner', {}).get('assignedTo'),
        'AssigneeEmail': properties.get('owner', {}).get('email'),
        'Label': [{
            'Name': label.get('labelName'),
            'Type': label.get('labelType')
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


def watchlist_data_to_xsoar_format(watchlist_data):
    """
    Convert the watchlist data from the raw to XSOAR format.

    :param watchlist_data: (dict) The alert raw data.
    """
    properties = watchlist_data.get('properties', {})

    formatted_data = {
        'Name': watchlist_data.get('name'),
        'ID': properties.get('watchlistId'),
        'Description': properties.get('description'),
        'Provider': properties.get('provider'),
        'Source': properties.get('source'),
        'Created': format_date(properties.get('created')),
        'Updated': format_date(properties.get('updated')),
        'CreatedBy': properties.get('createdBy', {}).get('name'),
        'UpdatedBy': properties.get('updatedBy', {}).get('name'),
        'Alias': properties.get('watchlistAlias'),
        'Label': properties.get('labels', []),
        'ItemsSearchKey': properties.get('itemsSearchKey')
    }
    return formatted_data


def alert_data_to_xsoar_format(alert_data):
    """
    Convert the alert data from the raw to XSOAR format.

    :param alert_data: (dict) The alert raw data.
    """
    properties = alert_data.get('properties', {})
    formatted_data = {
        'ID': properties.get('systemAlertId'),
        'Kind': alert_data.get('kind'),
        'Tactic': properties.get('tactics'),
        'DisplayName': properties.get('alertDisplayName'),
        'Description': properties.get('description'),
        'ConfidenceLevel': properties.get('confidenceLevel'),
        'Severity': properties.get('severity'),
        'VendorName': properties.get('vendorName'),
        'ProductName': properties.get('productName'),
        'ProductComponentName': properties.get('productComponentName'),
    }
    return formatted_data


def watchlist_item_data_to_xsoar_format(item_data):
    """
    Convert the watchlist item from the raw to XSOAR format.

    :param item_data: (dict) The item raw data.
    """
    properties = item_data.get('properties', {})
    formatted_data = {
        'Name': item_data.get('name'),
        'ID': properties.get('watchlistItemId'),
        'Created': format_date(properties.get('created')),
        'Updated': format_date(properties.get('updated')),
        'CreatedBy': demisto.get(properties, 'createdBy.name'),
        'UpdatedBy': demisto.get(properties, 'updatedBy.name'),
        'ItemsKeyValue': properties.get('itemsKeyValue'),
    }
    return formatted_data


def get_update_incident_request_data(client: AzureSentinelClient, args: Dict[str, str]):
    """
    Prepare etag and other mandatory incident properties for update_incident command.

    :param client: The client.
    :param args: The args for the command.
    """
    fetched_incident_data = get_incident_by_id_command(client, args).raw_response

    title = args.get('title')
    description = args.get('description')
    severity = args.get('severity')
    status = args.get('status')
    classification = args.get('classification')
    classification_comment = args.get('classification_comment')
    classification_reason = args.get('classification_reason')
    assignee_email = args.get('assignee_email')
    labels = argToList(args.get('labels', ''))

    if not title:
        title = demisto.get(fetched_incident_data, 'properties.title')
    if not description:
        description = demisto.get(fetched_incident_data, 'properties.description')
    if not severity:
        severity = demisto.get(fetched_incident_data, 'properties.severity')
    if not status:
        status = demisto.get(fetched_incident_data, 'properties.status')
    if not assignee_email:
        assignee_email = demisto.get(fetched_incident_data, 'properties.owner.email')

    existing_labels = demisto.get(fetched_incident_data, 'properties.labels')
    if not labels:  # not provided as arg
        labels_formatted = existing_labels

    else:
        labels_formatted = [{"labelName": label, "labelType": "User"}
                            for label in argToList(labels) if label]  # labels can not be blank
    incident_data = {
        'etag': fetched_incident_data.get('etag'),
        'properties': {
            'title': title,
            'description': description,
            'severity': severity,
            'status': status,
            'classification': classification,
            'classificationComment': classification_comment,
            'classificationReason': classification_reason,
            'labels': labels_formatted,
            'owner': {'email': assignee_email}
        }
    }
    remove_nulls_from_dictionary(incident_data['properties'])

    return incident_data


def comment_data_to_xsoar_format(comment_data, inc_id):
    """
    Convert the comment data from the raw to XSOAR format.

    :param comment_data: (dict) The comment raw data.
    :param inc_id: The id of the incident hold this comment.
    """
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


def incident_related_resource_data_to_xsoar_format(resource_data, incident_id):
    """
    Convert the incident relation from the raw to XSOAR format.

    :param resource_data: (dict) The related resource raw data.
    :param incident_id: The incident id.
    """
    properties = resource_data.get('properties', {})

    formatted_data = {
        'ID': properties.get('relatedResourceName'),
        'Kind': properties.get('relatedResourceKind'),
        'IncidentID': incident_id
    }
    return formatted_data


def entity_related_resource_data_to_xsoar_format(resource_data, entity_id):
    """
    Convert the entity relation from the raw to XSOAR format.

    :param resource_data: (dict) The related resource raw data.
    :param entity_id: The entity id.
    """
    properties = resource_data.get('properties', {})

    formatted_data = {
        'ID': properties.get('relatedResourceName'),
        'Kind': properties.get('relatedResourceKind'),
        'EntityID': entity_id
    }
    return formatted_data


def severity_to_level(severity):
    """
    Maps severity to a level represented by number.
    """
    if severity == 'Informational':
        return 0.5
    elif severity == 'Low':
        return 1
    elif severity == 'Medium':
        return 2
    elif severity == 'High':
        return 3
    return 0


def generic_list_incident_items(client, incident_id, items_kind, key_in_raw_result, outputs_prefix, xsoar_transformer):
    """
    Get a list of incident's items

    :param client: (AzureSentinelClient) The Azure Sentinel client to work with.
    :param incident_id:  (str) the incident id.
    :param items_kind: (str) the name of the entity e.g. entities, alerts.
    :param key_in_raw_result: (str) the key hold the relevant result in the raw data.
    :param outputs_prefix: (str) the context output key that will hold the command result.
    :param xsoar_transformer: (function) a function to transform the raw data to xsoar format.
    """

    url_suffix = f'incidents/{incident_id}/{items_kind}'

    result = client.http_request('POST', url_suffix)
    raw_items = result.get(key_in_raw_result, [])
    items = [dict(IncidentId=incident_id, **xsoar_transformer(item)) for item in raw_items]

    readable_output = tableToMarkdown(f'Incident {incident_id} {items_kind.capitalize()} ({len(items)} results)', items,
                                      headers=['ID', 'Kind', 'IncidentId'],
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs=items,
        outputs_prefix=outputs_prefix,
        outputs_key_field=['ID', 'IncidentId'],
        raw_response=result
    )


''' INTEGRATION COMMANDS '''


def get_incident_by_id_command(client, args):
    inc_id = args.get('incident_id')
    url_suffix = f'incidents/{inc_id}'

    result = client.http_request('GET', url_suffix)
    incident = incident_data_to_xsoar_format(result)
    readable_output = tableToMarkdown(f'Incident {inc_id} details', incident, url_keys=['IncidentUrl'],
                                      headers=INCIDENT_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.Incident',
        outputs=incident,
        outputs_key_field='ID',
        raw_response=result
    )


def test_module(client):
    """
    Test connection to Azure by calling the list incidents API with limit=1
    """
    client.http_request('GET', 'incidents', params={'$top': 1})
    return 'ok'


def list_incidents_command(client, args, is_fetch_incidents=False):
    filter_expression = args.get('filter')
    limit = None if is_fetch_incidents else min(200, int(args.get('limit')))
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

    incidents = [incident_data_to_xsoar_format(inc) for inc in result.get('value')]

    if is_fetch_incidents:
        return CommandResults(outputs=incidents, outputs_prefix='AzureSentinel.Incident')

    outputs = {'AzureSentinel.Incident(val.ID === obj.ID)': incidents}

    update_next_link_in_context(result, outputs)

    readable_output = tableToMarkdown(f'Incidents List ({len(incidents)} results)', incidents,
                                      headers=INCIDENT_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )


def list_watchlists_command(client, args):
    url_suffix = 'watchlists'
    specific_watchlists_alias = args.get('watchlist_alias')
    if specific_watchlists_alias:
        url_suffix += f'/{specific_watchlists_alias}'

    result = client.http_request('GET', url_suffix)

    iterable_watchlists = [result] if specific_watchlists_alias else result.get('value')
    watchlists = [watchlist_data_to_xsoar_format(watchlist) for watchlist in iterable_watchlists]
    readable_output = tableToMarkdown('Watchlists results', watchlists,
                                      headers=['Name', 'ID', 'Description'],
                                      headerTransform=pascalToSpace,
                                      removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.Watchlist',
        outputs=watchlists,
        outputs_key_field='ID',
        raw_response=result
    )


def delete_watchlist_command(client, args):
    alias = args.get('watchlist_alias')
    url_suffix = f'watchlists/{alias}'
    client.http_request('DELETE', url_suffix)
    return CommandResults(readable_output=f'Watchlist {alias} was deleted successfully.')


def delete_watchlist_item_command(client, args):
    alias = args.get('watchlist_alias')
    item_id = args.get('watchlist_item_id')
    url_suffix = f'watchlists/{alias}/watchlistItems/{item_id}'
    client.http_request('DELETE', url_suffix)
    return CommandResults(readable_output=f'Watchlist item {item_id} was deleted successfully.')


def create_update_watchlist_command(client, args):
    """ Create or update a watchlist in Azure Sentinel.

    :param client: (AzureSentinelClient) The Azure Sentinel client to work with.
    :param args:  (dict) arguments for this command.
    """

    # prepare the request
    alias = args.get('watchlist_alias')
    raw_content = ''
    path = args.get('file_entry_id')
    if path:
        path = demisto.getFilePath(path)
        with open(path['path'], 'rb') as file:
            raw_content = file.read().decode()
    data = {
        'properties': {
            'watchlistAlias': alias,
            'displayName': args.get('watchlist_display_name'),
            'description': args.get('description', ''),
            'provider': args.get('provider', 'XSOAR'),
            'source': 'Local file',
            'labels': argToList(args.get('labels', ''), ','),
            'numberOfLinesToSkip': arg_to_number(args.get('lines_to_skip', '0')),
            'rawContent': raw_content,
            'itemsSearchKey': args.get('items_search_key'),
            'contentType': args.get('content_type', 'Text/Csv'),
        }
    }

    # request
    raw_result = client.http_request('PUT', url_suffix=f'watchlists/{alias}', data=data)

    # prepare result
    watchlist = watchlist_data_to_xsoar_format(raw_result)

    readable_output = tableToMarkdown('Create watchlist results', watchlist,
                                      headers=['Name', 'ID', 'Description'],
                                      headerTransform=pascalToSpace,
                                      removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.Watchlist',
        outputs=watchlist,
        outputs_key_field='ID',
        raw_response=raw_result
    )


def create_update_watchlist_item_command(client, args):
    """ Create or update a watchlist item in Azure Sentinel.

    :param client: (AzureSentinelClient) The Azure Sentinel client to work with.
    :param args:  (dict) arguments for this command.
    """

    # prepare the request
    alias = args.get('watchlist_alias')
    watchlist_item_id = args.get('watchlist_item_id', uuid.uuid4())
    item_key_value_str = args.get('item_key_value', '{}')
    item_key_value = json.loads(item_key_value_str)
    item_data = {
        'properties': {
            'itemsKeyValue': item_key_value
        }
    }

    # request
    url_suffix = f'watchlists/{alias}/watchlistItems/{watchlist_item_id}'
    raw_item = client.http_request('PUT', url_suffix=url_suffix, data=item_data)

    # prepare result
    item = {'WatchlistAlias': alias, **watchlist_item_data_to_xsoar_format(raw_item)}
    readable_output = tableToMarkdown('Create watchlist item results', item,
                                      headers=['ID', 'ItemsKeyValue'],
                                      headerTransform=pascalToSpace,
                                      removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.WatchlistItem',
        outputs=item,
        outputs_key_field='ID',
        raw_response=raw_item
    )


def list_watchlist_items_command(client, args):
    """
    Get specific watchlist item or list of watchlist items.

    :param client: (AzureSentinelClient) The Azure Sentinel client to work with.
    :param args:  (dict) arguments for this command.
    """

    # prepare the request
    alias = args.get('watchlist_alias', '')
    url_suffix = f'watchlists/{alias}/watchlistItems'
    item_id = args.get('watchlist_item_id')
    if item_id:
        url_suffix += f'/{item_id}'

    # request
    result = client.http_request('GET', url_suffix)

    # prepare result
    raw_items = [result] if item_id else result.get('value')
    items = [{'WatchlistAlias': alias, **watchlist_item_data_to_xsoar_format(item)} for item in raw_items]
    readable_output = tableToMarkdown('Watchlist items results', items,
                                      headers=['ID', 'ItemsKeyValue'],
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.WatchlistItem',
        outputs=items,
        outputs_key_field='ID',
        raw_response=result
    )


def update_incident_command(client: AzureSentinelClient, args: Dict[str, Any]):
    inc_id = args.get('incident_id')
    inc_data = get_update_incident_request_data(client, args)

    url_suffix = f'incidents/{inc_id}'
    result = client.http_request('PUT', url_suffix, data=inc_data)
    incident = incident_data_to_xsoar_format(result)
    readable_output = tableToMarkdown(f'Updated incidents {inc_id} details', incident,
                                      headers=INCIDENT_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.Incident',
        outputs=incident,
        outputs_key_field='ID',
        raw_response=result
    )


def delete_incident_command(client, args):
    inc_id = args.get('incident_id')
    url_suffix = f'incidents/{inc_id}'

    client.http_request('DELETE', url_suffix)

    context = {
        'ID': inc_id,
        'Deleted': True
    }

    return CommandResults(
        readable_output=f'Incident {inc_id} was deleted successfully.',
        outputs_prefix='AzureSentinel.Incident',
        outputs=context,
        outputs_key_field='ID',
        raw_response={}
    )


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

    comments = [comment_data_to_xsoar_format(inc, inc_id) for inc in result.get('value')]

    outputs = {f'AzureSentinel.IncidentComment(val.ID === obj.ID && val.IncidentID === {inc_id})': comments}

    update_next_link_in_context(result, outputs)

    readable_output = tableToMarkdown(f'Incident {inc_id} Comments ({len(comments)} results)', comments,
                                      headers=COMMENT_HEADERS,  # disable-secrets-detection
                                      headerTransform=pascalToSpace,
                                      removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
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
    comment = comment_data_to_xsoar_format(result, inc_id)

    readable_output = tableToMarkdown(f'Incident {inc_id} new comment details', comment,
                                      headers=COMMENT_HEADERS,  # disable-secrets-detection
                                      headerTransform=pascalToSpace,
                                      removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.IncidentComment',
        outputs=comment,
        outputs_key_field=['ID', 'IncidentID'],
        raw_response=result
    )


def incident_delete_comment_command(client, args):
    inc_id = args.get('incident_id')
    comment_id = args.get('comment_id')
    url_suffix = f'incidents/{inc_id}/comments/{comment_id}'

    res = client.http_request('DELETE', url_suffix)
    if isinstance(res, requests.Response) and res.status_code == 204:
        readable_output = f'Comment {comment_id} does not exist.'
    else:
        readable_output = f'Comment {comment_id} was deleted successfully.'

    return CommandResults(readable_output=readable_output)


def list_incident_entities_command(client, args):
    """
    Get a list of incident's entities.

    :param client: (AzureSentinelClient) The Azure Sentinel client to work with.
    :param args:  (dict) arguments for this command.
    """

    def xsoar_transformer(entity):
        return dict(
            ID=entity.get('name'),
            Kind=entity.get('kind'),
            Properties=entity.get('properties')
        )

    return generic_list_incident_items(
        client=client, incident_id=args.get('incident_id'),
        items_kind='entities', key_in_raw_result='entities',
        outputs_prefix='AzureSentinel.IncidentEntity',
        xsoar_transformer=xsoar_transformer
    )


def list_incident_alerts_command(client, args):
    """
    Get a list of incident's alerts.

    :param client: (AzureSentinelClient) The Azure Sentinel client to work with.
    :param args:  (dict) arguments for this command.
    """
    return generic_list_incident_items(
        client=client, incident_id=args.get('incident_id'),
        items_kind='alerts', key_in_raw_result='value',
        outputs_prefix='AzureSentinel.IncidentAlert',
        xsoar_transformer=alert_data_to_xsoar_format
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
        incident_related_resource_data_to_xsoar_format(resource, inc_id) for resource in result.get('value')
    ]

    outputs = {f'AzureSentinel.IncidentRelatedResource(val.ID === obj.ID && val.IncidentID == {inc_id})': relations}

    update_next_link_in_context(result, outputs)

    readable_output = tableToMarkdown(f'Incident {inc_id} Relations ({len(relations)} results)', relations,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )


def update_next_link_in_context(result: dict, outputs: dict):
    """
    Update the output context with the next link if exist
    """
    # we don't want whitespaces in this value, so it won't be considered as two arguments in the CLI by mistake
    next_link = result.get('nextLink', '').replace(' ', '%20')
    if next_link:
        next_link_item = {
            'Description': NEXTLINK_DESCRIPTION,
            'URL': next_link,
        }
        outputs[f'AzureSentinel.NextLink(val.Description == "{NEXTLINK_DESCRIPTION}")'] = next_link_item


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
    command_result = list_incidents_command(client, command_args, is_fetch_incidents=True)
    items = command_result.outputs
    incidents = []
    current_fetch_ids = []

    for incident in items:
        incident_severity = severity_to_level(incident.get('Severity'))

        # fetch only incidents that weren't fetched in the last run and their severity is at least min_severity
        if incident.get('ID') not in last_fetch_ids and incident_severity >= min_severity:
            incident_created_time = dateparser.parse(incident.get('CreatedTimeUTC'))
            xsoar_incident = {
                'name': '[Azure Sentinel] ' + incident.get('Title'),
                'occurred': incident.get('CreatedTimeUTC'),
                'severity': incident_severity,
                'rawJSON': json.dumps(incident)
            }

            incidents.append(xsoar_incident)
            current_fetch_ids.append(incident.get('ID'))

            # Update last run to the latest fetch time
            if incident_created_time > latest_created_time:
                latest_created_time = incident_created_time

    next_run = {
        'last_fetch_time': latest_created_time.strftime(DATE_FORMAT),
        'last_fetch_ids': current_fetch_ids
    }
    return next_run, incidents


def threat_indicators_data_to_xsoar_format(ind_data):
    """
    Convert the threat indicators data from the raw to XSOAR format.

    :param ind_data: (dict) The incident raw data.
    """

    properties = ind_data.get('properties', {})
    pattern = properties.get('parsedPattern', [])[0]

    formatted_data = {
        'ID': ind_data.get('id'),
        'Name': ind_data.get('name'),
        'ETag': ind_data.get('etag'),
        'Type': ind_data.get('type'),
        'Kind': ind_data.get('kind'),

        'Confidence': properties.get('confidence', ''),
        'Created': format_date(properties.get('created', '')),
        'CreatedByRef': properties.get('createdByRef', ''),
        'ExternalId': properties.get('externalId', ''),
        'LastUpdatedTimeUtc': format_date(properties.get('lastUpdatedTimeUtc', '')),
        'Revoked': properties.get('revoked', ''),
        'Source': properties.get('source', ''),
        'Tags': properties.get('threatIntelligenceTags', 'No Tags'),
        'DisplayName': properties.get('displayName', ''),
        'Description': properties.get('description', ''),
        'Types': properties.get('threatTypes', ''),
        'KillChainPhases': [{
            'KillChainName': phase.get('killChainName'),
            'PhaseName': phase.get('phaseName')
        } for phase in properties.get('KillChainPhases', [])],

        'ParsedPattern': {
            'PatternTypeKey': pattern.get('patternTypeKey'),
            'PatternTypeValues': {
                'Value': pattern.get('patternTypeValues')[0].get('value'),
                'ValueType': pattern.get('patternTypeValues')[0].get('valueType')
            }
        },

        'Pattern': properties.get('pattern', ''),
        'PatternType': properties.get('patternType', ''),
        'ValidFrom': format_date(properties.get('validFrom', '')),
        'ValidUntil': format_date(properties.get('validUntil', '')),
        'Values': pattern.get('patternTypeValues')[0].get('value'),
        'Deleted': False
    }
    remove_nulls_from_dictionary(formatted_data)

    return formatted_data


def build_query_filter(args):
    filtering_args = {
        'minConfidence': args.get('min_confidence', ''),
        'maxConfidence': args.get('max_confidence', ''),
        'minValidUntil': format_date(args.get('min_valid_from', '')),
        'maxValidUntil': format_date(args.get('max_valid_from', '')),
        'sources': argToList(args.get('sources')),
        'keywords': argToList(args.get('keywords')),
        'threatTypes': argToList(args.get('threat_types')),
        'patternTypes': []
    }

    indicator_types = argToList(args.get('indicator_types'))
    if indicator_types:
        for ind_type in indicator_types:
            if ind_type == 'ipv4':
                filtering_args['patternTypes'].append('ipv4-address')
            elif ind_type == 'ipv6':
                filtering_args['patternTypes'].append('ipv6-address')
            elif ind_type == 'domain':
                filtering_args['patternTypes'].append('domain-name')
            else:
                filtering_args['patternTypes'].append(ind_type)

    include_disabled = args.get('include_disabled', 'false') == 'true'
    filtering_args['includeDisabled'] = include_disabled

    remove_nulls_from_dictionary(filtering_args)

    return filtering_args


def build_threat_indicator_data(args):
    value = args.get('value')

    data = {
        'patternType': value,
        'displayName': args.get('display_name'),
        'description': args.get('description'),
        'revoked': args.get('revoked', ''),
        'confidence': arg_to_number(args.get('confidence')),
        'threatTypes': argToList(args.get('threat_types')),
        'includeDisabled': args.get('include_disabled', ''),
        'source': DEFAULT_SOURCE,
        'threatIntelligenceTags': argToList(args.get('tags')),
        'validFrom': format_date(args.get('valid_from', '')),
        'validUntil': format_date(args.get('valid_until', '')),
        'createdByRef': args.get('created_by', ''),
    }

    indicator_type = args.get('indicator_type')
    if indicator_type == 'ipv4':
        indicator_type = 'ipv4-address'
    elif indicator_type == 'ipv6':
        indicator_type = 'ipv6-address'
    elif indicator_type == 'domain':
        indicator_type = 'domain-name'

    data['patternTypes'] = indicator_type

    if indicator_type == 'file':
        hash_type = args.get('hash_type')
        data['hashType'] = hash_type
        data['pattern'] = f"[file:hashes.'{hash_type}' = {value}]"
    else:
        data['pattern'] = f'[{indicator_type}:value = {value}]'

    data['killChainPhases'] = []

    kill_chains = argToList(args.get('kill_chains', []))
    if kill_chains:
        for kill_chain_phase in kill_chains:
            data['killChainPhases'].append(
                {'killChainName': kill_chain_phase,
                 'phaseName': kill_chain_phase})

    remove_nulls_from_dictionary(data)

    return data


def build_updated_indicator_data(new_ind_data, original_ind_data):
    original_extracted_data = extract_original_data_from_indicator(original_ind_data.get('properties'))
    new_data = build_threat_indicator_data(new_ind_data)

    original_extracted_data.update(new_data)

    return original_extracted_data


def extract_original_data_from_indicator(original_data):
    extracted_data = {
        'description': original_data.get('description', ''),
        'revoked': original_data.get('revoked', ''),
        'confidence': arg_to_number(original_data.get('confidence')),
        'threatTypes': argToList(original_data.get('threatTypes')),
        'killChainPhases': argToList(original_data.get('killChainPhases')),
        'threatIntelligenceTags': argToList(original_data.get('threatIntelligenceTags')),
        'validFrom': original_data.get('validFrom', ''),
        'validUntil': original_data.get('validUntil', ''),
        'createdByRef': original_data.get('createdByRef', ''),
        'created': original_data.get('created', ''),
        'externalId': original_data.get('externalId'),
        'displayName': original_data.get('displayName'),
        'source': original_data.get('source')
    }

    remove_nulls_from_dictionary(extracted_data)
    return extracted_data


def list_threat_indicator_command(client, args):
    url_suffix = 'threatIntelligence/main/indicators'
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))  # the default limit is 50

    next_link = args.get('next_link', '')
    if next_link:
        next_link = next_link.replace('%20', ' ')  # OData syntax can't handle '%' character
        result = client.http_request('GET', full_url=next_link)
    else:
        indicator_name = args.get('indicator_name')
        if indicator_name:
            url_suffix += f'/{indicator_name}'

        result = client.http_request('GET', url_suffix, params={'$top': limit})

    num_of_threat_indicators = 0
    threat_indicators = []

    if result.get('value'):
        threat_indicators = [threat_indicators_data_to_xsoar_format(ind) for ind in result.get('value')]
        num_of_threat_indicators = len(threat_indicators)

    outputs = {'AzureSentinel.ThreatIndicator': threat_indicators}
    update_next_link_in_context(result, outputs)

    readable_output = tableToMarkdown(
        f'Threat Indicators ({num_of_threat_indicators} results)',
        threat_indicators,
        headers=THREAT_INDICATORS_HEADERS,
        headerTransform=pascalToSpace,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        outputs_key_field='ID',
        raw_response=result
    )


def query_threat_indicators_command(client, args):
    url_suffix = 'threatIntelligence/main/queryIndicators'
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))  # the default limit is 50
    data = build_query_filter(args)
    next_link = args.get('next_link', '')
    if next_link:
        next_link = next_link.replace('%20', ' ')  # OData syntax can't handle '%' character
        result = client.http_request('POST', full_url=next_link, data=data)
    else:

        result = client.http_request('POST', url_suffix, params={'$top': limit}, data=data)

    num_of_threat_indicators = 0
    threat_indicators = []

    if result.get('value') is not None:
        threat_indicators = [threat_indicators_data_to_xsoar_format(ind) for ind in result.get('value')]
        num_of_threat_indicators = len(threat_indicators)

    outputs = {'AzureSentinel.ThreatIndicator': threat_indicators}
    update_next_link_in_context(result, outputs)

    readable_output = tableToMarkdown(
        f'Threat Indicators ({num_of_threat_indicators} results)',
        threat_indicators,
        headers=THREAT_INDICATORS_HEADERS,
        headerTransform=pascalToSpace,
        removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        outputs_key_field='ID',
        raw_response=result
    )


def create_threat_indicator_command(client, args):
    url_suffix = 'threatIntelligence/main/createIndicator'

    data = {'kind': 'indicator', 'properties': build_threat_indicator_data(args)}

    result = client.http_request('POST', url_suffix, data=data)

    threat_indicators = [threat_indicators_data_to_xsoar_format(result)]

    readable_output = tableToMarkdown('New threat Indicator was created', threat_indicators,
                                      headers=THREAT_INDICATORS_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.ThreatIndicator',
        outputs=threat_indicators,
        outputs_key_field='ID',
        raw_response=result
    )


def update_threat_indicator_command(client, args):
    indicator_name = args.get('indicator_name')
    get_indicator_url_suffix = f'threatIntelligence/main/indicators/{indicator_name}'

    original_data = client.http_request('GET', get_indicator_url_suffix)

    updated_data = build_updated_indicator_data(args, original_data)

    data = {
        "kind": "indicator",
        "properties": updated_data
    }

    update_indicator_url_suffix = f'threatIntelligence/main/indicators/{indicator_name}'

    result = client.http_request('PUT', update_indicator_url_suffix, data=data)
    threat_indicators = [threat_indicators_data_to_xsoar_format(result)]

    readable_output = tableToMarkdown(f'Threat Indicator {indicator_name} was updated',
                                      threat_indicators,
                                      headers=THREAT_INDICATORS_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.ThreatIndicator',
        outputs=threat_indicators,
        outputs_key_field='ID',
        raw_response=result
    )


def delete_threat_indicator_command(client, args):
    indicator_names = argToList(args.get('indicator_names'))
    outputs = []

    for indicator_name in indicator_names:
        url_suffix = f'threatIntelligence/main/indicators/{indicator_name}'
        client.http_request('DELETE', url_suffix)
        outputs.append({
            'Name': indicator_name,
            'Deleted': True
        })

    return CommandResults(
        readable_output='Threat Intelligence Indicators ' + ', '.join(indicator_names)
                        + ' were deleted successfully',
        outputs_prefix='AzureSentinel.ThreatIndicator',
        outputs_key_field='Name',
        outputs=outputs,
        raw_response={},
    )


def append_tags_threat_indicator_command(client, args):
    indicator_name = args.get('indicator_name')
    tags = argToList(args.get('tags'))
    url_suffix = f'threatIntelligence/main/indicators/{indicator_name}/appendTags'

    data = {'threatIntelligenceTags': tags}

    result = client.http_request('POST', url_suffix, data=data)

    threat_indicators = [threat_indicators_data_to_xsoar_format(result)]

    return CommandResults(
        readable_output=f'Tags were appended to {indicator_name} Threat Indicator.',
        outputs_prefix='AzureSentinel.ThreatIndicator',
        outputs=threat_indicators,
        outputs_key_field='ID',
        raw_response=result
    )


def replace_tags_threat_indicator_command(client, args):
    indicator_name = args.get('indicator_name')
    tags = argToList(args.get('tags'))
    url_suffix = f'threatIntelligence/main/indicators/{indicator_name}/replaceTags'

    data = {
        "properties": {
            'threatIntelligenceTags': tags
        }
    }

    result = client.http_request('POST', url_suffix, data=data)

    threat_indicators = [threat_indicators_data_to_xsoar_format(result)]

    return CommandResults(
        readable_output=f'Tags were replaced to {indicator_name} Threat Indicator.',
        outputs_prefix='AzureSentinel.ThreatIndicator',
        outputs=threat_indicators,
        outputs_key_field='ID',
        raw_response=result
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    LOG(f'Command being called is {demisto.command()}')
    try:
        client = AzureSentinelClient(
            server_url=params.get('server_url') or DEFAULT_AZURE_SERVER_URL,
            tenant_id=params.get('tenant_id', ''),
            client_id=params.get('credentials', {}).get('identifier'),
            client_secret=params.get('credentials', {}).get('password'),
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
            'azure-sentinel-incident-delete-comment': incident_delete_comment_command,
            'azure-sentinel-list-incident-relations': list_incident_relations_command,
            'azure-sentinel-list-incident-entities': list_incident_entities_command,
            'azure-sentinel-list-incident-alerts': list_incident_alerts_command,
            'azure-sentinel-list-watchlists': list_watchlists_command,
            'azure-sentinel-delete-watchlist': delete_watchlist_command,
            'azure-sentinel-watchlist-create-update': create_update_watchlist_command,
            'azure-sentinel-list-watchlist-items': list_watchlist_items_command,
            'azure-sentinel-delete-watchlist-item': delete_watchlist_item_command,
            'azure-sentinel-create-update-watchlist-item': create_update_watchlist_item_command,
            'azure-sentinel-threat-indicator-list': list_threat_indicator_command,
            'azure-sentinel-threat-indicator-query': query_threat_indicators_command,
            'azure-sentinel-threat-indicator-create': create_threat_indicator_command,
            'azure-sentinel-threat-indicator-update': update_threat_indicator_command,
            'azure-sentinel-threat-indicator-delete': delete_threat_indicator_command,
            'azure-sentinel-threat-indicator-tags-append': append_tags_threat_indicator_command,
            'azure-sentinel-threat-indicator-tags-replace': replace_tags_threat_indicator_command,
        }

        if demisto.command() == 'test-module':
            return_results(test_module(client))

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
            return_results(commands[demisto.command()](client, demisto.args()))  # type: ignore

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(
            f'Failed to execute {demisto.command()} command. Error: {str(e)}'
        )


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto  # noqa
from CommonServerPython import *  # noqa
from CommonServerUserPython import *  # noqa
# IMPORTS

import json
import urllib3
import requests
import dateparser
import uuid

from MicrosoftApiModule import *  # noqa: E402

# Disable insecure warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

''' CONSTANTS '''

APP_NAME = 'ms-azure-sentinel'

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DATE_FORMAT_WITH_MILLISECONDS = '%Y-%m-%dT%H:%M:%S.%fZ'

API_VERSION = '2024-03-01'

NEXT_LINK_DESCRIPTION = 'NextLink for listing commands'

XSOAR_USER_AGENT = 'SentinelPartner-PaloAltoNetworks-CortexXsoar/1.0.0'

AUTHORIZATION_ERROR_MSG = 'There was a problem in retrieving an updated access token.\n' \
                          'The response from the server did not contain the expected content.'

INCIDENT_HEADERS = ['ID', 'IncidentNumber', 'Title', 'Description', 'Severity', 'Status', 'IncidentUrl', 'ProviderIncidentUrl',
                    'AssigneeName', 'AssigneeEmail', 'AssigneeObjectID', 'AssigneeUPN', 'Label', 'FirstActivityTimeUTC',
                    'LastActivityTimeUTC', 'LastModifiedTimeUTC', 'CreatedTimeUTC', 'AlertsCount', 'BookmarksCount',
                    'CommentsCount', 'AlertProductNames', 'Tactics', 'FirstActivityTimeGenerated',
                    'LastActivityTimeGenerated']

COMMENT_HEADERS = ['ID', 'IncidentID', 'Message', 'AuthorName', 'AuthorEmail', 'CreatedTimeUTC']

ENTITIES_RETENTION_PERIOD_MESSAGE = '\nNotice that in the current Azure Sentinel API version, the retention period ' \
                                    'for GetEntityByID is 30 days.'

DEFAULT_LIMIT = 20

DEFAULT_SOURCE = 'Microsoft Sentinel'

THREAT_INDICATORS_HEADERS = ['Name', 'DisplayName', 'Values', 'Types', 'Source', 'Confidence', 'Tags']

# =========== Mirroring Mechanism Globals ===========

MIRROR_DIRECTION_DICT = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}

MIRROR_STATUS_DICT = {
    'Undetermined': 'Other',
    'TruePositive': 'Resolved',
    'BenignPositive': 'Resolved',
    'FalsePositive': 'False Positive',
}

MIRROR_DIRECTION = MIRROR_DIRECTION_DICT.get(demisto.params().get('mirror_direction'))
INTEGRATION_INSTANCE = demisto.integrationInstance()

INCOMING_MIRRORED_FIELDS = ['ID', 'Etag', 'Title', 'Description', 'Severity', 'Status', 'owner', 'tags', 'FirstActivityTimeUTC',
                                  'LastActivityTimeUTC', 'LastModifiedTimeUTC', 'CreatedTimeUTC', 'IncidentNumber', 'AlertsCount',
                                  'AlertProductNames', 'Tactics', 'relatedAnalyticRuleIds', 'IncidentUrl', 'ProviderIncidentUrl',
                                  'classification', 'classificationReason', 'classificationComment', 'alerts', 'entities',
                                  'comments', 'relations']

OUTGOING_MIRRORED_FIELDS = {'etag', 'title', 'description', 'severity', 'status', 'tags', 'firstActivityTimeUtc',
                            'lastActivityTimeUtc', 'classification', 'classificationComment', 'classificationReason'}
OUTGOING_MIRRORED_FIELDS = {filed: pascalToSpace(filed) for filed in OUTGOING_MIRRORED_FIELDS}

LEVEL_TO_SEVERITY = {0: 'Informational', 0.5: 'Informational', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'High'}
CLASSIFICATION_REASON = {'TruePositive': 'SuspiciousActivity', 'BenignPositive': 'SuspiciousButExpected'}


class AzureSentinelClient:
    def __init__(self, tenant_id: str, client_id: str,
                 client_secret: str, subscription_id: str,
                 resource_group_name: str, workspace_name: str, certificate_thumbprint: Optional[str],
                 private_key: Optional[str], verify: bool = True, proxy: bool = False,
                 managed_identities_client_id: Optional[str] = None,
                 azure_cloud: Optional[AzureCloud] = None):
        """
        AzureSentinelClient class that make use client credentials for authorization with Azure.

        :type azure_cloud: ``AzureCloud | None``
        :param azure_cloud: The Azure Cloud settings.

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

        :type certificate_thumbprint: ``str``
        :param certificate_thumbprint: The certificate thumbprint as appears in the AWS GUI.

        :type private_key: ``str``
        :param private_key: The certificate private key.

        :type verify: ``bool``
        :param verify: Whether the request should verify the SSL certificate.

        :type proxy: ``bool``
        :param proxy: Whether to run the integration using the system proxy.

        :type managed_identities_client_id: ``str``
        :param managed_identities_client_id: The Azure Managed Identities client id.
        """

        self.azure_cloud = azure_cloud or AZURE_WORLDWIDE_CLOUD
        base_url = urljoin(self.azure_cloud.endpoints.resource_manager, f'subscriptions/{subscription_id}/'
                           f'resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/'
                           f'{workspace_name}/providers/Microsoft.SecurityInsights')
        self._client = MicrosoftClient(
            tenant_id=tenant_id,
            auth_id=client_id,
            enc_key=client_secret,
            self_deployed=True,
            grant_type=CLIENT_CREDENTIALS,
            scope=urljoin(self.azure_cloud.endpoints.resource_manager, '.default'),
            ok_codes=(200, 201, 202, 204),
            verify=verify,
            proxy=proxy,
            azure_cloud=self.azure_cloud,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=self.azure_cloud.endpoints.resource_manager,
            base_url=base_url,
            command_prefix="azure-sentinel",
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


def get_error_kind(code):
    """
    Get the kind of the error based on the http error code.
    """
    return {
        400: 'BadRequest',
        401: 'UnAuthorized',
        403: 'Forbidden',
        404: 'NotFound',
    }.get(code)


def error_handler(response: requests.Response):
    """
    raise informative exception in case of error response
    """
    if response.status_code in (400, 401, 403, 404):
        try:
            error_json = response.json()
        except json.JSONDecodeError:
            error_json = {
                'error': {
                    'code': get_error_kind(code=response.status_code),
                    'message': response.text
                }
            }
        error_kind = error_json.get('error', {}).get('code', 'BadRequest')
        error_msg = error_json.get('error', {}).get('message', error_json)
        raise ValueError(
            f'[{error_kind} {response.status_code}] {error_msg}'
        )


def format_date(date):
    if not date:
        return None
    return dateparser.parse(date).strftime(DATE_FORMAT)  # type:ignore


def incident_data_to_xsoar_format(inc_data, is_fetch_incidents=False):
    """
    Convert the incident data from the raw to XSOAR format.

    :param inc_data: (dict) The incident raw data.
    :param is_fetch_incidents: (bool) Is it part of a fetch incidents command.
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
        'AssigneeObjectID': properties.get('owner', {}).get('objectId'),
        'AssigneeUPN': properties.get('owner', {}).get('userPrincipalName'),
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
        'ProviderIncidentUrl': properties.get('additionalData', {}).get('providerIncidentUrl'),
        'Tactics': properties.get('additionalData', {}).get('tactics'),
        'Techniques': properties.get('additionalData', {}).get('techniques'),
        'FirstActivityTimeGenerated': format_date(properties.get('firstActivityTimeGenerated')),
        'LastActivityTimeGenerated': format_date(properties.get('lastActivityTimeGenerated')),
        'Etag': inc_data.get('etag'),
        'Deleted': False
    }
    if is_fetch_incidents:
        formatted_data |= {
            'tags': [label.get('labelName') for label in properties.get('labels', [])],
            'owner': properties.get('owner'),
            'relatedAnalyticRuleIds': [rule_id.split('/')[-1] for rule_id in properties.get('relatedAnalyticRuleIds', [])],
            "classification": properties.get('classification'),
            "classificationComment": properties.get('classificationComment'),
            "classificationReason": properties.get('classificationReason')
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
        'Technique': properties.get('additionalData', {}).get('MitreTechniques'),
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
    assignee_objectid = args.get('assignee_objectid')
    user_principal_name = args.get('user_principal_name')
    labels = argToList(args.get('labels', ''))
    unassign = args.get('unassign')
    owner = demisto.get(fetched_incident_data, 'properties.owner', {})

    if not title:
        title = demisto.get(fetched_incident_data, 'properties.title')
    if not description:
        description = demisto.get(fetched_incident_data, 'properties.description')
    if not severity:
        severity = demisto.get(fetched_incident_data, 'properties.severity')
    if not status:
        status = demisto.get(fetched_incident_data, 'properties.status')
    if unassign == 'true':
        owner = {}
    elif assignee_objectid:
        owner = {'objectId': assignee_objectid}
    else:
        if user_principal_name:
            owner = {'userPrincipalName': user_principal_name}
        if assignee_email:
            owner['email'] = assignee_email

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
            'owner': owner
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


''' MIRRORING COMMANDS '''


def add_mirroring_fields(incident: Dict):
    """
        Updates the given incident to hold the needed mirroring fields.
    """
    incident['mirror_direction'] = MIRROR_DIRECTION
    incident['mirror_instance'] = INTEGRATION_INSTANCE


def get_modified_remote_data_command(client: AzureSentinelClient, args: Dict[str, Any]) -> GetModifiedRemoteDataResponse:
    """
    Gets the modified remote incidents IDs.
    Args:
        client: The client object.
        args: The command arguments.

    Returns:
        GetModifiedRemoteDataResponse object, which contains a list of the modified incidents IDs.
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = dateparser.parse(remote_args.last_update, settings={'TIMEZONE': 'UTC'}).strftime(  # type: ignore[union-attr]
        DATE_FORMAT_WITH_MILLISECONDS)
    demisto.debug(f'Getting modified incidents from {last_update}')

    raw_incidents = []

    next_link = True
    while next_link:
        full_url = next_link if isinstance(next_link, str) else None
        params = None if full_url else {'$filter': f'properties/lastModifiedTimeUtc ge {last_update}'}

        response = client.http_request('GET', 'incidents', full_url=full_url, params=params)
        raw_incidents += response.get('value', [])
        next_link = response.get('nextLink')

    modified_ids_to_mirror = [raw_incident.get('name') for raw_incident in raw_incidents]

    demisto.debug(f'All ids to mirror in are: {modified_ids_to_mirror}')
    return GetModifiedRemoteDataResponse(modified_ids_to_mirror)


def get_remote_incident_data(client: AzureSentinelClient, incident_id: str):
    """
    Gets the remote incident data.
    Args:
        client: The client object.
        incident_id: The incident ID to retrieve.

    Returns:
        mirrored_data: The raw mirrored data.
        updated_object: The updated object to set in the XSOAR incident.
    """
    mirrored_data = client.http_request('GET', f'incidents/{incident_id}')
    incident_mirrored_data = incident_data_to_xsoar_format(mirrored_data, is_fetch_incidents=True)
    fetch_incidents_additional_info(client, incident_mirrored_data)
    updated_object: Dict[str, Any] = {}

    for field in INCOMING_MIRRORED_FIELDS:
        value = incident_mirrored_data.get(field)
        if value is not None:
            updated_object[field] = value

    return mirrored_data, updated_object


def set_xsoar_incident_entries(updated_object: Dict[str, Any], entries: List, remote_incident_id: str) -> None:
    """
    Sets the XSOAR incident entries.
    Args:
        updated_object: The updated object to set in the XSOAR incident.
        entries: The entries to set.
        remote_incident_id: The remote incident ID.
    Returns:
        None.
    """
    if demisto.params().get('close_incident'):
        if updated_object.get('Status') == 'Closed':
            close_reason = updated_object.get('classification', '')
            close_notes = updated_object.get('classificationComment', '')
            close_in_xsoar(entries, remote_incident_id, close_reason, close_notes)
        elif updated_object.get('Status') in ('New', 'Active'):
            reopen_in_xsoar(entries, remote_incident_id)


def close_in_xsoar(entries: List, remote_incident_id: str, close_reason: str, close_notes: str) -> None:
    demisto.debug(f'Incident is closed: {remote_incident_id}')
    entries.append({
        'Type': EntryType.NOTE,
        'Contents': {
            'dbotIncidentClose': True,
            'closeReason': MIRROR_STATUS_DICT.get(close_reason, close_reason),
            'closeNotes': f'{close_notes}\nClosed on Microsoft Sentinel'.strip()
        },
        'ContentsFormat': EntryFormat.JSON
    })


def reopen_in_xsoar(entries: List, remote_incident_id: str):
    demisto.debug(f'Incident is opened (or reopened): {remote_incident_id}')
    entries.append({
        'Type': EntryType.NOTE,
        'Contents': {
            'dbotIncidentReopen': True
        },
        'ContentsFormat': EntryFormat.JSON
    })


def get_remote_data_command(client: AzureSentinelClient, args: Dict[str, Any]) -> GetRemoteDataResponse:
    """
    Args:
        client: The client object.
        args: The command arguments.
    Returns:
        GetRemoteDataResponse object, which contain the incident data to update.
    """
    remote_args = GetRemoteDataArgs(args)
    remote_incident_id = remote_args.remote_incident_id

    mirrored_data: Dict[str, Any] = {}
    entries: list = []

    try:
        demisto.debug(f'Performing get-remote-data command with incident id: {remote_incident_id} '
                      f'and last_update: {remote_args.last_update}')

        mirrored_data, updated_object = get_remote_incident_data(client, remote_incident_id)
        if updated_object:
            demisto.debug(f'Update incident {remote_incident_id} with fields: {updated_object}')
            set_xsoar_incident_entries(updated_object, entries, remote_incident_id)

        return GetRemoteDataResponse(mirrored_object=updated_object, entries=entries)

    except Exception as e:
        demisto.debug(f"Error in Microsoft Sentinel incoming mirror for incident: {remote_incident_id}\n"
                      f"Error message: {str(e)}")

        if not mirrored_data:
            mirrored_data = {'id': remote_incident_id}
        mirrored_data['in_mirror_error'] = str(e)

        return GetRemoteDataResponse(mirrored_object=mirrored_data, entries=[])


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    mapping_response = GetMappingFieldsResponse()
    incident_type_scheme = SchemeTypeMapping(type_name='Microsoft Sentinel Incident')

    for argument, description in OUTGOING_MIRRORED_FIELDS.items():
        incident_type_scheme.add_field(name=argument, description=description)
    mapping_response.add_scheme_type(incident_type_scheme)

    return mapping_response


def close_incident_in_remote(delta: Dict[str, Any], data: Dict[str, Any]) -> bool:
    """
    Closing in the remote system should happen only when both:
        1. The user asked for it
        2. A closing reason was provided (either in the delta or before in the data).
    """
    closing_field = 'classification'
    closing_reason = delta.get(closing_field, data.get(closing_field, ''))
    return demisto.params().get('close_ticket') and bool(closing_reason)


def extract_classification_reason(delta: Dict[str, str], data: Dict[str, str]):
    """
    Returns the classification reason based on `delta` and `data`.

    Args:
        delta (dict): Contains potential 'classification' and 'classificationReason' keys.
        data (dict): Default classification information, with 'classification' and 'classificationReason'.

    Returns:
        The resolved classification reason.
    """

    classification: str = delta.get("classification", "") or data.get(
        "classification", ""
    )
    if classification == "FalsePositive":
        return delta.get("classificationReason") or data.get(
            "classificationReason", "InaccurateData"
        )
    return CLASSIFICATION_REASON.get(classification, "")


def update_incident_request(client: AzureSentinelClient, incident_id: str, data: Dict[str, Any], delta: Dict[str, Any],
                            close_ticket: bool = False) -> Dict[str, Any]:
    """
    Args:
        client (AzureSentinelClient)
        incident_id (str): the incident ID
        data (Dict[str, Any]): all the data of the incident
        delta (Dict[str, Any]): the delta of the changes in the incident's data
        close_ticket (bool, optional): whether to close the ticket or not (defined by the close_incident_in_remote).
                                       Defaults to False.

    Returns:
        Dict[str, Any]: the response of the update incident request
    """

    fetched_incident_data = get_incident_by_id_command(client, {'incident_id': incident_id}).raw_response
    required_fields = ('severity', 'status', 'title')
    if any(field not in data for field in required_fields):
        raise DemistoException(f'Update incident request is missing one of the required fields for the '
                               f'API: {required_fields}')

    severity = data.get('severity', '')
    status = data.get('status', 'Active')
    if status == 'Closed' and delta.get('closingUserId') == '':
        # closingUserId='' it's mean the XSOAR incident was reopen
        # need to update the remote incident status to Active
        demisto.debug(f'Reopen remote incident {incident_id}, set status to Active')
        status = 'Active'
    properties = {
        'title': data.get('title'),
        'description': delta.get('description'),
        'severity': severity if severity in LEVEL_TO_SEVERITY.values() else LEVEL_TO_SEVERITY[severity],
        'status': status,
        'firstActivityTimeUtc': delta.get('firstActivityTimeUtc'),
        'lastActivityTimeUtc': delta.get('lastActivityTimeUtc'),
        'owner': demisto.get(fetched_incident_data, 'properties.owner', {}),
        'labels': demisto.get(fetched_incident_data, 'properties.labels', [])
    }

    properties['labels'] += [{'labelName': label, 'type': 'User'} for label in delta.get('tags', [])]

    if close_ticket:
        properties |= {
            'status': 'Closed',
            'classification': delta.get('classification') or data.get('classification'),
            'classificationComment': delta.get('classificationComment') or data.get('classificationComment'),
            'classificationReason': extract_classification_reason(delta, data)
        }
    remove_nulls_from_dictionary(properties)
    data = {
        'etag': fetched_incident_data.get('etag') or delta.get('etag') or data.get('etag'),
        'properties': properties
    }
    demisto.debug(f'Updating incident with remote ID {incident_id} with data: {data}')
    response = client.http_request('PUT', f'incidents/{incident_id}', data=data)
    return response


def update_remote_incident(client: AzureSentinelClient, data: Dict[str, Any], delta: Dict[str, Any],
                           incident_status: IncidentStatus, incident_id: str) -> str:

    # we will run the mirror-out update only if there is relevant changes
    # (or closingUserId was changed meaning the incident wa reopened) or need to close the remote ticket
    relevant_keys_delta = OUTGOING_MIRRORED_FIELDS.keys() | {'closingUserId'}
    relevant_keys_delta &= delta.keys()
    # those fields are close incident fields and handled separately in close_incident_in_remote
    relevant_keys_delta -= {'classification', 'classificationComment'}

    if incident_status in (IncidentStatus.DONE, IncidentStatus.ACTIVE):
        if incident_status == IncidentStatus.DONE and close_incident_in_remote(delta, data):
            demisto.debug(f'XSOAR incident closed, closing incident with remote ID {incident_id} in remote system.')
            return str(update_incident_request(client, incident_id, data, delta, close_ticket=True))
        if relevant_keys_delta:
            demisto.debug(f'Updating incident with remote ID {incident_id} in remote system.')
            return str(update_incident_request(client, incident_id, data, delta))
        else:
            demisto.debug(f'No relevant changes detected for the incident with remote ID {incident_id}, not updating.')

    demisto.debug(f'Incident with remote ID {incident_id} is not Active or Closed, not updating. (status: {incident_status})')
    return ''


def update_remote_system_command(client: AzureSentinelClient, args: Dict[str, Any]):
    """ Mirrors out local changes to the remote system.
    Args:
        client: The client object.
        args: The command arguments.
    Returns:
        The remote incident id that was modified. This is important when the incident is newly created remotely.
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    delta = parsed_args.delta
    data = parsed_args.data
    remote_incident_id = parsed_args.remote_incident_id
    demisto.debug(f'Got the following data {data}, and delta {delta}.')
    if parsed_args.incident_changed and delta:
        demisto.debug(f'Got the following delta keys {list(delta.keys())}.')
        try:
            if result := update_remote_incident(
                client, data, delta, parsed_args.inc_status, remote_incident_id
            ):
                demisto.debug(f'Incident updated successfully. Result: {result}')

        except Exception as e:
            demisto.error(f'Error in Microsoft Sentinel outgoing mirror for incident {remote_incident_id}. '
                          f'Error message: {str(e)}')
    else:
        demisto.debug(f"Skipping updating remote incident {remote_incident_id} as it didn't change.")

    return remote_incident_id


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


def test_module(client: AzureSentinelClient, _: Dict[str, Any]):
    """
    Test connection to Azure by calling the list incidents API with limit=1
    """
    client.http_request('GET', 'incidents', params={'$top': 1})
    return 'ok'


def list_incidents_command(client: AzureSentinelClient, args, is_fetch_incidents=False):
    """ Retrieves incidents from Sentinel.
    Args:
        client: An AzureSentinelClient client.
        args: Demisto args.
        is_fetch_incidents: Is it part of a fetch incidents command.
    Returns:
        A CommandResult object with the array of incidents as output.
    """
    filter_expression = args.get('filter')
    limit = min(DEFAULT_LIMIT, int(args.get('limit')))
    next_link = args.get('next_link', '')

    if next_link:
        next_link = next_link.replace('%20', ' ')  # Next link syntax can't handle '%' character
        result = client.http_request('GET', full_url=next_link)
    else:
        url_suffix = 'incidents'
        params = {
            '$top': limit,
            '$filter': filter_expression,
            '$orderby': args.get('orderby', 'properties/createdTimeUtc asc')
        }
        remove_nulls_from_dictionary(params)

        result = client.http_request('GET', url_suffix, params=params)

    incidents = [incident_data_to_xsoar_format(inc, is_fetch_incidents) for inc in result.get('value')]

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
    limit = min(DEFAULT_LIMIT, int(args.get('limit')))
    next_link = args.get('next_link', '')

    if next_link:
        next_link = next_link.replace('%20', ' ')  # Next link syntax can't handle '%' character
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
        return {
            'ID': entity.get('name'),
            'Kind': entity.get('kind'),
            'Properties': entity.get('properties')
        }

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
        next_link = next_link.replace('%20', ' ')  # Next link syntax can't handle '%' character
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
            'Description': NEXT_LINK_DESCRIPTION,
            'URL': next_link,
        }
        outputs[f'AzureSentinel.NextLink(val.Description == "{NEXT_LINK_DESCRIPTION}")'] = next_link_item


def fetch_incidents_additional_info(client: AzureSentinelClient, incidents: List | Dict):
    """Fetches additional info of an incidents array or a single incident.

    Args:
        client: An AzureSentinelClient client.
        incidents: An incidents array or a single incident to fetch additional info for.

    Returns:
        None. Updates the incidents array with the additional info.
    """
    additional_fetch = {'Alerts': {'method': 'POST', 'result_key': 'value'},
                        'Entities': {'method': 'POST', 'result_key': 'entities'},
                        'Comments': {'method': 'GET', 'result_key': 'value'},
                        'Relations': {'method': 'GET', 'result_key': 'value'}}

    if isinstance(incidents, dict):
        incidents = [incidents]

    for incident in incidents:
        for additional_info in demisto.params().get('fetch_additional_info', []):
            info_type = additional_info.lower()
            method = additional_fetch[additional_info]['method']
            results_key = additional_fetch[additional_info]['result_key']
            incident_id = incident.get('ID')

            incident[info_type] = client.http_request(method, f'incidents/{incident_id}/{info_type}').get(results_key)


def fetch_incidents(client: AzureSentinelClient, last_run: dict, first_fetch_time: str, min_severity: int) -> tuple:
    """Fetching incidents.
    Args:
        first_fetch_time: The first fetch time.
        client: An AzureSentinelClient client.
        last_run: An dictionary of the last run.
        min_severity: A minimum severity of incidents to fetch.

    Returns:
        (tuple): 1. The LastRun object updated with the last run details.
        2. An array of incidents.

    """
    # Get the last fetch details, if exist
    limit = demisto.params().get("limit", DEFAULT_LIMIT)
    last_fetch_time = last_run.get('last_fetch_time')
    last_fetch_ids = last_run.get('last_fetch_ids', [])
    last_incident_number = last_run.get('last_incident_number')
    demisto.debug(f"{last_fetch_time=}, {last_fetch_ids=}, {last_incident_number=}")

    if last_fetch_time is None or not last_incident_number:
        demisto.debug("handle via timestamp")
        if last_fetch_time is None:
            last_fetch_time_str, _ = parse_date_range(first_fetch_time, DATE_FORMAT)
            latest_created_time = dateparser.parse(last_fetch_time_str)
            if not latest_created_time:
                raise DemistoException(f'Got empty latest_created_time. {last_fetch_time_str=} {last_fetch_time=}')
        else:
            latest_created_time = dateparser.parse(last_fetch_time)
            if not latest_created_time:
                raise DemistoException(f'Got empty latest_created_time. {last_fetch_time=}')

        latest_created_time_str = latest_created_time.strftime(DATE_FORMAT)
        command_args = {
            'filter': f'properties/createdTimeUtc ge {latest_created_time_str}',
            'orderby': 'properties/createdTimeUtc asc',
            'limit': limit
        }

    else:
        demisto.debug("last fetch time is empty, trying to fetch incidents by last incident id")
        latest_created_time = dateparser.parse(last_fetch_time)
        if latest_created_time is None:
            raise DemistoException(f"{last_fetch_time=} couldn't be parsed")
        command_args = {
            'filter': f'properties/incidentNumber gt {last_incident_number}',
            'orderby': 'properties/incidentNumber asc',
            'limit': limit
        }

    raw_incidents = list_incidents_command(client, command_args, is_fetch_incidents=True).outputs
    if isinstance(raw_incidents, dict):
        raw_incidents = [raw_incidents]
    demisto.debug(f"raw incidents id before dedup: {[incident['ID'] for incident in raw_incidents]}")
    raw_incidents = list(filter(lambda incident: incident['ID'] not in last_fetch_ids, raw_incidents))
    demisto.debug(f"raw incidents id after dedup: {[incident['ID'] for incident in raw_incidents]}")

    fetch_incidents_additional_info(client, raw_incidents)

    return process_incidents(raw_incidents, min_severity,
                             latest_created_time, last_incident_number)  # type: ignore[attr-defined]


def fetch_incidents_command(client, params):
    # How much time before the first fetch to retrieve incidents
    first_fetch_time = params.get('fetch_time', '3 days').strip()
    min_severity = severity_to_level(params.get('min_severity', 'Informational'))
    # Set and define the fetch incidents command to run after activated via integration settings.
    last_run = demisto.getLastRun()
    demisto.debug(f"Current last run is {last_run}")
    next_run, incidents = fetch_incidents(
        client=client,
        last_run=last_run,
        first_fetch_time=first_fetch_time,
        min_severity=min_severity
    )
    demisto.debug(f"New last run is {last_run}")
    demisto.setLastRun(next_run)
    demisto.incidents(incidents)


def process_incidents(raw_incidents: list, min_severity: int, latest_created_time: datetime,
                      last_incident_number):
    """Processing the raw incidents
    Args:
        raw_incidents: The incidents that were fetched from the API.
        last_incident_number: The last incident number that was fetched.
        latest_created_time: The latest created time.
        min_severity: The minimum severity.

    Returns:
        A next_run dictionary, and an array of incidents.
    """

    incidents = []
    current_fetch_ids = []
    if not last_incident_number:
        last_incident_number = 0

    for incident in raw_incidents:
        incident_severity = severity_to_level(incident.get('Severity'))
        demisto.debug(f"{incident.get('ID')=}, {incident_severity=}, {incident.get('IncidentNumber')=}")

        incident_created_time = dateparser.parse(incident.get('CreatedTimeUTC'))
        current_fetch_ids.append(incident.get('ID'))
        if incident_severity >= min_severity:
            add_mirroring_fields(incident)
            xsoar_incident = {
                'name': '[Azure Sentinel] ' + incident.get('Title'),
                'occurred': incident.get('CreatedTimeUTC'),
                'severity': incident_severity,
                'rawJSON': json.dumps(incident)
            }
            incidents.append(xsoar_incident)
        else:
            demisto.debug(f"drop creation of {incident.get('IncidentNumber')=} "
                          f"due to the {incident_severity=} is lower then {min_severity=}")

        # Update last run to the latest fetch time
        if incident_created_time is None:
            raise DemistoException(f"{incident.get('CreatedTimeUTC')=} couldn't be parsed")

        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time
        if incident.get('IncidentNumber') > last_incident_number:
            last_incident_number = incident.get('IncidentNumber')
    next_run = {
        'last_fetch_time': latest_created_time.strftime(DATE_FORMAT),
        'last_fetch_ids': current_fetch_ids,
        'last_incident_number': last_incident_number,
    }
    return next_run, incidents


def threat_indicators_data_to_xsoar_format(ind_data):
    """
    Convert the threat indicators data from the raw to XSOAR format.

    :param ind_data: (dict) The incident raw data.
    """

    properties = ind_data.get('properties', {})
    pattern = properties.get('parsedPattern', [])[0] if properties.get('parsedPattern', []) else {}

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
                'Value': dict_safe_get(pattern, ['patternTypeValues', 0, 'value']),
                'ValueType': dict_safe_get(pattern, ['patternTypeValues', 0, 'valueType']),
            }
        } if pattern else None,

        'Pattern': properties.get('pattern', ''),
        'PatternType': properties.get('patternType', ''),
        'ValidFrom': format_date(properties.get('validFrom', '')),
        'ValidUntil': format_date(properties.get('validUntil', '')),
        'Values': dict_safe_get(pattern, ['patternTypeValues', 0, 'value']),
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
        'keywords': ' '.join(argToList(args.get('keywords'))),
        'threatTypes': argToList(args.get('threat_types')),
        'patternTypes': []
    }

    indicator_types = argToList(args.get('indicator_types'))
    if indicator_types:
        for ind_type in indicator_types:
            pattern_type = {
                'ipv4': '{ind_type}-address',
                'ipv6': '{ind_type}-address',
                'domain': '{ind_type}-name',
            }.get(ind_type, "{ind_type}").format(ind_type=ind_type)
            filtering_args['patternTypes'].append(pattern_type)

    include_disabled = args.get('include_disabled', 'false') == 'true'
    filtering_args['includeDisabled'] = include_disabled

    remove_nulls_from_dictionary(filtering_args)

    return filtering_args


def build_threat_indicator_data(args, source):
    value = args.get('value')

    data = {
        'displayName': args.get('display_name'),
        'description': args.get('description'),
        'revoked': args.get('revoked', ''),
        'confidence': arg_to_number(args.get('confidence')),
        'threatTypes': argToList(args.get('threat_types')),
        'includeDisabled': args.get('include_disabled', ''),
        'source': source,
        'threatIntelligenceTags': argToList(args.get('tags')),
        'validFrom': format_date(args.get('valid_from', '')),
        'validUntil': format_date(args.get('valid_until', '')),
        'createdByRef': args.get('created_by', ''),
    }

    indicator_type = args.get('indicator_type')
    if indicator_type == 'ipv4':
        indicator_type = 'ipv4-addr'
    elif indicator_type == 'ipv6':
        indicator_type = 'ipv6-addr'
    elif indicator_type == 'domain':
        indicator_type = 'domain-name'

    data['patternType'] = indicator_type

    if indicator_type == 'file':
        hash_type = args.get('hash_type')
        data['hashType'] = hash_type
        data['pattern'] = f"[file:hashes.'{hash_type}' = '{value}']"
    else:
        data['pattern'] = f"[{indicator_type}:value = '{value}']"

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
    # When updating an indicator, one can not change the original source
    source = original_extracted_data.get('source')
    new_data = build_threat_indicator_data(new_ind_data, source)

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
        'source': original_data.get('source', DEFAULT_SOURCE)
    }

    remove_nulls_from_dictionary(extracted_data)
    return extracted_data


def list_threat_indicator_command(client, args):
    url_suffix = 'threatIntelligence/main/indicators'
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))  # the default limit is 50

    next_link = args.get('next_link', '')
    if next_link:
        next_link = next_link.replace('%20', ' ')  # Next link syntax can't handle '%' character
        result = client.http_request('GET', full_url=next_link)
    else:
        if indicator_name := args.get('indicator_name'):
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
        next_link = next_link.replace('%20', ' ')  # Next link syntax can't handle '%' character
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

    data = {'kind': 'indicator', 'properties': build_threat_indicator_data(args, source=DEFAULT_SOURCE)}

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


def list_alert_rule_command(client: AzureSentinelClient, args: Dict[str, Any]) -> CommandResults:
    limit = int(args.get('limit', 50))
    rule_id = args.get('rule_id')

    url_suffix = 'alertRules' + (f'/{rule_id}' if rule_id else '')

    raw_results: list = []
    next_link = True
    while next_link:
        full_url = next_link if isinstance(next_link, str) else None

        response = client.http_request('GET', url_suffix, full_url=full_url)

        raw_results += [response] if rule_id else response.get('value', [])

        next_link = response.get('nextLink')
        if len(raw_results) >= limit:
            next_link = False

    raw_results = raw_results[:limit]

    readable_result = [
        {
            'ID': rule.get('name'),
            'Kind': rule.get('kind'),
            'Severity': rule.get('properties', {}).get('severity'),
            'Display Name': rule.get('properties', {}).get('displayName'),
            'Description': rule.get('properties', {}).get('description'),
            'Enabled': rule.get('properties', {}).get('enabled')
        } for rule in raw_results]
    tabel_name = 'Azure Sentinel Alert Rules' + (f' ({len(raw_results)} results)' if len(raw_results) > 1 else '')
    readable_output = tableToMarkdown(tabel_name, readable_result, sort_headers=False)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.AlertRule',
        outputs=raw_results,
        outputs_key_field='name',
        raw_response=raw_results
    )


def list_alert_rule_template_command(client: AzureSentinelClient, args: Dict[str, Any]) -> CommandResults:
    limit = int(args.get('limit', 50))
    template_id = args.get('template_id')

    url_suffix = 'alertRuleTemplates' + (f'/{template_id}' if template_id else '')

    raw_results: list = []
    next_link = True
    while next_link:
        full_url = next_link if isinstance(next_link, str) else None

        response = client.http_request('GET', url_suffix, full_url=full_url)

        raw_results += [response] if template_id else response.get('value', [])

        next_link = response.get('nextLink')
        if len(raw_results) >= limit:
            next_link = False

    raw_results = raw_results[:limit]

    readable_result = [
        {
            'ID': rule.get('name'),
            'Kind': rule.get('kind'),
            'Severity': rule.get('properties', {}).get('severity'),
            'Display Name': rule.get('properties', {}).get('displayName'),
            'Description': rule.get('properties', {}).get('description'),
            'Status': rule.get('properties', {}).get('status'),
            'Created Date UTC': rule.get('properties', {}).get('createdDateUTC'),
            'Last Updated Date UTC': rule.get('properties', {}).get('lastUpdatedDateUTC'),
            'Alert Rules Created By Template Count': rule.get('properties', {}).get('alertRulesCreatedByTemplateCount'),
        } for rule in raw_results]
    tabel_name = 'Azure Sentinel Alert Rule Template' + (f' ({len(raw_results)} results)' if len(raw_results) > 1 else '')
    readable_output = tableToMarkdown(tabel_name, readable_result, sort_headers=False)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.AlertRuleTemplate',
        outputs=raw_results,
        outputs_key_field='name',
        raw_response=raw_results
    )


def delete_alert_rule_command(client: AzureSentinelClient, args: Dict[str, Any]) -> CommandResults:
    rule_id = args.get('rule_id')
    url_suffix = f'alertRules/{rule_id}'
    response = client.http_request('DELETE', url_suffix)

    if isinstance(response, requests.Response) and response.status_code == 204:
        return CommandResults(readable_output=f'Alert rule {rule_id} does not exist.')

    return CommandResults(readable_output=f'Alert rule {rule_id} was deleted successfully.')


def list_subscriptions_command(client: AzureSentinelClient) -> CommandResults:      # pragma: no cover

    full_url = urljoin(client.azure_cloud.endpoints.resource_manager, 'subscriptions?api-version=2020-01-01')

    response = client.http_request('GET', full_url=full_url)
    data_from_response = response.get('value', [])

    readable_output = tableToMarkdown(
        'Azure Sentinel Subscriptions',
        data_from_response,
        ['subscriptionId', 'tenantId', 'displayName', 'state'], removeNull=True,
        headerTransform=string_to_table_header)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.Subscription',
        outputs=data_from_response,
        outputs_key_field='subscriptionId',
        raw_response=response
    )


def list_resource_groups_command(client: AzureSentinelClient,
                                 args: Dict[str, Any], subscription_id: str) -> CommandResults:     # pragma: no cover
    tag = args.get('tag')
    limit = arg_to_number(args.get('limit', 50))
    subscription_id = subscription_id

    # extracting the tag name and value from the tag argument that is received from the user as a string
    filter_by_tag = azure_tag_formatter(tag) if tag else ''

    full_url = urljoin(client.azure_cloud.endpoints.resource_manager, f'subscriptions/{subscription_id}/resourcegroups?$filter=\
{filter_by_tag}&$top={limit}&api-version=2021-04-01')

    response = client.http_request('GET', full_url=full_url)
    data_from_response = response.get('value', [])

    readable_output = tableToMarkdown(
        'Azure Sentinel Resource Groups',
        data_from_response,
        ['name', 'location', 'tags', 'properties.provisioningState'], removeNull=True,
        headerTransform=string_to_table_header)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.ResourceGroup',
        outputs=data_from_response,
        outputs_key_field='name',
        raw_response=response
    )


def validate_required_arguments_for_alert_rule(args: Dict[str, Any]) -> None:
    required_args_by_kind = {
        'fusion': ['rule_name', 'template_name', 'enabled'],
        'microsoft_security_incident_creation': ['rule_name', 'displayName', 'enabled', 'product_filter'],
        'scheduled': ['rule_name', 'displayName', 'enabled', 'query', 'query_frequency', 'query_period', 'severity',
                      'suppression_duration', 'suppression_enabled', 'trigger_operator', 'trigger_threshold']
    }

    kind = args.get('kind', '')
    if not kind:
        raise DemistoException('The "kind" argument is required for alert rule.')
    for arg in required_args_by_kind.get(kind, []):
        if not args.get(arg):
            raise DemistoException(f'"{arg}" is required for "{kind}" alert rule.')


def create_data_for_alert_rule(args: Dict[str, Any]) -> Dict[str, Any]:
    validate_required_arguments_for_alert_rule(args)

    properties = {
        'alertRuleTemplateName': args.get('template_name'),
        'enabled': argToBoolean(args.get('enabled')) if args.get('enabled') else None,
        'displayName': args.get('displayName'),
        'productFilter': string_to_table_header(args.get('product_filter', '')),
        'description': args.get('description'),
        'displayNamesExcludeFilter': args.get('name_exclude_filter'),
        'displayNamesFilter': args.get('name_include_filter'),
        'severitiesFilter': args.get('severity_filter'),
        'query': args.get('query'),
        'queryFrequency': args.get('query_frequency'),
        'queryPeriod': args.get('query_period'),
        'severity': pascalToSpace(args.get('severity')),
        'suppressionDuration': args.get('suppression_duration'),
        'suppressionEnabled': argToBoolean(args.get('suppression_enabled')) if args.get('suppression_enabled') else None,
        'triggerOperator': underscoreToCamelCase(args.get('trigger_operator')),
        'triggerThreshold': args.get('trigger_threshold'),
        'tactics': argToList(args.get('tactics')),
        'techniques': argToList(args.get('techniques'))
    }
    remove_nulls_from_dictionary(properties)

    return {
        'kind': underscoreToCamelCase(args.get('kind')),
        'etag': args.get('etag'),
        'properties': properties
    }


def create_and_update_alert_rule_command(client: AzureSentinelClient, args: Dict[str, Any]) -> CommandResults:
    rule_json = json.loads(args.get('rule_json', '')) if args.get('rule_json') else None
    data = rule_json or create_data_for_alert_rule(args)
    demisto.debug(f'Try to creating/updating alert rule with the following data: {data}')

    response = client.http_request('PUT', f'alertRules/{args.get("rule_name")}', data=data)

    readable_result = {
        'ID': response.get('id').split('/')[-1],
        'Name': response.get('name'),
        'Kind': response.get('kind'),
        'Severity': response.get('properties', {}).get('severity'),
        'Display Name': response.get('properties', {}).get('displayName'),
        'Description': response.get('properties', {}).get('description'),
        'Enabled': response.get('properties', {}).get('enabled'),
        'Etag': response.get('etag')
    }
    readable_output = tableToMarkdown('Azure Sentinel Alert Rule successfully created/updated',
                                      readable_result,
                                      removeNull=True,
                                      sort_headers=False)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.AlertRule',
        outputs=response,
        outputs_key_field='name',
        raw_response=response
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f'Command being called is {command}')
    try:
        client_secret = params.get('credentials', {}).get('password')
        certificate_thumbprint = params.get('creds_certificate', {}).get('identifier') or \
            params.get('certificate_thumbprint')
        private_key = (replace_spaces_in_credential(params.get('creds_certificate', {}).get('password'))
                       or params.get('private_key'))
        managed_identities_client_id = get_azure_managed_identities_client_id(params)
        if not managed_identities_client_id and not client_secret and not (certificate_thumbprint and private_key):
            raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.')

        tenant_id = params.get('creds_tenant_id', {}).get('password', '') or params.get('tenant_id', '')

        if not tenant_id:
            raise ValueError('Tenant ID must be provided.')

        subscription_id = args.get('subscription_id') or params.get('subscriptionID', '')
        resource_group_name = args.get('resource_group_name') or params.get('resourceGroupName', '')

        client = AzureSentinelClient(
            azure_cloud=get_azure_cloud(params, 'AzureSentinel'),
            tenant_id=tenant_id,
            client_id=params.get('credentials', {}).get('identifier'),
            client_secret=client_secret,
            subscription_id=subscription_id,
            resource_group_name=resource_group_name,
            workspace_name=params.get('workspaceName', ''),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            managed_identities_client_id=managed_identities_client_id
        )

        commands = {
            'test-module': test_module,
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
            'azure-sentinel-list-alert-rule': list_alert_rule_command,
            'azure-sentinel-list-alert-rule-template': list_alert_rule_template_command,
            'azure-sentinel-delete-alert-rule': delete_alert_rule_command,
            'azure-sentinel-create-alert-rule': create_and_update_alert_rule_command,
            'azure-sentinel-update-alert-rule': create_and_update_alert_rule_command,
            # mirroring commands
            'get-modified-remote-data': get_modified_remote_data_command,
            'get-remote-data': get_remote_data_command,
            'update-remote-system': update_remote_system_command
        }

        if command == 'fetch-incidents':
            fetch_incidents_command(client, params)

        # mirroring command
        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command())
        elif command == 'azure-sentinel-subscriptions-list':
            return_results(list_subscriptions_command(client))
        elif command == 'azure-sentinel-resource-group-list':
            return_results(list_resource_groups_command(client, args, subscription_id))
        elif command == 'azure-sentinel-auth-reset':
            return_results(reset_auth())

        elif command in commands:
            return_results(commands[command](client, args))  # type: ignore

    except Exception as e:
        return_error(
            f'Failed to execute {command} command. Error: {str(e)}'
        )


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

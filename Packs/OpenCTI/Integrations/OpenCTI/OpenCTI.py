from pycti import OpenCTIApiClient, Identity
import urllib3
import sys
from io import StringIO
import copy
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


demisto.debug('pack name = ITX - OpenCTI, pack version = 1.0.0')


# Disable insecure warnings
urllib3.disable_warnings()

# Disable info logging from the api
logging.getLogger().setLevel(logging.ERROR)

XSOAR_TYPES_TO_OPENCTI = {
    'account': "User-Account",
    'domain': "Domain-Name",
    'email': "Email-Addr",
    'file-md5': "StixFile",
    'file-sha1': "StixFile",
    'file-sha256': "StixFile",
    'file': 'StixFile',
    'host': "X-OpenCTI-Hostname",
    'ip': "IPv4-Addr",
    'ipv6': "IPv6-Addr",
    'registry key': "Windows-Registry-Key",
    'url': "Url"
}
OPENCTI_TYPES_TO_XSOAR = {
    "User-Account": 'Account',
    "Domain-Name": 'Domain',
    "Email-Addr": 'Email',
    "StixFile": "File",
    "X-OpenCTI-Hostname": 'Host',
    "IPv4-Addr": 'IP',
    "IPv6-Addr": 'IPv6',
    "Windows-Registry-Key": 'Registry Key',
    "Url": 'URL'
}
KEY_TO_CTI_NAME = {
    'description': 'x_opencti_description',
    'score': 'x_opencti_score'
}
FILE_TYPES = {
    'file-md5': "file.hashes.md5",
    'file-sha1': "file.hashes.sha-1",
    'file-sha256': "file.hashes.sha-256"
}
OBSERVABLE_TYPE_TO_STIX_PATTERN_MAPPING = {
    "IPv4-Addr": "[ipv4-addr:value = '{{indicator}}']",
    "IPv6-Addr": "[ipv6-addr:value = '{{indicator}}']",
    "Domain-Name": "[domain-name:value = '{{indicator}}']",
    "Url": "[url:value = '{{indicator}}']",
    "Email-Addr": "[email-addr:value = '{{indicator}}']",
    "StixFile": "[file:hashes.'SHA-256' = '{{indicator}}']",
    "Process": "[process:pid = '{{indicator}}']",
    "User-Account": "[user-account:user_id = '{{indicator}}']",
    "Windows-Registry-Key": "[windows-registry-key:key = '{{indicator}}']"
}


def label_create(client: OpenCTIApiClient, label_name: str | None):
    """ Create label at opencti

        Args:
            client: OpenCTI Client object
            label_name(str): label name to create

        Returns:
            readable_output, raw_response
        """
    try:
        label = client.label.create(value=label_name)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create label. {e}")
    return label


def build_observable_list(observable_list: list[str]) -> list[str]:
    """Builds an observable list for the query
    Args:
        observable_list: List of XSOAR observables types to return..

    Returns:
        observables: list of OPENCTI observables types"""
    result = []
    if 'ALL' in observable_list:
        # Replaces "ALL" for all types supported on XSOAR.
        result = ['User-Account', 'Domain-Name', 'Email-Addr', 'StixFile', 'X-OpenCTI-Hostname', 'IPv4-Addr',
                  'IPv6-Addr', 'Windows-Registry-Key', 'Url']
    else:
        result = [XSOAR_TYPES_TO_OPENCTI.get(observable.lower(), observable) for observable in observable_list]
    return result


def reset_last_run():
    """
    Reset the last run from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


def get_observables(
    client: OpenCTIApiClient,
    observable_types: list[str],
    score: list | None = None,
    limit: int | None = 500,
    last_run_id: str | None = None,
    search: str = "",
    additional_filters: list[dict] = None,
    get_all: bool = False
) -> dict:
    """ Retrieving observables from the API

    Args:
        score: Range of scores to filter by.
        client: OpenCTI Client object.
        observable_types: List of observables types to return.
        last_run_id: The last id from the previous call to use pagination.
        limit: the max observables to fetch
        search: The observable's value to filter by.
        additional_filters: List of filters to apply. Items format: {key: str, operator: str, values: list[str], mode: str}.
        get_all: Whether to fetch all observables or just the page (default False).

    Returns:
        observables: dict of observables
    """
    observable_type = build_observable_list(observable_types)
    filters: dict[str, Any] = {
        'mode': 'and',
        'filters': [{
            'key': 'entity_type',
            'values': observable_type,
            'operator': 'eq',
            'mode': 'or'
        }],
        'filterGroups': []
    }
    if score:
        filters["filters"].append({
            'key': 'x_opencti_score',
            'values': score,
            'operator': 'eq',
            'mode': 'or'
        })
    if additional_filters:
        for filter_item in additional_filters:
            filters["filters"].append(filter_item)

    observables = client.stix_cyber_observable.list(
        after=last_run_id,
        first=limit,
        withPagination=True,
        getAll=get_all,
        filters=filters,
        search=search
    )
    return observables


def get_indicators(
    client: OpenCTIApiClient,
    label: str = None,
    created_by: str = None,
    creator: str = None,
    created_after: str = None,
    created_before: str = None,
    valid_from_after: str = None,
    valid_from_before: str = None,
    valid_until_after: str = None,
    valid_until_before: str = None,
    indicator_types: list[str] = None,
    limit: int | None = 50,
    last_run_id: str = None,
    search: str = "",
    additional_filters: list[dict] = None,
    get_all: bool = False
) -> dict:
    """Retrieving indicators from the OpenCTI API with filters and pagination.

    Args:
        client: OpenCTI Client object.
        label: The label to filter by.
        created_by: The creator of the indicator.
        creator: The creator of the indicator.
        created_after: The date and time after which the indicator was created.
        created_before: The date and time before which the indicator was created.
        valid_from_after: The date and time after which the indicator is valid from.
        valid_from_before: The date and time before which the indicator is valid from.
        valid_until_after: The date and time after which the indicator is valid until.
        valid_until_before: The date and time before which the indicator is valid until.
        indicator_types: The types of indicator to filter by.
        limit: The maximum number of indicators to fetch (default 50).
        last_run_id: The last ID from the previous call for pagination.
        search: Search string for the indicator value.
        additional_filters: List of filters to apply. Items format: {key: str, operator: str, values: list[str], mode: str}.
        get_all: Whether to fetch all indicators or just the page (default False).

    Returns:
        A dictionary containing indicators and pagination information.
    """
    filters: dict[str, Any] = {
        'mode': 'and',
        'filters': [],
        'filterGroups': []
    }

    if label:
        filters["filters"].append({
            'key': 'objectLabel',
            'values': [label],
            'operator': 'eq',
            'mode': 'or'
        })
    if created_by:
        filters["filters"].append({
            'key': 'createdBy',
            'values': [created_by],
            'operator': 'eq',
            'mode': 'or'
        })
    if creator:
        filters["filters"].append({
            'key': 'creator_id',
            'values': [creator],
            'operator': 'eq'
        })
    if indicator_types:
        filters["filters"].append({
            'key': 'indicator_types',
            'values': indicator_types,
            'operator': 'eq',
            'mode': 'or'
        })
    if created_after:
        filters["filters"].append({
            'key': 'created_at',
            'values': [created_after],
            'operator': 'gt'
        })
    if created_before:
        filters["filters"].append({
            'key': 'created_at',
            'values': [created_before],
            'operator': 'lt'
        })
    if valid_from_after:
        filters["filters"].append({
            'key': 'valid_from',
            'values': [valid_from_after],
            'operator': 'gt'
        })
    if valid_from_before:
        filters["filters"].append({
            'key': 'valid_from',
            'values': [valid_from_before],
            'operator': 'lt'
        })
    if valid_until_after:
        filters["filters"].append({
            'key': 'valid_until',
            'values': [valid_until_after],
            'operator': 'gt'
        })
    if valid_until_before:
        filters["filters"].append({
            'key': 'valid_until',
            'values': [valid_until_before],
            'operator': 'lt'
        })
    if additional_filters:
        for filter_item in additional_filters:
            filters["filters"].append(filter_item)

    try:
        indicator_list = client.indicator.list(
            after=last_run_id,
            first=limit,
            withPagination=True,
            getAll=get_all,
            filters=filters,
            search=search
        )
        return indicator_list
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Failed to retrieve indicators. {e}")


def get_incidents(
    client: OpenCTIApiClient,
    label: str = None,
    created_by: str = None,
    creator: str = None,
    created_after: str = None,
    created_before: str = None,
    incident_types: list[str] = None,
    limit: int | None = 50,
    last_run_id: str = None,
    search: str = "",
    additional_filters: list[dict] = None,
    get_all: bool = False
) -> dict:
    """Retrieving incidents from the OpenCTI API with filters and pagination.

    Args:
        client: OpenCTI Client object.
        label: The label to filter by.
        created_by: The creator of the incident.
        creator: The creator of the incident.
        created_after: The date and time after which the incident was created.
        created_before: The date and time before which the incident was created.
        incident_types: The types of incident to filter by.
        limit: The maximum number of incidents to fetch (default 50).
        last_run_id: The last ID from the previous call for pagination.
        search: Search string for the incident value.
        additional_filters: List of filters to apply. Items format: {key: str, operator: str, values: list[str], mode: str}.
        get_all: Whether to fetch all incidents or just the page (default False).

    Returns:
        A dictionary containing incidents and pagination information.
    """
    filters: dict[str, Any] = {
        'mode': 'and',
        'filters': [],
        'filterGroups': []
    }

    if label:
        filters["filters"].append({
            'key': 'objectLabel',
            'values': [label],
            'operator': 'eq',
            'mode': 'or'
        })
    if created_by:
        filters["filters"].append({
            'key': 'createdBy',
            'values': [created_by],
            'operator': 'eq',
            'mode': 'or'
        })
    if creator:
        filters["filters"].append({
            'key': 'creator_id',
            'values': [creator],
            'operator': 'eq'
        })
    if incident_types:
        filters["filters"].append({
            'key': 'incident_types',
            'values': incident_types,
            'operator': 'eq',
            'mode': 'or'
        })
    if created_after:
        filters["filters"].append({
            'key': 'created_at',
            'values': [created_after],
            'operator': 'gt'
        })
    if created_before:
        filters["filters"].append({
            'key': 'created_at',
            'values': [created_before],
            'operator': 'lt'
        })
    if additional_filters:
        for filter_item in additional_filters:
            filters["filters"].append(filter_item)

    try:
        incident_list = client.incident.list(
            after=last_run_id,
            first=limit,
            withPagination=True,
            getAll=get_all,
            filters=filters,
            search=search
        )
        return incident_list
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Failed to retrieve incidents. {e}")


def build_stix_pattern(
    indicator: str,
    observable_type: str
) -> str:
    """
    Build a STIX pattern for the given indicator and observable type.
    """
    if observable_type not in OBSERVABLE_TYPE_TO_STIX_PATTERN_MAPPING:
        raise DemistoException(f"Invalid observable type: {observable_type}")

    pattern_template = OBSERVABLE_TYPE_TO_STIX_PATTERN_MAPPING[observable_type]
    if observable_type == "location":
        latitude, longitude = (value.strip() for value in indicator.split(",", 1))
        pattern = pattern_template.replace("{{latitude}}", latitude).replace("{{longitude}}", longitude)
    else:
        pattern = pattern_template.replace("{{indicator}}", indicator)

    return pattern


def incident_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Create incident at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
    """
    name = args.get("name")
    incident_type = args.get("incident_type", None)
    confidence = int(args.get("confidence", 50))
    severity = args.get('severity', None)
    description = args.get("description", None)
    source = args.get("source", None)
    objective = args.get("objective", None)
    created_by = args.get("created_by")
    first_seen = args.get("first_seen", None)
    last_seen = args.get("last_seen", None)
    label_id = args.get("label_id", None)
    marking_id = args.get("marking_id", None)
    external_references_id = args.get("external_references_id", None)

    try:
        result = client.incident.create(
            name=name,
            incident_type=incident_type,
            confidence=confidence,
            severity=severity,
            description=description,
            source=source,
            objective=objective,
            createdBy=created_by,
            first_seen=first_seen,
            last_seen=last_seen,
            objectLabel=label_id,
            objectMarking=marking_id,
            externalReferences=external_references_id
        )
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create incident. {e}")

    if incident_id := result.get('id'):
        readable_output = f'Incident created successfully. New Incident id: {incident_id}.'
        return CommandResults(outputs_prefix='OpenCTI.Incident',
                              outputs_key_field='id',
                              outputs={
                                  'id': result.get('id')
                              },
                              readable_output=readable_output,
                              raw_response=result)
    else:
        raise DemistoException("Can't create incident.")


def incident_delete_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Delete incident at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
    """
    try:
        client.stix_domain_object.delete(
            id=args.get("id")
        )
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't delete incident. {e}")

    return CommandResults(readable_output='Incident deleted.')


def incident_types_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Get incident types list from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
    """
    try:
        # This GraphQL query retrieves a list of incident types from OpenCTI's vocabulary, categorized under
        # 'incident_type_ov'. The query fetches the following fields of each incident type: ID, name, and description.
        query = """
            query OpenVocabFieldQuery($category: VocabularyCategory!, $orderBy: VocabularyOrdering, $orderMode: OrderingMode) {
            vocabularies(category: $category, orderBy: $orderBy, orderMode: $orderMode) {
                edges {
                node {
                    id
                    name
                    description
                }
                }
            }
            }
        """
        query_variables = {
            "category": "incident_type_ov"
        }
        result = client.query(query=query, variables=query_variables)
        incident_types_list = result['data']['vocabularies']['edges']
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't list incident types. {e}")

    if incident_types_list:
        incident_types = [
            incident_type['node']
            for incident_type in incident_types_list
        ]
        readable_output = tableToMarkdown('Incident Types', incident_types, headers=[
                                          'id', 'name', 'description'], headerTransform=pascalToSpace)

        outputs = {
            'OpenCTI.IncidentTypes.IncidentTypesList(val.id === obj.id)': incident_types
        }
        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=result
        )
    else:
        return CommandResults(readable_output='No incident types')


def get_incidents_command(client: OpenCTIApiClient, args: Dict[str, Any]) -> CommandResults:
    """List incidents in OpenCTI with optional filters and pagination.

    Args:
        client: OpenCTI Client object.
        args: demisto.args()

    Returns:
        CommandResults object with readable_output, raw_response, and pagination cursor.
    """
    limit = arg_to_number(args.get('limit', '50'))
    last_run_id = args.get('last_run_id')
    label = args.get('label_id')
    created_by = args.get('created_by')
    creator = args.get('creator')
    created_after = args.get('created_after')
    created_before = args.get('created_before')
    search = args.get('search', '')
    incident_types = argToList(args.get('incident_types'))
    additional_filters = argToList(args.get("additional_filters", []))
    get_all = argToBoolean(args.get('all_results', 'false'))

    raw_response = get_incidents(
        client=client,
        label=label,
        created_by=created_by,
        creator=creator,
        created_after=created_after,
        created_before=created_before,
        incident_types=incident_types,
        limit=limit,
        last_run_id=last_run_id,
        search=search,
        additional_filters=additional_filters,
        get_all=get_all
    )

    last_run = None
    if not get_all:
        last_run = raw_response.get('pagination', {}).get('endCursor')

    if incidents_list := raw_response if get_all else copy.deepcopy(raw_response.get('entities', {})):
        incidents = [
            {
                "id": incident.get("id"),
                "name": incident.get("name"),
                "description": incident.get("description"),
                "source": incident.get("source"),
                "confidence": incident.get("confidence"),
                "severity": incident.get("severity"),
                "objective": incident.get("objective"),
                "createdBy": incident.get("createdBy")["name"] if incident.get("createdBy") else "",
                "creators": [label["name"] for label in incident.get("creators", [])],
                "labels": [label["value"] for label in incident.get("objectLabel", [])],
                "incidentTypes": incident.get("incident_types"),
                "created": incident.get("created"),
                "updatedAt": incident.get("updated_at")
            }
            for incident in incidents_list
        ]

        readable_output = tableToMarkdown(
            "Incidents",
            incidents,
            headers=["id", "name", "description", "source", "confidence", "severity", "objective",
                     "createdBy", "creators", "labels", "incidentTypes", "created", "updatedAt"],
            headerTransform=pascalToSpace
        )
        outputs = {
            'OpenCTI.Incidents(val.lastRunID)': {'lastRunID': last_run},
            'OpenCTI.Incidents.IncidentList(val.id === obj.id)': incidents
        }

        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=incidents_list
        )
    else:
        return CommandResults(readable_output="No incidents.")


def indicator_types_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Get indicator types list from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
    """
    try:
        # This GraphQL query retrieves a list of indicator types from OpenCTI's vocabulary, categorized under
        # 'indicator_type_ov'. The query fetches the following fields of each indicator type: ID, name, and description.
        query = """
            query OpenVocabFieldQuery($category: VocabularyCategory!, $orderBy: VocabularyOrdering, $orderMode: OrderingMode) {
            vocabularies(category: $category, orderBy: $orderBy, orderMode: $orderMode) {
                edges {
                node {
                    id
                    name
                    description
                }
                }
            }
            }
        """
        query_variables = {
            "category": "indicator_type_ov"
        }
        result = client.query(query=query, variables=query_variables)
        indicator_types_list = result['data']['vocabularies']['edges']
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't list indicator types. {e}")

    if indicator_types_list:
        indicator_types = [
            indicator_type['node']
            for indicator_type in indicator_types_list
        ]
        readable_output = tableToMarkdown('Indicator Types', indicator_types, headers=[
                                          'id', 'name', 'description'], headerTransform=pascalToSpace)

        outputs = {
            'OpenCTI.IndicatorTypes.IndicatorTypesList(val.id === obj.id)': indicator_types
        }
        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=result
        )
    else:
        return CommandResults(readable_output="No indicator types.")


def relationship_create_command(client: OpenCTIApiClient, args: Dict[str, Any]) -> CommandResults:
    """ Create relationship at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
    """
    from_id = args.get("from_id")
    to_id = args.get("to_id")
    relationship_type = args.get("relationship_type")
    description = args.get("description", None)
    confidence = args.get("confidence", None)
    if confidence:
        confidence = int(confidence)

    try:
        result = client.stix_core_relationship.create(
            fromId=from_id,
            toId=to_id,
            relationship_type=relationship_type,
            description=description,
            confidence=confidence
        )
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create relationship. {e}")

    if relationship_id := result.get('id'):
        readable_output = f'Relationship created successfully. New Relationship id: {relationship_id}.'
        return CommandResults(
            outputs_prefix='OpenCTI.Relationship',
            outputs_key_field='id',
            outputs={
                'id': relationship_id,
                'relationshipType': result.get('relationship_type'),
            },
            readable_output=readable_output,
            raw_response=result
        )
    else:
        raise DemistoException("Can't create relationship.")


def relationship_delete_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
    """ Delete relationship from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    relationship_id = args.get("id")
    try:
        client.stix_core_relationship.delete(id=relationship_id)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't delete relationship. {e}")
    return CommandResults(readable_output='Relationship deleted.')


def relationship_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Get relationships list from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    from_id = args.get("from_id")
    limit = arg_to_number(args.get('limit', '50'))
    last_run_id = args.get('last_run_id')
    relationships_list = client.stix_core_relationship.list(
        fromOrToId=from_id, first=limit, after=last_run_id, withPagination=True)

    if relationships_list:
        new_last_run = relationships_list.get('pagination').get('endCursor')
        relationships = [
            {
                'id': relationship.get('id'),
                'relationshipType': relationship.get('relationship_type'),
                'fromId': relationship.get('from').get('id'),
                'toId': relationship.get('to').get('id'),
                'toEntityType': relationship.get('to').get('entity_type')
            }
            for relationship in relationships_list.get('entities')]
        readable_output = tableToMarkdown(
            'Relationships',
            relationships,
            headers=['id', 'relationshipType', 'fromId', 'toId', 'toEntityType'],
            headerTransform=pascalToSpace
        )
        outputs = {
            'OpenCTI.Relationships(val.relationshipsLastRun)': {'relationshipsLastRun': new_last_run},
            'OpenCTI.Relationships.RelationshipsList(val.id === obj.id)': relationships
        }
        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=relationships_list
        )
    else:
        return CommandResults(readable_output='No relationships')


def get_observables_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
    """ Gets observable from opencti to readable output

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    observable_types = argToList(args.get("observable_types", "ALL"))
    last_run_id = args.get("last_run_id")
    limit = arg_to_number(args.get('limit', 50))
    start = arg_to_number(args.get('score_start', 0))
    end = arg_to_number(args.get('score_end', 100))  # type:ignore
    score = args.get('score')
    search = args.get("search", "")
    additional_filters = argToList(args.get("additional_filters", []))
    get_all = argToBoolean(args.get('all_results', 'false'))
    scores = None
    if score:
        if score.lower() == "unknown":
            scores = [None]
        elif score.isdigit():
            scores = [score]
        else:
            raise DemistoException("Invalid score was provided.")

    elif start or end:
        scores = [str(i) for i in range(start, end + 1)]  # type:ignore

    raw_response = get_observables(
        client=client,
        observable_types=observable_types,
        limit=limit,
        last_run_id=last_run_id,
        score=scores,
        search=search,
        additional_filters=additional_filters,
        get_all=get_all
    )

    last_run = None
    if not get_all:
        last_run = raw_response.get('pagination', {}).get('endCursor')  # type: ignore

    if observables_list := raw_response if get_all else copy.deepcopy(raw_response.get('entities', {})):
        observables = [{'type': OPENCTI_TYPES_TO_XSOAR.get(observable['entity_type'], observable['entity_type']),
                       'value': observable.get('observable_value'),
                        'id': observable.get('id'),
                        'createdBy': observable.get('createdBy').get('id')
                        if observable.get('createdBy') else None,
                        'score': observable.get('x_opencti_score'),
                        'description': observable.get('x_opencti_description'),
                        'labels': [label.get('value') for label in observable.get('objectLabel')],
                        'marking': [mark.get('definition') for mark in observable.get('objectMarking')],
                        'externalReferences': observable.get('externalReferences')
                        }
                       for observable in observables_list]

        readable_output = tableToMarkdown('Observables', observables,
                                          headers=["type", "value", "id"],
                                          removeNull=True)

        outputs = {
            'OpenCTI.Observables(val.lastRunID)': {'lastRunID': last_run},
            'OpenCTI.Observables.ObservablesList(val.id === obj.id)': observables
        }
        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=observables_list
        )
    else:
        return CommandResults(readable_output='No observables.')


def observable_delete_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
    """ Delete observable from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    observable_id = args.get("id")
    try:
        client.stix_cyber_observable.delete(id=observable_id)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't delete observable. {e}")
    return CommandResults(readable_output='Observable deleted.')


def observable_field_update_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
    """ Update observable field at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    observable_id = args.get("id")
    # works only with score and description
    key = KEY_TO_CTI_NAME[args.get("field")]  # type: ignore
    value = args.get("value")
    try:
        result = client.stix_cyber_observable.update_field(id=observable_id, key=key, value=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't update observable. {e}")

    return CommandResults(
        outputs_prefix='OpenCTI.Observable',
        outputs_key_field='id',
        outputs={'id': result.get('id')},
        readable_output=f'Observable {observable_id} updated successfully.',
        raw_response=result
    )


def observable_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Create observable at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    redirect_std_out = argToBoolean(demisto.params().get('redirect_std_out', 'false'))
    observable_type = args.get("type")
    created_by = args.get("created_by")
    marking_id = args.get("marking_id")
    label_id = args.get("label_id")
    external_references_id = args.get("external_references_id")
    description = args.get("description")
    score = arg_to_number(args.get("score", '50'))
    value = args.get("value")
    create_indicator = argToBoolean(args.get("create_indicator", 'false'))
    data = {'type': XSOAR_TYPES_TO_OPENCTI.get(observable_type.lower(), observable_type),  # type:ignore
            'value': value}
    if observable_type == 'Registry Key':
        data['key'] = value
    if observable_type == 'Account':
        data['account_login'] = value

    simple_observable_key = None
    simple_observable_value = None
    if 'file' in observable_type.lower():  # type: ignore
        simple_observable_key = FILE_TYPES.get(observable_type.lower(), observable_type)  # type: ignore
        simple_observable_value = value
    try:
        # cti code prints to stdout so we need to catch it.
        if redirect_std_out:
            sys.stdout = StringIO()
        result = client.stix_cyber_observable.create(
            simple_observable_key=simple_observable_key,
            simple_observable_value=simple_observable_value,
            type=observable_type,
            createdBy=created_by, objectMarking=marking_id,
            objectLabel=label_id, externalReferences=external_references_id,
            simple_observable_description=description,
            x_opencti_score=score, observableData=data,
            createIndicator=create_indicator
        )
        if redirect_std_out:
            sys.stdout = sys.__stdout__
    except KeyError as e:
        raise DemistoException(f'Missing argument at data {e}')

    if id := result.get('id'):
        readable_output = f'Observable created successfully. New Observable id: {id}'
        outputs = {
            'id': result.get('id'),
            'value': value,
            'type': observable_type
        }
    else:
        raise DemistoException("Can't create observable.")

    return CommandResults(
        outputs_prefix='OpenCTI.Observable',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def observable_add_marking(client: OpenCTIApiClient, id: str | None, value: str | None):
    """ Add observable marking to opencti
        Args:
            client: OpenCTI Client object
            id(str): observable id to update
            value(str): marking name to add

        Returns:
            true if added successfully, else false.
        """
    try:
        result = client.stix_cyber_observable.add_marking_definition(id=id, marking_definition_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't add marking to observable. {e}")
    return result


def observable_add_label(client: OpenCTIApiClient, id: str | None, value: str | None):
    """ Add observable label to opencti
        Args:
            client: OpenCTI Client object
            id(str): observable id to update
            value(str): label name to add

        Returns:
            true if added successfully, else false.
        """
    try:
        result = client.stix_cyber_observable.add_label(id=id, label_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't add label to observable. {e}")
    return result


def observable_field_add_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Add observable marking or label to opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output
        """
    observable_id = args.get("id")
    # works only with marking and label
    key = args.get("field")
    value = args.get("value")
    result = {}

    if key == 'marking':
        result = observable_add_marking(client=client, id=observable_id, value=value)

    elif key == 'label':
        result = observable_add_label(client=client, id=observable_id, value=value)
    if result:
        return CommandResults(readable_output=f'Added {key} successfully.')
    else:
        raise DemistoException(f"Can't add {key}.")


def observable_remove_label(client: OpenCTIApiClient, id: str | None, value: str | None):
    """ Remove observable label from opencti
        Args:
            client: OpenCTI Client object
            id(str): observable id to update
            value(str): label name to remove

        Returns:
            true if removed successfully, else false.
        """
    try:
        result = client.stix_cyber_observable.remove_label(id=id, label_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't remove label from observable. {e}")
    return result


def observable_remove_marking(client: OpenCTIApiClient, id: str | None, value: str | None):
    """ Remove observable marking from opencti
        Args:
            client: OpenCTI Client object
            id(str): observable id to update
            value(str): marking name to remove

        Returns:
            true if removed successfully, else false.
        """

    try:
        result = client.stix_cyber_observable.remove_marking_definition(id=id, marking_definition_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't remove marking from observable. {e}")
    return result


def observable_field_remove_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Remove observable marking or label from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output
        """
    observable_id = args.get("id")
    # works only with marking and label
    key = args.get("field")
    value = args.get("value")
    result = {}

    if key == 'marking':
        result = observable_remove_marking(client=client, id=observable_id, value=value)

    elif key == 'label':
        result = observable_remove_label(client=client, id=observable_id, value=value)

    if result:
        return CommandResults(readable_output=f'{key}: {value} was removed successfully from observable: {observable_id}.')
    else:
        raise DemistoException(f"Can't remove {key}.")


def indicator_add_marking(client: OpenCTIApiClient, id: str | None, value: str | None):
    """ Add indicator marking to opencti
        Args:
            client: OpenCTI Client object
            id(str): indicator id to update
            value(str): marking name to add

        Returns:
            true if added successfully, else false.
        """
    try:
        result = client.stix_domain_object.add_marking_definition(id=id, marking_definition_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't add marking to indicator. {e}")
    return result


def indicator_add_label(client: OpenCTIApiClient, id: str | None, value: str | None):
    """ Add indicator label to opencti
        Args:
            client: OpenCTI Client object
            id(str): indicator id to update
            value(str): label name to add

        Returns:
            true if added successfully, else false.
        """
    try:
        result = client.stix_domain_object.add_label(id=id, label_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't add label to indicator. {e}")
    return result


def indicator_field_add_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Add indicator marking or label to opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output
        """
    indicator_id = args.get("id")
    # works only with marking and label
    key = args.get("field")
    value = args.get("value")
    result = {}

    if key == 'marking':
        result = indicator_add_marking(client=client, id=indicator_id, value=value)

    elif key == 'label':
        result = indicator_add_label(client=client, id=indicator_id, value=value)
    if result:
        return CommandResults(readable_output=f'Added {key} successfully.')
    else:
        raise DemistoException(f"Can't add {key}.")


def indicator_remove_label(client: OpenCTIApiClient, id: str | None, value: str | None):
    """ Remove indicator label from opencti
        Args:
            client: OpenCTI Client object
            id(str): indicator id to update
            value(str): label name to remove

        Returns:
            true if removed successfully, else false.
        """
    try:
        result = client.stix_domain_object.remove_label(id=id, label_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't remove label from indicator. {e}")
    return result


def indicator_remove_marking(client: OpenCTIApiClient, id: str | None, value: str | None):
    """ Remove indicator marking from opencti
        Args:
            client: OpenCTI Client object
            id(str): indicator id to update
            value(str): marking name to remove

        Returns:
            true if removed successfully, else false.
        """

    try:
        result = client.stix_domain_object.remove_marking_definition(id=id, marking_definition_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't remove marking from indicator. {e}")
    return result


def indicator_field_remove_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Remove indicator marking or label from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output
        """
    indicator_id = args.get("id")
    # works only with marking and label
    key = args.get("field")
    value = args.get("value")
    result = {}

    if key == 'marking':
        result = indicator_remove_marking(client=client, id=indicator_id, value=value)

    elif key == 'label':
        result = indicator_remove_label(client=client, id=indicator_id, value=value)

    if result:
        return CommandResults(readable_output=f'{key}: {value} was removed successfully from indicator: {indicator_id}.')
    else:
        raise DemistoException(f"Can't remove {key}.")


def indicator_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Create an indicator in OpenCTI.

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            CommandResults object with readable_output, raw_response
    """
    name = args["name"]
    indicator = args["indicator"]
    main_observable_type = XSOAR_TYPES_TO_OPENCTI.get(
        args["main_observable_type"].lower(),
        args["main_observable_type"]
    )
    pattern = build_stix_pattern(indicator, main_observable_type)

    description = args.get("description", None)
    indicator_types = args.get("indicator_types", None)
    confidence = int(args.get("confidence", 50))
    score = int(args.get("score", 50))
    valid_from = args.get("valid_from", None)
    valid_until = args.get("valid_until", None)
    created_by = args.get("created_by", None)
    label_id = args.get("label_id", None)
    marking_id = args.get("marking_id", None)
    external_references_id = args.get("external_references_id", None)
    create_observables = argToBoolean(args.get("create_observables", 'false'))

    try:
        result = client.indicator.create(
            name=name,
            description=description,
            pattern=pattern,
            pattern_type="stix",
            x_opencti_main_observable_type=main_observable_type,
            indicator_types=indicator_types,
            confidence=confidence,
            x_opencti_score=score,
            valid_from=valid_from,
            valid_until=valid_until,
            createdBy=created_by,
            objectLabel=label_id,
            objectMarking=marking_id,
            externalReferences=external_references_id,
            x_opencti_create_observables=create_observables
        )
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create indicator. {e}")

    if indicator_id := result.get('id'):
        readable_output = f'Indicator created successfully. New Indicator id: {indicator_id}.'
        return CommandResults(
            outputs_prefix='OpenCTI.Indicator',
            outputs_key_field='id',
            outputs={
                'id': result.get('id'),
            },
            readable_output=readable_output,
            raw_response=result
        )
    else:
        raise DemistoException("Can't create indicator.")


def indicator_update_command(client: OpenCTIApiClient, args: Dict[str, Any]) -> CommandResults:
    """ Update an existing indicator in OpenCTI using a GraphQL mutation.

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            CommandResults object with readable_output, raw_response
    """
    indicator_id = args.get("id")

    update_fields = []
    if name := args.get("name"):
        update_fields.append({"key": "name", "value": name})
    if description := args.get("description"):
        update_fields.append({"key": "description", "value": description})
    if confidence := args.get("confidence"):
        update_fields.append({"key": "confidence", "value": int(confidence)})
    if score := args.get("score"):
        update_fields.append({"key": "x_opencti_score", "value": int(score)})
    if valid_from := args.get("valid_from"):
        update_fields.append({"key": "valid_from", "value": valid_from})
    if valid_until := args.get("valid_until"):
        update_fields.append({"key": "valid_until", "value": valid_until})
    if indicator_types := args.get("indicator_types"):
        update_fields.append({"key": "indicator_types", "value": indicator_types.split(',')})
    if created_by := args.get("created_by"):
        update_fields.append({"key": "createdBy", "value": created_by})
    if label_id := args.get("label_id"):
        update_fields.append({"key": "objectLabel", "value": label_id.split(',')})
    if marking_id := args.get("marking_id"):
        update_fields.append({"key": "objectMarking", "value": marking_id.split(',')})
    if external_references_id := args.get("external_references_id"):
        update_fields.append({"key": "externalReferences", "value": external_references_id.split(',')})

    mutation = """
        mutation IndicatorEditionOverviewFieldPatchMutation(
        $id: ID!
        $input: [EditInput!]!
        $commitMessage: String
        $references: [String]
        ) {
        indicatorFieldPatch(id: $id, input: $input, commitMessage: $commitMessage, references: $references) {
            id
            name
            confidence
            description
            valid_from
            valid_until
            x_opencti_score
            indicator_types
        }
        }
    """

    variables = {
        "id": indicator_id,
        "input": update_fields,
        "commitMessage": args.get("commit_message"),
        "references": args.get("references")
    }

    try:
        result = client.query(mutation, variables)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't update indicator. {e}")

    if updated_indicator := result.get("data", {}).get("indicatorFieldPatch", None):
        readable_output = 'Indicator updated successfully.'
        return CommandResults(
            outputs_prefix='OpenCTI.Indicator',
            outputs_key_field='id',
            outputs={
                "id": updated_indicator.get("id"),
                "name": updated_indicator.get("name"),
                "validFrom": updated_indicator.get("valid_from"),
                "validUntil": updated_indicator.get("valid_until")
            },
            readable_output=readable_output,
            raw_response=result
        )
    else:
        raise DemistoException("Can't update indicator.")


def get_indicators_command(client: OpenCTIApiClient, args: Dict[str, Any]) -> CommandResults:
    """List indicators in OpenCTI with optional filters and pagination.

    Args:
        client: OpenCTI Client object.
        args: demisto.args()

    Returns:
        CommandResults object with readable_output, raw_response, and pagination cursor.
    """
    limit = arg_to_number(args.get('limit', '50'))
    last_run_id = args.get('last_run_id')
    label = args.get('label_id')
    created_by = args.get('created_by')
    creator = args.get('creator')
    created_after = args.get('created_after')
    created_before = args.get('created_before')
    valid_until_after = args.get('valid_until_after')
    valid_until_before = args.get('valid_until_before')
    valid_from_after = args.get('valid_from_after')
    valid_from_before = args.get('valid_from_before')
    search = args.get('search', '')
    indicator_types = argToList(args.get('indicator_types'))
    additional_filters = argToList(args.get("additional_filters", []))
    get_all = argToBoolean(args.get('all_results', 'false'))

    raw_response = get_indicators(
        client=client,
        label=label,
        created_by=created_by,
        creator=creator,
        created_after=created_after,
        created_before=created_before,
        valid_until_after=valid_until_after,
        valid_until_before=valid_until_before,
        valid_from_after=valid_from_after,
        valid_from_before=valid_from_before,
        indicator_types=indicator_types,
        limit=limit,
        last_run_id=last_run_id,
        search=search,
        additional_filters=additional_filters,
        get_all=get_all
    )

    last_run = None
    if not get_all:
        last_run = raw_response.get('pagination', {}).get('endCursor')

    if indicators_list := raw_response if get_all else copy.deepcopy(raw_response.get('entities', {})):
        indicators = [
            {
                "id": indicator.get("id"),
                "name": indicator.get("name"),
                "description": indicator.get("description"),
                "pattern": indicator.get("pattern"),
                "validFrom": indicator.get("valid_from"),
                "validUntil": indicator.get("valid_until"),
                "score": indicator.get("x_opencti_score"),
                "confidence": indicator.get("confidence"),
                "createdBy": indicator.get("createdBy")["name"] if indicator.get("createdBy") else "",
                "creators": [label["name"] for label in indicator.get("creators", [])],
                "labels": [label["value"] for label in indicator.get("objectLabel", [])],
                "indicatorTypes": indicator.get("indicator_types"),
                "created": indicator.get("created"),
                "updatedAt": indicator.get("updated_at")
            }
            for indicator in indicators_list
        ]

        readable_output = tableToMarkdown(
            "Indicators",
            indicators,
            headers=["id", "name", "description", "pattern", "validFrom", "validUntil", "confidence",
                     "score", "createdBy", "creators", "labels", "indicatorTypes", "created", "updatedAt"],
            headerTransform=pascalToSpace
        )
        outputs = {
            'OpenCTI.Indicators(val.lastRunID)': {'lastRunID': last_run},
            'OpenCTI.Indicators.IndicatorList(val.id === obj.id)': indicators
        }

        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=indicators_list
        )
    else:
        return CommandResults(readable_output="No indicators.")


def organization_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Get organizations list from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    limit = arg_to_number(args.get('limit', '50'))
    last_run_id = args.get('last_run_id')
    organizations_list = client.identity.list(types='Organization', first=limit, after=last_run_id, withPagination=True)

    if organizations_list:
        new_last_run = organizations_list.get('pagination').get('endCursor')
        organizations = [
            {'name': organization.get('name'), 'id': organization.get('id')}
            for organization in organizations_list.get('entities')]
        readable_output = tableToMarkdown('Organizations', organizations, headers=['name', 'id'],
                                          headerTransform=pascalToSpace)
        outputs = {
            'OpenCTI.Organizations(val.organizationsLastRun)': {'organizationsLastRun': new_last_run},
            'OpenCTI.Organizations.OrganizationsList(val.id === obj.id)': organizations
        }
        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=organizations_list
        )
    else:
        return CommandResults(readable_output='No organizations')


def organization_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Create organization at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    name = args.get("name")
    description = args.get("description")
    reliability = args.get('reliability')
    try:
        identity = Identity(client)
        result = identity.create(name=name, type='Organization', x_opencti_reliability=reliability,
                                 description=description)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create organization. {e}")

    if organization_id := result.get('id'):
        readable_output = f'Organization {name} was created successfully with id: {organization_id}.'
        return CommandResults(outputs_prefix='OpenCTI.Organization',
                              outputs_key_field='id',
                              outputs={'id': result.get('id')},
                              readable_output=readable_output,
                              raw_response=result)
    else:
        raise DemistoException("Can't create organization.")


def label_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Get label list from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    limit = arg_to_number(args.get('limit', '50'))
    last_run_id = args.get('last_run_id')
    label_list = client.label.list(first=limit, after=last_run_id, withPagination=True)

    if label_list:
        new_last_run = label_list.get('pagination').get('endCursor')
        labels = [
            {'value': label.get('value'), 'id': label.get('id')}
            for label in label_list.get('entities')]
        readable_output = tableToMarkdown('Labels', labels, headers=['value', 'id'],
                                          headerTransform=pascalToSpace)

        outputs = {
            'OpenCTI.Labels(val.labelsLastRun)': {'labelsLastRun': new_last_run},
            'OpenCTI.Labels.LabelsList(val.id === obj.id)': labels
        }
        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=label_list
        )
    else:
        return CommandResults(readable_output='No labels')


def label_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Create label at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    name = args.get("name")
    result = label_create(client=client, label_name=name)

    if label_id := result.get('id'):
        readable_output = f'Label {name} was created successfully with id: {label_id}.'
        return CommandResults(outputs_prefix='OpenCTI.Label',
                              outputs_key_field='id',
                              outputs={'id': result.get('id')},
                              readable_output=readable_output,
                              raw_response=result)
    else:
        raise DemistoException("Can't create label.")


def external_reference_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Create external reference at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    external_references_source_name = args.get('source_name')
    external_references_url = args.get('url')

    result = client.external_reference.create(
        source_name=external_references_source_name,
        url=external_references_url
    )

    if external_reference_id := result.get('id'):
        readable_output = f'Reference {external_references_source_name} was created successfully with id: ' \
                          f'{external_reference_id}.'
        return CommandResults(outputs_prefix='OpenCTI.externalReference',
                              outputs_key_field='id',
                              outputs={'id': result.get('id')},
                              readable_output=readable_output,
                              raw_response=result)
    else:
        raise DemistoException("Can't create external reference.")


def marking_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Get marking list from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    limit = arg_to_number(args.get('limit', '50'))
    last_run_id = args.get('last_run_id')
    marking_list = client.marking_definition.list(first=limit, after=last_run_id, withPagination=True)

    if marking_list:
        new_last_run = marking_list.get('pagination').get('endCursor')
        markings = [
            {'value': mark.get('definition'), 'id': mark.get('id')}
            for mark in marking_list.get('entities')]

        readable_output = tableToMarkdown('Markings', markings, headers=['value', 'id'],
                                          headerTransform=pascalToSpace)
        outputs = {
            'OpenCTI.MarkingDefinitions(val.markingsLastRun)': {'markingsLastRun': new_last_run},
            'OpenCTI.MarkingDefinitions.MarkingDefinitionsList(val.id === obj.id)': markings
        }

        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=marking_list
        )
    else:
        return CommandResults(readable_output='No markings')


def main():
    params = demisto.params()
    args = demisto.args()

    credentials = params.get('credentials', {})
    api_key = credentials.get('password')
    base_url = params.get('base_url').strip('/')
    verify = not argToBoolean(params.get('insecure'))

    try:
        client = OpenCTIApiClient(base_url, api_key, ssl_verify=verify, log_level='error',
                                  proxies=handle_proxy())
        command = demisto.command()
        demisto.info(f"Command being called is {command}")

        # Switch case
        if command == "test-module":
            '''When setting up an OpenCTI Client it is checked that it is valid and allows requests to be sent.
            and if not he immediately sends an error'''
            get_observables_command(client, args)
            return_results('ok')

        elif command == "opencti-get-observables":
            return_results(get_observables_command(client, args))

        elif command == "opencti-observable-delete":
            return_results(observable_delete_command(client, args))

        elif command == "opencti-observable-field-update":
            return_results(observable_field_update_command(client, args))

        elif command == "opencti-observable-create":
            return_results(observable_create_command(client, args))

        elif command == "opencti-observable-field-add":
            return_results(observable_field_add_command(client, args))

        elif command == "opencti-observable-field-remove":
            return_results(observable_field_remove_command(client, args))

        elif command == "opencti-organization-list":
            return_results(organization_list_command(client, args))

        elif command == "opencti-organization-create":
            return_results(organization_create_command(client, args))

        elif command == "opencti-label-list":
            return_results(label_list_command(client, args))

        elif command == "opencti-label-create":
            return_results(label_create_command(client, args))

        elif command == "opencti-external-reference-create":
            return_results(external_reference_create_command(client, args))

        elif command == "opencti-marking-definition-list":
            return_results(marking_list_command(client, args))

        elif command == "opencti-incident-create":
            return_results(incident_create_command(client, args))

        elif command == "opencti-incident-delete":
            return_results(incident_delete_command(client, args))

        elif command == "opencti-get-incidents":
            return_results(get_incidents_command(client, args))

        elif command == "opencti-incident-types-list":
            return_results(incident_types_list_command(client, args))

        elif command == "opencti-relationship-create":
            return_results(relationship_create_command(client, args))

        elif command == "opencti-relationship-delete":
            return_results(relationship_delete_command(client, args))

        elif command == "opencti-relationship-list":
            return_results(relationship_list_command(client, args))

        elif command == "opencti-indicator-create":
            return_results(indicator_create_command(client, args))

        elif command == "opencti-indicator-update":
            return_results(indicator_update_command(client, args))

        elif command == "opencti-indicator-field-add":
            return_results(indicator_field_add_command(client, args))

        elif command == "opencti-indicator-field-remove":
            return_results(indicator_field_remove_command(client, args))

        elif command == "opencti-get-indicators":
            return_results(get_indicators_command(client, args))

        elif command == "opencti-indicator-types-list":
            return_results(indicator_types_list_command(client, args))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Error:\n [{e}]")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

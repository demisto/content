import copy
import ipaddress
import re
import sys
from io import StringIO

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from pycti import Identity, OpenCTIApiClient

demisto.debug("pack name = ITX - OpenCTI, pack version = 1.0.0")


# Disable insecure warnings
urllib3.disable_warnings()

# Disable info logging from the api
logging.getLogger().setLevel(logging.ERROR)

XSOAR_TYPES_TO_OPENCTI = {
    "account": "User-Account",
    "domain": "Domain-Name",
    "email": "Email-Addr",
    "file-md5": "StixFile",
    "file-sha1": "StixFile",
    "file-sha256": "StixFile",
    "file": "StixFile",
    "host": "X-OpenCTI-Hostname",
    "ip": "IPv4-Addr",
    "ipv6": "IPv6-Addr",
    "registry key": "Windows-Registry-Key",
    "url": "Url",
}
OPENCTI_TYPES_TO_XSOAR = {
    "User-Account": "Account",
    "Domain-Name": "Domain",
    "Email-Addr": "Email",
    "StixFile": "File",
    "X-OpenCTI-Hostname": "Host",
    "IPv4-Addr": "IP",
    "IPv6-Addr": "IPv6",
    "Windows-Registry-Key": "Registry Key",
    "Url": "URL",
}
KEY_TO_CTI_NAME = {"description": "x_opencti_description", "score": "x_opencti_score"}
FILE_TYPES = {"file-md5": "file.hashes.md5", "file-sha1": "file.hashes.sha-1", "file-sha256": "file.hashes.sha-256"}
OBSERVABLE_TYPE_TO_STIX_PATTERN_MAPPING = {
    "IPv4-Addr": "[ipv4-addr:value = '{{indicator}}']",
    "IPv6-Addr": "[ipv6-addr:value = '{{indicator}}']",
    "Domain-Name": "[domain-name:value = '{{indicator}}']",
    "Url": "[url:value = '{{indicator}}']",
    "Email-Addr": "[email-addr:value = '{{indicator}}']",
    "StixFile": "[file:hashes.'SHA-256' = '{{indicator}}']",
    "Process": "[process:pid = '{{indicator}}']",
    "User-Account": "[user-account:user_id = '{{indicator}}']",
    "Windows-Registry-Key": "[windows-registry-key:key = '{{indicator}}']",
}
CONTAINER_CLIENT_ATTRIBUTES = {
    "report": "report",
    "grouping": "grouping",
    "case-incident": "case_incident",
    "case-rft": "case_rft",
    "case-rfi": "case_rfi",
}
DEFAULT_REPUTATION_THRESHOLD = 70
DEFAULT_SUSPICIOUS_THRESHOLD = 20
DEFAULT_RELIABILITY = "B - Usually reliable"
OPENCTI_LINK_TEXT = "View in OpenCTI"
MAX_ENTITY_RELATIONSHIPS = 100
# Reputation command -> OpenCTI observable types, indicator main observable types, DBot type and context key.
REPUTATION_COMMANDS = {
    "ip": {
        "observable_types": ["IPv4-Addr", "IPv6-Addr"],
        "main_observable_types": ["IPv4-Addr", "IPv6-Addr"],
        "dbot_type": DBotScoreType.IP,
        "relationship_type": FeedIndicatorType.IP,
    },
    "domain": {
        "observable_types": ["Domain-Name"],
        "main_observable_types": ["Domain-Name"],
        "dbot_type": DBotScoreType.DOMAIN,
        "relationship_type": FeedIndicatorType.Domain,
    },
    "email": {
        "observable_types": ["Email-Addr"],
        "main_observable_types": ["Email-Addr"],
        "dbot_type": DBotScoreType.EMAIL,
        "relationship_type": FeedIndicatorType.Email,
    },
    "url": {
        "observable_types": ["Url"],
        "main_observable_types": ["Url"],
        "dbot_type": DBotScoreType.URL,
        "relationship_type": FeedIndicatorType.URL,
    },
    "file": {
        "observable_types": ["StixFile"],
        "main_observable_types": ["StixFile", "File"],
        "dbot_type": DBotScoreType.FILE,
        "relationship_type": FeedIndicatorType.File,
    },
}
# OpenCTI entity type -> XSOAR indicator type, for the XSOAR relationships of the reputation commands.
# Entities of another type (an indicator, a note...) have no XSOAR relationship.
OPENCTI_TYPES_TO_RELATIONSHIP_TYPES = {
    "Malware": ThreatIntel.ObjectsNames.MALWARE,
    "Threat-Actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "Threat-Actor-Group": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "Threat-Actor-Individual": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "Intrusion-Set": ThreatIntel.ObjectsNames.INTRUSION_SET,
    "Campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "Attack-Pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "Tool": ThreatIntel.ObjectsNames.TOOL,
    "Infrastructure": ThreatIntel.ObjectsNames.INFRASTRUCTURE,
    "Report": ThreatIntel.ObjectsNames.REPORT,
    "Course-Of-Action": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    "Vulnerability": FeedIndicatorType.CVE,
    "IPv4-Addr": FeedIndicatorType.IP,
    "IPv6-Addr": FeedIndicatorType.IPv6,
    "Domain-Name": FeedIndicatorType.Domain,
    "Hostname": FeedIndicatorType.Host,
    "Url": FeedIndicatorType.URL,
    "Email-Addr": FeedIndicatorType.Email,
    "StixFile": FeedIndicatorType.File,
    "Autonomous-System": FeedIndicatorType.AS,
    "Country": FeedIndicatorType.Location,
    "City": FeedIndicatorType.Location,
    "Region": FeedIndicatorType.Location,
    "Administrative-Area": FeedIndicatorType.Location,
    "Position": FeedIndicatorType.Location,
    "Organization": FeedIndicatorType.Identity,
    "Individual": FeedIndicatorType.Identity,
    "Sector": FeedIndicatorType.Identity,
    "System": FeedIndicatorType.Identity,
}
# OpenCTI relationship type -> XSOAR relationship name, when they differ. Other unknown types become related-to.
OPENCTI_RELATIONSHIP_NAMES = {"indicates": EntityRelationship.Relationships.INDICATOR_OF}
# Hash length -> (STIX / OpenCTI hash name, XSOAR File context field).
FILE_HASH_TYPES = {32: ("MD5", "md5"), 40: ("SHA-1", "sha1"), 64: ("SHA-256", "sha256")}


def label_create(client: OpenCTIApiClient, label_name: str | None):
    """Create label at opencti

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
    if "ALL" in observable_list:
        # Replaces "ALL" for all types supported on XSOAR.
        result = [
            "User-Account",
            "Domain-Name",
            "Email-Addr",
            "StixFile",
            "X-OpenCTI-Hostname",
            "IPv4-Addr",
            "IPv6-Addr",
            "Windows-Registry-Key",
            "Url",
        ]
    else:
        result = [XSOAR_TYPES_TO_OPENCTI.get(observable.lower(), observable) for observable in observable_list]
    return result


def reset_last_run():
    """
    Reset the last run from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output="Fetch history deleted successfully")


def get_observables(
    client: OpenCTIApiClient,
    observable_types: list[str],
    score: list | None = None,
    limit: int | None = 500,
    last_run_id: str | None = None,
    search: str = "",
    additional_filters: list[dict] = None,
    get_all: bool = False,
) -> dict:
    """Retrieving observables from the API

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
        "mode": "and",
        "filters": [{"key": "entity_type", "values": observable_type, "operator": "eq", "mode": "or"}],
        "filterGroups": [],
    }
    if score:
        filters["filters"].append({"key": "x_opencti_score", "values": score, "operator": "eq", "mode": "or"})
    if additional_filters:
        for filter_item in additional_filters:
            filters["filters"].append(filter_item)

    observables = client.stix_cyber_observable.list(
        after=last_run_id, first=limit, withPagination=True, getAll=get_all, filters=filters, search=search
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
    get_all: bool = False,
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
    filters: dict[str, Any] = {"mode": "and", "filters": [], "filterGroups": []}

    if label:
        filters["filters"].append({"key": "objectLabel", "values": [label], "operator": "eq", "mode": "or"})
    if created_by:
        filters["filters"].append({"key": "createdBy", "values": [created_by], "operator": "eq", "mode": "or"})
    if creator:
        filters["filters"].append({"key": "creator_id", "values": [creator], "operator": "eq"})
    if indicator_types:
        filters["filters"].append({"key": "indicator_types", "values": indicator_types, "operator": "eq", "mode": "or"})
    if created_after:
        filters["filters"].append({"key": "created_at", "values": [created_after], "operator": "gt"})
    if created_before:
        filters["filters"].append({"key": "created_at", "values": [created_before], "operator": "lt"})
    if valid_from_after:
        filters["filters"].append({"key": "valid_from", "values": [valid_from_after], "operator": "gt"})
    if valid_from_before:
        filters["filters"].append({"key": "valid_from", "values": [valid_from_before], "operator": "lt"})
    if valid_until_after:
        filters["filters"].append({"key": "valid_until", "values": [valid_until_after], "operator": "gt"})
    if valid_until_before:
        filters["filters"].append({"key": "valid_until", "values": [valid_until_before], "operator": "lt"})
    if additional_filters:
        for filter_item in additional_filters:
            filters["filters"].append(filter_item)

    try:
        indicator_list = client.indicator.list(
            after=last_run_id, first=limit, withPagination=True, getAll=get_all, filters=filters, search=search
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
    get_all: bool = False,
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
    filters: dict[str, Any] = {"mode": "and", "filters": [], "filterGroups": []}

    if label:
        filters["filters"].append({"key": "objectLabel", "values": [label], "operator": "eq", "mode": "or"})
    if created_by:
        filters["filters"].append({"key": "createdBy", "values": [created_by], "operator": "eq", "mode": "or"})
    if creator:
        filters["filters"].append({"key": "creator_id", "values": [creator], "operator": "eq"})
    if incident_types:
        filters["filters"].append({"key": "incident_types", "values": incident_types, "operator": "eq", "mode": "or"})
    if created_after:
        filters["filters"].append({"key": "created_at", "values": [created_after], "operator": "gt"})
    if created_before:
        filters["filters"].append({"key": "created_at", "values": [created_before], "operator": "lt"})
    if additional_filters:
        for filter_item in additional_filters:
            filters["filters"].append(filter_item)

    try:
        incident_list = client.incident.list(
            after=last_run_id, first=limit, withPagination=True, getAll=get_all, filters=filters, search=search
        )
        return incident_list
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Failed to retrieve incidents. {e}")


def build_stix_pattern(indicator: str, observable_type: str) -> str:
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
    """Create incident at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    name = args.get("name")
    incident_type = args.get("incident_type", None)
    confidence = int(args.get("confidence", 50))
    severity = args.get("severity", None)
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
            externalReferences=external_references_id,
        )
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create incident. {e}")

    if incident_id := result.get("id"):
        readable_output = f"Incident created successfully. New Incident id: {incident_id}."
        return CommandResults(
            outputs_prefix="OpenCTI.Incident",
            outputs_key_field="id",
            outputs={"id": result.get("id")},
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create incident.")


def incident_delete_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Delete incident at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    try:
        client.stix_domain_object.delete(id=args.get("id"))
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't delete incident. {e}")

    return CommandResults(readable_output="Incident deleted.")


def incident_types_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Get incident types list from opencti

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
        query_variables = {"category": "incident_type_ov"}
        result = client.query(query=query, variables=query_variables)
        incident_types_list = result["data"]["vocabularies"]["edges"]
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't list incident types. {e}")

    if incident_types_list:
        incident_types = [incident_type["node"] for incident_type in incident_types_list]
        readable_output = tableToMarkdown(
            "Incident Types", incident_types, headers=["id", "name", "description"], headerTransform=pascalToSpace
        )

        outputs = {"OpenCTI.IncidentTypes.IncidentTypesList(val.id === obj.id)": incident_types}
        return CommandResults(outputs=outputs, readable_output=readable_output, raw_response=result)
    else:
        return CommandResults(readable_output="No incident types")


def get_incidents_command(client: OpenCTIApiClient, args: Dict[str, Any]) -> CommandResults:
    """List incidents in OpenCTI with optional filters and pagination.

    Args:
        client: OpenCTI Client object.
        args: demisto.args()

    Returns:
        CommandResults object with readable_output, raw_response, and pagination cursor.
    """
    limit = arg_to_number(args.get("limit", "50"))
    last_run_id = args.get("last_run_id")
    label = args.get("label_id")
    created_by = args.get("created_by")
    creator = args.get("creator")
    created_after = args.get("created_after")
    created_before = args.get("created_before")
    search = args.get("search", "")
    incident_types = argToList(args.get("incident_types"))
    additional_filters = argToList(args.get("additional_filters", []))
    get_all = argToBoolean(args.get("all_results", "false"))

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
        get_all=get_all,
    )

    last_run = None
    if not get_all:
        last_run = raw_response.get("pagination", {}).get("endCursor")

    if incidents_list := raw_response if get_all else copy.deepcopy(raw_response.get("entities", {})):
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
                "updatedAt": incident.get("updated_at"),
            }
            for incident in incidents_list
        ]

        readable_output = tableToMarkdown(
            "Incidents",
            incidents,
            headers=[
                "id",
                "name",
                "description",
                "source",
                "confidence",
                "severity",
                "objective",
                "createdBy",
                "creators",
                "labels",
                "incidentTypes",
                "created",
                "updatedAt",
            ],
            headerTransform=pascalToSpace,
        )
        outputs = {
            "OpenCTI.Incidents(val.lastRunID)": {"lastRunID": last_run},
            "OpenCTI.Incidents.IncidentList(val.id === obj.id)": incidents,
        }

        return CommandResults(outputs=outputs, readable_output=readable_output, raw_response=incidents_list)
    else:
        return CommandResults(readable_output="No incidents.")


def indicator_types_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Get indicator types list from opencti

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
        query_variables = {"category": "indicator_type_ov"}
        result = client.query(query=query, variables=query_variables)
        indicator_types_list = result["data"]["vocabularies"]["edges"]
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't list indicator types. {e}")

    if indicator_types_list:
        indicator_types = [indicator_type["node"] for indicator_type in indicator_types_list]
        readable_output = tableToMarkdown(
            "Indicator Types", indicator_types, headers=["id", "name", "description"], headerTransform=pascalToSpace
        )

        outputs = {"OpenCTI.IndicatorTypes.IndicatorTypesList(val.id === obj.id)": indicator_types}
        return CommandResults(outputs=outputs, readable_output=readable_output, raw_response=result)
    else:
        return CommandResults(readable_output="No indicator types.")


def relationship_create_command(client: OpenCTIApiClient, args: Dict[str, Any]) -> CommandResults:
    """Create relationship at opencti

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
            fromId=from_id, toId=to_id, relationship_type=relationship_type, description=description, confidence=confidence
        )
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create relationship. {e}")

    if relationship_id := result.get("id"):
        readable_output = f"Relationship created successfully. New Relationship id: {relationship_id}."
        return CommandResults(
            outputs_prefix="OpenCTI.Relationship",
            outputs_key_field="id",
            outputs={
                "id": relationship_id,
                "relationshipType": result.get("relationship_type"),
            },
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create relationship.")


def relationship_delete_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
    """Delete relationship from opencti

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
    return CommandResults(readable_output="Relationship deleted.")


def relationship_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Get relationships list from opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    from_id = args.get("from_id")
    limit = arg_to_number(args.get("limit", "50"))
    last_run_id = args.get("last_run_id")
    relationships_list = client.stix_core_relationship.list(
        fromOrToId=from_id, first=limit, after=last_run_id, withPagination=True
    )

    if relationships_list:
        new_last_run = relationships_list.get("pagination").get("endCursor")
        relationships = [
            {
                "id": relationship.get("id"),
                "relationshipType": relationship.get("relationship_type"),
                "fromId": relationship.get("from").get("id"),
                "toId": relationship.get("to").get("id"),
                "toEntityType": relationship.get("to").get("entity_type"),
            }
            for relationship in relationships_list.get("entities")
        ]
        readable_output = tableToMarkdown(
            "Relationships",
            relationships,
            headers=["id", "relationshipType", "fromId", "toId", "toEntityType"],
            headerTransform=pascalToSpace,
        )
        outputs = {
            "OpenCTI.Relationships(val.relationshipsLastRun)": {"relationshipsLastRun": new_last_run},
            "OpenCTI.Relationships.RelationshipsList(val.id === obj.id)": relationships,
        }
        return CommandResults(outputs=outputs, readable_output=readable_output, raw_response=relationships_list)
    else:
        return CommandResults(readable_output="No relationships")


def get_observables_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
    """Gets observable from opencti to readable output

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    observable_types = argToList(args.get("observable_types", "ALL"))
    last_run_id = args.get("last_run_id")
    limit = arg_to_number(args.get("limit", 50))
    start = arg_to_number(args.get("score_start", 0))
    end = arg_to_number(args.get("score_end", 100))  # type:ignore
    score = args.get("score")
    search = args.get("search", "")
    additional_filters = argToList(args.get("additional_filters", []))
    get_all = argToBoolean(args.get("all_results", "false"))
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
        get_all=get_all,
    )

    last_run = None
    if not get_all:
        last_run = raw_response.get("pagination", {}).get("endCursor")  # type: ignore

    if observables_list := raw_response if get_all else copy.deepcopy(raw_response.get("entities", {})):
        observables = [
            {
                "type": OPENCTI_TYPES_TO_XSOAR.get(observable["entity_type"], observable["entity_type"]),
                "value": observable.get("observable_value"),
                "id": observable.get("id"),
                "createdBy": observable.get("createdBy").get("id") if observable.get("createdBy") else None,
                "score": observable.get("x_opencti_score"),
                "description": observable.get("x_opencti_description"),
                "labels": [label.get("value") for label in observable.get("objectLabel")],
                "marking": [mark.get("definition") for mark in observable.get("objectMarking")],
                "externalReferences": observable.get("externalReferences"),
            }
            for observable in observables_list
        ]

        readable_output = tableToMarkdown("Observables", observables, headers=["type", "value", "id"], removeNull=True)

        outputs = {
            "OpenCTI.Observables(val.lastRunID)": {"lastRunID": last_run},
            "OpenCTI.Observables.ObservablesList(val.id === obj.id)": observables,
        }
        return CommandResults(outputs=outputs, readable_output=readable_output, raw_response=observables_list)
    else:
        return CommandResults(readable_output="No observables.")


def observable_delete_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
    """Delete observable from opencti

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
    return CommandResults(readable_output="Observable deleted.")


def observable_field_update_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
    """Update observable field at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    observable_id = args.get("id")
    # works only with score and description
    key = KEY_TO_CTI_NAME[args.get("field")]  # type: ignore
    value: Any = args.get("value")
    if key == "x_opencti_score":
        value = int(value)
    try:
        result = client.stix_cyber_observable.update_field(id=observable_id, input=[{"key": key, "value": value}])
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't update observable. {e}")

    if not result:
        raise DemistoException("Can't update observable.")
    return CommandResults(
        outputs_prefix="OpenCTI.Observable",
        outputs_key_field="id",
        outputs={"id": result.get("id")},
        readable_output=f"Observable {observable_id} updated successfully.",
        raw_response=result,
    )


def observable_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Create observable at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    redirect_std_out = argToBoolean(demisto.params().get("redirect_std_out", "false"))
    observable_type = args.get("type")
    created_by = args.get("created_by")
    marking_id = args.get("marking_id")
    label_id = args.get("label_id")
    external_references_id = args.get("external_references_id")
    description = args.get("description")
    score = arg_to_number(args.get("score", "50"))
    value = args.get("value")
    create_indicator = argToBoolean(args.get("create_indicator", "false"))
    data = {
        "type": XSOAR_TYPES_TO_OPENCTI.get(observable_type.lower(), observable_type),  # type:ignore
        "value": value,
    }
    if observable_type == "Registry Key":
        data["key"] = value
    if observable_type == "Account":
        data["account_login"] = value

    simple_observable_key = None
    simple_observable_value = None
    if "file" in observable_type.lower():  # type: ignore
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
            createdBy=created_by,
            objectMarking=marking_id,
            objectLabel=label_id,
            externalReferences=external_references_id,
            simple_observable_description=description,
            x_opencti_score=score,
            observableData=data,
            createIndicator=create_indicator,
        )
        if redirect_std_out:
            sys.stdout = sys.__stdout__
    except KeyError as e:
        raise DemistoException(f"Missing argument at data {e}")

    if id := result.get("id"):
        readable_output = f"Observable created successfully. New Observable id: {id}"
        outputs = {"id": result.get("id"), "value": value, "type": observable_type}
    else:
        raise DemistoException("Can't create observable.")

    return CommandResults(
        outputs_prefix="OpenCTI.Observable",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result,
    )


def observable_add_marking(client: OpenCTIApiClient, id: str | None, value: str | None):
    """Add observable marking to opencti
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
    """Add observable label to opencti
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
    """Add observable marking or label to opencti

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

    if key == "marking":
        result = observable_add_marking(client=client, id=observable_id, value=value)

    elif key == "label":
        result = observable_add_label(client=client, id=observable_id, value=value)
    if result:
        return CommandResults(readable_output=f"Added {key} successfully.")
    else:
        raise DemistoException(f"Can't add {key}.")


def observable_remove_label(client: OpenCTIApiClient, id: str | None, value: str | None):
    """Remove observable label from opencti
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
    """Remove observable marking from opencti
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
    """Remove observable marking or label from opencti

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

    if key == "marking":
        result = observable_remove_marking(client=client, id=observable_id, value=value)

    elif key == "label":
        result = observable_remove_label(client=client, id=observable_id, value=value)

    if result:
        return CommandResults(readable_output=f"{key}: {value} was removed successfully from observable: {observable_id}.")
    else:
        raise DemistoException(f"Can't remove {key}.")


def indicator_add_marking(client: OpenCTIApiClient, id: str | None, value: str | None):
    """Add indicator marking to opencti
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
    """Add indicator label to opencti
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
    """Add indicator marking or label to opencti

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

    if key == "marking":
        result = indicator_add_marking(client=client, id=indicator_id, value=value)

    elif key == "label":
        result = indicator_add_label(client=client, id=indicator_id, value=value)
    if result:
        return CommandResults(readable_output=f"Added {key} successfully.")
    else:
        raise DemistoException(f"Can't add {key}.")


def indicator_remove_label(client: OpenCTIApiClient, id: str | None, value: str | None):
    """Remove indicator label from opencti
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
    """Remove indicator marking from opencti
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
    """Remove indicator marking or label from opencti

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

    if key == "marking":
        result = indicator_remove_marking(client=client, id=indicator_id, value=value)

    elif key == "label":
        result = indicator_remove_label(client=client, id=indicator_id, value=value)

    if result:
        return CommandResults(readable_output=f"{key}: {value} was removed successfully from indicator: {indicator_id}.")
    else:
        raise DemistoException(f"Can't remove {key}.")


def indicator_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Create an indicator in OpenCTI.

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        CommandResults object with readable_output, raw_response
    """
    name = args["name"]
    indicator = args["indicator"]
    main_observable_type = XSOAR_TYPES_TO_OPENCTI.get(args["main_observable_type"].lower(), args["main_observable_type"])
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
    create_observables = argToBoolean(args.get("create_observables", "false"))

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
            x_opencti_create_observables=create_observables,
        )
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create indicator. {e}")

    if indicator_id := result.get("id"):
        readable_output = f"Indicator created successfully. New Indicator id: {indicator_id}."
        return CommandResults(
            outputs_prefix="OpenCTI.Indicator",
            outputs_key_field="id",
            outputs={
                "id": result.get("id"),
            },
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create indicator.")


def indicator_update_command(client: OpenCTIApiClient, args: Dict[str, Any]) -> CommandResults:
    """Update an existing indicator in OpenCTI using a GraphQL mutation.

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
        update_fields.append({"key": "indicator_types", "value": indicator_types.split(",")})
    if created_by := args.get("created_by"):
        update_fields.append({"key": "createdBy", "value": created_by})
    if label_id := args.get("label_id"):
        update_fields.append({"key": "objectLabel", "value": label_id.split(",")})
    if marking_id := args.get("marking_id"):
        update_fields.append({"key": "objectMarking", "value": marking_id.split(",")})
    if external_references_id := args.get("external_references_id"):
        update_fields.append({"key": "externalReferences", "value": external_references_id.split(",")})

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
        "references": args.get("references"),
    }

    try:
        result = client.query(mutation, variables)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't update indicator. {e}")

    if updated_indicator := result.get("data", {}).get("indicatorFieldPatch", None):
        readable_output = "Indicator updated successfully."
        return CommandResults(
            outputs_prefix="OpenCTI.Indicator",
            outputs_key_field="id",
            outputs={
                "id": updated_indicator.get("id"),
                "name": updated_indicator.get("name"),
                "validFrom": updated_indicator.get("valid_from"),
                "validUntil": updated_indicator.get("valid_until"),
            },
            readable_output=readable_output,
            raw_response=result,
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
    limit = arg_to_number(args.get("limit", "50"))
    last_run_id = args.get("last_run_id")
    label = args.get("label_id")
    created_by = args.get("created_by")
    creator = args.get("creator")
    created_after = args.get("created_after")
    created_before = args.get("created_before")
    valid_until_after = args.get("valid_until_after")
    valid_until_before = args.get("valid_until_before")
    valid_from_after = args.get("valid_from_after")
    valid_from_before = args.get("valid_from_before")
    search = args.get("search", "")
    indicator_types = argToList(args.get("indicator_types"))
    additional_filters = argToList(args.get("additional_filters", []))
    get_all = argToBoolean(args.get("all_results", "false"))

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
        get_all=get_all,
    )

    last_run = None
    if not get_all:
        last_run = raw_response.get("pagination", {}).get("endCursor")

    if indicators_list := raw_response if get_all else copy.deepcopy(raw_response.get("entities", {})):
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
                "updatedAt": indicator.get("updated_at"),
            }
            for indicator in indicators_list
        ]

        readable_output = tableToMarkdown(
            "Indicators",
            indicators,
            headers=[
                "id",
                "name",
                "description",
                "pattern",
                "validFrom",
                "validUntil",
                "confidence",
                "score",
                "createdBy",
                "creators",
                "labels",
                "indicatorTypes",
                "created",
                "updatedAt",
            ],
            headerTransform=pascalToSpace,
        )
        outputs = {
            "OpenCTI.Indicators(val.lastRunID)": {"lastRunID": last_run},
            "OpenCTI.Indicators.IndicatorList(val.id === obj.id)": indicators,
        }

        return CommandResults(outputs=outputs, readable_output=readable_output, raw_response=indicators_list)
    else:
        return CommandResults(readable_output="No indicators.")


def organization_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Get organizations list from opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    limit = arg_to_number(args.get("limit", "50"))
    last_run_id = args.get("last_run_id")
    organizations_list = client.identity.list(types="Organization", first=limit, after=last_run_id, withPagination=True)

    if organizations_list:
        new_last_run = organizations_list.get("pagination").get("endCursor")
        organizations = [
            {"name": organization.get("name"), "id": organization.get("id")}
            for organization in organizations_list.get("entities")
        ]
        readable_output = tableToMarkdown("Organizations", organizations, headers=["name", "id"], headerTransform=pascalToSpace)
        outputs = {
            "OpenCTI.Organizations(val.organizationsLastRun)": {"organizationsLastRun": new_last_run},
            "OpenCTI.Organizations.OrganizationsList(val.id === obj.id)": organizations,
        }
        return CommandResults(outputs=outputs, readable_output=readable_output, raw_response=organizations_list)
    else:
        return CommandResults(readable_output="No organizations")


def organization_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Create organization at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    name = args.get("name")
    description = args.get("description")
    reliability = args.get("reliability")
    try:
        identity = Identity(client)
        result = identity.create(name=name, type="Organization", x_opencti_reliability=reliability, description=description)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create organization. {e}")

    if organization_id := result.get("id"):
        readable_output = f"Organization {name} was created successfully with id: {organization_id}."
        return CommandResults(
            outputs_prefix="OpenCTI.Organization",
            outputs_key_field="id",
            outputs={"id": result.get("id")},
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create organization.")


def label_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Get label list from opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    limit = arg_to_number(args.get("limit", "50"))
    last_run_id = args.get("last_run_id")
    label_list = client.label.list(first=limit, after=last_run_id, withPagination=True)

    if label_list:
        new_last_run = label_list.get("pagination").get("endCursor")
        labels = [{"value": label.get("value"), "id": label.get("id")} for label in label_list.get("entities")]
        readable_output = tableToMarkdown("Labels", labels, headers=["value", "id"], headerTransform=pascalToSpace)

        outputs = {
            "OpenCTI.Labels(val.labelsLastRun)": {"labelsLastRun": new_last_run},
            "OpenCTI.Labels.LabelsList(val.id === obj.id)": labels,
        }
        return CommandResults(outputs=outputs, readable_output=readable_output, raw_response=label_list)
    else:
        return CommandResults(readable_output="No labels")


def label_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Create label at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    name = args.get("name")
    result = label_create(client=client, label_name=name)

    if label_id := result.get("id"):
        readable_output = f"Label {name} was created successfully with id: {label_id}."
        return CommandResults(
            outputs_prefix="OpenCTI.Label",
            outputs_key_field="id",
            outputs={"id": result.get("id")},
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create label.")


def external_reference_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Create external reference at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    external_references_source_name = args.get("source_name")
    external_references_url = args.get("url")

    result = client.external_reference.create(source_name=external_references_source_name, url=external_references_url)

    if external_reference_id := result.get("id"):
        readable_output = (
            f"Reference {external_references_source_name} was created successfully with id: {external_reference_id}."
        )
        return CommandResults(
            outputs_prefix="OpenCTI.externalReference",
            outputs_key_field="id",
            outputs={"id": result.get("id")},
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create external reference.")


def marking_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Get marking list from opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    limit = arg_to_number(args.get("limit", "50"))
    last_run_id = args.get("last_run_id")
    marking_list = client.marking_definition.list(first=limit, after=last_run_id, withPagination=True)

    if marking_list:
        new_last_run = marking_list.get("pagination").get("endCursor")
        markings = [{"value": mark.get("definition"), "id": mark.get("id")} for mark in marking_list.get("entities")]

        readable_output = tableToMarkdown("Markings", markings, headers=["value", "id"], headerTransform=pascalToSpace)
        outputs = {
            "OpenCTI.MarkingDefinitions(val.markingsLastRun)": {"markingsLastRun": new_last_run},
            "OpenCTI.MarkingDefinitions.MarkingDefinitionsList(val.id === obj.id)": markings,
        }

        return CommandResults(outputs=outputs, readable_output=readable_output, raw_response=marking_list)
    else:
        return CommandResults(readable_output="No markings")


def incident_response_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Create incident response at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    name = args.get("name")
    response_types = args.get("incident_response_type", None)
    severity = args.get("severity", None)
    priority = args.get("priority", None)
    description = args.get("description", None)
    created_by = args.get("created_by")
    incident_response_date = args.get("incident_response_date", None)
    label_id = args.get("label_id", None)
    marking_id = args.get("marking_id", None)
    external_references_id = args.get("external_references_id", None)

    try:
        result = client.case_incident.create(
            name=name,
            created=incident_response_date,
            response_types=response_types,
            severity=severity,
            priority=priority,
            description=description,
            createdBy=created_by,
            objectLabel=label_id,
            objectMarking=marking_id,
            externalReferences=external_references_id,
        )
    except Exception as e:
        demisto.error(traceback.format_exc())
        raise DemistoException(f"Can't create incident response. {e}")

    if result and (incident_response_id := result.get("id")):
        readable_output = f"Incident response created successfully. New Incident Response id: {incident_response_id}."
        return CommandResults(
            outputs_prefix="OpenCTI.IncidentResponse",
            outputs_key_field="id",
            outputs={"id": result.get("id")},
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create incident response.")


def malware_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Create malware at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    name = args.get("name")
    description = args.get("description", None)
    is_family = argToBoolean(args.get("is_family", False))
    malware_types = argToList(args.get("malware_types"))

    try:
        result = client.malware.create(name=name, description=description, is_family=is_family, malware_types=malware_types)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create malware. {e}")

    if result and (malware_id := result.get("id")):
        readable_output = f"Malware created successfully. New Malware id: {malware_id}."
        return CommandResults(
            outputs_prefix="OpenCTI.Malware",
            outputs_key_field="id",
            outputs={"id": result.get("id")},
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create malware.")


def vulnerability_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Create vulnerability at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    name = args.get("name")
    description = args.get("description", None)

    try:
        result = client.vulnerability.create(name=name, description=description)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create vulnerability. {e}")

    if result and (vulnerability_id := result.get("id")):
        readable_output = f"Vulnerability created successfully. New Vulnerability id: {vulnerability_id}."
        return CommandResults(
            outputs_prefix="OpenCTI.Vulnerability",
            outputs_key_field="id",
            outputs={"id": result.get("id")},
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create vulnerability.")


def intrusion_set_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Create intrusion-set at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    name = args.get("name")
    description = args.get("description", None)
    try:
        result = client.intrusion_set.create(name=name, description=description)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create intrusion set. {e}")

    if result and (intrusion_set_id := result.get("id")):
        readable_output = f"Intrusion set created successfully. New Intrusion Set id: {intrusion_set_id}."
        return CommandResults(
            outputs_prefix="OpenCTI.IntrusionSet",
            outputs_key_field="id",
            outputs={"id": result.get("id")},
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create intrusion set.")


def threat_actor_group_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Create threat-actor-group at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    name = args.get("name")
    description = args.get("description", None)
    try:
        result = client.threat_actor_group.create(name=name, description=description)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create threat-actor-group. {e}")

    if result and (threat_actor_group_id := result.get("id")):
        readable_output = f"Threat Actor Group created successfully. New Threat Actor Group id: {threat_actor_group_id}."
        return CommandResults(
            outputs_prefix="OpenCTI.ThreatActorGroup",
            outputs_key_field="id",
            outputs={"id": result.get("id")},
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create threat-actor-group.")


def campaign_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Create campaign at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    name = args.get("name")
    description = args.get("description", None)
    first_seen = args.get("first_seen", None)
    last_seen = args.get("last_seen", None)

    try:
        result = client.campaign.create(name=name, description=description, first_seen=first_seen, last_seen=last_seen)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create campaign. {e}")

    if result and (campaign_id := result.get("id")):
        readable_output = f"Campaign created successfully. New Campaign id: {campaign_id}."
        return CommandResults(
            outputs_prefix="OpenCTI.Campaign",
            outputs_key_field="id",
            outputs={"id": result.get("id")},
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create campaign.")


def grouping_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Create grouping at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    name = args.get("name")
    description = args.get("description", None)
    context = args.get("context")

    try:
        result = client.grouping.create(name=name, description=description, context=context)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create grouping. {e}")

    if result and (grouping_id := result.get("id")):
        readable_output = f"Grouping created successfully. New Grouping id: {grouping_id}."
        return CommandResults(
            outputs_prefix="OpenCTI.Grouping",
            outputs_key_field="id",
            outputs={"id": result.get("id")},
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create grouping.")


def report_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Create report at opencti

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    name = args.get("name")
    description = args.get("description", None)
    published = args.get("published")

    try:
        result = client.report.create(name=name, description=description, published=published)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't create report. {e}")

    if result and (report_id := result.get("id")):
        readable_output = f"Report created successfully. New Report id: {report_id}."
        return CommandResults(
            outputs_prefix="OpenCTI.Report",
            outputs_key_field="id",
            outputs={"id": result.get("id")},
            readable_output=readable_output,
            raw_response=result,
        )
    else:
        raise DemistoException("Can't create report.")


def add_object_to_container_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """Add object Id into a container Id

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    container_type = args.get("container_type")
    container_id = args.get("container_id")
    object_id = args.get("object_id")

    client_attribute = CONTAINER_CLIENT_ATTRIBUTES.get(container_type or "")
    if not client_attribute:
        supported = ", ".join(f"'{name}'" for name in CONTAINER_CLIENT_ATTRIBUTES)
        error = (
            f"Can't add object into container. Invalid container_type: {container_type}. "
            f"Supported containers are: {supported}."
        )
        demisto.error(error)
        raise DemistoException(error)

    try:
        added = getattr(client, client_attribute).add_stix_object_or_stix_relationship(
            id=container_id,
            stixObjectOrStixRelationshipId=object_id,
        )
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't add object into {container_type}. {e}")

    if not added:
        raise DemistoException(f"Can't add object into {container_type}.")
    return CommandResults(readable_output=f"Object added into {container_type}")


def opencti_score_to_dbot_score(
    score: Any,
    threshold: int | None = DEFAULT_REPUTATION_THRESHOLD,
    suspicious_threshold: int | None = DEFAULT_SUSPICIOUS_THRESHOLD,
) -> int:
    """Map an OpenCTI indicator score (x_opencti_score, 0-100) to a DBot score.

    Args:
        score: x_opencti_score of the OpenCTI indicator, None when no indicator was found.
        threshold: score above which the indicator is malicious.
        suspicious_threshold: score above which the indicator is suspicious.

    Returns:
        Common.DBotScore.NONE when there is no score (the value is unknown to OpenCTI), BAD above the malicious
        threshold, SUSPICIOUS above the suspicious threshold, GOOD otherwise.
    """
    try:
        score = min(max(int(score), 0), 100)
    except (TypeError, ValueError):
        return Common.DBotScore.NONE
    threshold = DEFAULT_REPUTATION_THRESHOLD if threshold is None else threshold
    suspicious_threshold = DEFAULT_SUSPICIOUS_THRESHOLD if suspicious_threshold is None else suspicious_threshold
    if score > threshold:
        return Common.DBotScore.BAD
    if score > suspicious_threshold:
        return Common.DBotScore.SUSPICIOUS
    return Common.DBotScore.GOOD


def get_reputation_thresholds(params: dict) -> tuple[int, int]:
    """Return the (suspicious, malicious) score thresholds of the integration parameters.

    Raises:
        DemistoException: a threshold is not between 0 and 100, or the suspicious one is above the malicious one.
    """
    thresholds = []
    for name, default in (
        ("reputation_suspicious_threshold", DEFAULT_SUSPICIOUS_THRESHOLD),
        ("reputation_threshold", DEFAULT_REPUTATION_THRESHOLD),
    ):
        value = arg_to_number(params.get(name), arg_name=name)
        value = default if value is None else value
        if not 0 <= value <= 100:
            raise DemistoException(f"The {name} parameter must be between 0 and 100, got {value}.")
        thresholds.append(value)
    suspicious_threshold, malicious_threshold = thresholds
    if suspicious_threshold > malicious_threshold:
        raise DemistoException(
            f"The suspicious score threshold ({suspicious_threshold}) must not be above the malicious score threshold "
            f"({malicious_threshold})."
        )
    return suspicious_threshold, malicious_threshold


def is_valid_ip(value: str) -> bool:
    """Return True when the value is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def get_file_hash_type(value: str) -> tuple[str, str] | None:
    """Return the (OpenCTI hash name, XSOAR File field) of an MD5, SHA-1 or SHA-256 hash, None otherwise."""
    value = (value or "").strip()
    if not re.fullmatch(r"[A-Fa-f0-9]+", value):
        return None
    return FILE_HASH_TYPES.get(len(value))


def build_reputation_pattern(value: str, indicator_type: str) -> str | None:
    """Build the STIX pattern an OpenCTI indicator of this value would have."""
    if indicator_type == "file":
        hash_type = get_file_hash_type(value)
        return f"[file:hashes.'{hash_type[0]}' = '{value}']" if hash_type else None
    if indicator_type == "ip":
        observable_type = "IPv6-Addr" if ":" in value else "IPv4-Addr"
    else:
        observable_type = {"domain": "Domain-Name", "email": "Email-Addr", "url": "Url"}[indicator_type]
    return build_stix_pattern(value, observable_type)


def get_names(items: list | None, key: str) -> list[str]:
    """Return the `key` value of every item of an OpenCTI list (labels, markings, creators)."""
    return [item.get(key) for item in items or [] if item and item.get(key)]


def get_external_references(entity: dict) -> list[dict]:
    """Return the source name and URL of the external references of an OpenCTI entity."""
    references = []
    for reference in entity.get("externalReferences") or []:
        source_name = reference.get("source_name") or reference.get("sourceName")
        url = reference.get("url")
        if source_name or url:
            references.append({"sourceName": source_name, "url": url})
    return references


def entity_name(entity: dict) -> str | None:
    """Return the display name of an OpenCTI entity or observable."""
    return entity.get("name") or entity.get("observable_value") or entity.get("value")


def is_incoming_relationship(relationship: dict) -> bool:
    """Return True when the related entity is the source of the relationship (see get_entity_relationships)."""
    return bool(relationship.get("relatedEntityId")) and relationship.get("relatedEntityId") == relationship.get("fromId")


def get_entity_relationships(client: OpenCTIApiClient, entity_id: str, excluded_entity_id: str | None = None) -> list[dict]:
    """Return the relationships of an OpenCTI observable or indicator with the entity on their other side.

    Args:
        client: OpenCTI Client object
        entity_id: ID of the observable or indicator
        excluded_entity_id: ID of an entity whose relationships with this one are left out (the indicator of the
            observable, or the reverse: their based-on relationship only links the two objects already returned)

    Returns:
        The relationships. A failure is logged and does not fail the reputation command.
    """
    try:
        raw_relationships = (
            client.stix_core_relationship.list(fromOrToId=entity_id, first=MAX_ENTITY_RELATIONSHIPS, withPagination=False) or []
        )
    except Exception as e:
        demisto.error(f"Can't list the relationships of {entity_id}. {e}")
        return []

    relationships = []
    for relationship in raw_relationships:
        from_entity = relationship.get("from") or {}
        to_entity = relationship.get("to") or {}
        outgoing = from_entity.get("id") == entity_id
        related_entity = to_entity if outgoing else from_entity
        if excluded_entity_id and related_entity.get("id") == excluded_entity_id:
            continue
        relationships.append(
            {
                "id": relationship.get("id"),
                "relationshipType": relationship.get("relationship_type"),
                "fromId": from_entity.get("id"),
                "fromName": entity_name(from_entity),
                "fromEntityType": from_entity.get("entity_type"),
                "toId": to_entity.get("id"),
                "toName": entity_name(to_entity),
                "toEntityType": to_entity.get("entity_type"),
                "relatedEntityId": related_entity.get("id"),
                "relatedEntityName": entity_name(related_entity),
                "relatedEntityType": related_entity.get("entity_type"),
            }
        )
    return relationships


def find_observable(client: OpenCTIApiClient, value: str, indicator_type: str) -> dict | None:
    """Find the OpenCTI observable that has exactly this value (this hash for files)."""
    if indicator_type == "file":
        value_filter = {"key": f"hashes.{get_file_hash_type(value)[0]}", "values": [value], "operator": "eq"}  # type: ignore[index]
    else:
        value_filter = {"key": "value", "values": [value], "operator": "eq"}
    filters = {
        "mode": "and",
        "filters": [
            {
                "key": "entity_type",
                "values": REPUTATION_COMMANDS[indicator_type]["observable_types"],
                "operator": "eq",
                "mode": "or",
            },
            value_filter,
        ],
        "filterGroups": [],
    }
    observables = client.stix_cyber_observable.list(first=1, withPagination=False, filters=filters)
    return observables[0] if observables else None


def find_indicator(client: OpenCTIApiClient, value: str, indicator_type: str) -> dict | None:
    """Find the OpenCTI STIX indicator whose pattern matches exactly this value.

    The pattern is first matched by an exact filter, then among the results of a full-text search.
    """
    pattern = build_reputation_pattern(value, indicator_type)
    base_filters = [
        {
            "key": "x_opencti_main_observable_type",
            "values": REPUTATION_COMMANDS[indicator_type]["main_observable_types"],
            "operator": "eq",
            "mode": "or",
        },
        {"key": "pattern_type", "values": ["stix"], "operator": "eq"},
    ]
    exact_filters = {
        "mode": "and",
        "filters": [*base_filters, {"key": "pattern", "values": [pattern], "operator": "eq"}],
        "filterGroups": [],
    }
    indicators = client.indicator.list(first=1, withPagination=False, filters=exact_filters)
    if not indicators:
        search_filters = {"mode": "and", "filters": base_filters, "filterGroups": []}
        candidates = client.indicator.list(first=10, withPagination=False, filters=search_filters, search=f'"{value}"')
        indicators = [indicator for indicator in candidates or [] if indicator.get("pattern") == pattern]
    return indicators[0] if indicators else None


def build_observable_details(observable: dict | None, value: str, indicator_type: str, relationships: list[dict]) -> dict:
    """Build the OpenCTI.Observable context of a reputation command."""
    if not observable:
        return {"found": False, "value": value, "type": indicator_type}
    entity_type = observable.get("entity_type") or ""
    return {
        "found": True,
        "id": observable.get("id"),
        "value": value,
        "type": OPENCTI_TYPES_TO_XSOAR.get(entity_type, entity_type),
        "entityType": entity_type,
        "score": observable.get("x_opencti_score"),
        "description": observable.get("x_opencti_description"),
        "createdBy": (observable.get("createdBy") or {}).get("name"),
        "creators": get_names(observable.get("creators"), "name"),
        "labels": get_names(observable.get("objectLabel"), "value"),
        "markings": get_names(observable.get("objectMarking"), "definition"),
        "externalReferences": get_external_references(observable),
        "relationships": relationships,
        "created": observable.get("created_at"),
        "updatedAt": observable.get("updated_at"),
    }


def build_indicator_details(indicator: dict, relationships: list[dict]) -> dict:
    """Build the OpenCTI.Indicator context of a reputation command."""
    return {
        "id": indicator.get("id"),
        "name": indicator.get("name"),
        "description": indicator.get("description"),
        "patternType": indicator.get("pattern_type"),
        "pattern": indicator.get("pattern"),
        "mainObservableType": indicator.get("x_opencti_main_observable_type"),
        "indicatorTypes": indicator.get("indicator_types") or [],
        "score": indicator.get("x_opencti_score"),
        "confidence": indicator.get("confidence"),
        "validFrom": indicator.get("valid_from"),
        "validUntil": indicator.get("valid_until"),
        "revoked": indicator.get("revoked"),
        "detection": indicator.get("x_opencti_detection"),
        "created": indicator.get("created"),
        "updatedAt": indicator.get("updated_at"),
        "createdBy": (indicator.get("createdBy") or {}).get("name"),
        "creators": get_names(indicator.get("creators"), "name"),
        "labels": get_names(indicator.get("objectLabel"), "value"),
        "markings": get_names(indicator.get("objectMarking"), "definition"),
        "externalReferences": get_external_references(indicator),
        "relationships": relationships,
    }


def opencti_link(platform_url: str, entity_id: str | None, text: str | None = None) -> str | None:
    """Return a markdown link to an OpenCTI entity page, or the plain text when there is no platform URL or ID."""
    text = text or entity_id
    if not platform_url or not entity_id:
        return text
    return f"[{text}]({platform_url}/dashboard/id/{entity_id})"


def relationships_to_markdown(title: str, relationships: list[dict], platform_url: str = "") -> str:
    """Render relationships as a Relationship / Entity type / Entity table. Incoming relationships are marked with ←.

    The related entities link to their OpenCTI page when the platform URL is given.
    """
    rows = [
        {
            "Relationship": ("← " if is_incoming_relationship(relationship) else "") + str(relationship.get("relationshipType")),
            "Entity type": relationship.get("relatedEntityType"),
            "Entity": opencti_link(platform_url, relationship.get("relatedEntityId"), relationship.get("relatedEntityName")),
        }
        for relationship in relationships
    ]
    return tableToMarkdown(title, rows, headers=["Relationship", "Entity type", "Entity"], removeNull=True)


def build_entity_relationships(
    value: str, indicator_type: str, relationships: list[dict], reliability: str
) -> list[EntityRelationship]:
    """Convert the OpenCTI relationships of a value into XSOAR relationships, the value being entity A.

    Args:
        value: the value checked by the reputation command
        indicator_type: ip, domain, email, url or file
        relationships: the relationships of its observable and indicator (see get_entity_relationships)
        reliability: reliability of the source

    Returns:
        One XSOAR relationship per related entity and relationship name. Related entities whose type has no
        XSOAR equivalent are left out.
    """
    entity_a_type = REPUTATION_COMMANDS[indicator_type]["relationship_type"]
    if indicator_type == "ip" and ":" in value:
        entity_a_type = FeedIndicatorType.IPv6

    entity_relationships = []
    seen = set()
    for relationship in relationships:
        entity_b = relationship.get("relatedEntityName")
        entity_b_type = OPENCTI_TYPES_TO_RELATIONSHIP_TYPES.get(relationship.get("relatedEntityType") or "")
        if not entity_b or not entity_b_type:
            continue
        opencti_name = relationship.get("relationshipType") or ""
        name = OPENCTI_RELATIONSHIP_NAMES.get(opencti_name, opencti_name)
        if not EntityRelationship.Relationships.is_valid(name):
            name = EntityRelationship.Relationships.RELATED_TO
        if is_incoming_relationship(relationship):
            name = EntityRelationship.Relationships.get_reverse(name)
        if (name, entity_b, entity_b_type) in seen:
            continue
        seen.add((name, entity_b, entity_b_type))
        entity_relationships.append(
            EntityRelationship(
                name=name,
                entity_a=value,
                entity_a_type=entity_a_type,
                entity_b=entity_b,
                entity_b_type=entity_b_type,
                source_reliability=reliability,
                brand="OpenCTI",
            )
        )
    return entity_relationships


def build_reputation_indicator(
    value: str, indicator_type: str, dbot_score: Common.DBotScore, relationships: list[EntityRelationship]
) -> Common.Indicator:
    """Build the XSOAR standard indicator (Common.IP, Common.Domain...) of a reputation command."""
    if indicator_type == "ip":
        return Common.IP(ip=value, dbot_score=dbot_score, relationships=relationships)
    if indicator_type == "domain":
        return Common.Domain(domain=value, dbot_score=dbot_score, relationships=relationships)
    if indicator_type == "email":
        return Common.EMAIL(address=value, dbot_score=dbot_score, relationships=relationships)
    if indicator_type == "url":
        return Common.URL(url=value, dbot_score=dbot_score, relationships=relationships)
    hash_field = get_file_hash_type(value)[1]  # type: ignore[index]
    return Common.File(dbot_score=dbot_score, relationships=relationships, **{hash_field: value})


def reputation_result(
    client: OpenCTIApiClient,
    value: str,
    indicator_type: str,
    threshold: int | None,
    reliability: str,
    create_relationships: bool,
    platform_url: str = "",
    suspicious_threshold: int | None = DEFAULT_SUSPICIOUS_THRESHOLD,
) -> CommandResults:
    """Check the reputation of one value in OpenCTI: its observable and its indicator, with their relationships."""
    observable = find_observable(client, value, indicator_type)
    indicator = find_indicator(client, value, indicator_type)
    observable_id = observable.get("id") if observable else None
    indicator_id = indicator.get("id") if indicator else None
    observable_relationships = get_entity_relationships(client, observable_id, indicator_id) if observable_id else []
    observable_details = build_observable_details(observable, value, indicator_type, observable_relationships)
    indicator_details = None
    if indicator:
        indicator_relationships = get_entity_relationships(client, indicator_id, observable_id)  # type: ignore[arg-type]
        indicator_details = build_indicator_details(indicator, indicator_relationships)
    score = indicator_details.get("score") if indicator_details else None

    dbot_score_value = opencti_score_to_dbot_score(score, threshold, suspicious_threshold)
    dbot_score = Common.DBotScore(
        indicator=value,
        indicator_type=REPUTATION_COMMANDS[indicator_type]["dbot_type"],
        integration_name="OpenCTI",
        score=dbot_score_value,
        reliability=DBotScoreReliability.get_dbot_score_reliability_from_str(reliability),
        malicious_description=f"OpenCTI score: {score}" if dbot_score_value == Common.DBotScore.BAD else None,
    )

    outputs: dict = {"OpenCTI.Observable(val.value && val.value == obj.value)": observable_details}
    indicator_id = indicator_details.get("id") if indicator_details else None
    observable_id = observable_details.get("id")
    summary = {
        "Value": value,
        "OpenCTI Score": score if score is not None else "Unknown",
        "Indicator ID": indicator_id,
        "Indicator Link": opencti_link(platform_url, indicator_id, OPENCTI_LINK_TEXT) if platform_url and indicator_id else None,
        "Observable ID": observable_id,
        "Observable Link": opencti_link(platform_url, observable_id, OPENCTI_LINK_TEXT)
        if platform_url and observable_id
        else None,
        "Labels": ", ".join((indicator_details or observable_details).get("labels", [])),
        "Markings": ", ".join((indicator_details or observable_details).get("markings", [])),
    }
    readable_output = tableToMarkdown(
        f"OpenCTI reputation for {indicator_type} {value}",
        {header: cell for header, cell in summary.items() if cell is not None},
        headers=[header for header, cell in summary.items() if cell is not None],
        removeNull=True,
    )
    if indicator_details:
        outputs["OpenCTI.Indicator(val.id && val.id == obj.id)"] = indicator_details
        readable_output += tableToMarkdown(
            "Indicator",
            indicator_details,
            headers=["name", "pattern", "score", "confidence", "validFrom", "validUntil", "revoked", "detection", "createdBy"],
            headerTransform=pascalToSpace,
            removeNull=True,
        )
    for title, details in (("Indicator relationships", indicator_details), ("Observable relationships", observable_details)):
        if details and details.get("relationships"):
            readable_output += relationships_to_markdown(title, details["relationships"], platform_url)

    entity_relationships = []
    if create_relationships:
        entity_relationships = build_entity_relationships(
            value,
            indicator_type,
            (indicator_details or {}).get("relationships", []) + observable_details.get("relationships", []),
            reliability,
        )
    demisto.debug(f"OpenCTI reputation for {value}: {create_relationships=}, {len(entity_relationships)} XSOAR relationships.")

    return CommandResults(
        outputs=outputs,
        indicator=build_reputation_indicator(value, indicator_type, dbot_score, entity_relationships),
        relationships=entity_relationships,
        readable_output=readable_output,
        raw_response={"observable": observable_details, "indicator": indicator_details},
    )


def reputation_command(
    client: OpenCTIApiClient,
    args: Dict[str, Any],
    indicator_type: str,
    threshold: int | None = DEFAULT_REPUTATION_THRESHOLD,
    reliability: str = DEFAULT_RELIABILITY,
    create_relationships: bool = True,
    platform_url: str = "",
    suspicious_threshold: int | None = DEFAULT_SUSPICIOUS_THRESHOLD,
) -> list[CommandResults]:
    """Check the reputation of IPs, domains, emails, URLs or file hashes in OpenCTI.

    Args:
        client: OpenCTI Client object
        args: demisto.args()
        indicator_type: ip, domain, email, url or file (the command name)
        threshold: OpenCTI score above which an indicator is malicious
        suspicious_threshold: OpenCTI score above which an indicator is suspicious (below: good)
        reliability: reliability of the source
        create_relationships: whether to create the XSOAR relationships of the values
        platform_url: OpenCTI URL, used to link the indicators, observables and related entities to their page

    Returns:
        One CommandResults per value. A value that can't be checked doesn't fail the others.
    """
    values = argToList(args.get(indicator_type))
    if not values:
        raise DemistoException(f"Please provide at least one value in the '{indicator_type}' argument.")

    results = []
    for value in values:
        if indicator_type == "ip" and not is_valid_ip(value):
            results.append(CommandResults(readable_output=f"{value} is not a valid IP address."))
            continue
        if indicator_type == "file" and not get_file_hash_type(value):
            results.append(CommandResults(readable_output=f"{value} is not a valid MD5, SHA-1 or SHA-256 hash."))
            continue
        try:
            results.append(
                reputation_result(
                    client,
                    value,
                    indicator_type,
                    threshold,
                    reliability,
                    create_relationships,
                    platform_url,
                    suspicious_threshold,
                )
            )
        except Exception as e:
            demisto.error(traceback.format_exc())
            results.append(
                CommandResults(
                    readable_output=f"Can't check the reputation of {value} in OpenCTI. {e}", entry_type=EntryType.WARNING
                )
            )
    return results


def main():
    params = demisto.params()
    args = demisto.args()

    credentials = params.get("credentials", {})
    api_key = credentials.get("password")
    base_url = params.get("base_url").strip("/")
    verify = not argToBoolean(params.get("insecure", False))
    reliability = params.get("integrationReliability") or DEFAULT_RELIABILITY
    create_relationships = argToBoolean(params.get("create_relationships", True))

    try:
        client = OpenCTIApiClient(base_url, api_key, ssl_verify=verify, log_level="error", proxies=handle_proxy())
        command = demisto.command()
        demisto.info(f"Command being called is {command}")

        # Switch case
        if command == "test-module":
            """When setting up an OpenCTI Client it is checked that it is valid and allows requests to be sent.
            and if not he immediately sends an error"""
            get_reputation_thresholds(params)
            get_observables_command(client, args)
            return_results("ok")

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

        elif command == "opencti-incident-response-create":
            return_results(incident_response_create_command(client, args))

        elif command == "opencti-malware-create":
            return_results(malware_create_command(client, args))

        elif command == "opencti-vulnerability-create":
            return_results(vulnerability_create_command(client, args))

        elif command == "opencti-intrusion-set-create":
            return_results(intrusion_set_create_command(client, args))

        elif command == "opencti-threat-actor-group-create":
            return_results(threat_actor_group_create_command(client, args))

        elif command == "opencti-campaign-create":
            return_results(campaign_create_command(client, args))

        elif command == "opencti-grouping-create":
            return_results(grouping_create_command(client, args))

        elif command == "opencti-report-create":
            return_results(report_create_command(client, args))

        elif command == "opencti-add-object-to-container":
            return_results(add_object_to_container_create_command(client, args))

        elif command in REPUTATION_COMMANDS:
            suspicious_threshold, malicious_threshold = get_reputation_thresholds(params)
            return_results(
                reputation_command(
                    client,
                    args,
                    command,
                    malicious_threshold,
                    reliability,
                    create_relationships,
                    base_url,
                    suspicious_threshold=suspicious_threshold,
                )
            )

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Error:\n [{e}]")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

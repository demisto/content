import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


#### CONSTANTS ####

INTEGRATION_NAME = "Unit 42 Intelligence"

# API endpoints
SERVER_URL = "https://prod-us.tas.crtx.paloaltonetworks.com"
LOOKUP_ENDPOINT = "/api/v1/lookups/indicator/{indicator_type}/{indicator_value}"

# Score mappings
VERDICT_TO_SCORE = {
    "malicious": Common.DBotScore.BAD,
    "suspicious": Common.DBotScore.SUSPICIOUS,
    "benign": Common.DBotScore.GOOD,
    "unknown": Common.DBotScore.NONE,
}

# Indicator type mappings
INDICATOR_TYPE_MAPPING = {
    "ip": FeedIndicatorType.IP,
    "domain": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "file": FeedIndicatorType.File,
    "filehash_sha256": FeedIndicatorType.File,
    "exploit": FeedIndicatorType.CVE,
    "malware_family": ThreatIntel.ObjectsNames.MALWARE,
    "actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "threat_actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "attack pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "technique": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "malicious_behavior": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "malicious behavior": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
}

# Define valid regions enum
VALID_REGIONS = {
    "australia and oceania": "Australia And Oceania",
    "antarctica": "Antarctica",
    "north america": "North America",
    "south asia": "South Asia",
    "europe": "Europe",
    "central america and the caribbean": "Central America And The Caribbean",
    "africa": "Africa",
    "east and southeast asia": "East And Southeast Asia",
    "middle east": "Middle East",
    "central asia": "Central Asia",
    "south america": "South America",
}


#### CLIENT CLASS ####


class Client(BaseClient):
    """Client class to interact with Unit 42 Intelligence API"""

    def __init__(
        self,
        verify: bool,
        proxy: bool,
        reliability: str,
    ):
        headers = {"Authorization": f"Bearer {demisto.getLicenseID()}", "Content-Type": "application/json"}
        super().__init__(base_url=SERVER_URL, verify=verify, proxy=proxy, headers=headers)
        self.reliability = reliability

    def lookup_indicator(self, indicator_type: str, indicator_value: str) -> requests.Response:
        """
        Lookup an indicator in Unit 42 Intelligence

        Args:
            indicator_type: Type of indicator (ip, domain, url, filehash_sha256)
            indicator_value: Value of the indicator

        Returns:
            requests.Response object
        """
        if indicator_type.lower() == "url":
            # URL-encode the indicator value to handle special characters safely in the API request
            # Example: "http://example.com/path?param=value" becomes "http%3A%2F%2Fexample.com%2Fpath%3Fparam%3Dvalue"
            indicator_value = urllib.parse.quote(indicator_value, safe="")

        endpoint = LOOKUP_ENDPOINT.format(indicator_type=indicator_type, indicator_value=indicator_value)

        return self._http_request(method="GET", url_suffix=endpoint, ok_codes=(200, 404), resp_type="response")


#### HELPER FUNCTION ####


def create_dbot_score(
    indicator: str,
    indicator_type: str,
    verdict: str,
    reliability: str = DBotScoreReliability.A_PLUS_PLUS,
) -> Common.DBotScore:
    """
    Create DBotScore object

    Args:
        indicator: The indicator value
        indicator_type: Type of indicator
        verdict: Verdict from API
        reliability: Source reliability

    Returns:
        DBotScore object
    """
    score: int = VERDICT_TO_SCORE.get(verdict.lower() or "unknown", Common.DBotScore.NONE)

    # Add malicious description if the verdict is malicious
    malicious_description = None
    if verdict.lower() == "malicious":
        malicious_description = f"Unit 42 Intelligence classified this {indicator_type.lower()} as malicious"

    return Common.DBotScore(
        indicator=indicator,
        indicator_type=indicator_type,
        integration_name=INTEGRATION_NAME,
        score=score,
        reliability=reliability,
        malicious_description=malicious_description,
    )


def remove_mitre_technique_id_prefix(threat_name: str) -> str:
    """
    Remove MITRE technique ID prefix from threat name if present

    Args:
        threat_name: The threat name that may contain MITRE technique ID prefix

    Returns:
        Threat name with MITRE technique ID prefix removed if applicable

    Examples:
        >>> remove_mitre_technique_id_prefix("T1590 - Gather Victim Network Information")
        "Gather Victim Network Information"
        >>> remove_mitre_technique_id_prefix("Regular Threat Name")
        "Regular Threat Name"
        >>> remove_mitre_technique_id_prefix("T123 - Some Technique")
        "Some Technique"
        >>> remove_mitre_technique_id_prefix("Not a MITRE ID - Something")
        "Not a MITRE ID - Something"
    """
    if " - " in threat_name:
        parts = threat_name.split(" - ", 1)
        if len(parts) == 2 and parts[0].startswith("T") and parts[0][1:].isdigit():
            return parts[1]
    return threat_name


def create_relationships(
    indicator: str, indicator_type: str, threat_objects: list[dict[str, Any]], create_relationships: bool
) -> list[EntityRelationship]:
    """
    Create relationships between indicator and threat objects

    Args:
        indicator: The indicator value
        indicator_type: Type of indicator
        threat_objects: List of threat object associations
        create_relationships: Whether to create relationships

    Returns:
        List of EntityRelationship objects or empty list
    """
    relationships: list[EntityRelationship] = []

    if not create_relationships or not threat_objects:
        demisto.debug(f"Skipping create_relationships as {create_relationships} and {threat_objects=}")
        return relationships

    for threat_obj in threat_objects:
        threat_name = threat_obj.get("name", "")
        threat_class = threat_obj.get("threat_object_class", "").lower()

        # Remove MITRE technique ID prefix for attack patterns
        if INDICATOR_TYPE_MAPPING[threat_class] == ThreatIntel.ObjectsNames.ATTACK_PATTERN:
            threat_name = remove_mitre_technique_id_prefix(threat_name)

        if not threat_name or threat_class not in INDICATOR_TYPE_MAPPING:
            demisto.debug(f"Skipping create_relationships for threat_name {threat_name} and threat_class {threat_class}")
            continue

        relationship = EntityRelationship(
            name=EntityRelationship.Relationships.RELATED_TO,
            entity_a=indicator,
            entity_a_type=indicator_type,
            entity_b=threat_name,
            entity_b_type=INDICATOR_TYPE_MAPPING[threat_class],
            source_reliability=DBotScoreReliability.A_PLUS_PLUS,
            brand=INTEGRATION_NAME,
        )
        relationships.append(relationship)

    return relationships


def extract_response_data(response: dict[str, Any]) -> dict[str, Any]:
    """
    Extract data from API response

    Args:
        response: API response as dictionary

    Returns:
        Dictionary containing extracted data
    """
    return {
        "indicator_value": response.get("indicator_value", ""),
        "indicator_type": response.get("indicator_type", ""),
        "counts": response.get("counts", []),
        "verdict": response.get("verdict", "unknown"),
        "verdict_categories": [item.get("value") for item in response.get("verdict_categories", [])],
        "first_seen": response.get("first_seen", ""),
        "last_seen": response.get("last_seen", ""),
        "updated_at": response.get("updated_at", ""),
        "seen_by": response.get("sources", []),
        "threat_object_associations": response.get("threat_object_associations", []),
        "indicator_details": response.get("indicator_details", {}),
    }


def extract_tags_from_threat_objects(threat_objects: list[dict[str, Any]]) -> list[str]:
    """
    Extract tags from threat object associations

    Args:
        threat_objects: List of threat object associations

    Returns:
        List of tag names
    """
    tags = []
    for threat_obj in threat_objects:
        name = threat_obj.get("name")
        if name:
            tags.append(name)

        # Add aliases as additional tags
        aliases = threat_obj.get("aliases", [])
        if aliases:
            tags.extend([alias for alias in aliases if alias])

    return list(set(tags))  # Remove duplicates


def extract_malware_families_from_threat_objects(threat_objects: list[dict[str, Any]]) -> str | None:
    """
    Extract malware families from threat object associations

    Args:
        threat_objects: List of threat object associations

    Returns:
        Malware family name if found, None otherwise
    """
    for threat_obj in threat_objects:
        threat_class = threat_obj.get("threat_object_class", "").lower()
        if threat_class == "malware_family":
            name = threat_obj.get("name")
            if name:
                return name

    return None


def build_threat_object_description(threat_obj: dict[str, Any]) -> str:
    """
    Build a comprehensive description for a threat object including highlights, methods, and targets

    Args:
        threat_obj: The threat object data

    Returns:
        Formatted description string with sections for highlights, methods, and targets
    """
    description = threat_obj.get("description", "").replace("\\n", "\n")

    # Add highlights section if available
    highlights = demisto.get(threat_obj, "battlecard_details.highlights", "").replace("\\n", "\n")
    if highlights and highlights != "Highlights / Key Takeaways (external)":  # Do not add if it is only the default title
        description += "\n\n##"
        description += highlights

    # Add methods section if available (for threat actors)
    methods = demisto.get(threat_obj, "battlecard_details.threat_actor_details.methods", "").replace("\\n", "\n")
    if methods:
        description += "\n\n##"
        description += methods

    # Add targets section if available (for threat actors)
    targets = demisto.get(threat_obj, "battlecard_details.threat_actor_details.targets", "").replace("\\n", "\n")
    if targets:
        description += "\n\n##"
        description += targets

    return description


def create_publications(publications_data: list) -> list:
    """
    Creates the publications list of the indicator

    Args:
        publications_data: A list of all publications from threat object

    Returns:
        A list of publications of the indicator
    """
    publications = []

    for data in publications_data:
        timestamp = data.get("created", "")
        title = data.get("title", "")
        url = data.get("url", "")
        source = data.get("source", INTEGRATION_NAME)

        publications.append({"link": url, "title": title, "timestamp": timestamp, "source": source})

    return publications


def create_threat_object_relationships(
    threat_obj: dict[str, Any], threat_object_name: str, threat_class: str
) -> list[EntityRelationship]:
    """
    Create threat object relationships from related_threat_objects

    Args:
        threat_obj: The threat object data
        threat_object_name: Name of the threat object
        threat_class: The threat object class

    Returns:
        List of EntityRelationship objects
    """
    relationships = []
    related_threat_objects = threat_obj.get("related_threat_objects", [])

    for related_obj in related_threat_objects:
        if not isinstance(related_obj, dict):
            continue

        related_name = related_obj.get("name")
        related_class = related_obj.get("class", "").lower()

        if related_name and related_class:
            entity_relationship = EntityRelationship(
                name=EntityRelationship.Relationships.RELATED_TO,
                entity_a=threat_object_name,
                entity_a_type=INDICATOR_TYPE_MAPPING[threat_class],
                entity_b=related_name,
                entity_b_type=INDICATOR_TYPE_MAPPING[related_class],
                source_reliability=DBotScoreReliability.A_PLUS_PLUS,
                brand=INTEGRATION_NAME,
            )
            relationships.append(entity_relationship.to_entry())

    return relationships


def create_campaigns_relationships(
    threat_obj: dict[str, Any], threat_object_name: str, threat_class: str
) -> list[EntityRelationship]:
    """
    Create campaigns relationships from campaigns list

    Args:
        threat_obj: The threat object data
        threat_object_name: Name of the threat object
        threat_class: The threat object class

    Returns:
        List of EntityRelationship objects
    """
    relationships = []
    campaigns = demisto.get(threat_obj, "battlecard_details.campaigns", [])

    for campaign in campaigns:
        if isinstance(campaign, str) and campaign.strip():
            entity_relationship = EntityRelationship(
                name=EntityRelationship.Relationships.RELATED_TO,
                entity_a=threat_object_name,
                entity_a_type=INDICATOR_TYPE_MAPPING[threat_class],
                entity_b=string_to_table_header(campaign),
                entity_b_type=ThreatIntel.ObjectsNames.CAMPAIGN,
                source_reliability=DBotScoreReliability.A_PLUS_PLUS,
                brand=INTEGRATION_NAME,
            )
            relationships.append(entity_relationship.to_entry())

    return relationships


def create_attack_patterns_relationships(
    threat_obj: dict[str, Any], threat_actor_name: str, threat_class: str
) -> list[EntityRelationship]:
    """
    Create attack patterns relationships from attack patterns associations

    Args:
        threat_obj: The threat object data
        threat_actor_name: Name of the threat actor
        threat_class: The threat object class

    Returns:
        List of EntityRelationship objects
    """
    relationships = []
    attack_patterns = demisto.get(threat_obj, "battlecard_details.attack_patterns", [])

    for pattern in attack_patterns:
        mitre_id = pattern.get("mitreid", "")
        pattern_name = pattern.get("name", "")

        # Skip items with a dot in the mitreid
        if "." in mitre_id:
            demisto.debug(f"Skipping attack pattern {pattern_name} with mitreid {mitre_id}")
            continue

        if pattern_name and pattern_name.endswith("(enterprise)"):
            # Remove (enterprise) suffix if present
            pattern_name = pattern_name.removesuffix("(enterprise)").strip()

            entity_relationship = EntityRelationship(
                name=EntityRelationship.Relationships.USES,
                entity_a=threat_actor_name,
                entity_a_type=INDICATOR_TYPE_MAPPING[threat_class],
                entity_b=string_to_table_header(pattern_name),
                entity_b_type=ThreatIntel.ObjectsNames.ATTACK_PATTERN,
                source_reliability=DBotScoreReliability.A_PLUS_PLUS,
                brand=INTEGRATION_NAME,
            )
            relationships.append(entity_relationship.to_entry())

    return relationships


def create_malware_relationships(
    threat_obj: dict[str, Any], threat_actor_name: str, threat_class: str
) -> list[EntityRelationship]:
    """
    Create malware relationships from malware_associations

    Args:
        threat_obj: The threat object data
        threat_actor_name: Name of the threat actor
        threat_class: The threat object class

    Returns:
        List of EntityRelationship objects
    """
    relationships = []
    malware_associations = demisto.get(threat_obj, "battlecard_details.threat_actor_details.malware_associations", [])

    for relationship in malware_associations:
        name = relationship.get("name")
        aliases = relationship.get("aliases", [])

        if name:
            # Create a relationship using the name
            entity_relationship = EntityRelationship(
                name=EntityRelationship.Relationships.USES,
                entity_a=threat_actor_name,
                entity_a_type=INDICATOR_TYPE_MAPPING[threat_class],
                entity_b=string_to_table_header(name),
                entity_b_type=ThreatIntel.ObjectsNames.MALWARE,
                source_reliability=DBotScoreReliability.A_PLUS_PLUS,
                brand=INTEGRATION_NAME,
            )
            relationships.append(entity_relationship.to_entry())
        elif aliases:
            # Create a relationship for each alias if no name exists
            for alias in aliases:
                entity_relationship = EntityRelationship(
                    name=EntityRelationship.Relationships.USES,
                    entity_a=threat_actor_name,
                    entity_a_type=INDICATOR_TYPE_MAPPING[threat_class],
                    entity_b=string_to_table_header(alias),
                    entity_b_type=ThreatIntel.ObjectsNames.MALWARE,
                    source_reliability=DBotScoreReliability.A_PLUS_PLUS,
                    brand=INTEGRATION_NAME,
                )
                relationships.append(entity_relationship.to_entry())

    return relationships


def create_tools_relationships(threat_obj: dict[str, Any], threat_actor_name: str, threat_class: str) -> list[EntityRelationship]:
    """
    Create tools relationships from tools associations

    Args:
        threat_obj: The threat object data
        threat_actor_name: Name of the threat actor
        threat_class: The threat object class

    Returns:
        List of EntityRelationship objects
    """
    relationships = []
    tools_associations = demisto.get(threat_obj, "battlecard_details.threat_actor_details.tools", [])

    for tool in tools_associations:
        tool_name = tool.get("name")

        if tool_name:
            entity_relationship = EntityRelationship(
                name=EntityRelationship.Relationships.USES,
                entity_a=threat_actor_name,
                entity_a_type=INDICATOR_TYPE_MAPPING[threat_class],
                entity_b=string_to_table_header(tool_name),
                entity_b_type=ThreatIntel.ObjectsNames.TOOL,
                source_reliability=DBotScoreReliability.A_PLUS_PLUS,
                brand=INTEGRATION_NAME,
                fields={"tags": f"mitre-id: {tool.get('mitreid')}" if tool.get("mitreid") else ""},
            )
            relationships.append(entity_relationship.to_entry())

    return relationships


def create_vulnerabilities_relationships(
    threat_obj: dict[str, Any], threat_actor_name: str, threat_class: str
) -> list[EntityRelationship]:
    """
    Create vulnerabilities relationships from vulnerabilities associations

    Args:
        threat_obj: The threat object data
        threat_actor_name: Name of the threat actor
        threat_class: The threat object class

    Returns:
        List of EntityRelationship objects
    """
    relationships = []
    vulnerabilities = demisto.get(threat_obj, "battlecard_details.threat_actor_details.vulnerability_associations", [])

    for vulnerability in vulnerabilities:
        cve_id = vulnerability.get("cve")

        if cve_id:
            entity_relationship = EntityRelationship(
                name=EntityRelationship.Relationships.EXPLOITS,
                entity_a=threat_actor_name,
                entity_a_type=INDICATOR_TYPE_MAPPING[threat_class],
                entity_b=cve_id.upper(),
                entity_b_type=FeedIndicatorType.CVE,
                source_reliability=DBotScoreReliability.A_PLUS_PLUS,
                brand=INTEGRATION_NAME,
            )
            relationships.append(entity_relationship.to_entry())

    return relationships


def create_actor_relationships(
    threat_obj: dict[str, Any], malware_family_name: str, threat_class: str
) -> list[EntityRelationship]:
    """
    Create actor relationships from actor_associations

    Args:
        threat_obj: The threat object data
        malware_family_name: Name of the malware family
        threat_class: The threat object class

    Returns:
        List of EntityRelationship objects
    """
    relationships = []
    actor_associations = demisto.get(threat_obj, "battlecard_details.malware_family_details.actor_associations", [])

    for relationship in actor_associations:
        aliases = relationship.get("aliases", [])
        name = relationship.get("name")

        if aliases:
            # Create a relationship for each alias
            for alias in aliases:
                entity_relationship = EntityRelationship(
                    name=EntityRelationship.Relationships.USED_BY,
                    entity_a=malware_family_name,
                    entity_a_type=INDICATOR_TYPE_MAPPING[threat_class],
                    entity_b=string_to_table_header(alias),
                    entity_b_type=ThreatIntel.ObjectsNames.THREAT_ACTOR,
                    source_reliability=DBotScoreReliability.A_PLUS_PLUS,
                    brand=INTEGRATION_NAME,
                )
                relationships.append(entity_relationship.to_entry())
        elif name:
            # Create a relationship using the name if no aliases exist
            entity_relationship = EntityRelationship(
                name=EntityRelationship.Relationships.USED_BY,
                entity_a=malware_family_name,
                entity_a_type=INDICATOR_TYPE_MAPPING[threat_class],
                entity_b=string_to_table_header(name),
                entity_b_type=ThreatIntel.ObjectsNames.THREAT_ACTOR,
                source_reliability=DBotScoreReliability.A_PLUS_PLUS,
                brand=INTEGRATION_NAME,
            )
            relationships.append(entity_relationship.to_entry())

    return relationships


def create_location_indicators_and_relationships(threat_obj: dict[str, Any], threat_actor_name: str) -> list[dict[str, Any]]:
    """
    Create location indicators from affected regions and origin field and build relationships

    Args:
        threat_obj: The threat object data
        threat_actor_name: Name of the threat actor to create relationships with

    Returns:
        List of location indicators with relationships
    """
    location_indicators: list = []

    # Handle affected regions
    affected_regions = demisto.get(threat_obj, "battlecard_details.threat_actor_details.affected_regions", [])

    # in case affected_regions is "null", return empty list.
    if not isinstance(affected_regions, list):
        return location_indicators

    for region in affected_regions:
        if isinstance(region, str) and region.strip():
            region_lower = region.strip().lower()

            # Use the standardized region name if it matches our enum
            standardized_region = VALID_REGIONS.get(region_lower)
            if not standardized_region:
                demisto.debug(f"Skipping region {region} as it is not in the valid regions enum")
                continue

            # Create EntityRelationship for the location
            entity_relationship = EntityRelationship(
                name=EntityRelationship.Relationships.TARGETS,
                entity_a=threat_actor_name,
                entity_a_type=ThreatIntel.ObjectsNames.THREAT_ACTOR,
                entity_b=standardized_region,
                entity_b_type=FeedIndicatorType.Location,
                source_reliability=DBotScoreReliability.A_PLUS_PLUS,
                brand=INTEGRATION_NAME,
            )

            location_indicator = {
                "value": standardized_region,
                "type": FeedIndicatorType.Location,
                "score": Common.DBotScore.NONE,
                "service": INTEGRATION_NAME,
                "relationships": [entity_relationship.to_entry()],
                "fields": {
                    "geocountry": standardized_region,
                },
            }
            location_indicators.append(location_indicator)

    return location_indicators


def get_threat_object_score(threat_class: str) -> int:
    """
    Get the appropriate score for a threat object based on its class

    Args:
        threat_class: The threat object class (lowercase)

    Returns:
        Appropriate ThreatIntel score or Common.DBotScore.NONE as default
    """
    if threat_class not in INDICATOR_TYPE_MAPPING:
        return Common.DBotScore.NONE

    threat_type = INDICATOR_TYPE_MAPPING[threat_class]

    if threat_type == ThreatIntel.ObjectsNames.MALWARE:
        return ThreatIntel.ObjectsScore.MALWARE
    elif threat_type == ThreatIntel.ObjectsNames.THREAT_ACTOR:
        return ThreatIntel.ObjectsScore.THREAT_ACTOR
    elif threat_type == ThreatIntel.ObjectsNames.CAMPAIGN:
        return ThreatIntel.ObjectsScore.CAMPAIGN
    elif threat_type == ThreatIntel.ObjectsNames.ATTACK_PATTERN:
        return ThreatIntel.ObjectsScore.ATTACK_PATTERN

    return Common.DBotScore.NONE


def create_threat_object_indicators(
    threat_objects: list[dict[str, Any]], reliability: str = "A++ - Reputation script"
) -> list[dict[str, Any]]:
    """
    Create threat object indicators from threat object associations

    Args:
        threat_objects: List of threat object associations
        reliability: Source reliability

    Returns:
        List of threat object indicators
    """
    indicators = []

    for threat_obj in threat_objects:
        name = threat_obj.get("name")
        threat_class = threat_obj.get("threat_object_class", "").lower()

        if not name or threat_class not in INDICATOR_TYPE_MAPPING:
            continue

        # Create relationships
        relationships = []
        relationships += create_threat_object_relationships(threat_obj, name, threat_class)
        relationships += create_campaigns_relationships(threat_obj, name, threat_class)
        relationships += create_attack_patterns_relationships(threat_obj, name, threat_class)
        relationships += create_malware_relationships(threat_obj, name, threat_class)
        relationships += create_tools_relationships(threat_obj, name, threat_class)
        relationships += create_vulnerabilities_relationships(threat_obj, name, threat_class)
        relationships += create_actor_relationships(threat_obj, name, threat_class)

        # Create fields with threat object details
        fields = {
            "description": build_threat_object_description(threat_obj),
            "reportedby": threat_obj.get("sources"),
            "aliases": [string_to_table_header(alias) for alias in threat_obj.get("aliases", [])],
            "industrysectors": [
                string_to_table_header(industry) for industry in demisto.get(threat_obj, "battlecard_details.industries", [])
            ],
            "primarymotivation": string_to_table_header(
                demisto.get(threat_obj, "battlecard_details.threat_actor_details.primary_motivation", "")
            ),
            "publications": create_publications(threat_obj.get("publications", [])),
            "geocountry": demisto.get(threat_obj, "battlecard_details.threat_actor_details.origin", "").upper(),
            "ismalwarefamily": "True" if threat_class == "malware_family" else "False",
        }

        indicator_data = {
            "value": name,
            "type": INDICATOR_TYPE_MAPPING[threat_class],
            "score": get_threat_object_score(threat_class),
            "service": INTEGRATION_NAME,
            "relationships": relationships,
            "fields": fields,
            "rawJSON": threat_obj,
        }

        indicators.append(indicator_data)

        # Create location indicators from affected regions
        location_indicators = create_location_indicators_and_relationships(threat_obj, name)
        indicators.extend(location_indicators)

    return indicators


def create_context_data(response_data: dict[str, Any]) -> dict[str, Any]:
    """
    Create context data for indicators

    Args:
        response_data: Extracted response data

    Returns:
        Dictionary containing context data
    """
    return {
        "Value": response_data["indicator_value"],
        "Type": INDICATOR_TYPE_MAPPING.get(response_data["indicator_type"]),
        "Verdict": string_to_table_header(response_data["verdict"]),
        "VerdictCategories": list({string_to_table_header(item) for item in response_data["verdict_categories"]}),
        "Counts": response_data["counts"],
        "FirstSeen": response_data["first_seen"],
        "LastSeen": response_data["last_seen"],
        "SeenBy": list({string_to_table_header(item) for item in response_data["seen_by"]}),
        "EnrichedThreatObjectAssociation": response_data["threat_object_associations"],
    }


def construct_404_response(indicator_value: str, indicator_type: str) -> dict[str, Any]:
    """
    Construct a 404 response for a missing indicator

    Args:
        indicator_value: Value of the indicator
        indicator_type: Type of indicator

    Returns:
        Dictionary containing indicator default response in cases of 404
    """
    return {
        "indicator_value": indicator_value,
        "indicator_type": indicator_type,
        "verdict": "Unknown",
        "verdict_categories": [],
        "counts": [{"count_type": "wf_sample", "count_values": {"benign": 0, "grayware": 0, "malware": 0}}],
        "first_seen": "",
        "last_seen": "",
        "seen_by": [],
        "threat_object_associations": [],
        "is_observed": False,
        "sources": [],
    }


#### TEST MODULE ####


def test_module(client: Client) -> str:
    """
    Test the integration by making a simple API call

    Args:
        client: Unit 42 Intelligence client

    Returns:
        'ok' if test passed, error message otherwise
    """
    try:
        # Test with a known safe domain
        client.lookup_indicator("domain", "example.com")
        return "ok"
    except Exception as e:
        return f"Test failed: {str(e)}"


#### COMMAND FUNCTIONS ####


def ip_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Enrich IP address with Unit 42 Intelligence

    Args:
        client: Unit 42 Intelligence client
        args: Command arguments

    Returns:
        CommandResults object
    """
    ip = args.get("ip", "")
    create_relationships_flag = argToBoolean(args.get("create_relationships", True))
    create_threat_object_indicators_flag = argToBoolean(args.get("create_threat_object_indicators", False))

    response = client.lookup_indicator("ip", ip)

    if response.status_code == 404:
        response_data = construct_404_response(ip, "IP")
    else:
        response_data = extract_response_data(response.json())

    threat_objects = response_data["threat_object_associations"]

    # Create DBotScore
    dbot_score = create_dbot_score(ip, DBotScoreType.IP, response_data["verdict"], client.reliability)

    # Extract tags and malware families from threat objects
    tags = extract_tags_from_threat_objects(threat_objects)
    malware_families = extract_malware_families_from_threat_objects(threat_objects)

    # Create enriched IP indicator with tags and malware families
    ip_indicator = Common.IP(ip=ip, dbot_score=dbot_score, tags=tags, malware_family=malware_families)

    # Create relationships
    relationships = create_relationships(ip, FeedIndicatorType.IP, threat_objects, create_relationships_flag)

    # Create indicators from relationships
    if create_threat_object_indicators_flag:
        threat_indicators = create_threat_object_indicators(threat_objects, client.reliability)
        if threat_indicators:
            demisto.createIndicators(threat_indicators)

    # Create context data
    context_data = create_context_data(response_data)

    readable_output = tableToMarkdown(
        f"Unit 42 Intelligence results for IP: {ip}",
        context_data,
        headers=["Value", "Verdict", "VerdictCategories", "SeenBy", "FirstSeen", "LastSeen"],
        headerTransform=pascalToSpace,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="Unit42Intelligence.IP",
        outputs_key_field="Value",
        outputs=context_data,
        readable_output=readable_output,
        indicator=ip_indicator,
        relationships=relationships,
    )


def domain_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Enrich domain with Unit 42 Intelligence

    Args:
        client: Unit 42 Intelligence client
        args: Command arguments

    Returns:
        CommandResults object
    """
    domain = args.get("domain", "")
    create_relationships_flag = argToBoolean(args.get("create_relationships", True))
    create_threat_object_indicators_flag = argToBoolean(args.get("create_threat_object_indicators", False))

    response = client.lookup_indicator("domain", domain)

    if response.status_code == 404:
        response_data = construct_404_response(domain, "Domain")
    else:
        response_data = extract_response_data(response.json())
    threat_objects = response_data["threat_object_associations"]

    # Create DBotScore
    dbot_score = create_dbot_score(domain, DBotScoreType.DOMAIN, response_data["verdict"], client.reliability)

    # Extract tags and malware families from threat objects
    tags = extract_tags_from_threat_objects(threat_objects)
    malware_families = extract_malware_families_from_threat_objects(threat_objects)

    # Create enriched Domain indicator with tags and malware families
    domain_indicator = Common.Domain(domain=domain, dbot_score=dbot_score, tags=tags, malware_family=malware_families)

    # Create relationships
    relationships = create_relationships(domain, FeedIndicatorType.Domain, threat_objects, create_relationships_flag)

    # Create indicators from relationships
    if create_threat_object_indicators_flag:
        threat_indicators = create_threat_object_indicators(threat_objects, client.reliability)
        if threat_indicators:
            demisto.createIndicators(threat_indicators)

    # Create context data
    context_data = create_context_data(response_data)

    readable_output = tableToMarkdown(
        f"Unit 42 Intelligence results for Domain: {domain}",
        context_data,
        headers=["Value", "Verdict", "VerdictCategories", "SeenBy", "FirstSeen", "LastSeen"],
        headerTransform=pascalToSpace,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="Unit42Intelligence.Domain",
        outputs_key_field="Value",
        outputs=context_data,
        readable_output=readable_output,
        indicator=domain_indicator,
        relationships=relationships,
    )


def url_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Enrich URL with Unit 42 Intelligence

    Args:
        client: Unit 42 Intelligence client
        args: Command arguments

    Returns:
        CommandResults object
    """
    url = args.get("url", "")
    create_relationships_flag = argToBoolean(args.get("create_relationships", True))
    create_threat_object_indicators_flag = argToBoolean(args.get("create_threat_object_indicators", False))

    response = client.lookup_indicator("url", url)

    if response.status_code == 404:
        response_data = construct_404_response(url, "URL")
    else:
        response_data = extract_response_data(response.json())
    threat_objects = response_data["threat_object_associations"]

    # Create DBotScore
    dbot_score = create_dbot_score(url, DBotScoreType.URL, response_data["verdict"], client.reliability)

    # Extract tags and malware families from threat objects
    tags = extract_tags_from_threat_objects(threat_objects)
    malware_families = extract_malware_families_from_threat_objects(threat_objects)

    # Create enriched URL indicator with tags and malware families
    url_indicator = Common.URL(url=url, dbot_score=dbot_score, tags=tags, malware_family=malware_families)

    # Create relationships
    relationships = create_relationships(url, FeedIndicatorType.URL, threat_objects, create_relationships_flag)

    # Create indicators from relationships
    if create_threat_object_indicators_flag:
        threat_indicators = create_threat_object_indicators(threat_objects, client.reliability)
        if threat_indicators:
            demisto.createIndicators(threat_indicators)

    # Create context data
    context_data = create_context_data(response_data)

    readable_output = tableToMarkdown(
        f"Unit 42 Intelligence results for URL: {url}",
        context_data,
        headers=["Value", "Verdict", "VerdictCategories", "SeenBy", "FirstSeen", "LastSeen"],
        headerTransform=pascalToSpace,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="Unit42Intelligence.URL",
        outputs_key_field="Value",
        outputs=context_data,
        readable_output=readable_output,
        indicator=url_indicator,
        relationships=relationships,
    )


def file_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Enrich file hash with Unit 42 Intelligence

    Args:
        client: Unit 42 Intelligence client
        args: Command arguments

    Returns:
        CommandResults object
    """
    file_hash = args.get("file", "")
    create_relationships_flag = argToBoolean(args.get("create_relationships", True))
    create_threat_object_indicators_flag = argToBoolean(args.get("create_threat_object_indicators", False))

    # Validate hash type - Unit 42 Intelligence only supports SHA256
    hash_type = get_hash_type(file_hash)
    if hash_type != "sha256":
        return CommandResults(
            readable_output=f"Unit 42 Intelligence only supports SHA256 hashes. Provided hash type: {hash_type}"
        )

    response = client.lookup_indicator("filehash_sha256", file_hash)

    if response.status_code == 404:
        response_data = construct_404_response(file_hash, "File")
    else:
        response_data = extract_response_data(response.json())
    threat_objects = response_data["threat_object_associations"]

    # Create DBotScore
    dbot_score = create_dbot_score(file_hash, DBotScoreType.FILE, response_data["verdict"], client.reliability)

    # Extract tags and malware families from threat objects
    tags = extract_tags_from_threat_objects(threat_objects)
    malware_families = extract_malware_families_from_threat_objects(threat_objects)

    # Create enriched File indicator with proper hash field assignment
    file_indicator = Common.File(
        size=demisto.get(response_data, "indicator_details.file_size", ""),
        file_type=demisto.get(response_data, "indicator_details.file_type", ""),
        imphash=demisto.get(response_data, "indicator_details.file_hashes.imphash", ""),
        md5=demisto.get(response_data, "indicator_details.file_hashes.md5", ""),
        sha1=demisto.get(response_data, "indicator_details.file_hashes.sha1", ""),
        sha256=file_hash,
        ssdeep=demisto.get(response_data, "indicator_details.file_hashes.ssdeep", ""),
        dbot_score=dbot_score,
        tags=tags,
        malware_family=malware_families,
    )

    # Create relationships
    relationships = create_relationships(file_hash, FeedIndicatorType.File, threat_objects, create_relationships_flag)

    # Create indicators from relationships
    if create_threat_object_indicators_flag:
        threat_indicators = create_threat_object_indicators(threat_objects, client.reliability)
        if threat_indicators:
            demisto.createIndicators(threat_indicators)

    # Create context data
    context_data = create_context_data(response_data)

    readable_output = tableToMarkdown(
        f"Unit 42 Intelligence results for File: {file_hash}",
        context_data,
        headers=["Value", "Verdict", "VerdictCategories", "SeenBy", "FirstSeen", "LastSeen"],
        headerTransform=pascalToSpace,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="Unit42Intelligence.File",
        outputs_key_field="Value",
        outputs=context_data,
        readable_output=readable_output,
        indicator=file_indicator,
        relationships=relationships,
    )


#### MAIN FUNCTION ####


def main() -> None:
    """Main function, parses params and runs command functions"""

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # Get parameters
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    reliability = params.get("integration_reliability", "A++ - Reputation script")
    create_relationships = argToBoolean(params.get("create_relationships", True))
    create_threat_object_indicators = argToBoolean(params.get("create_threat_object_indicators", False))

    # Add create_relationships to args for commands
    args["create_relationships"] = create_relationships
    args["create_threat_object_indicators"] = create_threat_object_indicators

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            verify=verify_certificate,
            proxy=proxy,
            reliability=reliability,
        )

        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "ip":
            results = []
            ips = argToList(args.get("ip", ""))
            for ip in ips:
                args["ip"] = ip
                results.append(ip_command(client, args))
            return_results(results)

        elif command == "domain":
            results = []
            domains = argToList(args.get("domain", ""))
            for domain in domains:
                args["domain"] = domain
                results.append(domain_command(client, args))
            return_results(results)

        elif command == "url":
            results = []
            urls = argToList(args.get("url", ""))
            for url in urls:
                args["url"] = url
                results.append(url_command(client, args))
            return_results(results)

        elif command == "file":
            results = []
            files = argToList(args.get("file", ""))
            for file in files:
                args["file"] = file
                results.append(file_command(client, args))
            return_results(results)

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

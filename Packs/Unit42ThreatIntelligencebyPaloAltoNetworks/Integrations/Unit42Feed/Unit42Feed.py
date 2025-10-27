from CommonServerPython import *
from CommonServerUserPython import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
INTEGRATION_NAME = "Unit 42 Feed"
API_LIMIT = 5000
TOTAL_INDICATOR_LIMIT = 200000

# API endpoints
BASE_URL = "https://prod-us.tas.crtx.paloaltonetworks.com"
INDICATORS_ENDPOINT = "/api/v1/feeds/indicators"
THREAT_OBJECTS_ENDPOINT = "/api/v1/feeds/threat_objects"

# Mapping from API indicator types to XSOAR indicator types
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

VERDICT_TO_SCORE = {
    "malicious": Common.DBotScore.BAD,
    "suspicious": Common.DBotScore.SUSPICIOUS,
    "benign": Common.DBotScore.GOOD,
    "unknown": Common.DBotScore.NONE,
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


class Client(BaseClient):
    def __init__(self, headers, verify=False, proxy=False):
        """Implements class for Unit 42 feed.

        Args:
            headers: headers for the request.
            verify: boolean, if *false*, feed HTTPS server certificate is verified. Default: *false*
            proxy: boolean, if *false* feed HTTPS server certificate will not use proxies. Default: *false*
        """
        super().__init__(base_url=BASE_URL, headers=headers, verify=verify, proxy=proxy)

    def get_indicators(
        self,
        indicator_types: list | None = None,
        limit: int = API_LIMIT,
        start_time: str | None = None,
        next_page_token: str | None = None,
    ) -> dict:
        """Get indicators from the Unit 42 feed.

        Args:
            indicator_types: A list of indicator types to fetch (ip, filehash_sha256, domain, url)
            limit: Maximum number of indicators to return
            start_time: Start time for fetching indicators
            next_page_token: Token for pagination

        Returns:
            Dict containing indicators and pagination info
        """
        params: dict[str, Any] = {}
        if indicator_types:
            params["indicator_types"] = [i.lower().replace("file", "filehash_sha256") for i in indicator_types]
        if limit:
            params["limit"] = limit
        if start_time:
            params["start_time"] = start_time
        if next_page_token:
            params["page_token"] = next_page_token

        response = self._http_request(method="GET", url_suffix=INDICATORS_ENDPOINT, params=params)

        return response

    def get_threat_objects(self, limit: int = API_LIMIT, next_page_token: str | None = None) -> dict:
        """Get threat objects from the Unit 42 feed.

        Args:
            limit: Maximum number of threat objects to return
            next_page_token: Token for pagination

        Returns:
            Dict containing threat objects and pagination info
        """
        params: dict[str, Any] = {}
        if limit:
            params["limit"] = limit
        if next_page_token:
            params["page_token"] = next_page_token

        response = self._http_request(method="GET", url_suffix=THREAT_OBJECTS_ENDPOINT, params=params)

        return response


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
        timestamp = data.get("created_at", "")
        title = data.get("title", "")
        url = data.get("url", "")
        source = data.get("source", INTEGRATION_NAME)

        publications.append({"link": url, "title": title, "timestamp": timestamp, "source": source})

    return publications


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


def create_location_indicators_and_relationships(threat_obj: dict[str, Any], threat_actor_name: str) -> list[dict[str, Any]]:
    """
    Create location indicators from affected regions and origin field and build relationships

    Args:
        threat_obj: The threat object data
        threat_actor_name: Name of the threat actor to create relationships with

    Returns:
        List of location indicators with relationships
    """
    location_indicators: list[dict[str, Any]] = []

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


def create_vulnerabilities_relationships(threat_obj: dict[str, Any], threat_actor_name: str, threat_class: str) -> list[dict]:
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


def create_actor_relationships(threat_obj: dict[str, Any], malware_family_name: str, threat_class: str) -> list[dict]:
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


def create_tools_relationships(threat_obj: dict[str, Any], threat_actor_name: str, threat_class: str) -> list[dict]:
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


def create_malware_relationships(threat_obj: dict[str, Any], threat_actor_name: str, threat_class: str) -> list[dict]:
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


def create_attack_patterns_relationships(threat_obj: dict[str, Any], threat_actor_name: str, threat_class: str) -> list[dict]:
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


def create_campaigns_relationships(threat_obj: dict[str, Any], threat_object_name: str, threat_class: str) -> list[dict]:
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


def create_relationships_and_tags(
    indicator_value: str, indicator_type: str, threat_object_associations: list
) -> tuple[list[Any], list[str]]:
    """
    Create relationships and tags from threat object associations

    Args:
        indicator_value: The indicator value (entity_a)
        indicator_type: The indicator type for mapping
        threat_object_associations: List of threat object associations

    Returns:
        Tuple of List of EntityRelationship objects and tags
    """
    relationships: list[Any] = []
    tags: list[str] = []

    for assoc in threat_object_associations:
        if not assoc or not assoc.get("name") or not assoc.get("threat_object_class"):
            continue

        threat_name = assoc.get("name")
        threat_class = assoc.get("threat_object_class")

        tags.append(threat_name)

        if argToBoolean(demisto.params().get("create_relationships")):
            reliability = demisto.params().get("feedReliability", "A++ - Reputation script")

            # Map threat class to XSOAR threat intel object type
            entity_a_type = INDICATOR_TYPE_MAPPING.get(indicator_type, Common.Indicator)
            entity_b_type = INDICATOR_TYPE_MAPPING.get(threat_class, Common.Indicator)

            # Determine relationship type based on threat class
            if threat_class in ["actor", "threat_actor"]:
                relationship_name = EntityRelationship.Relationships.USED_BY
            elif threat_class == "campaign":
                relationship_name = EntityRelationship.Relationships.PART_OF
            elif threat_class in ["attack pattern", "technique"]:
                relationship_name = EntityRelationship.Relationships.USES
            elif threat_class == "exploit":
                relationship_name = EntityRelationship.Relationships.EXPLOITS
            elif threat_class in ["malicious behavior", "malicious_behavior"]:
                relationship_name = EntityRelationship.Relationships.INDICATOR_OF
            else:
                relationship_name = EntityRelationship.Relationships.RELATED_TO

            relationship = EntityRelationship(
                name=relationship_name,
                entity_a=indicator_value,
                entity_a_type=entity_a_type,
                entity_b=threat_name,
                entity_b_type=entity_b_type,
                source_reliability=reliability,
                brand=INTEGRATION_NAME,
            )

            relationships.append(relationship.to_entry())

    return relationships, tags


def map_indicator(indicator_data: dict, feed_tags: list = [], tlp_color: str | None = None) -> dict:
    """Map an indicator from the Unit 42 API to XSOAR format.

    Args:
        indicator_data: Indicator data from the API.
        feed_tags: List of tags to add to the indicator.
        tlp_color: Traffic Light Protocol color to add to the indicator.

    Returns:
        Indicator in XSOAR format.
    """
    indicator_value = indicator_data.get("indicator_value", "")
    indicator_type = indicator_data.get("indicator_type", "")

    # Map the indicator type to XSOAR type
    xsoar_indicator_type = INDICATOR_TYPE_MAPPING.get(indicator_type, Common.Indicator)

    # Create DBotScore
    verdict = str(indicator_data.get("verdict") or "")
    dbot_score = VERDICT_TO_SCORE.get(verdict, Common.DBotScore.NONE)

    # Create relationships and tags
    relationships: list[Any] = []
    tags: list[str] = []
    if indicator_data.get("threat_object_associations"):
        relationships, tags = create_relationships_and_tags(
            indicator_value, indicator_type, indicator_data.get("threat_object_associations") or []
        )

    # Create fields
    fields = {
        "updateddate": indicator_data.get("updated_at"),
        "creationdate": indicator_data.get("first_seen"),
        "reportedby": indicator_data.get("source"),
        "tags": list(set(feed_tags + tags)),
        "trafficlightprotocol": tlp_color,
    }
    if xsoar_indicator_type == FeedIndicatorType.File:
        fields["md5"] = demisto.get(indicator_data, "indicator_details.file_hashes.md5")
        fields["sha1"] = demisto.get(indicator_data, "indicator_details.file_hashes.sha1")
        fields["sha256"] = demisto.get(indicator_data, "indicator_details.file_hashes.sha256")
        fields["ssdeep"] = demisto.get(indicator_data, "indicator_details.file_hashes.ssdeep")
        fields["imphash"] = demisto.get(indicator_data, "indicator_details.file_hashes.imphash")
        fields["pehash"] = demisto.get(indicator_data, "indicator_details.file_hashes.pehash")
        fields["filetype"] = demisto.get(indicator_data, "indicator_details.file_type")
        fields["fileextension"] = demisto.get(indicator_data, "indicator_details.file_type", "").split(".")[-1]
        fields["size"] = demisto.get(indicator_data, "indicator_details.file_size")

    # Create the indicator object
    indicator: dict = {
        "value": indicator_value,
        "type": xsoar_indicator_type,
        "score": dbot_score,
        "service": INTEGRATION_NAME,
        "relationships": relationships,
        "fields": fields,
        "rawJSON": indicator_data,
    }

    return indicator


def map_threat_object(threat_object: dict, feed_tags: list = [], tlp_color: str | None = None) -> list:
    """Map a threat object from the Unit 42 API to XSOAR format.

    Args:
        threat_object: Threat object data from the API.
        feed_tags: List of tags to add to the threat object.
        tlp_color: Traffic Light Protocol color to add to the threat object.

    Returns:
        List of threat objects in XSOAR format.
    """
    result: list = []

    # Get basic threat object properties
    name = threat_object.get("name", "")
    threat_class = threat_object.get("threat_object_class", "").lower()

    # Map the threat object class to XSOAR type
    xsoar_indicator_type = INDICATOR_TYPE_MAPPING.get(str(threat_class), Common.Indicator)

    # Create relationships
    relationships, tags = create_relationships_and_tags(name, threat_class, threat_object.get("related_threat_objects", []))
    if argToBoolean(demisto.params().get("create_relationships")):
        relationships += create_campaigns_relationships(threat_object, name, threat_class)
        relationships += create_attack_patterns_relationships(threat_object, name, threat_class)
        relationships += create_malware_relationships(threat_object, name, threat_class)
        relationships += create_tools_relationships(threat_object, name, threat_class)
        relationships += create_vulnerabilities_relationships(threat_object, name, threat_class)
        relationships += create_actor_relationships(threat_object, name, threat_class)

        # Create location indicators and relationships
        location_indicators = create_location_indicators_and_relationships(threat_object, name)
        result.extend(location_indicators)

    fields = {
        "description": build_threat_object_description(threat_object),
        "lastseenbysource": threat_object.get("last_hit", ""),
        "reportedby": threat_object.get("sources", []),
        "aliases": [string_to_table_header(alias) for alias in threat_object.get("aliases", [])],
        "industrysectors": [
            string_to_table_header(industry) for industry in demisto.get(threat_object, "battlecard_details.industries", [])
        ],
        "primarymotivation": string_to_table_header(
            demisto.get(threat_object, "battlecard_details.threat_actor_details.primary_motivation", "")
        ),
        "publications": create_publications(threat_object.get("publications", [])),
        "geocountry": demisto.get(threat_object, "battlecard_details.threat_actor_details.origin", "").upper(),
        "tags": tags + feed_tags,
        "trafficlightprotocol": tlp_color,
        "ismalwarefamily": "True" if threat_class == "malware_family" else "False",
    }

    # Create the threat object
    result.append(
        {
            "value": name,
            "type": xsoar_indicator_type,
            "score": get_threat_object_score(threat_class),
            "service": INTEGRATION_NAME,
            "relationships": relationships,
            "fields": fields,
            "rawJSON": threat_object,
        }
    )

    return result


def parse_indicators(indicators_data: list, feed_tags: list = [], tlp_color: str | None = None) -> list:
    """Parse indicators from the Unit 42 API into XSOAR format.

    Args:
        indicators_data: List of indicators from the API.
        feed_tags: List of tags to add to the indicators.
        tlp_color: Traffic Light Protocol color to add to the indicators.

    Returns:
        List of parsed indicators in XSOAR format.
    """
    indicators = []

    if indicators_data and isinstance(indicators_data, list):
        for indicator_data in indicators_data:
            indicator = map_indicator(indicator_data, feed_tags, tlp_color)
            indicators.append(indicator)

    return indicators


def parse_threat_objects(threat_objects_data: list, feed_tags: list = [], tlp_color: str | None = None) -> list:
    """Parse threat objects from the Unit 42 API into XSOAR format.

    Args:
        threat_objects_data: List of threat objects from the API.
        feed_tags: List of tags to add to the threat objects.
        tlp_color: Traffic Light Protocol color to add to the threat objects.

    Returns:
        List of parsed threat objects in XSOAR format.
    """
    threat_objects = []

    if threat_objects_data and isinstance(threat_objects_data, list):
        for threat_object_data in threat_objects_data:
            new_threat_objects = map_threat_object(threat_object_data, feed_tags, tlp_color)
            threat_objects.extend(new_threat_objects)

    return threat_objects


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    # Test connection by getting a small number of indicators
    try:
        client.get_indicators(limit=1)
        return "ok"
    except Exception as e:
        return f"Failed to connect to Unit 42 API. Check your Server URL and License. Error: {str(e)}"


def fetch_indicators(client: Client, params: dict, current_time: datetime) -> list:
    """Retrieves indicators from the feed

    Args:
        client: Client object with request
        params: demisto.params()
        current_time: The current fetch time.
    Returns:
        List. Processed indicators from feed.
    """
    indicators = []

    # Get indicator types from params
    feed_types = argToList(params.get("feed_types"))
    indicator_types = argToList(params.get("indicator_types"))

    default_start = (current_time - timedelta(hours=24)).strftime(DATE_FORMAT)
    last_run = demisto.getLastRun() or {}
    start_time = last_run.get("last_successful_run", default_start)

    feed_tags = argToList(params.get("feedTags", []))
    tlp_color = params.get("tlp_color")

    if "Indicators" in feed_types:
        # Get indicators from the API
        response = client.get_indicators(indicator_types=indicator_types, start_time=start_time)

        # Parse indicators
        if response and isinstance(response, dict) and response.get("data"):
            data = response.get("data", [])
            if isinstance(data, list):
                indicators.extend(parse_indicators(data, feed_tags, tlp_color))

                # Handle pagination if needed
                metadata = response.get("metadata", {})
                next_page_token = metadata.get("next_page_token") if isinstance(metadata, dict) else None

                # Keep track of total indicator count (starts at API_LIMIT because one call already completed)
                indicator_count = API_LIMIT
                while next_page_token and indicator_count < TOTAL_INDICATOR_LIMIT:
                    # Get next page of indicators
                    response = client.get_indicators(
                        indicator_types=indicator_types, start_time=start_time, next_page_token=next_page_token
                    )
                    if response and isinstance(response, dict) and response.get("data"):
                        data = response.get("data", [])
                        if isinstance(data, list):
                            indicators.extend(parse_indicators(data, feed_tags, tlp_color))
                        metadata = response.get("metadata", {})
                        next_page_token = metadata.get("next_page_token") if isinstance(metadata, dict) else None
                        # increment indicator_count by max number of objects fetches in single call
                        indicator_count += API_LIMIT
                    else:
                        break

    if "Threat Objects" in feed_types and start_time:
        response = client.get_threat_objects()

        # Parse threat objects
        if response and isinstance(response, dict) and response.get("data"):
            data = response.get("data", [])
            if isinstance(data, list):
                indicators.extend(parse_threat_objects(data, feed_tags, tlp_color))

            # Handle pagination if needed
            metadata = response.get("metadata", {})
            next_page_token = metadata.get("next_page_token") if isinstance(metadata, dict) else None
            while next_page_token:
                # Get next page of threat objects
                response = client.get_threat_objects(next_page_token=next_page_token)
                if response and isinstance(response, dict) and response.get("data"):
                    data = response.get("data", [])
                    if isinstance(data, list):
                        indicators.extend(parse_threat_objects(data, feed_tags, tlp_color))
                    metadata = response.get("metadata", {})
                    next_page_token = metadata.get("next_page_token") if isinstance(metadata, dict) else None
                else:
                    break

    return indicators


def get_indicators_command(client: Client, args: dict, feed_tags: list = [], tlp_color: str | None = None) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Client object with request
        args: demisto.args()
        feed_tags: feed tags.
        tlp_color: Traffic Light Protocol color.
    Returns:
        Demisto Outputs.
    """
    limit = arg_to_number(args.get("limit", "10")) or 10  # Default to 10 if None
    indicator_types = argToList(args.get("indicator_types"))
    next_page_token = args.get("next_page_token")

    # Get indicators from the API
    response = client.get_indicators(indicator_types=indicator_types, limit=limit, next_page_token=next_page_token)

    indicators = []
    if response and isinstance(response, dict) and response.get("data"):
        data = response.get("data", [])
        if isinstance(data, list):
            indicators = parse_indicators(data, feed_tags, tlp_color)

    # Create human readable output
    headers = ["value", "type", "score"]
    human_readable = tableToMarkdown("Unit 42 Indicators:", indicators, headers=headers, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="Unit42.Indicator",
        outputs_key_field="value",
        outputs=indicators,
        raw_response=response,
    )


def get_threat_objects_command(client: Client, args: dict, feed_tags: list = [], tlp_color: str | None = None) -> CommandResults:
    """Wrapper for retrieving threat objects from the feed to the war-room.

    Args:
        client: Client object with request
        args: demisto.args()
        feed_tags: feed tags.
        tlp_color: Traffic Light Protocol color.
    Returns:
        Demisto Outputs.
    """
    limit = arg_to_number(args.get("limit", "10")) or 10  # Default to 10 if None
    next_page_token = args.get("next_page_token")

    # Get threat objects from the API
    response = client.get_threat_objects(limit=limit, next_page_token=next_page_token)

    threat_objects = []
    if response and isinstance(response, dict) and response.get("data"):
        data = response.get("data", [])
        if isinstance(data, list):
            threat_objects = parse_threat_objects(data, feed_tags, tlp_color)

    # Create human readable output
    headers = ["value", "type", "score"]
    human_readable = tableToMarkdown("Unit 42 Threat Objects:", threat_objects, headers=headers, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="Unit42.ThreatObject",
        outputs_key_field="value",
        outputs=threat_objects,
        raw_response=response,
    )


def main():
    """
    The main function parses the params and runs the command functions
    """
    params = demisto.params()

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    if (arg_to_number(params.get("feedFetchInterval", "720")) or 720) < 720:
        return_error("Feed Fetch Interval parameter must be set to at least 12 hours.")

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    headers = {"Authorization": f"Bearer {demisto.getLicenseID()}"}

    try:
        client = Client(headers=headers, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))

        elif command == "fetch-indicators":
            now = datetime.now()
            indicators = fetch_indicators(client, params, now)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
            demisto.setLastRun({"last_successful_run": now.strftime(DATE_FORMAT)})
            demisto.info(
                f"The fetch-indicators command completed successfully. Next run will fetch from: {now.strftime(DATE_FORMAT)}"
            )

        elif command == "unit42-get-indicators":
            return_results(get_indicators_command(client, demisto.args()))

        elif command == "unit42-get-threat-objects":
            return_results(get_threat_objects_command(client, demisto.args()))

    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

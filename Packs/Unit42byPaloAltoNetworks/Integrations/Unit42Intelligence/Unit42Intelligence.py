import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


#### CONSTANTS ####

INTEGRATION_NAME = "Unit 42 Intelligence"
INTEGRATION_COMMAND_NAME = "unit42-intelligence"
VENDOR = "Unit 42 by Palo Alto Networks"

# API endpoints
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
    "malicious_behavior": Common.Indicator,
    "malicious behavior": Common.Indicator,
}


#### CLIENT CLASS ####

class Client(BaseClient):
    """Client class to interact with Unit 42 Intelligence API"""

    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        reliability: str,
    ):
        headers = {"Authorization": f"Bearer {demisto.getLicenseID()}", "Content-Type": "application/json"}
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)
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
    reliability: str = "A++ - 1st party feed and enrichment",
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

        if not threat_name or threat_class not in INDICATOR_TYPE_MAPPING:
            demisto.debug(f"Skipping create_relationships for threat_name {threat_name} and threat_class {threat_class}")
            continue

        relationship = EntityRelationship(
            name=EntityRelationship.Relationships.RELATED_TO,
            entity_a=indicator,
            entity_a_type=indicator_type,
            entity_b=threat_name,
            entity_b_type=INDICATOR_TYPE_MAPPING[threat_class],
            source_reliability=DBotScoreReliability.A,
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
        "verdict_category": [item.get("value") for item in response.get("verdict_category", [])],
        "first_seen": response.get("first_seen", ""),
        "last_seen": response.get("last_seen", ""),
        "seen_by": response.get("source", []),
        "relationships": response.get("threat_object_association", []),
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
    if highlights:
        description += "\n\n### Highlights\n"
        description += highlights
    
    # Add methods section if available (for threat actors)
    methods = demisto.get(threat_obj, "battlecard_details.threat_actor_details.methods", "").replace("\\n", "\n")
    if methods:
        description += "\n\n### Methods\n"
        description += methods
    
    # Add targets section if available (for threat actors)
    targets = demisto.get(threat_obj, "battlecard_details.threat_actor_details.targets", "").replace("\\n", "\n")
    if targets:
        description += "\n\n### Targets\n"
        description += targets
    
    return description


def extract_malware_associations(threat_obj: dict[str, Any]) -> list[dict[str, str]]:
    """
    Extract malware names and aliases from malware_associations
    
    Args:
        threat_obj: The threat object data
        
    Returns:
        List of malware relationship objects with name and type
    """
    malware_relationships = []
    malware_associations = demisto.get(threat_obj, "battlecard_details.threat_actor_details.malware_associations", [])
    
    for malware in malware_associations:
        if isinstance(malware, dict):
            # Add the main name
            if malware.get("name"):
                malware_relationships.append({"name": malware["name"], "type": "malware"})
            
            # Add all aliases
            aliases = malware.get("aliases", [])
            if isinstance(aliases, list):
                for alias in aliases:
                    if alias and isinstance(alias, str):
                        malware_relationships.append({"name": alias, "type": "malware"})
    
    return malware_relationships


def extract_actor_associations(threat_obj: dict[str, Any]) -> list[dict[str, str]]:
    """
    Extract actor names and aliases from actor_associations
    
    Args:
        threat_obj: The threat object data
        
    Returns:
        List of actor relationship objects with name and type
    """
    actor_relationships = []
    actor_associations = demisto.get(threat_obj, "battlecard_details.malware_family_details.actor_associations", [])
    
    for actor in actor_associations:
        if isinstance(actor, dict):
            # Add the main name
            if actor.get("name"):
                actor_relationships.append({"name": actor["name"], "type": "threat_actor"})
            
            # Add all aliases
            aliases = actor.get("aliases", [])
            if isinstance(aliases, list):
                for alias in aliases:
                    if alias and isinstance(alias, str):
                        actor_relationships.append({"name": alias, "type": "threat_actor"})
    
    return actor_relationships


def create_location_and_geo_indicators_and_relationships(
    threat_obj: dict[str, Any],
    threat_actor_name: str
) -> list[dict[str, Any]]:
    """
    Create location indicators from affected regions and origin field and build relationships
    
    Args:
        threat_obj: The threat object data
        threat_actor_name: Name of the threat actor to create relationships with
        
    Returns:
        List of location indicators with relationships
    """
    location_indicators = []
    
    # Handle affected regions
    affected_regions = demisto.get(threat_obj, "battlecard_details.threat_actor_details.affected_regions", [])
    
    for region in affected_regions:
        if isinstance(region, str) and region.strip():
            location_indicator = {
                "value": region.strip(),
                "type": FeedIndicatorType.Location,
                "score": Common.DBotScore.NONE,
                "service": INTEGRATION_NAME,
                "relationships": [{
                    "name": "targets",
                    "reverseName": "targeted-by",
                    "type": "IndicatorToIndicator",
                    "entityA": threat_actor_name,
                    "entityAType": ThreatIntel.ObjectsNames.THREAT_ACTOR,
                    "entityB": region.strip(),
                    "entityBType": FeedIndicatorType.Location
                }],
                "fields": {
                    "geocountry": region.strip(),
                    "tags": ["affected-region"]
                },
                "rawJSON": {"region": region, "source": "Unit42Intelligence"}
            }
            location_indicators.append(location_indicator)
    
    # Handle origin field
    origin = demisto.get(threat_obj, "battlecard_details.threat_actor_details.origin", "")
    if origin and isinstance(origin, str) and origin.strip():
        origin_indicator = {
            "value": origin.strip(),
            "type": FeedIndicatorType.GeoCountry,
            "score": Common.DBotScore.NONE,
            "service": INTEGRATION_NAME,
            "relationships": [{
                "name": "originates-from",
                "reverseName": "origin-of",
                "type": "IndicatorToIndicator",
                "entityA": threat_actor_name,
                "entityAType": ThreatIntel.ObjectsNames.THREAT_ACTOR,
                "entityB": origin.strip(),
                "entityBType": FeedIndicatorType.GeoCountry
            }],
            "fields": {
                "geocountry": origin.strip(),
                "tags": ["origin-country"]
            },
            "rawJSON": {"origin": origin, "source": "Unit42Intelligence"}
        }
        location_indicators.append(origin_indicator)
    
    return location_indicators


def get_threat_object_score(threat_class: str) -> int:
    """
    Get the appropriate score for a threat object based on its class
    
    Args:
        threat_class: The threat object class (lowercase)
        
    Returns:
        Appropriate ThreatIntel score or Common.DBotScore.NONE as default
    """
    if threat_class not in THREAT_INTEL_TYPE_MAPPING:
        return Common.DBotScore.NONE
        
    threat_type = THREAT_INTEL_TYPE_MAPPING[threat_class]
    
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
    threat_objects: list[dict[str, Any]],
    reliability: str = "A++ - 1st party feed and enrichment"
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
        score = get_threat_object_score(threat_class)
        relationships = threat_obj.get("related_threat_objects", [])  # TODO: verify what is inside the list
        relationships += demisto.get(threat_obj, "battlecard_details.campaigns", [])
        relationships += extract_malware_associations(threat_obj)
        relationships += extract_actor_associations(threat_obj)
        
        if not name or threat_class not in INDICATOR_TYPE_MAPPING:
            continue
        
        # Create DBotScore for threat object
        # dbot_score = create_dbot_score(
        #     indicator=name,
        #     indicator_type=DBotScoreType.CUSTOM,
        #     verdict="unknown",
        #     reliability=reliability
        # )

        description = build_threat_object_description(threat_obj)

        # Create fields with threat object details
        fields = {
            # "name": name,
            # "threat_object_class": threat_class,
            "description": description,
            "reportedby": threat_obj.get("source"),
            "aliases": threat_obj.get("aliases", []),
            "lastseenbysource": threat_obj.get("last_hit"),
            "tags": threat_obj.get("threat_object_group_names", []),
            "industrysectors": demisto.get(threat_obj, "battlecard_details.industries", []),
            "primarymotivation": demisto.get(threat_obj, "battlecard_details.primary_motivation", []),
        }
        
        indicator_data = {
            "value": name,
            "type": INDICATOR_TYPE_MAPPING[threat_class],
            "score": score,
            "service": INTEGRATION_NAME,
            "relationships": relationships,
            "fields": fields,
            "rawJSON": threat_obj,
        }
        
        indicators.append(indicator_data)
        
        # Create location and GEO indicators from affected regions
        location_and_geo_indicators = create_location_and_geo_indicators_and_relationships(threat_obj, name)
        indicators.extend(location_and_geo_indicators)
    
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
        "VerdictCategory": list({string_to_table_header(item) for item in response_data["verdict_category"]}),
        "Counts": response_data["counts"],
        "FirstSeen": response_data["first_seen"],
        "LastSeen": response_data["last_seen"],
        "SeenBy": list({string_to_table_header(item) for item in response_data["seen_by"]}),
        "EnrichedThreatObjectAssociation": response_data["relationships"],
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
        human_readable = f"### The IP indicator: {ip} was not found in Unit 42 Intelligence"
        return CommandResults(readable_output=human_readable)

    response_data = extract_response_data(response.json())
    threat_objects = response_data["relationships"]

    # Create DBotScore
    dbot_score = create_dbot_score(ip, DBotScoreType.IP, response_data["verdict"], client.reliability)

    # Extract tags and malware families from threat objects
    tags = extract_tags_from_threat_objects(threat_objects)
    malware_families = extract_malware_families_from_threat_objects(threat_objects)

    # Create enriched IP indicator with tags and malware families
    ip_indicator = Common.IP(
        ip=ip,
        dbot_score=dbot_score,
        tags=tags,
        malware_family=malware_families
    )

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
        headers=["Value", "Verdict", "VerdictCategory", "SeenBy", "FirstSeen", "LastSeen"],
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
        human_readable = f"### The domain indicator: {domain} was not found in Unit 42 Intelligence"
        return CommandResults(readable_output=human_readable)

    response_data = extract_response_data(response.json())
    threat_objects = response_data["relationships"]

    # Create DBotScore
    dbot_score = create_dbot_score(domain, DBotScoreType.DOMAIN, response_data["verdict"], client.reliability)

    # Extract tags and malware families from threat objects
    tags = extract_tags_from_threat_objects(threat_objects)
    malware_families = extract_malware_families_from_threat_objects(threat_objects)

    # Create enriched Domain indicator with tags and malware families
    domain_indicator = Common.Domain(
        domain=domain,
        dbot_score=dbot_score,
        tags=tags,
        malware_family=malware_families
    )

    # Create relationships
    relationships = create_relationships(
        domain, FeedIndicatorType.Domain, threat_objects, create_relationships_flag
    )

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
        headers=["Value", "Verdict", "VerdictCategory", "SeenBy", "FirstSeen", "LastSeen"],
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
        human_readable = f"### The URL indicator: {url} was not found in Unit 42 Intelligence"
        return CommandResults(readable_output=human_readable)

    response_data = extract_response_data(response.json())
    threat_objects = response_data["relationships"]

    # Create DBotScore
    dbot_score = create_dbot_score(url, DBotScoreType.URL, response_data["verdict"], client.reliability)

    # Extract tags and malware families from threat objects
    tags = extract_tags_from_threat_objects(threat_objects)
    malware_families = extract_malware_families_from_threat_objects(threat_objects)

    # Create enriched URL indicator with tags and malware families
    url_indicator = Common.URL(
        url=url,
        dbot_score=dbot_score,
        tags=tags,
        malware_family=malware_families
    )

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
        headers=["Value", "Verdict", "VerdictCategory", "SeenBy", "FirstSeen", "LastSeen"],
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
        human_readable = f"### The file indicator: {file_hash} was not found in Unit 42 Intelligence"
        return CommandResults(readable_output=human_readable)

    response_data = extract_response_data(response.json())
    threat_objects = response_data["relationships"]

    # Create DBotScore
    dbot_score = create_dbot_score(file_hash, DBotScoreType.FILE, response_data["verdict"], client.reliability)

    # Extract tags and malware families from threat objects
    tags = extract_tags_from_threat_objects(threat_objects)
    malware_families = extract_malware_families_from_threat_objects(threat_objects)

    # Create enriched File indicator with proper hash field assignment
    hash_val_arg = {hash_type: file_hash}
    file_indicator = Common.File(
        dbot_score=dbot_score,
        tags=tags,
        malware_family=malware_families
        **hash_val_arg
    )

    # Create relationships
    relationships = create_relationships(
        file_hash, FeedIndicatorType.File, threat_objects, create_relationships_flag
    )

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
        headers=["Value", "Verdict", "VerdictCategory", "SeenBy", "FirstSeen", "LastSeen"],
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
    base_url = params.get("url", "").rstrip("/")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    reliability = params.get("integration_reliability", "A++ - 1st party feed and enrichment")
    create_relationships = argToBoolean(params.get("create_relationships", True))
    create_threat_object_indicators = argToBoolean(params.get("create_threat_object_indicators", False))

    # Add create_relationships to args for commands
    args["create_relationships"] = create_relationships
    args["create_threat_object_indicators"] = create_threat_object_indicators

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            reliability=reliability,
        )

        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "ip":
            return_results(ip_command(client, args))

        elif command == "domain":
            return_results(domain_command(client, args))

        elif command == "url":
            return_results(url_command(client, args))

        elif command == "file":
            return_results(file_command(client, args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

from CommonServerPython import *
from CommonServerUserPython import *
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
INTEGRATION_NAME = "Unit42Feed"

# Mapping from API indicator types to XSOAR indicator types
INDICATOR_TYPE_MAP = {
    "ip": FeedIndicatorType.IP,
    "domain": FeedIndicatorType.Domain,
    "domain-name": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "md5": FeedIndicatorType.File,
    "sha-1": FeedIndicatorType.File,
    "sha-256": FeedIndicatorType.File,
    "file:hashes": FeedIndicatorType.File,
}


# Define ThreatTypes enum for threat object classification
class ThreatTypes:
    Malware = "Malware"
    Campaign = "Campaign"
    Actor = "Actor"
    Tool = "Tool"
    Report = "Report"
    Other = "Other"


# Mapping from API threat object classes to XSOAR threat types
THREAT_OBJECT_CLASS_MAP = {
    "malware_family": ThreatIntel.ObjectsNames.MALWARE,
    "campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "threat_actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "malicious_behavior": Common.Indicator,
    "exploit": FeedIndicatorType.CVE,
    "attack_pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN
}


class Client(BaseClient):
    def __init__(self, base_url, headers, verify=False, proxy=False):
        """Implements class for Unit 42 feed.

        Args:
            base_url: feed URL.
            headers: headers for the request.
            verify: boolean, if *false*, feed HTTPS server certificate is verified. Default: *false*
            proxy: boolean, if *false* feed HTTPS server certificate will not use proxies. Default: *false*
        """
        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy)

    def get_indicators(
        self,
        indicator_types: str | None = None,
        limit: int = 100,
        start_time: str | None = None,
        next_page_token: str | None = None,
    ) -> dict:
        """Get indicators from the Unit 42 feed.

        Args:
            indicator_types: Comma separated list of indicator types to fetch (ip, filehash_sha256, domain, url, or None for all)
            limit: Maximum number of indicators to return
            start_time: Start time for fetching indicators
            next_page_token: Token for pagination

        Returns:
            Dict containing indicators and pagination info
        """
        params = {}
        if indicator_types and indicator_types != "All":
            params["indicator_types"] = indicator_types
        if limit:
            params["limit"] = limit
        if start_time:
            params["start_time"] = start_time
        if next_page_token:
            params["next_page_token"] = next_page_token

        response = self._http_request(
            method="GET", url_suffix="/api/v1/feeds/indicators", params=params
        )

        return response

    def get_threat_objects(self, limit: int = 100, next_page_token: str | None = None) -> dict:
        """Get threat objects from the Unit 42 feed.

        Args:
            limit: Maximum number of threat objects to return
            next_page_token: Token for pagination

        Returns:
            Dict containing threat objects and pagination info
        """
        params = {}
        if limit:
            params["limit"] = limit
        if next_page_token:
            params["next_page_token"] = next_page_token

        response = self._http_request(method="GET", url_suffix="/api/v1/feeds/threat_objects", params=params)

        return response

def get_threat_object_score(threat_class: str) -> int:
    """
    Get the appropriate score for a threat object based on its class

    Args:
        threat_class: The threat object class (lowercase)

    Returns:
        Appropriate ThreatIntel score or Common.DBotScore.NONE as default
    """
    if threat_class not in INDICATOR_TYPE_MAP:
        return Common.DBotScore.NONE

    threat_type = INDICATOR_TYPE_MAP[threat_class]

    if threat_type == ThreatIntel.ObjectsNames.MALWARE:
        return ThreatIntel.ObjectsScore.MALWARE
    elif threat_type == ThreatIntel.ObjectsNames.THREAT_ACTOR:
        return ThreatIntel.ObjectsScore.THREAT_ACTOR
    elif threat_type == ThreatIntel.ObjectsNames.CAMPAIGN:
        return ThreatIntel.ObjectsScore.CAMPAIGN
    elif threat_type == ThreatIntel.ObjectsNames.ATTACK_PATTERN:
        return ThreatIntel.ObjectsScore.ATTACK_PATTERN

    return Common.DBotScore.NONE

def map_indicator(indicator_data: dict, feed_tags: list = [], tlp_color: str | None = None) -> dict:
    """Map an indicator from the Unit 42 API to XSOAR format.

    Args:
        indicator_data: Indicator data from the API.
        feed_tags: List of tags to add to the indicator.
        tlp_color: Traffic Light Protocol color to add to the indicator.

    Returns:
        Indicator in XSOAR format.
    """
    indicator_type = indicator_data.get("indicator_type", "")
    indicator_value = indicator_data.get("indicator_value", "")

    # Map the indicator type to XSOAR type
    xsoar_type = INDICATOR_TYPE_MAP.get(str(indicator_type), FeedIndicatorType.File)

    # Create the indicator object
    indicator: dict = {
        "value": indicator_value,
        "type": xsoar_type,
        "rawJSON": indicator_data,
        "fields": {
            "updateddate": indicator_data.get("updated_at"),
            "reportedby": "Unit42",
            "score": indicator_data.get("verdict"),
        },
    }

    # Add tags from threat object associations
    threat_object_association = indicator_data.get("threat_object_association", [])
    # Process threat object associations for tags and relationships
    if threat_object_association and "fields" in indicator and isinstance(indicator["fields"], dict):
        # Add tags from threat object associations
        threat_tags = [assoc.get("name") for assoc in threat_object_association if assoc and assoc.get("name")]
        # Use a single if statement to avoid nesting
        indicator["fields"]["tags"] = list(set(threat_tags + feed_tags)) if threat_tags else feed_tags.copy() if feed_tags else []

        # Add relationships from threat object associations
        relationships = [
            {"name": assoc.get("name"), "class": assoc.get("class")}
            for assoc in threat_object_association
            if assoc and assoc.get("name") and assoc.get("class")
        ]
        # Assign relationships only if they exist
        indicator["fields"]["relationships"] = relationships if relationships else []

    # Add file-specific fields
    if (
        indicator_type
        and isinstance(indicator_type, str)
        and indicator_type.startswith("filehash_")
        and "fields" in indicator
        and isinstance(indicator["fields"], dict)
    ):
        if indicator_data.get("file_type"):
            indicator["fields"]["filetype"] = indicator_data.get("file_type")
        if indicator_data.get("size"):
            indicator["fields"]["size"] = indicator_data.get("size")
        if indicator_data.get("ssdeep"):
            indicator["fields"]["ssdeep"] = indicator_data.get("ssdeep")
        if indicator_data.get("imphash"):
            indicator["fields"]["imphash"] = indicator_data.get("imphash")
        if indicator_data.get("sha1"):
            indicator["fields"]["sha1"] = indicator_data.get("sha1")
        if indicator_data.get("md5"):
            indicator["fields"]["md5"] = indicator_data.get("md5")

    # Add first seen date
    if indicator_data.get("first_seen") and "fields" in indicator and isinstance(indicator["fields"], dict):
        indicator["fields"]["creationdate"] = indicator_data.get("first_seen")

    # Add TLP color if provided
    if tlp_color and "fields" in indicator and isinstance(indicator["fields"], dict):
        indicator["fields"]["trafficlightprotocol"] = tlp_color

    return indicator


def map_threat_object(threat_object: dict, feed_tags: list = [], tlp_color: str | None = None) -> dict:
    """Map a threat object from the Unit 42 API to XSOAR format.

    Args:
        threat_object: Threat object data from the API.
        feed_tags: List of tags to add to the threat object.
        tlp_color: Traffic Light Protocol color to add to the threat object.

    Returns:
        Threat object in XSOAR format.
    """
    # Get basic threat object properties
    name = threat_object.get("name", "")
    obj_class = threat_object.get("class", "")

    # Map the threat object class to XSOAR type
    xsoar_type = THREAT_OBJECT_CLASS_MAP.get(str(obj_class), ThreatTypes.Other)

    # Create the threat object
    result: dict = {
        "value": name,
        "type": xsoar_type,
        "score": get_threat_object_score(threat_class),
        "service": INTEGRATION_NAME,
        "rawJSON": threat_object,
        "fields": {
            "updateddate": threat_object.get("updated_at"),
            "reportedby": "Unit42",
        },
    }

    # Add description if available
    if threat_object.get("description") and "fields" in result and isinstance(result["fields"], dict):
        result["fields"]["description"] = threat_object.get("description")

    # Add aliases if available
    aliases = threat_object.get("aliases")
    if aliases and "fields" in result and isinstance(result["fields"], dict):
        result["fields"]["aliases"] = aliases

    # Add publications if available
    publications_data = threat_object.get("publications", [])
    if publications_data and isinstance(publications_data, list) and "fields" in result and isinstance(result["fields"], dict):
        publications = []
        for pub in publications_data:
            if pub and pub.get("name") and pub.get("url"):
                publications.append({"name": pub.get("name"), "url": pub.get("url")})
        if publications:
            result["fields"]["publications"] = publications

    # Add tags
    tags = feed_tags.copy() if feed_tags else []
    threat_tags = threat_object.get("tags", [])
    if threat_tags and isinstance(threat_tags, list):
        tags.extend(threat_tags)
    if tags and "fields" in result and isinstance(result["fields"], dict):
        result["fields"]["tags"] = list(set(tags))

    # Add relationships
    relationships_data = threat_object.get("relationships", [])
    if relationships_data and isinstance(relationships_data, list) and "fields" in result and isinstance(result["fields"], dict):
        relationships = []
        for rel in relationships_data:
            if rel and rel.get("name") and rel.get("class"):
                relationships.append(
                    {
                        "name": rel.get("name"),
                        "class": rel.get("class"),
                        "relationship_type": rel.get("relationship_type", "related-to"),
                    }
                )
        if relationships:
            result["fields"]["relationships"] = relationships

    # Add MITRE ATT&CK techniques
    attack_techniques = threat_object.get("attack_techniques", [])
    if attack_techniques and isinstance(attack_techniques, list) and "fields" in result and isinstance(result["fields"], dict):
        techniques = []
        for tech in attack_techniques:
            if tech and tech.get("technique_id") and tech.get("technique_name"):
                techniques.append(
                    {
                        "id": tech.get("technique_id"),
                        "name": tech.get("technique_name"),
                        "tactic": tech.get("tactic", ""),
                    }
                )
        if techniques:
            result["fields"]["attack_techniques"] = techniques

    # Add first seen and last seen dates
    if threat_object.get("first_seen") and "fields" in result and isinstance(result["fields"], dict):
        result["fields"]["firstseenbysource"] = threat_object.get("first_seen")
    if threat_object.get("last_seen"):
        result["fields"]["lastseenbysource"] = threat_object.get("last_seen")

    # Add TLP color if provided
    if tlp_color and "fields" in result and isinstance(result["fields"], dict):
        result["fields"]["trafficlightprotocol"] = tlp_color

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
            threat_object = map_threat_object(threat_object_data, feed_tags, tlp_color)
            threat_objects.append(threat_object)

    return threat_objects


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    # Test connection by getting a small number of indicators
    response = client.get_indicators(limit=1)
    if response and response.get("data"):
        return "ok"
    return "Failed to connect to Unit 42 API. Check your Server URL and License."


def fetch_indicators(
    client: Client, params: dict, feed_tags: list = [], tlp_color: str | None = None, current_time: str | None = None
) -> list:
    """Retrieves indicators from the feed

    Args:
        client: Client object with request
        params: demisto.params()
        feed_tags: feed tags.
        tlp_color: Traffic Light Protocol color.
        current_time: The current fetch time.
    Returns:
        List. Processed indicators from feed.
    """
    # Get indicator types from params
    indicator_types = ",".join(params.get("indicator_types", ["All"]))
    start_time = demisto.getLastRun().get("last_successful_run", (current_time - timedelta(hours=12)).strftime(DATE_FORMAT))

    # Get indicators from the API
    response = client.get_indicators(indicator_types=indicator_types, start_time=start_time)

    # Parse indicators
    indicators = []
    if response and isinstance(response, dict) and response.get("data"):
        data = response.get("data", [])
        if isinstance(data, list):
            indicators.extend(parse_indicators(data, feed_tags, tlp_color))

            # Handle pagination if needed
            metadata = response.get("metadata", {})
            next_page_token = metadata.get("next_page_token") if isinstance(metadata, dict) else None
            while next_page_token:
                # Get next page of indicators
                response = client.get_indicators(indicator_types=indicator_types, next_page_token=next_page_token)
                if response and isinstance(response, dict) and response.get("data"):
                    data = response.get("data", [])
                    if isinstance(data, list):
                        indicators.extend(parse_indicators(data, feed_tags, tlp_color))
                    metadata = response.get("metadata", {})
                    next_page_token = metadata.get("next_page_token") if isinstance(metadata, dict) else None
                else:
                    break

    # Get threat objects twice a day (every 12 hours)
    if start_time:
        start_time_utc = datetime.strptime(start_time, DATE_FORMAT).replace(tzinfo=timezone.utc)
        time_diff = (datetime.now(timezone.utc) - start_time_utc).total_seconds()
        if time_diff >= 6 * 3600:
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
    indicator_types = ",".join(args.get("indicator_types", ["All"]))
    next_page_token = args.get("next_page_token")

    # Get indicators from the API
    response = client.get_indicators(indicator_types=indicator_types, limit=limit, next_page_token=next_page_token)

    indicators = []
    if response and isinstance(response, dict) and response.get("data"):
        data = response.get("data", [])
        if isinstance(data, list):
            indicators = parse_indicators(data, feed_tags, tlp_color)

    # Create pagination context
    pagination_context = {}
    if response and isinstance(response, dict) and response.get("metadata"):
        metadata = response.get("metadata", {})
        if isinstance(metadata, dict) and metadata.get("next_page_token"):
            pagination_context["next_page_token"] = metadata.get("next_page_token")

    # Create human readable output
    headers = ["value", "type", "score"]
    human_readable = tableToMarkdown("Unit 42 Indicators:", indicators, headers=headers, removeNull=True)

    # Add pagination information to human readable output if available
    if pagination_context:
        human_readable += f"\n\nTo get the next page of results, use next_page_token: {pagination_context.get('next_page_token')}"

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

    # Create pagination context
    pagination_context = {}
    if response and isinstance(response, dict) and response.get("metadata"):
        metadata = response.get("metadata", {})
        if isinstance(metadata, dict) and metadata.get("next_page_token"):
            pagination_context["next_page_token"] = metadata.get("next_page_token")

    # Create human readable output
    headers = ["value", "type", "description"]
    human_readable = tableToMarkdown("Unit 42 Threat Objects:", threat_objects, headers=headers, removeNull=True)

    # Add pagination information to human readable output if available
    if pagination_context:
        human_readable += f"\n\nTo get the next page of results, use next_page_token: {pagination_context.get('next_page_token')}"

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
    url = params.get("url")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # Get feed tags and TLP color from params
    feed_tags = argToList(params.get("feedTags", []))
    tlp_color = params.get("tlp_color")

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    headers = {"Authorization": f"Bearer {demisto.getLicenseID()}"}

    try:
        client = Client(base_url=url, headers=headers, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))

        elif command == "fetch-indicators" or command == "unit42-fetch-indicators":
            now = datetime.now()
            indicators = fetch_indicators(client, params, feed_tags, tlp_color, now)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
            demisto.setLastRun({"last_successful_run": now.strftime(DATE_FORMAT)})
            demisto.info(f"Fetch-indicators completed. Next run will fetch from: {now.strftime(DATE_FORMAT)}")

        elif command == "unit42-get-indicators":
            return_results(get_indicators_command(client, demisto.args(), feed_tags, tlp_color))

        elif command == "unit42-get-threat-objects":
            return_results(get_threat_objects_command(client, demisto.args(), feed_tags, tlp_color))

    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

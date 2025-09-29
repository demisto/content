from CommonServerPython import *
from CommonServerUserPython import *
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
INTEGRATION_NAME = "Unit42Feed"
LIMIT = 5000

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
    "malicious_behavior": Common.Indicator,
    "malicious behavior": Common.Indicator,
}

VERDICT_TO_SCORE = {
    "malicious": Common.DBotScore.BAD,
    "suspicious": Common.DBotScore.SUSPICIOUS,
    "benign": Common.DBotScore.GOOD,
    "unknown": Common.DBotScore.NONE,
}


#### DBotScoreReliability ####
class DBotScoreReliability:
    """
    Enum: Source reliability levels
    Values are case sensitive

    :return: None
    :rtype: ``None``
    """

    A_PLUS_PLUS = "A++ - Reputation script"
    A_PLUS = "A+ - 3rd party enrichment"
    A = "A - Completely reliable"
    B = "B - Usually reliable"
    C = "C - Fairly reliable"
    D = "D - Not usually reliable"
    E = "E - Unreliable"
    F = "F - Reliability cannot be judged"

    def __init__(self):
        # required to create __init__ for create_server_docs.py purpose
        pass

    @staticmethod
    def is_valid_type(_type):
        # type: (str) -> bool

        return _type in (
            DBotScoreReliability.A_PLUS_PLUS,
            DBotScoreReliability.A_PLUS,
            DBotScoreReliability.A,
            DBotScoreReliability.B,
            DBotScoreReliability.C,
            DBotScoreReliability.D,
            DBotScoreReliability.E,
            DBotScoreReliability.F,
        )

    @staticmethod
    def get_dbot_score_reliability_from_str(reliability_str):  # pragma: no cover
        if reliability_str == DBotScoreReliability.A_PLUS_PLUS:
            return DBotScoreReliability.A_PLUS_PLUS
        if reliability_str == DBotScoreReliability.A_PLUS:
            return DBotScoreReliability.A_PLUS
        elif reliability_str == DBotScoreReliability.A:
            return DBotScoreReliability.A
        elif reliability_str == DBotScoreReliability.B:
            return DBotScoreReliability.B
        elif reliability_str == DBotScoreReliability.C:
            return DBotScoreReliability.C
        elif reliability_str == DBotScoreReliability.D:
            return DBotScoreReliability.D
        elif reliability_str == DBotScoreReliability.E:
            return DBotScoreReliability.E
        elif reliability_str == DBotScoreReliability.F:
            return DBotScoreReliability.F
        raise Exception("Please use supported reliability only.")

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
        limit: int = LIMIT,
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
        params = {}
        if indicator_types:
            params["indicator_type"] = ",".join(indicator_types).lower().replace("file", "filehash_sha256")
        if limit:
            params["limit"] = limit
        if start_time:
            params["start_time"] = start_time
        if next_page_token:
            params["page_token"] = next_page_token

        response = self._http_request(method="GET", url_suffix=INDICATORS_ENDPOINT, params=params)

        return response

    def get_threat_objects(self, limit: int = LIMIT, next_page_token: str | None = None) -> dict:
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
            params["page_token"] = next_page_token

        response = self._http_request(method="GET", url_suffix=THREAT_OBJECTS_ENDPOINT, params=params)

        return response


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


def create_relationships_and_tags(indicator_value: str, indicator_type: str, threat_object_associations: list) -> list:
    """
    Create relationships and tags from threat object associations

    Args:
        indicator_value: The indicator value (entity_a)
        indicator_type: The indicator type for mapping
        threat_object_associations: List of threat object associations

    Returns:
        Tuple of List of EntityRelationship objects and tags
    """
    relationships = []
    tags = []

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
    dbot_score = VERDICT_TO_SCORE.get(indicator_data.get("verdict"), Common.DBotScore.NONE)

    # Create relationships and tags
    relationships = []
    tags = []
    if indicator_data.get("threat_object_associations"):
        relationships, tags = create_relationships_and_tags(indicator_value, indicator_type, indicator_data.get("threat_object_associations"))

    # Create fields
    fields = {
        "updateddate": indicator_data.get("updated_at"),
        "creationdate": indicator_data.get("first_seen"),
        "reportedby": indicator_data.get("source"),
        "tags": tags,
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
    threat_class = threat_object.get("threat_object_class", "").lower()

    # Map the threat object class to XSOAR type
    xsoar_indicator_type = INDICATOR_TYPE_MAPPING.get(str(threat_class), Common.Indicator)
    
    fields = {
        "description": threat_object.get("description"),
        "updateddate": threat_object.get("updated_at"),
        "reportedby": threat_object.get("source"),
    }

    # Create the threat object
    result: dict = {
        "value": name,
        "type": xsoar_indicator_type,
        "score": get_threat_object_score(threat_class),
        "service": INTEGRATION_NAME,
        "relationships": [],
        "fields": fields,
        "rawJSON": threat_object,
    }

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


def fetch_indicators(client: Client, params: dict, current_time: str | None = None) -> list:
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
    start_time = demisto.getLastRun().get("last_successful_run", (current_time - timedelta(hours=24)).strftime(DATE_FORMAT))

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

                # # Handle pagination if needed
                # metadata = response.get("metadata", {})
                # next_page_token = metadata.get("next_page_token") if isinstance(metadata, dict) else None
                # while next_page_token:
                #     # Get next page of indicators
                #     response = client.get_indicators(
                #         indicator_types=indicator_types, start_time=start_time, next_page_token=next_page_token
                #     )
                #     if response and isinstance(response, dict) and response.get("data"):
                #         data = response.get("data", [])
                #         if isinstance(data, list):
                #             indicators.extend(parse_indicators(data, feed_tags, tlp_color))
                #         metadata = response.get("metadata", {})
                #         next_page_token = metadata.get("next_page_token") if isinstance(metadata, dict) else None
                #     else:
                #         break

    if "Threat Objects" in feed_types and start_time:
        # Get threat objects twice a day (every 12 hours)
        start_time_utc = datetime.strptime(start_time, DATE_FORMAT).replace(tzinfo=timezone.utc)
        time_diff = (datetime.now(timezone.utc) - start_time_utc).total_seconds()

        if time_diff >= 6 * 3600:
            response = client.get_threat_objects()

            # Parse threat objects
            if response and isinstance(response, dict) and response.get("data"):
                data = response.get("data", [])
                if isinstance(data, list):
                    indicators.extend(parse_threat_objects(data, feed_tags, tlp_color))

                # # Handle pagination if needed
                # metadata = response.get("metadata", {})
                # next_page_token = metadata.get("next_page_token") if isinstance(metadata, dict) else None
                # while next_page_token:
                #     # Get next page of threat objects
                #     response = client.get_threat_objects(next_page_token=next_page_token)
                #     if response and isinstance(response, dict) and response.get("data"):
                #         data = response.get("data", [])
                #         if isinstance(data, list):
                #             indicators.extend(parse_threat_objects(data, feed_tags, tlp_color))
                #         metadata = response.get("metadata", {})
                #         next_page_token = metadata.get("next_page_token") if isinstance(metadata, dict) else None
                #     else:
                #         break

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

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    if arg_to_number(params.get("feedFetchInterval", 720)) < 720:
        return_error("Feed Fetch Interval parameter must be set to at least 12 hours.")

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    headers = {"Authorization": f"Bearer {demisto.getLicenseID()}"}

    try:
        client = Client(headers=headers, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))

        elif command == "fetch-indicators" or command == "unit42-fetch-indicators":
            now = datetime.now()
            indicators = fetch_indicators(client, params, now)
            if command == "fetch-indicators":
                for b in batch(indicators, batch_size=2000):
                    demisto.createIndicators(b)
            else:
                demisto.debug(len(indicators))

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

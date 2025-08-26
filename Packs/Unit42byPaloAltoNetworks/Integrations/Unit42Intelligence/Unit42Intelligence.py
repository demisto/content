import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
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
    "exploit": FeedIndicatorType.CVE,
    "malware_family": ThreatIntel.ObjectsNames.MALWARE,
    "actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "attack pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "malicious_behavior": "",  # Todo add the correct type
    "malicious behavior": "",  # Todo add the correct type
}


class Client(BaseClient):
    """Client class to interact with Unit 42 Intelligence API"""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify: bool,
        proxy: bool,
        reliability: str,
    ):
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
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


def create_dbot_score(
    indicator: str,
    indicator_type: str,
    verdict: str,
    reliability: str = "A - Completely reliable",
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


def create_indicators_from_relationships(relationship: dict[str, Any]):
    """
    Create indicators from relationship

    Args:
        relationship: Relationship as dictionary

    Returns:
        Indicator object based on the relationship type
    """
    indicator_name = relationship["name"]
    indicator_type = relationship["threat_object_class"]
    verdict = relationship.get("verdict", "unknown")

    if not any([indicator_name, indicator_type]):
        demisto.debug(f"Skipping create_indicators_from_relationships for {indicator_name=}, {indicator_type=}, {verdict=}")
        return

    dbot_score = create_dbot_score(
        indicator=indicator_name,
        indicator_type=indicator_type,
        verdict=verdict,
    )
    # Retrieve the indicator type from the mapping dictionary based on the relationship type
    indicator_type = INDICATOR_TYPE_MAPPING.get(indicator_type, "Indicator")
    # Create indicator based on type
    indicator: Common.IP | Common.Domain | Common.URL | Common.File | Common.CustomIndicator | None = None
    if indicator_type == "IP":
        indicator = Common.IP(ip=indicator_name, dbot_score=dbot_score)
    elif indicator_type == "Domain":
        indicator = Common.Domain(domain=indicator_name, dbot_score=dbot_score)
    elif indicator_type == "URL":
        indicator = Common.URL(url=indicator_name, dbot_score=dbot_score)
    elif indicator_type == "File":
        indicator = Common.File(sha256=indicator_name, dbot_score=dbot_score)
    else:
        # Create custom indicator for unknown types
        indicator = Common.CustomIndicator(
            indicator_type=indicator_type,
            value=indicator_name,
            dbot_score=dbot_score,
            data={"value": indicator_name},
            context_prefix=indicator_type.capitalize(),
        )

    command_results = CommandResults(
        indicator=indicator,
    )
    return_results(command_results)


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
        "Type": response_data["indicator_type"],
        "Verdict": response_data["verdict"],
        "VerdictCategory": response_data["verdict_category"],
        "Counts": response_data["counts"],
        "FirstSeen": response_data["first_seen"],
        "LastSeen": response_data["last_seen"],
        "SeenBy": response_data["seen_by"],
        "EnrichedThreatObjectAssociation": response_data["relationships"],
    }


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
    create_indicators_from_relationships_flag = argToBoolean(args.get("create_indicators_from_relationships", False))

    response = client.lookup_indicator("ip", ip)

    if response.status_code == 404:
        return CommandResults(readable_output="Indicator not found")

    response_data = extract_response_data(response.json())

    # Create DBotScore
    dbot_score = create_dbot_score(ip, DBotScoreType.IP, response_data["verdict"], client.reliability)

    # Create IP indicator
    ip_indicator = Common.IP(ip=ip, dbot_score=dbot_score)

    # Create relationships
    relationships = create_relationships(ip, FeedIndicatorType.IP, response_data["relationships"], create_relationships_flag)

    # Create indicators from relationships
    if create_indicators_from_relationships_flag:
        create_indicators_from_relationships(response_data["relationships"])

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
    create_indicators_from_relationships_flag = argToBoolean(args.get("create_indicators_from_relationships", False))

    response = client.lookup_indicator("domain", domain)
    
    if response.status_code == 404:
        return CommandResults(readable_output="Indicator not found")

    response_data = extract_response_data(response.json())

    # Create DBotScore
    dbot_score = create_dbot_score(domain, DBotScoreType.DOMAIN, response_data["verdict"], client.reliability)

    # Create Domain indicator
    domain_indicator = Common.Domain(domain=domain, dbot_score=dbot_score)

    # Create relationships
    relationships = create_relationships(
        domain, FeedIndicatorType.Domain, response_data["relationships"], create_relationships_flag
    )

    # Create indicators from relationships
    if create_indicators_from_relationships_flag:
        create_indicators_from_relationships(response_data["relationships"])

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
    create_indicators_from_relationships_flag = argToBoolean(args.get("create_indicators_from_relationships", False))

    response = client.lookup_indicator("url", url)

    if response.status_code == 404:
        return CommandResults(readable_output="Indicator not found")

    response_data = extract_response_data(response.json())

    # Create DBotScore
    dbot_score = create_dbot_score(url, DBotScoreType.URL, response_data["verdict"], client.reliability)

    # Create URL indicator
    url_indicator = Common.URL(url=url, dbot_score=dbot_score)

    # Create relationships
    relationships = create_relationships(url, FeedIndicatorType.URL, response_data["relationships"], create_relationships_flag)

    # Create indicators from relationships
    if create_indicators_from_relationships_flag:
        create_indicators_from_relationships(response_data["relationships"])

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
    create_indicators_from_relationships_flag = argToBoolean(args.get("create_indicators_from_relationships", False))

    response = client.lookup_indicator("filehash_sha256", file_hash)
    
    if response.status_code == 404:
        return CommandResults(readable_output="Indicator not found")

    response_data = extract_response_data(response.json())

    # Create DBotScore
    dbot_score = create_dbot_score(file_hash, DBotScoreType.FILE, response_data["verdict"], client.reliability)

    # Create File indicator
    file_indicator = Common.File(
        sha256=file_hash if len(file_hash) == 64 else None,
        sha1=file_hash if len(file_hash) == 40 else None,
        md5=file_hash if len(file_hash) == 32 else None,
        dbot_score=dbot_score,
    )

    # Create relationships
    relationships = create_relationships(
        file_hash, FeedIndicatorType.File, response_data["relationships"], create_relationships_flag
    )

    # Create indicators from relationships
    if create_indicators_from_relationships_flag:
        create_indicators_from_relationships(response_data["relationships"])

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


def main() -> None:
    """Main function, parses params and runs command functions"""

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # Get parameters
    base_url = params.get("url", "").rstrip("/")
    api_key = params.get("credentials", {}).get("password", "")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    reliability = params.get("integration_reliability", "A - Completely reliable")
    create_relationships = argToBoolean(params.get("create_relationships", True))
    create_indicators_from_relationships = argToBoolean(params.get("create_indicators_from_relationships", False))

    # Add create_relationships to args for commands
    args["create_relationships"] = create_relationships
    args["create_indicators_from_relationships"] = create_indicators_from_relationships

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
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

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
INDICATOR_TYPE_MAPPING = {"ip": "ip", "domain": "domain", "url": "url", "file": "filehash_sha256"}


class Client(BaseClient):
    """Client class to interact with Unit 42 Intelligence API"""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool, reliability: str):
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)
        self.reliability = reliability

    def lookup_indicator(self, indicator_type: str, indicator_value: str) -> dict[str, Any]:
        """
        Lookup an indicator in Unit 42 Intelligence

        Args:
            indicator_type: Type of indicator (ip, domain, url, filehash_sha256)
            indicator_value: Value of the indicator

        Returns:
            API response as dictionary
        """
        endpoint = LOOKUP_ENDPOINT.format(indicator_type=indicator_type, indicator_value=indicator_value)

        response = self._http_request(method="GET", url_suffix=endpoint, timeout=60)

        return response


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


def create_dbot_score(indicator: str, indicator_type: str, verdict: str, reliability: str) -> Common.DBotScore:
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
    score = VERDICT_TO_SCORE.get(verdict.lower() or "unknown", Common.DBotScore.NONE)

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
    indicator: str, indicator_type: str, tags: list[dict[str, Any]], create_relationships: bool
) -> list[EntityRelationship]:
    """
    Create relationships between indicator and threat objects

    Args:
        indicator: The indicator value
        indicator_type: Type of indicator
        tags: List of threat tags
        create_relationships: Whether to create relationships

    Returns:
        List of EntityRelationship objects or empty list
    """
    relationships: list[EntityRelationship] = []

    if not any([create_relationships, tags]):
        return relationships

    for tag in tags:
        tag_name = tag.get("name", "")
        tag_type = tag.get("type", "").lower()

        # TODO: implement the mapping
        if tag_type == "malware_family":
            entity_b_type = FeedIndicatorType.Malware
        else:
            continue

        relationship = EntityRelationship(
            name=EntityRelationship.Relationships.RELATED_TO,
            entity_a=indicator,
            entity_a_type=indicator_type,
            entity_b=tag_name,
            entity_b_type=entity_b_type,
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
        "verdict": response.get("verdict", "unknown"),
        "verdict_category": response.get("verdict_category", ""),
        "first_seen": response.get("first_seen", ""),
        "last_seen": response.get("last_seen", ""),
        "seen_by": response.get("seen_by", []),
        "tags": response.get("enriched_threat_object_association", []),
    }


def create_context_data(indicator_key: str, indicator_value: str, response_data: dict[str, Any]) -> dict[str, Any]:
    """
    Create context data for indicators

    Args:
        indicator_key: The key name for the indicator (Address, Name, Data, Hash)
        indicator_value: The indicator value
        response_data: Extracted response data

    Returns:
        Dictionary containing context data
    """
    return {
        indicator_key: indicator_value,
        "Verdict": response_data["verdict"],
        "VerdictCategory": response_data["verdict_category"],
        "FirstSeen": response_data["first_seen"],
        "LastSeen": response_data["last_seen"],
        "SeenBy": response_data["seen_by"],
        "Tags": [tag.get("name", "") for tag in response_data["tags"]],
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

    response = client.lookup_indicator("ip", ip)

    response_data = extract_response_data(response)

    # Create DBotScore
    dbot_score = create_dbot_score(ip, DBotScoreType.IP, response_data["verdict"], client.reliability)

    # Create IP indicator
    ip_indicator = Common.IP(ip=ip, dbot_score=dbot_score)

    # Create relationships
    relationships = create_relationships(
        ip, FeedIndicatorType.ip_to_indicator_type(ip), response_data["tags"], create_relationships_flag
    )

    # Create context data
    context_data = create_context_data("Address", ip, response_data)

    readable_output = tableToMarkdown(
        f"Unit 42 Intelligence results for IP: {ip}",
        context_data,
        headers=["Address", "Verdict", "VerdictCategory", "FirstSeen", "LastSeen", "Tags"],
    )

    return CommandResults(
        outputs_prefix="Unit42.IP",
        outputs_key_field="Address",
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

    response = client.lookup_indicator("domain", domain)

    response_data = extract_response_data(response)

    # Create DBotScore
    dbot_score = create_dbot_score(domain, DBotScoreType.DOMAIN, response_data["verdict"], client.reliability)

    # Create Domain indicator
    domain_indicator = Common.Domain(domain=domain, dbot_score=dbot_score)

    # Create relationships
    relationships = create_relationships(domain, FeedIndicatorType.Domain, response_data["tags"], create_relationships_flag)

    # Create context data
    context_data = create_context_data("Name", domain, response_data)

    readable_output = tableToMarkdown(
        f"Unit 42 Intelligence results for Domain: {domain}",
        context_data,
        headers=["Name", "Verdict", "VerdictCategory", "FirstSeen", "LastSeen", "Tags"],
    )

    return CommandResults(
        outputs_prefix="Unit42.Domain",
        outputs_key_field="Name",
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

    response = client.lookup_indicator("url", url)

    response_data = extract_response_data(response)

    # Create DBotScore
    dbot_score = create_dbot_score(url, DBotScoreType.URL, response_data["verdict"], client.reliability)

    # Create URL indicator
    url_indicator = Common.URL(url=url, dbot_score=dbot_score)

    # Create relationships
    relationships = create_relationships(url, FeedIndicatorType.URL, response_data["tags"], create_relationships_flag)

    # Create context data
    context_data = create_context_data("Data", url, response_data)

    readable_output = tableToMarkdown(
        f"Unit 42 Intelligence results for URL: {url}",
        context_data,
        headers=["Data", "Verdict", "VerdictCategory", "FirstSeen", "LastSeen", "Tags"],
    )

    return CommandResults(
        outputs_prefix="Unit42.URL",
        outputs_key_field="Data",
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

    response = client.lookup_indicator("filehash_sha256", file_hash)

    response_data = extract_response_data(response)

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
    relationships = create_relationships(file_hash, FeedIndicatorType.File, response_data["tags"], create_relationships_flag)

    # Create context data
    context_data = create_context_data("Hash", file_hash, response_data)

    readable_output = tableToMarkdown(
        f"Unit 42 Intelligence results for File: {file_hash}",
        context_data,
        headers=["Hash", "Verdict", "VerdictCategory", "FirstSeen", "LastSeen", "Tags"],
    )

    return CommandResults(
        outputs_prefix="Unit42.File",
        outputs_key_field="Hash",
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
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    reliability = params.get("integration_reliability", "A - Completely reliable")
    create_relationships = params.get("create_relationships", True)

    # Add create_relationships to args for commands
    args["create_relationships"] = create_relationships

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(base_url=base_url, api_key=api_key, verify=verify_certificate, proxy=proxy, reliability=reliability)

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

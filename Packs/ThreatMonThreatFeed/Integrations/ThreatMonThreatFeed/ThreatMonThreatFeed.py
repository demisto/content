import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
from typing import Any

DEFAULT_BASE_URL = "https://ioc.threatmonit.io"
DEFAULT_LIMIT = 500
CREATE_INDICATORS_BATCH_SIZE = 2000
FEED_SOURCE_TAG = "ThreatMon"


class Client(BaseClient):
    """
    Client class to interact with the ThreatMon IOC API.
    """

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.api_token = api_token

    def get_daily_iocs(self, data_type: str = "all", size: int = DEFAULT_LIMIT, collection_ids: str = None) -> dict:
        """
        Fetches daily IOC details from the API.
        """
        params: dict[str, Any] = {"api_token": self.api_token, "data_type": data_type, "size": size}
        if collection_ids:
            params["collection_id"] = collection_ids

        return self._http_request(
            method="GET", url_suffix="/api/daily-ioc-details/", params=params, headers={"Accept": "application/json"}
        )


def strip_port(value: str) -> str:
    """
    Strips a trailing port from an indicator value while keeping IPv6 addresses intact.

    Handles the following forms:
    - ``[2001:db8::1]:443`` -> ``2001:db8::1``
    - ``1.2.3.4:8080``      -> ``1.2.3.4``
    - ``2001:db8::1``       -> ``2001:db8::1`` (unbracketed IPv6, left untouched)
    """
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    # Only strip when there is a single colon, i.e. an IPv4:port pair. Unbracketed
    # IPv6 addresses contain multiple colons and must not be split.
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value


def map_indicator_type(ioc_type: str) -> str | None:
    """
    Maps a ThreatMon ioc_type to an XSOAR FeedIndicatorType.

    Returns ``None`` when the ioc_type is missing or not recognized, so the caller can
    skip the indicator instead of ingesting it with an invalid type.
    """
    if ioc_type:
        ioc_type = ioc_type.lower()
        if "ip" in ioc_type:
            return FeedIndicatorType.IP
        elif "domain" in ioc_type:
            return FeedIndicatorType.Domain
        elif "url" in ioc_type:
            return FeedIndicatorType.URL
        elif "file" in ioc_type or "hash" in ioc_type:
            return FeedIndicatorType.File
    return None


def parse_indicator(ioc: dict, feed_tags: list, tlp_color: str | None) -> dict | None:
    """
    Parses a ThreatMon IOC object into an XSOAR indicator.

    Returns ``None`` when the indicator has no value or its type cannot be determined,
    so the caller can skip it instead of failing the whole fetch.
    """
    value = ioc.get("ioc_value")
    ioc_type = ioc.get("ioc_type", "")

    mapped_type = map_indicator_type(ioc_type)
    if not value or not mapped_type:
        return None

    # Prefer the extracted IP for IP indicators, to avoid a port number in the value.
    extracted_ip = ioc.get("extracted_ip")

    if mapped_type == FeedIndicatorType.IP:
        value = extracted_ip or value
        if value:
            value = strip_port(value)

    source = ioc.get("source") or []
    tags = ioc.get("tags") or []
    categories = ioc.get("categories") or []

    # Combine tags from the API and from the feed settings, removing duplicates.
    combined_tags = list(dict.fromkeys([t for t in (tags + categories + source + feed_tags) if t]))

    # Construct the description showing all metadata.
    description_parts = []
    if source:
        description_parts.append(f"Source: {', '.join(source) if isinstance(source, list) else source}")
    if ioc.get("confidence_level"):
        description_parts.append(f"Confidence Level: {ioc.get('confidence_level')}")
    if ioc.get("severity"):
        description_parts.append(f"Severity: {ioc.get('severity')}")
    if ioc.get("status"):
        description_parts.append(f"Status: {ioc.get('status')}")
    if ioc.get("isp"):
        description_parts.append(f"ISP: {ioc.get('isp')}")

    resolved_ips = ioc.get("resolved_ips")
    if resolved_ips:
        description_parts.append(f"Resolved IPs: {', '.join(resolved_ips)}")
    if categories:
        description_parts.append(f"Categories: {', '.join(categories)}")
    if tags:
        description_parts.append(f"Tags: {', '.join(tags)}")
    if ioc.get("timestamp"):
        description_parts.append(f"Timestamp: {ioc.get('timestamp')}")
    if ioc.get("score") is not None:
        description_parts.append(f"API Score: {ioc.get('score')}")

    description = "\n".join(description_parts)

    fields = {
        "tags": combined_tags,
        "description": description,
        "modified": ioc.get("updated_at") or ioc.get("timestamp") or ioc.get("created_at"),
        "confidence": ioc.get("confidence_level"),
        "threatseverity": ioc.get("severity"),
        "status": ioc.get("status"),
        "isp": ioc.get("isp"),
        "resolvedips": resolved_ips,
        "geolocation": ioc.get("geo_location"),
        "threat_score": ioc.get("score"),
        "threatscore": ioc.get("score"),
        "extractedip": extracted_ip,
        "extracted_ip": extracted_ip,
    }

    if tlp_color:
        fields["trafficlightprotocol"] = tlp_color

    return {
        "value": value,
        "type": mapped_type,
        "service": FEED_SOURCE_TAG,
        "rawJSON": ioc,
        "fields": fields,
    }


def calculate_verdict(feed_reputation: str) -> int:
    """
    Calculates the XSOAR DBot score based on the feedReputation setting.
    """
    mapping = {"Unknown": 0, "None": 0, "Benign": 1, "Good": 1, "Suspicious": 2, "Malicious": 3, "Bad": 3}
    return mapping.get(feed_reputation, 3)


def build_indicators(client: Any, params: dict, limit: int, last_timestamp: str | None = None) -> tuple[list, str | None]:
    """
    Fetches IOCs from the API and builds XSOAR indicators.

    Returns the list of indicators and the newest timestamp seen, so both the fetch and
    the get-indicators commands can share the same building logic.
    """
    data_type = params.get("data_type") or "all"
    tlp_color = params.get("tlp_color")
    feed_reputation = params.get("feedReputation") or "Bad"
    collection_ids = params.get("collection_ids")
    feed_tags = [FEED_SOURCE_TAG] + argToList(params.get("feedTags"))

    response = client.get_daily_iocs(data_type=data_type, size=limit, collection_ids=collection_ids)
    iocs = response.get("iocs", []) or []

    indicators = []
    latest_timestamp = last_timestamp

    for ioc in iocs:
        # Track the newest timestamp to skip previously fetched IOCs.
        ioc_timestamp = ioc.get("created_at") or ioc.get("timestamp") or ioc.get("updated_at")

        if last_timestamp and ioc_timestamp and ioc_timestamp <= last_timestamp:
            continue

        parsed = parse_indicator(ioc, feed_tags=feed_tags, tlp_color=tlp_color)
        if parsed:
            parsed["score"] = calculate_verdict(feed_reputation)
            indicators.append(parsed)

        if ioc_timestamp and (not latest_timestamp or ioc_timestamp > latest_timestamp):
            latest_timestamp = ioc_timestamp

    return indicators, latest_timestamp


def test_module(client: Any, params: dict) -> str:
    """
    Tests API connectivity and that a returned IOC can be parsed into an indicator.
    """
    try:
        data_type = params.get("data_type") or "all"
        response = client.get_daily_iocs(data_type=data_type, size=1)
        iocs = response.get("iocs", []) or []
        if iocs:
            # Exercise the indicator builder to make sure the response shape is understood.
            parse_indicator(iocs[0], feed_tags=[FEED_SOURCE_TAG], tlp_color=params.get("tlp_color"))
        return "ok"
    except Exception as e:
        return f"Test failed: {str(e)}"


def fetch_indicators_command(
    client: Any, params: dict, limit: int, last_run: dict
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Fetches indicators from the ThreatMon API for the feed fetch interval.
    """
    new_last_run = last_run.copy() if last_run else {}
    last_timestamp = new_last_run.get("last_timestamp")

    try:
        indicators, latest_timestamp = build_indicators(client, params, limit, last_timestamp)
        if latest_timestamp:
            new_last_run["last_timestamp"] = latest_timestamp
    except Exception as e:
        demisto.error(f"Error fetching indicators from ThreatMon: {str(e)}\n{traceback.format_exc()}")
        raise e

    return indicators, new_last_run


def get_indicators_command(client: Any, params: dict, args: dict) -> CommandResults:
    """
    Retrieves a sample of indicators from the feed to the war room, for testing and debugging.
    Does not create indicators in the system.
    """
    limit = arg_to_number(args.get("limit")) or 10
    indicators, _ = build_indicators(client, params, limit)
    indicators = indicators[:limit]

    if not indicators:
        return CommandResults(readable_output="### No indicators were found.")

    table = [
        {
            "Value": indicator.get("value"),
            "Type": indicator.get("type"),
            "Score": indicator.get("score"),
            "Tags": ", ".join(indicator.get("fields", {}).get("tags", [])),
        }
        for indicator in indicators
    ]
    human_readable = tableToMarkdown(f"Indicators from {FEED_SOURCE_TAG}:", table, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        raw_response=[indicator.get("rawJSON") for indicator in indicators],
    )


def main():
    params = demisto.params()
    base_url = (params.get("url") or "").strip() or DEFAULT_BASE_URL

    api_token = params.get("api_token") or params.get("credentials", {}).get("password")
    if not api_token:
        # Fallback to the credentials identifier if the token was placed there.
        api_token = params.get("credentials", {}).get("identifier")

    if not api_token:
        return_error("Missing API Token (api_token).")

    verify_cert = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    client = Client(base_url=base_url, api_token=api_token, verify=verify_cert, proxy=proxy)

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        if command == "test-module":
            return_results(test_module(client, params))

        elif command == "threatmon-get-indicators":
            return_results(get_indicators_command(client, params, demisto.args()))

        elif command == "fetch-indicators":
            last_run = demisto.getLastRun() or {}
            limit = arg_to_number(params.get("limit")) or arg_to_number(params.get("max_fetch")) or DEFAULT_LIMIT

            indicators, new_last_run = fetch_indicators_command(client, params, limit, last_run)

            # Send the indicators to XSOAR in batches to avoid overloading the server.
            for indicators_batch in batch(indicators, batch_size=CREATE_INDICATORS_BATCH_SIZE):
                demisto.createIndicators(indicators_batch)

            demisto.setLastRun(new_last_run)

        else:
            raise DemistoException(f"Unsupported command: {command}")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

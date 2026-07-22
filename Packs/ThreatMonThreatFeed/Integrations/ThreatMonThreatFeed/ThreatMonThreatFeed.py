import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client class to interact with ThreatMon IOC API
    """

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.api_token = api_token

    def get_daily_iocs(self, data_type: str = "all", size: int = 500, collection_ids: str = None) -> dict:
        """
        Fetches daily IOC details from the API
        """
        params = {"api_token": self.api_token, "data_type": data_type, "size": size}
        if collection_ids:
            params["collection_id"] = collection_ids

        return self._http_request(
            method="GET", url_suffix="/api/daily-ioc-details/", params=params, headers={"Accept": "application/json"}
        )


def map_indicator_type(ioc_type: str) -> str:
    """
    Maps ThreatMon ioc_type to XSOAR FeedIndicatorType
    """
    if not ioc_type:
        return FeedIndicatorType.Indicator
    ioc_type = ioc_type.lower()
    if "ip" in ioc_type:
        return FeedIndicatorType.IP
    elif "domain" in ioc_type:
        return FeedIndicatorType.Domain
    elif "url" in ioc_type:
        return FeedIndicatorType.URL
    elif "file" in ioc_type or "hash" in ioc_type:
        return FeedIndicatorType.File
    else:
        return FeedIndicatorType.Indicator


def parse_indicator(ioc: dict, feed_tags: list, tlp_color: str) -> dict:
    """
    Parses a ThreatMon IOC object into an XSOAR indicator format
    """
    value = ioc.get("ioc_value")
    ioc_type = ioc.get("ioc_type", "")
    mapped_type = map_indicator_type(ioc_type)

    # Use extracted_ip if it is an IP type indicator to avoid port number in value
    if mapped_type == FeedIndicatorType.IP:
        value = ioc.get("extracted_ip") or value
        if value and ":" in value:
            value = value.split(":")[0]

    source = ioc.get("source") or []
    tags = ioc.get("tags") or []
    categories = ioc.get("categories") or []

    # Combine tags from API and feed settings
    combined_tags = list(dict.fromkeys([t for t in (tags + categories + source + feed_tags) if t]))

    # Construct the description showing all metadata
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

    # Map fields
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
        "extractedip": ioc.get("extracted_ip"),
        "extracted_ip": ioc.get("extracted_ip"),
    }

    if tlp_color:
        fields["trafficlightprotocol"] = tlp_color

    return {"value": value, "type": mapped_type, "rawData": ioc, "fields": fields}


def calculate_verdict(feed_reputation: str) -> int:
    """
    Calculates the XSOAR DBotScore based on feedReputation setting
    """
    try:
        mapping = {"Unknown": 0, "None": 0, "Benign": 1, "Good": 1, "Suspicious": 2, "Malicious": 3, "Bad": 3}
        return mapping.get(feed_reputation, Common.DBotScore.MALICIOUS)
    except Exception:
        # Fallback if Common.DBotScore is not available in unit test context
        return 3


def test_module(client: Any, params: dict) -> str:
    """
    Tests API connectivity
    """
    try:
        data_type = params.get("data_type", "all")
        client.get_daily_iocs(data_type=data_type, size=1)
        return "ok"
    except Exception as e:
        return f"Test failed: {str(e)}"


def fetch_indicators_command(
    client: Any, params: dict, limit: int, last_run: dict
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Fetch indicators from ThreatMon API
    """
    data_type = params.get("data_type") or "all"
    tlp_color = params.get("tlp_color")
    feed_reputation = params.get("feedReputation", "Malicious")
    collection_ids = params.get("collection_ids")

    indicators = []
    new_last_run = last_run.copy() if last_run else {}
    last_timestamp = new_last_run.get("last_timestamp")

    try:
        response = client.get_daily_iocs(data_type=data_type, size=limit, collection_ids=collection_ids)
        iocs = response.get("iocs", []) or []

        latest_timestamp = last_timestamp

        for ioc in iocs:
            # We track the newest timestamp to skip previously fetched ones
            ioc_timestamp = ioc.get("created_at") or ioc.get("timestamp") or ioc.get("updated_at")

            if last_timestamp and ioc_timestamp and ioc_timestamp <= last_timestamp:
                continue

            parsed = parse_indicator(ioc, feed_tags=["ThreatMon"], tlp_color=tlp_color)
            if parsed:
                parsed["score"] = calculate_verdict(feed_reputation)
                indicators.append(parsed)

            if ioc_timestamp and (not latest_timestamp or ioc_timestamp > latest_timestamp):
                latest_timestamp = ioc_timestamp

        if latest_timestamp:
            new_last_run["last_timestamp"] = latest_timestamp

    except Exception as e:
        demisto.error(f"Error fetching indicators from ThreatMon: {str(e)}")
        raise e

    return indicators, new_last_run


def main():
    params = demisto.params()
    base_url = (params.get("url") or "").strip()
    if not base_url:
        base_url = "https://ioc.threatmonit.io"

    api_token = params.get("api_token") or params.get("credentials", {}).get("password")
    if not api_token:
        # Fallback to check credentials identifier if needed
        api_token = params.get("credentials", {}).get("identifier")

    if not api_token:
        return_error("Missing API Token (api_token).")

    verify_cert = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # Configure Client
    client = Client(base_url=base_url, api_token=api_token, verify=verify_cert, proxy=proxy)

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        if command == "test-module":
            return_results(test_module(client, params))

        elif command == "fetch-indicators":
            last_run = demisto.getLastRun() or {}
            limit = int(params.get("limit") or params.get("max_fetch") or 500)

            indicators, new_last_run = fetch_indicators_command(client, params, limit, last_run)

            # Send to XSOAR
            demisto.createIndicators(indicators)

            demisto.setLastRun(new_last_run)

        else:
            raise DemistoException(f"Unsupported command: {command}")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

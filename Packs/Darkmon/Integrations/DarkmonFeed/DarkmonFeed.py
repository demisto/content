"""Darkmon Feed integration - indicator firehose ingest.

Split out of the main Darkmon integration to match the Cortex content
convention: feed: true and isfetch: true live in separate integrations
within the same pack (see Anomali, RecordedFuture, ReversingLabs, etc.).

This module owns:
  - fetch-indicators (TIM feed pull, scheduled by feedFetchInterval)
  - darkmon-get-indicators (manual debug pull)
  - test-module (instance test)

The main Darkmon integration owns everything else (reputation,
dmontip-* automation, fetch-incidents).
"""

from typing import Any

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

VENDOR = "Darkmon"
DEFAULT_BASE_URL = "https://api.darkmon.com/tip/2025.1"
DEFAULT_SIZE = 20

# Map Darkmon API indicator-type strings to XSOAR FeedIndicatorType values
FEED_INDICATOR_TYPE_MAP = {
    "IP": FeedIndicatorType.IP,
    "Domain": FeedIndicatorType.Domain,
    "URL": FeedIndicatorType.URL,
    "Email": FeedIndicatorType.Email,
    "File": FeedIndicatorType.File,
    "Account": FeedIndicatorType.Account,
}


class Client(BaseClient):
    """Minimal Darkmon API client for the feed half.

    Mirrors only the methods needed by fetch-indicators and the debug
    darkmon-get-indicators command. Mirrors the auth + transport behavior
    of the main Darkmon integration's Client so a single API key works
    against both integrations.
    """

    def __init__(
        self, base_url: str, headers: dict, verify: bool = True, proxy: bool = False
    ):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def validate_api_key(self) -> bool:
        self._http_request("GET", url_suffix="/health", ok_codes=(200,))
        return True

    def get_indicators(self, size: int = DEFAULT_SIZE) -> dict:
        return self._http_request(
            "GET",
            url_suffix="/indicators",
            params={"size": size},
        )


def _apply_indicator_fields(item: dict, ioc_type: str, indicator_obj: dict) -> None:
    """Type-specific field population on the indicator."""
    fields = indicator_obj["fields"]
    if classification := item.get("classification"):
        fields["darkmonclassification"] = classification
    if sources := item.get("compromise_sources"):
        fields["darkmoncompromisesources"] = sources
    if first := item.get("first_compromise"):
        fields["darkmonfirstcompromise"] = first
    if last := item.get("last_compromise"):
        fields["darkmonlastcompromise"] = last
    if stealers := item.get("stealers"):
        fields["darkmonstealers"] = stealers


def test_module(client: Client) -> str:
    client.validate_api_key()
    return "ok"


def fetch_indicators_command(client: Client, params: dict) -> list[dict]:
    """TIM feed pull - returns indicator dicts XSOAR will ingest."""
    tlp_color = params.get("tlp_color")
    feed_tags = argToList(params.get("feedTags", ""))
    limit = arg_to_number(params.get("limit", DEFAULT_SIZE)) or DEFAULT_SIZE

    result = client.get_indicators(size=limit)
    ioc_objects = result.get("iocObjects", []) or []

    indicators: list[dict[str, Any]] = []
    for item in ioc_objects:
        ioc_type = item.get("type") or ""
        value = item.get("value")
        if not value:
            continue

        indicator_type = FEED_INDICATOR_TYPE_MAP.get(ioc_type, ioc_type)

        raw_data = {"value": value, "type": indicator_type, **item}
        indicator_obj: dict[str, Any] = {
            "value": value,
            "type": indicator_type,
            "service": VENDOR,
            "rawJSON": raw_data,
            "fields": {},
        }

        if event_info := item.get("eventInfo"):
            indicator_obj["fields"]["description"] = event_info
        if ts := item.get("timestamp"):
            indicator_obj["fields"]["firstseenbysource"] = ts
            indicator_obj["fields"]["lastseenbysource"] = ts

        _apply_indicator_fields(item, ioc_type, indicator_obj)

        if feed_tags:
            existing = indicator_obj["fields"].get("tags", [])
            indicator_obj["fields"]["tags"] = existing + feed_tags

        if tlp_color:
            indicator_obj["fields"]["trafficlightprotocol"] = tlp_color

        indicators.append(indicator_obj)

    return indicators


def darkmon_get_indicators_command(client: Client, args: dict) -> CommandResults:
    """Debug: fetch a page of indicators on demand."""
    limit = arg_to_number(args.get("limit", DEFAULT_SIZE)) or DEFAULT_SIZE
    raw = client.get_indicators(size=limit)
    iocs = raw.get("iocObjects", []) or []
    table = tableToMarkdown(
        f"{VENDOR} Indicators (page)",
        iocs,
        headers=["type", "value", "classification", "timestamp"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="Darkmon.Indicator",
        outputs_key_field="value",
        outputs=iocs,
        raw_response=raw,
        readable_output=table,
    )


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = (params.get("X-API-KEY") or {}).get("password")
    if not api_key:
        raise DemistoException("API key is required")

    base_url = (params.get("base_url") or DEFAULT_BASE_URL).rstrip("/")
    headers = {"X-API-KEY": api_key, "Accept": "application/json"}

    client = Client(
        base_url=base_url,
        headers=headers,
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
    )

    try:
        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-indicators":
            indicators = fetch_indicators_command(client, params)
            for batch_indicators in batch(indicators, batch_size=2000):
                demisto.createIndicators(batch_indicators)
        elif command == "darkmon-get-indicators":
            return_results(darkmon_get_indicators_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

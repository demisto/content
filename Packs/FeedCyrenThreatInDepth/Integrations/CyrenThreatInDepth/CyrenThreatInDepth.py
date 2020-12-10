import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from enum import Enum
from typing import Dict, List, Callable, Tuple
import traceback
import requests
import json

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


MAX_API_COUNT: int = 100000


class FeedPath(str, Enum):
    DATA = "data"
    INFO = "info"


class FeedName(str, Enum):
    IP_REPUTATION = "ip_reputation"
    PHISHING_URLS = "phishing_urls"
    MALWARE_URLS = "malware_urls"
    MALWARE_FILES = "malware_files"


class FeedAction(str, Enum):
    ADD = "+"
    UPDATE = "="
    REMOVE = "-"


class FeedCategory(str, Enum):
    SPAM = "spam"
    PHISHING = "phishing"
    MALWARE = "malware"
    CONFIRMED_CLEAN = "confirmed clean"


class FeedEntryBase(object):
    def __init__(self, entry: Dict, feed_name: str):
        self.entry = entry
        self.feed_name = feed_name
        self.payload = self.entry.get("payload", dict())
        self.detection = self.payload.get("detection", dict())
        self.categories = self.detection.get("category", [])

    def to_indicator_object(self) -> Dict:
        fields = dict(name=self.feed_name, tags=self.categories,
                      associations=self.payload.get("detection_methods", []),
                      firstseenbysource=self.payload.get("first_seen"),
                      lastseenbysource=self.payload.get("last_seen"))

        relationships = self.payload.get("relationships", [])
        if any(relationships):
            relationship_indicators = []
            for relationship in relationships:
                relationship_value = None
                relationship_type = "Indicator"
                if "sha256_hash" in relationship:
                    relationship_value = relationship["sha256_hash"]
                elif "ip" in relationship:
                    relationship_value = relationship["ip"]
                else:
                    continue
                relationship_indicators.append(dict(type=relationship_type,
                                                    value=relationship_value,
                                                    description=relationship.get("relationship_description", "")))
            fields["feedrelatedindicators"] = relationship_indicators

        return dict(value=self.get_value(),
                    type=self.get_type(),
                    rawJSON=self.entry,
                    score=self.get_score(),
                    fields=fields)

    def get_score(self) -> int:
        action = self.payload.get("action")
        if action in [FeedAction.ADD, FeedAction.UPDATE]:
            if FeedCategory.CONFIRMED_CLEAN in self.categories:
                return 0
            else:
                return 3

        if action == FeedAction.REMOVE:
            return 0

        # TODO good idea?
        return 3

    def get_offset(self) -> int:
        offset = self.entry.get("offset")
        if not offset:
            raise ValueError("expected an 'offset' field")

        return offset

    def get_type(self) -> str:
        raise NotImplementedError

    def get_value(self) -> str:
        raise NotImplementedError


class UrlFeedEntry(FeedEntryBase):
    def get_type(self) -> str:
        return FeedIndicatorType.URL

    def get_value(self) -> str:
        value = self.payload.get("url", "")
        value = value.rstrip("\n").rstrip("/")
        return value


class IpReputationFeedEntry(FeedEntryBase):
    def get_type(self) -> str:
        return FeedIndicatorType.IP

    def get_value(self) -> str:
        return self.payload.get("identifier")

    def get_score(self) -> int:
        action = self.payload.get("action")
        if action in [FeedAction.ADD, FeedAction.UPDATE]:
            if FeedCategory.SPAM in self.categories:
                return 3
            if FeedCategory.PHISHING in self.categories or FeedCategory.MALWARE in self.categories:
                return 2
            if FeedCategory.CONFIRMED_CLEAN in self.categories:
                return 0

        if action == FeedAction.REMOVE:
            return 0

        # TODO good idea?
        return 3


class MalwareFileFeedEntry(FeedEntryBase):
    def get_type(self) -> str:
        return FeedIndicatorType.File

    def get_value(self) -> str:
        return self.payload.get("identifier")


FEED_TO_ENTRY_CLASS: Dict[str, Callable] = {
    FeedName.IP_REPUTATION: IpReputationFeedEntry,
    FeedName.PHISHING_URLS: UrlFeedEntry,
    FeedName.MALWARE_URLS: UrlFeedEntry,
    FeedName.MALWARE_FILES: MalwareFileFeedEntry,
}


class Client(BaseClient):
    PARAMS = {"format": "jsonl"}

    def __init__(self, feed_name: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.feed_name = feed_name

    def _do_request(self, path: str, offset: int = -1, count: int = 0) -> requests.Response:
        params = self.PARAMS.copy()
        params["feedId"] = self.feed_name
        if offset > -1:
            params["offset"] = str(offset)
        if count > 0:
            params["count"] = str(count)

        demisto.info(f"using path {path}, params {params} for request")

        try:
            response = self._http_request(method="GET", url_suffix=path,
                                          params=params, resp_type="")
        except requests.ConnectionError as e:
            raise requests.ConnectionError(f"Failed to establish a new connection: {str(e)}")
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            demisto.error(f"exception in request: {response.status_code} {response.content!r} {path}")
            raise

        return response

    def fetch_entries(self, offset: int, count: int) -> List[Dict]:
        result = []
        response = self._do_request(path=FeedPath.DATA, offset=offset, count=count)

        for json_line in response.content.splitlines():
            try:
                result.append(json.loads(json_line))
            except json.JSONDecodeError as je:
                demisto.info(f"error while parsing single JSON feed line: {str(je)} {json_line!r}")
                continue

        return result

    def get_offsets(self) -> Dict[str, int]:
        response = self._do_request(path=FeedPath.INFO)
        try:
            return json.loads(response.content)
        except Exception as e:
            demisto.error(f"error while parsing JSON: {str(e)} {response.content!r}")
            raise


def test_module_command(client: Client) -> str:
    try:
        entries = client.fetch_entries(0, 10)
        if not any(entries):
            return "Test failed because no indicators could be fetched!"
    except Exception as e:
        return f"Test failed because of: {str(e)}!"

    return "ok"


def get_indicators_command(client: Client, args: Dict) -> Tuple[str, Dict, List]:
    max_indicators = int(args.get("max_indicators", 50))

    count = max_indicators
    end_offset = client.get_offsets().get("endOffset")
    if end_offset:
        offset = end_offset - max_indicators + 1
    else:
        offset = 0

    entries = client.fetch_entries(offset, count)
    indicators, _ = feed_entries_to_indicator(entries, client.feed_name)

    human_readable = tableToMarkdown("Indicators from Cyren Threat InDepth:", indicators,
                                     headers=["value", "type", "rawJSON", "score"])
    return human_readable, dict(), indicators


def feed_entries_to_indicator(entries: List[Dict], feed_name: str) -> Tuple[List[Dict], int]:
    indicators: List[Dict] = []
    max_offset: int = -1
    for entry in entries:
        entry_obj = FEED_TO_ENTRY_CLASS[feed_name](entry, feed_name)
        max_offset = max(entry_obj.get_offset() + 1, max_offset)
        indicators.append(entry_obj.to_indicator_object())

    return indicators, max_offset


def fetch_indicators_command(client: Client, initial_count: int, max_indicators: int, update_context: bool) -> List[Dict]:
    integration_context = demisto.getIntegrationContext()
    offset = integration_context.get("offset")
    count = max_indicators
    if not offset:
        offset = client.get_offsets().get("endOffset")
        if initial_count > 0:
            offset = offset - initial_count + 1
            count = max_indicators + initial_count

    count = min(MAX_API_COUNT, count)

    entries = client.fetch_entries(offset, count)
    demisto.info(f"pulled {len(entries)} for {client.feed_name}")
    indicators, max_offset = feed_entries_to_indicator(entries, client.feed_name)
    demisto.info(f"about to ingest {len(indicators)} for {client.feed_name}")

    if update_context:
        integration_context["offset"] = max_offset
        demisto.setIntegrationContext(integration_context)

    return indicators


def main():
    params = demisto.params()
    base_url = params.get("url", "https://api-feeds.cyren.com/v1/feed")
    api_token = params.get("apikey")
    feed_name = params.get("feed_name")
    max_indicators = int(params.get("max_indicators", MAX_API_COUNT))
    if max_indicators > MAX_API_COUNT:
        demisto.info(f"using a maximum value for max_indicators of {MAX_API_COUNT}!")
        max_indicators = MAX_API_COUNT
    proxy = params.get("proxy", False)
    verify_certificate = not params.get("insecure", False)

    headers = dict(Authorization=f"Bearer {api_token}")

    demisto.info(f"using feed {feed_name}, max {max_indicators}")

    client = Client(feed_name=feed_name,
                    base_url=base_url,
                    verify=verify_certificate,
                    headers=headers,
                    proxy=proxy)

    command = demisto.command()
    demisto.info(f"Command being called is {command}")
    commands: Dict[str, Callable] = {
        "cyren-threat-indepth-get-indicators": get_indicators_command,
    }
    try:
        if command == "fetch-indicators":
            indicators = fetch_indicators_command(client=client,
                                                  initial_count=0,
                                                  max_indicators=max_indicators,
                                                  update_context=True)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        elif command == "test-module":
            return_outputs(test_module_command(client))
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Error failed to execute {command}, error: [{e}]")


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

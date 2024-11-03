import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from enum import Enum
from collections.abc import Callable
import traceback
import requests
import json
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


MAX_API_COUNT: int = 100000
BASE_URL = "https://api-feeds.cyren.com/v1/feed"
VERSION = "1.5.0"
BAD_IP_RISK_BOUNDARY = 80


class FeedPath(str, Enum):
    DATA = "data"
    INFO = "info"


class FeedName(str, Enum):
    IP_REPUTATION = "ip_reputation"
    PHISHING_URLS = "phishing_urls"
    MALWARE_URLS = "malware_urls"
    MALWARE_FILES = "malware_files"


class RelationshipIndicatorType(str, Enum):
    IP = "IP"
    URL = "URL"
    SHA256 = "SHA-256"
    UNKNOWN = "UNKNOWN"


class FeedAction(str, Enum):
    ADD = "+"
    UPDATE = "="
    REMOVE = "-"

    def get_human_readable_name(self):
        name = str(self.name)
        return name.lower()


class FeedCategory(str, Enum):
    SPAM = "spam"
    PHISHING = "phishing"
    MALWARE = "malware"
    CONFIRMED_CLEAN = "confirmed clean"


class FeedSource(str, Enum):
    PRIMARY = "primary"
    RELATED = "related"


def get_relationship_value_type(relationship: dict) -> tuple[RelationshipIndicatorType, str, str]:
    related_entity_type = relationship.get("related_entity_type", "")
    relationship_value = relationship.get("related_entity_identifier", "")
    if related_entity_type == "file":
        return RelationshipIndicatorType.SHA256, relationship_value, FeedIndicatorType.File
    elif related_entity_type == "ip":
        return RelationshipIndicatorType.IP, relationship_value, FeedIndicatorType.IP

    return RelationshipIndicatorType.UNKNOWN, "", ""


class FeedEntryBase:
    def __init__(self, entry: dict, feed_name: str):
        self.entry = entry
        self.feed_name = feed_name
        self.payload = self.entry.get("payload", dict())
        self.meta = self.payload.get("meta", dict())
        self.detection = self.payload.get("detection", dict())
        self.categories = self.detection.get("category", [])
        self.action = FeedAction(self.payload.get("action"))
        self.relationships = self.payload.get("relationships", [])

    def to_indicator_objects(self) -> list[dict]:
        fields = self.get_fields()
        if any(self.relationships):
            relationship_indicators = []
            for relationship in self.relationships:
                relationship_type, relationship_value, _ = get_relationship_value_type(relationship)
                if not relationship_value:
                    continue

                relationship_indicators.append(dict(indicatortype=relationship_type.value,
                                                    relationshiptype=relationship.get("relationship_type", ""),
                                                    timestamp=relationship.get("relationship_ts"),
                                                    description=relationship.get("relationship_description", ""),
                                                    value=relationship_value,
                                                    entitycategory=relationship.get("related_entity_category", "")))
            fields["cyrenfeedrelationships"] = relationship_indicators

        raw_json = self.entry.copy()
        raw_json["source_tag"] = FeedSource.PRIMARY
        raw_json["tags"] = self.get_tags()
        primary = dict(value=self.get_value(), type=self.get_type(),
                       rawJSON=raw_json, score=self.get_score(),
                       fields=fields)

        indicators = self.get_indicators_from_relationships(primary)
        indicators.append(primary)
        return indicators

    def get_indicators_from_relationships(self, primary_indicator: dict) -> list[dict]:
        indicators = []
        for relationship in self.relationships:
            relationship_type, relationship_value, indicator_type = get_relationship_value_type(relationship)
            if not relationship_value:
                continue

            fields = dict(cyrenfeedrelationships=[dict(indicatortype=self.get_relationship_indicator_type().value,
                                                       relationshiptype=relationship.get("relationship_type"),
                                                       timestamp=relationship.get("relationship_ts"),
                                                       value=primary_indicator["value"],
                                                       entitycategory=relationship.get("related_entity_category"),
                                                       description=relationship.get("relationship_description"))])
            raw_json = dict(payload=relationship, source_tag=FeedSource.RELATED)
            indicators.append(dict(value=relationship_value,
                                   type=indicator_type,
                                   rawJSON=raw_json,
                                   score=self.get_relationship_score(primary_indicator, relationship),
                                   fields=fields))

        return indicators

    def get_score(self) -> int:
        if self.action in [FeedAction.ADD, FeedAction.UPDATE]:
            if FeedCategory.CONFIRMED_CLEAN in self.categories:
                return Common.DBotScore.NONE
            else:
                return Common.DBotScore.BAD

        if self.action == FeedAction.REMOVE:
            return Common.DBotScore.NONE

        return Common.DBotScore.BAD

    def get_relationship_score(self, primary_indicator: dict, relationship: dict) -> int:
        return Common.DBotScore.NONE

    def get_tags(self) -> list:
        detection_methods = self.payload.get("detection_methods", [])
        return self.categories + detection_methods

    def get_fields(self) -> dict:
        timestamp = self.entry.get("timestamp")
        fields = dict(updateddate=timestamp,
                      indicatoridentification=self.payload.get("identifier"))

        if self.action == FeedAction.ADD:
            fields["published"] = timestamp

        return fields

    def get_offset(self) -> int:
        offset = self.entry.get("offset")
        if not offset:
            raise ValueError("expected an 'offset' field")

        return offset

    def get_type(self) -> str:
        raise NotImplementedError

    def get_value(self) -> str:
        raise NotImplementedError

    def get_relationship_indicator_type(self) -> RelationshipIndicatorType:
        raise NotImplementedError


class UrlFeedEntry(FeedEntryBase):
    def get_type(self) -> str:
        return FeedIndicatorType.URL

    def get_value(self) -> str:
        value = self.payload.get("url", "")
        value = value.rstrip("\n").rstrip("/")
        return value

    def get_tags(self) -> list:
        industries = self.detection.get("industry", [])
        brands = self.detection.get("brand", [])
        return super().get_tags() + industries + brands

    def get_relationship_indicator_type(self) -> RelationshipIndicatorType:
        return RelationshipIndicatorType.URL


class MalwareUrlFeedEntry(UrlFeedEntry):
    def get_relationship_score(self, primary_indicator: dict, relationship: dict) -> int:
        if primary_indicator["score"] < 2 or relationship.get("related_entity_type") != "file":
            return super().get_relationship_score(primary_indicator, relationship)

        return primary_indicator["score"]


class IpReputationFeedEntry(FeedEntryBase):
    def get_type(self) -> str:
        return FeedIndicatorType.IP

    def get_value(self) -> str:
        return self.payload.get("identifier")

    def get_score(self) -> int:
        if self.action in [FeedAction.ADD, FeedAction.UPDATE]:
            if FeedCategory.SPAM in self.categories:
                risk = self.detection.get("risk", 0)
                if risk >= BAD_IP_RISK_BOUNDARY:
                    return Common.DBotScore.BAD
                return Common.DBotScore.SUSPICIOUS
            if FeedCategory.PHISHING in self.categories or FeedCategory.MALWARE in self.categories:
                return Common.DBotScore.SUSPICIOUS
            if FeedCategory.CONFIRMED_CLEAN in self.categories:
                return Common.DBotScore.NONE

        if self.action == FeedAction.REMOVE:
            return Common.DBotScore.NONE

        return Common.DBotScore.BAD

    def get_relationship_indicator_type(self) -> RelationshipIndicatorType:
        return RelationshipIndicatorType.IP


class MalwareFileFeedEntry(FeedEntryBase):
    def get_type(self) -> str:
        return FeedIndicatorType.File

    def get_value(self) -> str:
        return self.payload.get("identifier")

    def get_tags(self) -> list:
        family_names = self.detection.get("family_name", [])
        return super().get_tags() + family_names

    def get_relationship_indicator_type(self) -> RelationshipIndicatorType:
        return RelationshipIndicatorType.SHA256


FEED_TO_ENTRY_CLASS: dict[str, Callable] = {
    FeedName.IP_REPUTATION: IpReputationFeedEntry,
    FeedName.PHISHING_URLS: UrlFeedEntry,
    FeedName.MALWARE_URLS: MalwareUrlFeedEntry,
    FeedName.MALWARE_FILES: MalwareFileFeedEntry,
}


FEED_TO_VERSION: dict[str, str] = {
    FeedName.IP_REPUTATION: "_v2",
    FeedName.PHISHING_URLS: "_v2",
    FeedName.MALWARE_URLS: "_v2",
    FeedName.MALWARE_FILES: "_v2",
}


FEED_OPTION_TO_FEED: dict[str, str] = {
    "IP Reputation": FeedName.IP_REPUTATION,
    "Phishing URLs": FeedName.PHISHING_URLS,
    "Malware URLs": FeedName.MALWARE_URLS,
    "Malware Hashes": FeedName.MALWARE_FILES,
}


class InvalidAPITokenException(Exception):
    pass


class InvalidAPIUrlException(Exception):
    pass


class Client(BaseClient):
    PARAMS = {"format": "jsonl"}
    INVALID_TOKEN_TEXTS = [
        "unable to parse claims from token",
        "unable to parse token from header",
        "token was revoked",
        "claims are invalid",
    ]

    def __init__(self, feed_name: str, api_token: str, *args, **kwargs):
        if not feed_name:
            raise ValueError("please specify a correct feed name")

        super().__init__(*args, **kwargs)
        self.feed_name = feed_name
        self.request_headers = {
            "Authorization": f"Bearer {api_token}",
            "Cyren-Client-Name": "Palo Alto Cortex XSOAR",
            "Cyren-Client-Version": VERSION,
        }

    def _is_invalid_token(self, response: requests.Response) -> bool:
        if response.status_code != 400:
            return False

        for invalid_text in self.INVALID_TOKEN_TEXTS:
            if invalid_text in response.text:
                return True

        return False

    def _do_request(self, path: str, offset: int = -1, count: int = 0) -> requests.Response:
        params = self.PARAMS.copy()
        params["feedId"] = f"{self.feed_name}{FEED_TO_VERSION[self.feed_name]}"
        if offset > -1:
            params["offset"] = str(offset)
        if count > 0:
            params["count"] = str(count)

        demisto.debug(f"using path {path}, params {params} for request")

        try:
            response = self._http_request(method="GET", url_suffix=path,
                                          headers=self.request_headers,
                                          params=params, resp_type="",
                                          ok_codes=[200, 204, 201, 400, 404])
        except requests.ConnectionError as e:
            raise requests.ConnectionError(f"Failed to establish a new connection: {str(e)}")

        if self._is_invalid_token(response):
            raise InvalidAPITokenException

        if response.status_code == 404:
            raise InvalidAPIUrlException

        response.raise_for_status()

        return response

    def fetch_entries(self, offset: int, count: int) -> list[dict]:
        result = []
        response = self._do_request(path=FeedPath.DATA, offset=offset, count=count)

        for json_line in response.content.splitlines():
            try:
                result.append(json.loads(json_line))
            except json.JSONDecodeError as je:
                demisto.info(f"error while parsing single JSON feed line: {str(je)} {json_line!r}")
                continue

        return result

    def get_offsets(self) -> dict[str, int]:
        response = self._do_request(path=FeedPath.INFO)
        try:
            return json.loads(response.content)
        except Exception as e:
            demisto.error(f"error while parsing JSON: {str(e)} {response.content!r}")
            raise


def store_offset_in_context(offset: int) -> int:
    integration_context = get_integration_context()
    integration_context["offset"] = offset
    set_integration_context(integration_context)
    return offset


def get_offset_from_context() -> int:
    integration_context = get_integration_context()
    return integration_context.get("offset")


def test_module_command(client: Client) -> str:
    try:
        entries = client.fetch_entries(0, 10)
        if not any(entries):
            return "Test failed because no indicators could be fetched!"
    except InvalidAPITokenException:
        return "Test failed because of an invalid API token!"
    except InvalidAPIUrlException:
        return "Test failed because of an invalid API URL!"
    except Exception as e:
        return f"Test failed because of: {str(e)}!"

    return "ok"


def get_indicators_command(client: Client, args: dict) -> CommandResults:
    max_indicators = int(args.get("max_indicators", 50))

    count = max_indicators
    end_offset = client.get_offsets().get("endOffset")
    if end_offset:
        offset = max(end_offset - max_indicators + 1, 0)
    else:
        offset = 0

    entries = client.fetch_entries(offset, count)
    indicators, _ = feed_entries_to_indicator(entries, client.feed_name)

    human_readable = tableToMarkdown("Indicators from Cyren Threat InDepth:", indicators,
                                     headers=["value", "type", "rawJSON", "score"])
    return CommandResults(readable_output=human_readable,
                          raw_response=indicators)


def reset_offset_command(client: Client, args: dict) -> CommandResults:
    offset = int(args.get("offset", -1))
    offset_stored = get_offset_from_context()
    offset_api = int(client.get_offsets().get("endOffset", -1))
    if offset < 0 or offset > offset_api:
        offset = offset_api

    store_offset_in_context(offset)

    offset_stored_text = offset_stored or "not set before"
    readable_output = (
        f"Reset Cyren Threat InDepth {client.feed_name} feed client offset to {offset} "
        f"(API provided max offset of {offset_api}, was {offset_stored_text})."
    )
    return CommandResults(readable_output=readable_output, raw_response=offset)


def get_offset_command(client: Client, args: dict) -> CommandResults:
    offset_stored = get_offset_from_context()
    offset_api = int(client.get_offsets().get("endOffset", -1))
    offset_api_text = f"(API provided max offset of {offset_api})"
    if offset_stored:
        readable_output = (
            f"Cyren Threat InDepth {client.feed_name} feed client offset is {offset_stored} "
            f"{offset_api_text}."
        )
    else:
        readable_output = (
            f"Cyren Threat InDepth {client.feed_name} feed client offset has not been set yet "
            f"{offset_api_text}."
        )
    return CommandResults(readable_output=readable_output, raw_response=offset_stored)


def feed_entries_to_indicator(entries: list[dict], feed_name: str) -> tuple[list[dict], int]:
    indicators: list[dict] = []
    max_offset: int = -1
    for entry in entries:
        entry_obj = FEED_TO_ENTRY_CLASS[feed_name](entry, feed_name)
        max_offset = max(entry_obj.get_offset() + 1, max_offset)
        indicators = indicators + entry_obj.to_indicator_objects()

    return indicators, max_offset


def fetch_indicators_command(client: Client, initial_count: int, max_indicators: int, update_context: bool) -> list[dict]:
    offset = get_offset_from_context()
    count = max_indicators
    if not offset:
        offset = int(client.get_offsets().get("endOffset", -1))
        if initial_count > 0:
            offset = offset - initial_count + 1
            count = max_indicators + initial_count

    count = min(MAX_API_COUNT, count)

    entries = client.fetch_entries(offset, count)
    demisto.debug(f"pulled {len(entries)} for {client.feed_name}")
    indicators, max_offset = feed_entries_to_indicator(entries, client.feed_name)
    demisto.debug(f"about to ingest {len(indicators)} for {client.feed_name}")

    if update_context:
        store_offset_in_context(max_offset)

    return indicators


def main():
    params = demisto.params()
    api_token = params.get("apikey")

    feed_name = params.get("feed_name")
    feed_name = FEED_OPTION_TO_FEED.get(feed_name, "")

    max_indicators = int(params.get("max_indicators", MAX_API_COUNT))
    if max_indicators > MAX_API_COUNT:
        demisto.info(f"using a maximum value for max_indicators of {MAX_API_COUNT} instead of {max_indicators}!")
        max_indicators = MAX_API_COUNT

    proxy = params.get("proxy", False)
    verify_certificate = not params.get("insecure", False)

    demisto.info(f"using feed {feed_name}, max {max_indicators}")
    commands: dict[str, Callable] = {
        "cyren-threat-indepth-get-indicators": get_indicators_command,
        "cyren-threat-indepth-reset-client-offset": reset_offset_command,
        "cyren-threat-indepth-get-client-offset": get_offset_command,
    }

    command = demisto.command()
    demisto.info(f"Command being called is {command}")

    error = None
    try:
        client = Client(feed_name=feed_name,
                        base_url=BASE_URL,
                        verify=verify_certificate,
                        api_token=api_token,
                        proxy=proxy)

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
            return_results(commands[command](client, demisto.args()))
    except InvalidAPITokenException:
        error = "Invalid API token!"
    except InvalidAPIUrlException:
        error = "Invalid API URL!"
    except Exception as e:
        demisto.error(traceback.format_exc())
        error = f"Error failed to execute {command}, error: [{e}]"

    if error:
        return_error(error)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

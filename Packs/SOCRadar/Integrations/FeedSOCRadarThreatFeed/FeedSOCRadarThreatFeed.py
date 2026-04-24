import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import traceback
import urllib3
from json.decoder import JSONDecodeError

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


""" CONSTANTS """

SOCRADAR_API_ENDPOINT = "https://platform.socradar.com/api"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # XSOAR default in ISO8601 format
SOCRADAR_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_INDICATOR_FETCH_NUMBER = 1000
API_VERSION = "2"

MESSAGES: dict[str, str] = {
    "BAD_REQUEST_ERROR": "An error occurred while fetching the data.",
    "AUTHORIZATION_ERROR": "Authorization Error: make sure API Key is correctly set.",
    "RATE_LIMIT_EXCEED_ERROR": "Rate limit has been exceeded. Please make sure your API key's rate limit is adequate.",
}

INTEGRATION_NAME = "Feed SOCRadar ThreatFeed"


""" HELPER FUNCTIONS """


def parse_int_or_raise(str_to_parse: Any, error_msg=None) -> int:
    """Parse a string to integer. Raise ValueError exception if fails with given error_msg."""
    try:
        res = int(str_to_parse)
    except (TypeError, ValueError):
        if not error_msg:
            error_msg = f"Error while parsing integer! Provided string: {str_to_parse}"
        raise ValueError(error_msg)
    return res


def build_entry_context(indicators: Union[dict, List]) -> list[dict]:
    """Formatting indicators from SOCRadar Threat Feed/IOC API to Demisto Context.

    :type indicators: ``Union[Dict, List]``
    :param indicators: Indicators obtained from SOCRadar Threat Feed/IOC API.

    :return: List of context entry dictionaries.
    :rtype: ``list``
    """
    return_context = []

    for indicator_dict in indicators:
        indicator = indicator_dict.get("value", "")
        indicator_type = indicator_dict.get("type", "")
        indicator_context_dict = {
            "Indicator": indicator,
            "IndicatorType": indicator_type,
            "rawJSON": indicator_dict.get("rawJSON", {}),
            "FirstSeenDate": indicator_dict.get("fields", {}).get("firstseenbysource", ""),
            "LastSeenDate": indicator_dict.get("fields", {}).get("lastseenbysource", ""),
            "FeedMaintainerName": indicator_dict["fields"].get("collection_maintainer_name", ""),
            "SeenCount": indicator_dict["fields"].get("extra_info", {}).get("seen_count", 1),
            "Score": indicator_dict["fields"].get("extra_info", {}).get("score", 0),
        }

        if indicator_type == FeedIndicatorType.IP and indicator_dict["fields"].get("extra_info", {}).get("geo_location", []):
            geo_location_dict = indicator_dict["fields"]["extra_info"]["geo_location"]
            asn_code = geo_location_dict.get("AsnCode", "")
            asn_description = geo_location_dict.get("AsnName", "")
            asn = f"[{asn_code}] {asn_description}"
            geo_location_dict["ASN"] = asn
            geo_location_dict = {
                key: value for key, value in geo_location_dict.items() if key.lower() not in ("ip", "asncode", "asnname")
            }
            indicator_context_dict["GeoLocation"] = geo_location_dict

        return_context.append(indicator_context_dict)
    return return_context


def date_string_to_iso_format_parsing(date_str: str) -> Optional[str]:
    """Formats a datestring to the ISO-8601 format which the server expects to receive.

    :type date_str: ``str``
    :param date_str: String representation of the date.

    :return: ISO-8601 date string
    :rtype: ``str``
    """
    if not date_str:
        return None
    parsed_date_format = dateparser.parse(date_str, date_formats=[SOCRADAR_DATE_FORMAT], settings={"TIMEZONE": "UTC"})
    if parsed_date_format is None:
        demisto.debug(f"Could not parse date: {date_str}")
        return None
    return parsed_date_format.strftime(DATE_FORMAT)


def convert_to_demisto_indicator_type(socradar_indicator_type: str, indicator_value: str = None) -> str:
    """Maps SOCRadar indicator type to Cortex XSOAR indicator type.

    Converts the SOCRadar indicator types ('hostname', 'domain', 'url', 'ip', 'hash') to Cortex XSOAR indicator type
    (Domain, URL, IP, File) for mapping.

    :type socradar_indicator_type: ``str``
    :param socradar_indicator_type: indicator type as returned from the SOCRadar API (str)

    :type indicator_value: ``str``
    :param indicator_value: indicator itself (default None)

    :return: Cortex XSOAR Indicator Type (Domain, URL, IP, IPv6, File)
    :rtype: ``str``
    """
    indicator_type_mapping = {
        "hostname": FeedIndicatorType.Domain,
        "domain": FeedIndicatorType.Domain,
        "url": FeedIndicatorType.URL,
        "ip": (FeedIndicatorType.ip_to_indicator_type(indicator_value) if indicator_value else FeedIndicatorType.IP),
        "hash": FeedIndicatorType.File,
    }
    return indicator_type_mapping.get(socradar_indicator_type)


""" CLIENT CLASS """


class Client(ContentClient):
    """Client class to interact with SOCRadar Collection Based IOC Feed API."""

    def __init__(self, base_url, api_key, tags, tlp_color, verify, proxy):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.api_key = api_key
        self.tags = tags
        self.tlp_color = tlp_color

    def get_collection_feed(self, collection_uuid: str, response_format: str = "json") -> list:
        """Retrieve IOC feed for a specific collection UUID.

        :type collection_uuid: ``str``
        :param collection_uuid: UUID of the collection to fetch.

        :type response_format: ``str``
        :param response_format: Response format (json, csv, raw). Default is json.

        :return: List of IOC indicator dictionaries.
        :rtype: ``list``
        """
        suffix = f"/threat/intelligence/feed_list/{collection_uuid}.{response_format}"
        api_params = {
            "key": self.api_key,
            "v": API_VERSION,
        }
        response = self._http_request(
            method="GET",
            url_suffix=suffix,
            params=api_params,
            timeout=120,
            error_handler=self.handle_error_response,
        )
        return response

    def check_auth(self):
        """Check authentication status of the API key."""
        suffix = "/threat/intelligence/check/auth"
        api_params = {"key": self.api_key}
        response = self._http_request(
            method="GET",
            url_suffix=suffix,
            params=api_params,
            error_handler=self.handle_error_response,
        )
        return response

    def parse_raw_indicators(self, raw_indicators: list) -> list:
        """Creates a list of indicators from a given API response.

        :type raw_indicators: ``list``
        :param raw_indicators: List of dict that represent the response from the API.

        :return: List of indicators with the correct indicator type.
        :rtype: ``list``
        """
        parsed_indicators = []

        for indicator_dict in raw_indicators:
            if not indicator_dict:
                continue

            indicator = indicator_dict.get("feed", "")
            feed_type = indicator_dict.get("feed_type", "")

            indicator_type = convert_to_demisto_indicator_type(feed_type, indicator)
            if not indicator_type:
                indicator_type = auto_detect_indicator_type(indicator)

            first_seen_date = indicator_dict.get("first_seen_date", "")
            last_seen_date = indicator_dict.get("latest_seen_date", "")
            maintainer_name = indicator_dict.get("maintainer_name", "")
            extra_info = indicator_dict.get("extra_info", {})

            indicator_obj = {
                "type": indicator_type,
                "value": indicator,
                "rawJSON": {"value": indicator, "type": indicator_type},
                "fields": {
                    "firstseenbysource": date_string_to_iso_format_parsing(first_seen_date),
                    "lastseenbysource": date_string_to_iso_format_parsing(last_seen_date),
                    "collection_maintainer_name": maintainer_name,
                    "extra_info": extra_info,
                },
            }
            if self.tags:
                indicator_obj["fields"]["tags"] = self.tags

            if self.tlp_color:
                indicator_obj["fields"]["trafficlightprotocol"] = self.tlp_color

            parsed_indicators.append(indicator_obj)

        return parsed_indicators

    def build_iterator(self, collection_uuid: str, limit: int = None) -> list:
        """Builds a list of indicators for a specific collection UUID.

        :type collection_uuid: ``str``
        :param collection_uuid: The UUID of the collection to fetch indicators from.

        :type limit: ``int``
        :param limit: Maximum number of indicators to fetch. None means fetch all.

        :return: A list of JSON objects representing indicators fetched from a feed.
        :rtype: ``list``
        """
        try:
            raw_response = self.get_collection_feed(collection_uuid)

            if not isinstance(raw_response, list):
                demisto.debug(f"Unexpected response format for collection {collection_uuid}: {type(raw_response)}")
                return []

            parsed_indicators = self.parse_raw_indicators(raw_response)

            if limit is not None:
                parsed_indicators = parsed_indicators[:limit]

            return parsed_indicators

        except DemistoException as e:
            demisto.debug(f"Error while getting indicators for collection {collection_uuid}. Error: {e!s}")
            return []

    @staticmethod
    def handle_error_response(response) -> None:
        """Handles API response to display descriptive error messages based on status code.

        :param response: SOCRadar API response.
        :return: DemistoException for particular error code.
        """
        error_reason = ""
        try:
            json_resp = response.json()
            error_reason = json_resp.get("error") or json_resp.get("message")
        except JSONDecodeError:
            pass

        status_code_messages = {
            400: f"{MESSAGES['BAD_REQUEST_ERROR']} Reason: {error_reason}",
            401: MESSAGES["AUTHORIZATION_ERROR"],
            404: f"{MESSAGES['BAD_REQUEST_ERROR']} Reason: {error_reason}",
            429: MESSAGES["RATE_LIMIT_EXCEED_ERROR"],
        }

        if response.status_code in status_code_messages:
            demisto.debug(f"Response Code: {response.status_code}, Reason: {status_code_messages[response.status_code]}")
            raise DemistoException(status_code_messages[response.status_code])
        else:
            try:
                response.raise_for_status()
            except Exception as e:
                raise DemistoException(f"Error in API call [{response.status_code}] - {response.text}\n{e}")


""" COMMAND FUNCTIONS """


def test_module(client: Client, collection_uuids: list) -> str:
    """Tests by checking authentication and attempting to fetch from the first collection.

    :type client: ``Client``
    :param client: client to use

    :type collection_uuids: ``list``
    :param collection_uuids: Collection UUID list to fetch indicators from SOCRadar.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    client.check_auth()
    if collection_uuids:
        # Test with first collection UUID, limit 1 indicator
        client.build_iterator(collection_uuids[0], limit=1)
    return "ok"


def get_indicators_command(client: Client, args: dict[str, str]) -> CommandResults:
    """Retrieves indicators from the feed to the war-room.

    :type client: ``Client``
    :param client: Client object configured according to instance arguments.

    :type args: ``Dict[str, Any]``
    :param args: Contains all arguments for socradar-get-indicators command.

    :return: A ``CommandResults`` object that is then passed to ``return_results``.
    :rtype: ``CommandResults``
    """
    limit = parse_int_or_raise(args.get("limit", 10))
    collection_uuids = argToList(args.get("collection_uuids"))

    indicators = fetch_indicators(client, collection_uuids, limit)
    context_entry = build_entry_context(indicators)

    human_readable = tableToMarkdown(
        f"Indicators from SOCRadar Collection Based IOC Feed ({', '.join(collection_uuids)}):",
        context_entry,
        removeNull=True,
    )

    command_results = CommandResults(
        outputs_prefix="SOCRadarThreatFeed.Indicators",
        outputs_key_field="value",
        outputs=context_entry,
        readable_output=human_readable,
        raw_response=indicators,
    )
    return command_results


def fetch_indicators(client: Client, collection_uuids: list, limit: int = None) -> list[dict]:
    """Retrieves indicators from all configured collection UUIDs.

    :type client: ``Client``
    :param client: Client object configured according to instance arguments.

    :type collection_uuids: ``list``
    :param collection_uuids: Collection UUID list to fetch indicators from SOCRadar.

    :type limit: ``int``
    :param limit: Maximum number of indicators to fetch.

    :return: Fetched indicators list.
    :rtype: ``list[Dict]``
    """
    indicators: list[dict] = []
    for collection_uuid in collection_uuids:
        collection_uuid = collection_uuid.strip()
        if not collection_uuid:
            continue
        remaining_limit = None
        if limit is not None:
            remaining_limit = limit - len(indicators)
            if remaining_limit <= 0:
                break
        collection_indicators = client.build_iterator(collection_uuid, remaining_limit)
        indicators.extend(collection_indicators)

    if limit is not None:
        indicators = indicators[:limit]

    return indicators


def reset_last_fetch_dict() -> CommandResults:
    """Reset the last fetch from the integration context.

    :return: A ``CommandResults`` object that is then passed to ``return_results``.
    :rtype: ``CommandResults``
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output="Fetch history has been successfully deleted!")


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions."""
    params = demisto.params()
    args = demisto.args()
    api_key = params.get("apikey")
    base_url = SOCRADAR_API_ENDPOINT
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    feed_tags = argToList(params.get("feedTags"))
    tlp_color = params.get("tlp_color")
    collection_uuids = argToList(params.get("collection_uuids"))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            tags=feed_tags,
            tlp_color=tlp_color,
            verify=verify_certificate,
            proxy=proxy,
        )
        if command == "test-module":
            return_results(test_module(client, collection_uuids))
        elif command == "fetch-indicators":
            indicators = fetch_indicators(client, collection_uuids)
            # Submit indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)  # type: ignore
        elif command == "socradar-get-indicators":
            return_results(get_indicators_command(client, args))
        elif command == "socradar-reset-fetch-indicators":
            return_results(reset_last_fetch_dict())

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

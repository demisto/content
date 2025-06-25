import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
DEFAULT_MALICIOUS_THRESHOLD = 65
DEFAULT_SUSPICIOUS_THRESHOLD = 25
DEFAULT_BENIGN_THRESHOLD = 0
THREAT_STREAM = "Anomali ThreatStream Feed"
RETRY_COUNT = 2
LIMIT_RES_FROM_API = 1000
INDICATOR_STATUS = "active"
URL_SUFFIX = "v2/intelligence"
DEFAULT_CONFIDENCE_THRESHOLD = 65
DEFAULT_FEED_FETCH_INTERVAL = 240
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

INDICATOR_TYPE = {
    "domain": FeedIndicatorType.Domain,
    "ip": FeedIndicatorType.IP,
    "md5": FeedIndicatorType.File,
    "url": FeedIndicatorType.URL,
    "email": FeedIndicatorType.Email,
}

INDICATOR_TYPE_UPPER = {
    "domain": "Domain",
    "ip": "IP",
    "md5": "MD5",
    "url": "URL",
    "email": "Email",
}

RELATIONSHIPS_MAPPING = {
    "ip": [
        {"name": EntityRelationship.Relationships.RESOLVES_TO, "raw_field": "rdns", "entity_b_type": FeedIndicatorType.Domain},
        {"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"},
    ],
    "domain": [
        {"name": EntityRelationship.Relationships.RESOLVED_FROM, "raw_field": "ip", "entity_b_type": FeedIndicatorType.IP},
        {"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"},
    ],
    "url": [
        {"name": EntityRelationship.Relationships.RESOLVED_FROM, "raw_field": "ip", "entity_b_type": FeedIndicatorType.IP},
        {"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"},
    ],
    "md5": [{"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"}],
    "email": [{"name": EntityRelationship.Relationships.INDICATOR_OF, "raw_field": "meta.maltype", "entity_b_type": "Malware"}],
}

""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client to use in the Anomali ThreatStream Feed integration. Overrides BaseClient
    """

    def __init__(self, base_url, user_name, api_key, verify):
        super().__init__(base_url=base_url, verify=verify, ok_codes=(200, 201, 202))
        self.credentials = {
            "Authorization": f"apikey {user_name}:{api_key}",
        }

    def http_request(
        self,
        method,
        url_suffix,
        params=None,
        data=None,
        headers=None,
        files=None,
        json=None,
        without_credentials=False,
        resp_type="json",
    ):
        """
        A wrapper for requests lib to send our requests and handle requests and responses better.
        """
        headers = headers or {}
        if not without_credentials:
            headers.update(self.credentials)
        res = super()._http_request(
            method=method,
            url_suffix=url_suffix,
            headers=headers,
            params=params,
            data=data,
            json_data=json,
            files=files,
            resp_type=resp_type,
            error_handler=self.error_handler,
            retries=RETRY_COUNT,
        )
        return res

    def error_handler(self, res: requests.Response):  # pragma: no cover
        """
        Error handler to call by super()._http_request in case an error was occurred.
        Handles specific HTTP status codes and raises a DemistoException.

        Args:
            res (requests.Response): The HTTP response object.
        """
        # Handle error responses gracefully
        if res.status_code == 401:
            raise DemistoException(f"{THREAT_STREAM} - Got unauthorized from the server. Check the credentials. {res.text}")
        elif res.status_code == 204:
            return
        elif res.status_code == 404:
            raise DemistoException(f"{THREAT_STREAM} - The resource was not found. {res.text}")
        raise DemistoException(f"{THREAT_STREAM} - Error in API call {res.status_code} - {res.text}")


class DBotScoreCalculator:
    """
    Class for DBot score calculation based on thresholds and confidence.
    It supports instance-defined thresholds per indicator type or default thresholds.
    """

    def calculate_score(self, indicator):
        """
        Calculates the DBot score according to the indicator's confidence.

        Args:
            indicator (dict[str, Any]): The raw indicator dictionary from the API response.

        Returns:
            int: The calculated DBot score (Common.DBotScore.NONE, GOOD, SUSPICIOUS, BAD).
        """
        confidence = arg_to_number(indicator.get("confidence", None))
        if not confidence:
            demisto.debug(f"{THREAT_STREAM} - Confidence not found for indicator. Assigning default score.")
            return Common.DBotScore.NONE

        else:
            if confidence > DEFAULT_MALICIOUS_THRESHOLD:
                return Common.DBotScore.BAD
            if confidence > DEFAULT_SUSPICIOUS_THRESHOLD:
                return Common.DBotScore.SUSPICIOUS
            if confidence > DEFAULT_BENIGN_THRESHOLD:
                return Common.DBotScore.GOOD
            else:
                return Common.DBotScore.NONE


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication.

    Args:
        client (Client): The client object to use for API requests.

    Returns:
        str: 'ok' if the test passed, otherwise raises an exception.
    """

    client.http_request("GET", f"{URL_SUFFIX}/", params={"limit": 1})
    return "ok"


def handle_get_pagination(client: Client, initial_response: dict[str, Any], initial_limit: int) -> list[dict[str, Any]]:
    """
    Handles pagination for retrieving indicators from the feed.

    Args:
        client (Client): The client object to use for API requests.
        initial_response (dict[str, Any]): The initial API response containing indicators and pagination info.
        initial_limit (int): The initial limit set for the API request.

    Returns:
        list[dict[str, Any]]: A list of all fetched indicators, including those from subsequent pages.
    """
    indicators_raw: list[dict[str, Any]] = initial_response.get("objects", [])
    if not indicators_raw:
        return []

    remaining_limit = initial_limit - LIMIT_RES_FROM_API
    next_page = initial_response.get("meta", {}).get("next")

    while next_page and remaining_limit > 0:  # Loop continues as long as there's a next page link and the limit hasn't reached
        try:
            if next_page.startswith("/api/"):
                # /api/ is removed here as it appears in the base_url of the client.
                url_suffix_for_next_page = next_page[len("/api/") :]
            else:
                url_suffix_for_next_page = next_page  # Use as is if it's already relative

            url_suffix_for_next_page = url_suffix_for_next_page.replace("limit=1000", f"limit={remaining_limit}")

            demisto.debug(f"{THREAT_STREAM} - Fetching next page: {url_suffix_for_next_page}")
            res = client.http_request(method="GET", url_suffix=url_suffix_for_next_page)
            current_page_indicators = res.get("objects", [])

            if current_page_indicators:
                indicators_raw.extend(current_page_indicators)
            else:
                demisto.debug(f"{THREAT_STREAM} - No more indicators found on current page during pagination, breaking.")
                break

            remaining_limit = remaining_limit - LIMIT_RES_FROM_API
            next_page = res.get("meta", {}).get("next")

        except Exception as e:
            demisto.error(f"{THREAT_STREAM} - Error during pagination: {e}. Continuing with fetched indicators.")
            break  # Break pagination on error but process what's already fetched

    return indicators_raw


def get_indicators_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Wrapper for retrieving indicators from the feed to the war-room.
    This command is mainly used for testing and debugging purposes.

    Args:
        client (Client): The client object to use for API requests.
        args (dict[str, Any]): Arguments passed to the command (e.g., indicator_type, limit).

    Returns:
        CommandResults: An object containing the indicators' data.
    """

    indicator_type = args.get("indicator_type", "")
    limit = arg_to_number(args.get("limit")) if args.get("limit") else 10

    params: dict[str, Any] = {"limit": limit}
    if indicator_type:
        if indicator_type not in ["domain", "email", "ip", "md5", "url"]:
            demisto.error(f"{THREAT_STREAM} - Invalid indicator type.")
            return CommandResults(
                readable_output="""### Invalid indicator type. Select one of the following types: domain, email, ip, md5, url."""
            )
        else:
            params["type"] = indicator_type

    demisto.debug(f"{THREAT_STREAM} - Calling API to get indicators with params: {params}")
    res = client.http_request(method="GET", url_suffix=URL_SUFFIX, params=params)

    indicators_raw = handle_get_pagination(client, res, limit)  # type: ignore

    if not indicators_raw:
        demisto.debug(f"""{THREAT_STREAM} - No indicators found for the given criteria in the
                     'threatstream-feed-get-indicators' command.""")
        return CommandResults(readable_output="### No indicators were found.")

    parsed_indicators = parse_indicators_for_get_command(indicators_raw, sort_by=args.get("sort_by", "Modified Time"))
    demisto.debug(f"{THREAT_STREAM}-get-indicators command got {len(parsed_indicators)} indicators.")

    # Define headers dynamically based on whether an indicator type was specified
    headers = [
        "TargetIndustries",
        "Source",
        "ThreatStreamID",
        "Country Code",
        "Description",
        "Modified",
        "Organization",
        "Confidence",
        "Creation",
        "Expiration",
        "Tags",
        "TrafficLightProtocol",
        "Location",
        "ASN",
    ]

    if indicator_type:
        # Insert the dynamic indicator type header (e.g., "IP", "Domain") right after "Country Code"
        indicator_type = INDICATOR_TYPE_UPPER.get(indicator_type)
        headers.insert(headers.index("Country Code") + 1, indicator_type)

    human_readable = tableToMarkdown(
        name=f"Indicators from {THREAT_STREAM}:",
        t=parsed_indicators,
        headers=headers,
        removeNull=True,
        is_auto_json_transform=True,
    )

    return CommandResults(readable_output=human_readable, raw_response=indicators_raw)


def extract_tag_names(indicator: dict[str, Any]) -> list[str]:
    """
    Extracts the 'name' values from the 'tags' list within an indicator dictionary.

    This function safely handles cases where the 'tags' key might be missing or its
    value might be None, returning an empty list in such scenarios.

    Args:
        indicator (Dict[str, Any]): A dictionary representing an indicator, which may
                                     contain a 'tags' key with a list of tag dictionaries.

    Returns:
        List[str]: A list of tag names (strings) found in the 'tags' list.
                   Returns an empty list if 'tags' is not present, is None, or
                   contains no dictionaries with a 'name' key.
    """
    tags = indicator.get("tags")
    if tags is None:
        return []

    # Ensure tags is a list before attempting to iterate
    if not isinstance(tags, list):
        # This case handles if 'tags' exists but is not a list (e.g., a string, int, etc.)
        return []

    names = []
    for tag in tags:
        if isinstance(tag, dict) and "name" in tag:
            names.append(tag["name"])
    return names


def parse_indicators_for_get_command(indicators, sort_by: str = "Modified Time") -> list[dict[str, Any]]:
    """
    Parses a list of raw indicators from the API response into a format suitable for the War Room.
    The returned list is ordered in descending order by the specified timestamp.

    Args:
        indicators (list[dict[str, Any]]): List of raw indicator dictionaries from API response.
        sort_by (str): The field to sort the indicators by. Can be "Created" or "Modified". Defaults to "Modified".

    Returns:
        list[dict[str, Any]]: List of indicators formatted for War Room display,
    """
    res: list[dict[str, Any]] = []
    for indicator in indicators:
        indicator_type = INDICATOR_TYPE_UPPER.get(indicator.get("type"))  # e.g., "IP", "Domain", "Email"
        indicator_value = indicator.get("value")  # The actual value of the indicator

        dynamic_field: dict[str, Any] = {}
        if indicator_type and indicator_value:
            dynamic_field[indicator_type] = indicator_value  # Map "ip": "1.1.1.1" or "domain": "example.com"

        res.append(
            assign_params(
                TargetIndustries=indicator.get("target_industry"),
                Source=indicator.get("source"),
                ThreatStreamID=str(indicator.get("id")),
                CountryCode=indicator.get("country"),
                **dynamic_field,  # Unpack the dynamic field into the params
                Description=indicator.get("description"),
                Modified=indicator.get("modified_ts"),
                Organization=indicator.get("org"),
                Confidence=str(indicator.get("confidence")),
                Creation=indicator.get("created_ts"),
                Expiration=indicator.get("expires_ts"),
                Tags=extract_tag_names(indicator),
                TrafficLightProtocol=indicator.get("tlp"),
                Location=indicator.get("locations"),
                ASN=indicator.get("asn"),
            )
        )

    if sort_by == "Created Time":
        res.sort(key=lambda x: x.get("Creation") or "", reverse=True)
    else:  # sort_by == "Modified Time":
        res.sort(key=lambda x: x.get("Modified") or "", reverse=True)
    return res


def get_current_utc_time():
    """
    Returns the current UTC time as an aware datetime object.

    Returns:
        datetime: The current time in UTC with timezone information.
    """
    return datetime.now(timezone.utc)


def get_past_time(minutes_interval):
    """
    Calculates the time that is now minus the given time interval in minutes,
    and returns it in ISO 8601 format with milliseconds.

    Args:
        minutes_interval (int): The time interval in minutes to go back.

    Returns:
        str: The calculated past time in 'YYYY-MM-DDTHH:MM:SS.sss' format. i.e., 2023-08-01T11:57:00.080
    """
    now = get_current_utc_time()
    past_time = now - timedelta(minutes=minutes_interval)
    return past_time.replace(tzinfo=None).isoformat(timespec="milliseconds")


def handle_fetch_pagination(client: Client, initial_response: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Handles fetching all indicators from an API feed that supports pagination.

    This function takes the initial API response and iteratively fetches subsequent pages
    until no more 'next' pages are indicated or an error occurs during pagination.

    Args:
        client (Client): The client object configured for API requests.
        initial_response (dict[str, Any]): The response from the initial API call.
                                            Expected to contain 'objects' (list of indicators)
                                            and 'meta' (with a 'next' key for pagination).

    Returns:
        list[dict[str, Any]]: A consolidated list of all raw indicators fetched from
                              the initial response and all subsequent paginated responses.
    """
    all_raw_indicators: list[dict[str, Any]] = initial_response.get("objects", [])
    next_page = initial_response.get("meta", {}).get("next")

    while next_page:  # Loop continues as long as there's a next page link
        try:
            # Determine the URL suffix for the next page
            if next_page.startswith("/api/"):
                # /api/ is removed here as it appears in the base_url of the client.
                url_suffix_for_next_page = next_page[len("/api/") :]
            else:
                url_suffix_for_next_page = next_page  # Use as is if it's already relative

            demisto.debug(f"{THREAT_STREAM} - Fetching next page: {url_suffix_for_next_page}")
            response = client.http_request(method="GET", url_suffix=url_suffix_for_next_page)
            current_page_indicators = response.get("objects", [])

            if current_page_indicators:
                all_raw_indicators.extend(current_page_indicators)
            else:
                demisto.debug(f"{THREAT_STREAM} - No more indicators found on current page during pagination, breaking.")
                break

            next_page = response.get("meta", {}).get("next")  # Get the 'next' link for the subsequent page
        except Exception as e:
            # Log the error and break the pagination, but keep already fetched indicators
            demisto.error(f"{THREAT_STREAM} - Error during pagination: {e}. Continuing with fetched indicators.")
            break  # Break pagination on error but process what's already fetched

    return all_raw_indicators


def fetch_indicators_command(
    client: Client, params: dict[str, Any], last_run: dict[str, Any]
) -> tuple[str, list[dict[str, Any]]]:
    """
    Wrapper for fetching indicators from the feed to the Threat Intel Management (TIM) in Cortex XSOAR.
    This function handles pagination and updates the last run time.

    Args:
        client (Client): The client object to use for API requests.
        params (dict[str, Any]): Integration parameters.
        last_run (dict[str, Any]): The last run object from Demisto, used for incremental fetching.

    Returns:
        Tuple[str, list[dict[str, Any]]]: A tuple containing:
            - str: The timestamp for the next successful run.
            - list[dict[str, Any]]: A list of parsed indicators ready for Cortex XSOAR.
    """
    create_relationship = argToBoolean(params.get("createRelationships", True))
    tlp_color = params.get("tlp_color", "WHITE")
    reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(params.get("feedReliability", DBotScoreReliability.C))
    now = get_current_utc_time()
    order_by = params.get("fetchBy", "Modified Time")
    if order_by == "Created Time":
        order_by = "created_ts"
    else:  # order_by == "Modified Time"
        order_by = "modified_ts"
    confidence_threshold = arg_to_number(params.get("confidenceThreshold", DEFAULT_CONFIDENCE_THRESHOLD))

    # Initialize last_fetch_time based on the last_run object.
    # If it's the first run, or last_run is empty, fetch from a default interval.
    last_fetch_time = last_run.get("last_successful_run")
    feed_fetch_interval = arg_to_number(params.get("feedFetchInterval", DEFAULT_FEED_FETCH_INTERVAL))

    if not last_fetch_time:
        demisto.info(
            f"{THREAT_STREAM} - First fetch detected. Retrieving indicators from the last {feed_fetch_interval} minutes."
        )
        # For the very first run, fetch from the past interval.
        last_fetch_time = get_past_time(feed_fetch_interval)
    else:
        demisto.info(f"{THREAT_STREAM} - Fetching indicators {order_by.replace('_ts', '')} since {last_fetch_time}.")

    query: dict[str, Any] = assign_params(
        limit=LIMIT_RES_FROM_API, status=INDICATOR_STATUS, order_by=order_by, confidence__gt=confidence_threshold
    )

    if order_by == "modified_ts":
        query["modified_ts__gte"] = last_fetch_time
    else:  # order_by == "created_ts"
        query["created_ts__gte"] = last_fetch_time

    demisto.debug(f"{THREAT_STREAM} - Initial API call for fetch-indicators with params: {query}")
    response = client.http_request(method="GET", url_suffix=URL_SUFFIX, params=query)
    all_raw_indicators: list[dict[str, Any]] = handle_fetch_pagination(client, response)

    if not all_raw_indicators:
        demisto.info(f"{THREAT_STREAM} - No new indicators found since last run or no indicators matching criteria.")
        # Update last_run even if no indicators are found, to avoid refetching the same period.
        return now.strftime(DATE_FORMAT), []

    demisto.debug(f"{THREAT_STREAM} - Total raw indicators fetched: {len(all_raw_indicators)}")
    parsed_indicators_list: list[dict[str, Any]] = []

    for indicator_raw in all_raw_indicators:
        try:
            # Parse each raw indicator and calculate its DBot score
            parsed_indicator = parse_indicator_for_fetch(indicator_raw, tlp_color, create_relationship, reliability)
            parsed_indicators_list.append(parsed_indicator)
        except Exception as e:
            demisto.error(f"{THREAT_STREAM} - Error parsing indicator ID {indicator_raw.get('id')}:{e}. Skipping this indicator.")
            continue  # Continue to the next indicator even if one fails

    demisto.debug(f"{THREAT_STREAM} - Successfully parsed {len(parsed_indicators_list)} indicators for fetch.")
    # Return the current UTC timestamp for the next successful run and the list of parsed indicators
    return now.strftime(DATE_FORMAT), parsed_indicators_list


def create_relationships(reliability: str, indicator: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Generates a list of relationship objects for a given indicator.
    Handles single and multiple related entities.

    Args:
        reliability (str): The reliability score for the relationship source.
        indicator (dict[str, Any]): The raw indicator dictionary.

    Returns:
        list[dict[str, Any]]: A list of relationship dictionaries formatted for Cortex XSOAR.
    """
    relationships: list[dict[str, Any]] = []
    indicator_type = indicator.get("type")
    indicator_value = indicator.get("value")

    if not indicator_type or not indicator_value:
        demisto.debug(f"{THREAT_STREAM} - Skipping relationship creation for indicator with missing type or value: {indicator}")
        return relationships

    # Get the relationship specifications for the current indicator type
    relations_specs = RELATIONSHIPS_MAPPING.get(indicator_type)
    if relations_specs:
        for relation_spec in relations_specs:
            raw_field_name = relation_spec["raw_field"]
            entity_b_type = relation_spec["entity_b_type"]
            relationship_name = relation_spec["name"]
            # Retrieve the value(s) for the related entity from the raw indicator
            entity_b_values = demisto.get(indicator, raw_field_name)
            if entity_b_values:
                relationships.append(
                    EntityRelationship(
                        entity_a=indicator_value,
                        entity_a_type=INDICATOR_TYPE.get(indicator_type),
                        name=relationship_name,
                        entity_b=entity_b_values,  # entity_b_item,
                        entity_b_type=entity_b_type,
                        source_reliability=reliability,
                        brand=THREAT_STREAM,
                    ).to_indicator()  # Convert the EntityRelationship object to a dictionary
                )
        demisto.debug(f"{THREAT_STREAM} - Relationship successfully created for indicator {indicator}")
    return relationships


def parse_indicator_for_fetch(
    indicator: dict[str, Any], tlp_color: str, create_relationship_param: bool, reliability: str
) -> dict[str, Any]:
    """
    Parses a single raw indicator from the API response into a format suitable for Cortex XSOAR's Indicators tab.
    This includes calculating DBot score and creating relationships.

    Args:
        indicator (dict[str, Any]): The raw data of the indicator from the API.
        tlp_color (str): The TLP color to assign to the indicator.
        create_relationship_param (bool): Flag to determine if relationships should be created.
        reliability (str): The reliability score for the indicator source.

    Returns:
        dict[str, Any]: An indicator dictionary formatted for Cortex XSOAR's `createIndicators` API.
    """
    # Calculate relationships first, as they depend on the raw indicator data
    if not create_relationship_param:
        demisto.debug(f"{THREAT_STREAM} - Skipping relationship creation for indicator {indicator}")
        relationships = []
    else:
        relationships = create_relationships(reliability, indicator)

    # indicator_type = indicator.get("type")  # e.g., "ip", "domain", "email", "md5", "url"
    indicator_type = INDICATOR_TYPE.get(str(indicator.get("type")))
    indicator_value = indicator.get("value")  # The actual value of the indicator (e.g., "1.1.1.1", "example.com")

    if not indicator_type or not indicator_value:
        raise ValueError(f"Indicator missing 'type' or 'value': {indicator}")

    dbot_score = DBotScoreCalculator().calculate_score(indicator)

    # Prepare dynamic field for the indicator value (e.g., {"ip": "1.1.1.1"})
    dynamic_field: dict[str, Any] = {}
    dynamic_field[indicator_type] = indicator_value

    # Assign common fields and dynamic fields
    fields = assign_params(
        TargetIndustries=indicator.get("target_industry"),
        Source=indicator.get("source"),
        ThreatStreamID=str(indicator.get("id")),
        CountryCode=indicator.get("country"),
        **dynamic_field,  # Unpack the dynamic field into the params for Cortex XSOAR
        Description=indicator.get("description"),
        Modified=indicator.get("modified_ts"),
        Organization=indicator.get("org"),
        Confidence=str(indicator.get("confidence")),
        Creation=indicator.get("created_ts"),
        Expiration=indicator.get("expires_ts"),
        Tags=extract_tag_names(indicator),
        TrafficLightProtocol=tlp_color,  # Use the configured TLP color
        Location=indicator.get("locations"),
        ASN=indicator.get("asn"),
    )

    return assign_params(
        value=indicator_value,
        type=indicator_type,
        fields=fields,
        relationships=relationships,
        rawJSON=indicator,
        score=dbot_score,
    )


def main():
    """
    Initiate integration command
    """
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    params = demisto.params()

    # init credentials
    user_name = params.get("credentials", {}).get("identifier")
    api_key = params.get("credentials", {}).get("password")
    server_url = params.get("url", "").strip("/")

    try:
        client = Client(
            base_url=f"{server_url}/api/",
            user_name=user_name,
            api_key=api_key,
            verify=not params.get("insecure", False),
        )

        if command == "test-module":
            # This call is made when clicking the integration 'Test' button.
            return_results(test_module(client))

        elif command == "threatstream-feed-get-indicators":
            return_results(get_indicators_command(client, demisto.args()))

        elif command == "fetch-indicators":
            next_run, res = fetch_indicators_command(client, params, demisto.getLastRun())
            for b in batch(res, batch_size=2000):
                demisto.debug(f"{THREAT_STREAM} {b=}")
                demisto.createIndicators(b)
            demisto.setLastRun({"last_successful_run": next_run})
            demisto.info(f"{THREAT_STREAM} - Fetch-indicators completed. Next run will fetch from: {next_run}")

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback stack
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()

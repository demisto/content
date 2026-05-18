"""Flashpoint Ignite Feed V2 Integration for Cortex XSOAR (aka Demisto)"""

""" IMPORTS """

import json  # noqa E402
from typing import Any  # noqa E402
from copy import deepcopy  # noqa E402

import urllib3  # noqa E402

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
LIMIT = 10
MAX_FETCH = 500
DEFAULT_FIRST_FETCH = "3 days"
CURRENT_TIME = "now"
DEFAULT_OFFSET = 0
DEFAULT_SORT_ORDER = "modified_at:asc"
DEFAULT_INDICATOR_TYPE = "Ignite Indicator"
TIMEOUT = 60
STATUS_LIST_TO_RETRY = (429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500))  # type: ignore
OK_CODES = (200, 201)
TOTAL_RETRIES = 4
BACKOFF_FACTOR = 7.5  # Sleep for [0s, 15s, 30s, 60s] between retries.

URL_SUFFIX = {"INDICATORS": "/technical-intelligence/v2/indicators"}

# Mapping old types to new ioc_types for v2 API
IOC_TYPE_MAPPING = {
    "ip": "ipv4,ipv6",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "domain",
    "url": "url",
    "file": "file",
    "extracted config": "extracted_config",
}

INDICATOR_TYPE_MAPPING = {
    "domain": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "file": FeedIndicatorType.File,
    "extracted_config": DEFAULT_INDICATOR_TYPE,
}

# Score mapping for v2 API
SCORE_MAPPING = {
    "informational": "informational",
    "suspicious": "suspicious",
    "malicious": "malicious",
}

MESSAGES = {
    "NO_PARAM_PROVIDED": "Please provide the {}.",
    "LIMIT_ERROR": "{} is an invalid value for limit. Limit must be between 1 and {}.",
    "NO_INDICATORS_FOUND": "No indicators were found for the given argument(s).",
    "INVALID_TYPES": "Invalid Types of the indicators provided: {}.",
    "INVALID_SCORE": "Invalid Severity provided: {}. Valid values are: Informational, Suspicious, Malicious.",
    "INVALID_SCORE_RANGE": "Minimum Severity Level of an indicator cannot be greater than "
    "Maximum Severity Level of an indicator.",
    "FROM_ERROR": "Invalid value for from: {}. From must be a non-negative integer.",
}

HTTP_ERRORS = {
    400: "Bad request [400]: An error occurred while fetching the data.",
    401: "Authentication error [401]: Please provide valid API Key.",
    403: "Forbidden [403]: Please provide valid API Key.",
    404: "Resource not found [404]: Invalid endpoint was called.",
    422: "Validation error [422]: Invalid request parameters.",
    500: "Internal server error [500]: Please try again after some time.",
}

INTEGRATION_VERSION = get_pack_version()
INTEGRATION_PLATFORM = "Cortex XSOAR"
DEFAULT_API_PATH = "https://api.flashpoint.io"
DEFAULT_PLATFORM_PATH = "https://app.flashpoint.io"
IGNITE_FEED_EVENT_HREF = "https://app.flashpoint.io/cti/malware/iocs/"

# Field mapping for v2 API response
FLASHPOINT_FEED_MAPPING_V2 = {
    "flashpointfeedindicatorid": {"path": "id", "type": "str"},
    "flashpointfeedindicatortype": {"path": "type", "type": "str"},
    "flashpointfeedapi": {"path": "href", "type": "url"},
    "flashpointfeedscorevalue": {"path": "score.value", "type": "str"},
    "flashpointfeedlastscoredate": {"path": "score.last_scored_at", "type": "date"},
    "flashpointfeedmodifieddate": {"path": "modified_at", "type": "date"},
    "flashpointfeedcreateddate": {"path": "created_at", "type": "date"},
    "flashpointfeedlastseendate": {"path": "last_seen_at", "type": "date"},
    "flashpointfeedplatformurl": {"path": "platform_urls.ignite", "type": "url"},
    "flashpointfeedaptdescription": {"path": "apt_description", "type": "str"},
    "flashpointfeedexternalreferences": {"path": "external_references", "type": "str"},
    "md5": {"path": "hashes.md5", "type": "str"},
    "sha1": {"path": "hashes.sha1", "type": "str"},
    "sha256": {"path": "hashes.sha256", "type": "str"},
    "flashpointfeedhtmlmalwaredescription": {"path": "malware_description", "type": "str"},
    "flashpointfeedmitreattackids": {"path": "mitre_attack_ids", "type": "str"},
    "flashpointfeedsightings": {"path": "sightings", "type": "str"},
    "flashpointfeedlatestsighting": {"path": "latest_sighting", "type": "str"},
    "flashpointfeedtotalsightings": {"path": "total_sightings", "type": "int"},
}


class Client(BaseClient):
    """Client class to interact with the Flashpoint Ignite V2 API."""

    def __init__(self, url, headers, verify, proxy):
        """Initialize class object.

        :type url: ``str``
        :param url: Base server address with suffix, for example: https://example.com.

        :type headers: ``Dict``
        :param headers: Additional headers to be included in the requests.

        :type verify: ``bool``
        :param verify: Use to indicate secure/insecure http request.

        :type proxy: ``bool``
        :param proxy: The proxy settings to be used.
        """
        self.url = url

        if DEFAULT_API_PATH in url:
            self.platform_url = DEFAULT_PLATFORM_PATH
        else:
            self.platform_url = url

        self.headers = headers
        self.verify = verify
        self.proxy = proxy

        super().__init__(base_url=self.url, headers=self.headers, verify=self.verify, proxy=self.proxy)

    def http_request(self, url_suffix: str, params: dict[str, Any] | None, method: str = "GET", resp_type: str = "json") -> Any:
        """
        Get http response based on url and given parameters.

        :param url_suffix: url encoded url suffix.
        :param params: URL parameters to specify the query.
        :param method: Specify http methods.
        :param resp_type: Response type to be returned.

        :return: http response on json.
        """
        resp = self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            ok_codes=OK_CODES,
            error_handler=self.handle_errors,
            status_list_to_retry=STATUS_LIST_TO_RETRY,
            retries=TOTAL_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            timeout=TIMEOUT,
            resp_type=resp_type,
        )

        return resp

    def check_indicator_type(self, indicator_value: str, indicator_type: str, default_map: bool = False) -> str:
        """
        Set the type of the indicator.

        :param indicator_value: Value of the indicator.
        :param indicator_type: Type of the indicator.
        :param default_map: To enable the default mapper setting for the indicator.

        :return: Type of the indicator.
        """
        ind_type = DEFAULT_INDICATOR_TYPE
        if not default_map:
            if indicator_type in INDICATOR_TYPE_MAPPING:
                ind_type = INDICATOR_TYPE_MAPPING.get(indicator_type, DEFAULT_INDICATOR_TYPE)
            else:
                ind_type = auto_detect_indicator_type(indicator_value)

        return ind_type or DEFAULT_INDICATOR_TYPE

    def create_relationship(self, entity_a: str, entity_a_type: str, entity_b_data: list) -> list:
        """
        Create a list of relationships objects from the tags.

        :param entity_a: the entity a of the relation which is the current indicator.
        :param entity_a_type: the entity a type which is the type of the current indicator.
        :param entity_b_data: list of entity_b_data returned from the API.

        :return: list of EntityRelationship objects containing all the relationships.
        """
        relationships = []
        for entity_b in entity_b_data:
            if entity_b:
                # operations for entity_b
                entity_b_value = entity_b.get("value", "")
                res_entity_b_type = entity_b.get("type", "")

                entity_b_type = self.check_indicator_type(
                    indicator_value=entity_b_value,
                    indicator_type=res_entity_b_type,
                )

                obj = EntityRelationship(
                    name=EntityRelationship.Relationships.INDICATOR_OF,
                    entity_a=entity_a,
                    entity_a_type=entity_a_type,
                    entity_b=entity_b_value,
                    entity_b_type=entity_b_type,
                )
                obj = obj.to_indicator()
                relationships.append(obj)

        return relationships

    def map_indicator_fields(self, resp: dict, indicator_obj: dict) -> None:
        """
        Map fields of indicators from the v2 API response.

        :param resp: raw response of indicator.
        :param indicator_obj: created indicator object.

        :return: None.
        """
        for key, value in FLASHPOINT_FEED_MAPPING_V2.items():
            true_value = None

            path = value.get("path", "")
            true_value = self._get_nested_value(resp, path)

            indicator_obj["fields"][key] = true_value

    def _get_nested_value(self, data: dict, path: str) -> Any:
        """
        Get nested value from dictionary using dot notation path.

        :param data: Dictionary to extract value from.
        :param path: Dot notation path (e.g., "parent.child.value").

        :return: Value at the path or None if not found.
        """
        if not path:
            return None

        paths = path.split(".")
        value = data

        try:
            for p in paths:
                if isinstance(value, dict):
                    value = value.get(p)  # type: ignore
                else:
                    return None
        except (AttributeError, TypeError):
            return None

        return value

    def create_indicators_from_response(self, response: Any, params: dict) -> list:
        """
        Create indicators from the v2 API response.

        :param response: response received from the API (items array).
        :param params: dictionary of parameters.

        :return: List of indicators.
        """
        indicators = []
        feed_tags = argToList(params.get("feedTags"))
        tlp_color = params.get("tlp_color")
        relationship = params.get("createRelationship", False)
        default_map = params.get("defaultMap", False)

        for resp in response:
            indicator_value = resp.get("value", "")
            res_indicator_type = resp.get("type", "")

            indicator_type = self.check_indicator_type(
                indicator_value=indicator_value,
                indicator_type=res_indicator_type,
                default_map=default_map,
            )
            indicator_obj = {
                "value": indicator_value,
                "type": indicator_type,
                "rawJSON": resp,
                "fields": {
                    "tags": feed_tags if feed_tags else [],
                },
            }
            if tlp_color:
                indicator_obj["fields"]["trafficlightprotocol"] = tlp_color

            if relationship:
                iocs_data = resp.get("relationships", {}).get("iocs", [])
                iocs_relationships = self.create_relationship(indicator_value, indicator_type, iocs_data)
                related_iocs_data = []
                sightings_data = deepcopy(resp.get("sightings", []))
                for sighting in sightings_data:
                    related_iocs_data.extend(sighting.get("related_iocs", []))
                related_iocs_data.extend(resp.get("latest_sighting", {}).get("related_iocs", []))
                related_iocs_relationships = self.create_relationship(indicator_value, indicator_type, related_iocs_data)

                all_relationships = iocs_relationships + related_iocs_relationships
                # Deduplicate relationships using JSON string comparison
                seen = set()
                unique_relationships = []
                for rel in all_relationships:
                    rel_key = json.dumps(rel, sort_keys=True)
                    if rel_key not in seen:
                        seen.add(rel_key)
                        unique_relationships.append(rel)
                indicator_obj["relationships"] = unique_relationships

            self.map_indicator_fields(resp, indicator_obj)

            indicators.append(indicator_obj)

        return indicators

    def fetch_indicators(self, params: dict, resp_type: str = "json") -> Any:
        """
        Fetch the list of indicators based on specified arguments.

        :param params: Parameters to be sent with API call.
        :param resp_type: Response type to be returned.

        :return: API response.
        """
        response = self.http_request(url_suffix=URL_SUFFIX["INDICATORS"], params=params, method="GET", resp_type=resp_type)

        return response

    @staticmethod
    def handle_errors(resp) -> None:
        """Handle http errors."""
        status = resp.status_code

        # Handle 422 validation errors with detailed message
        if status == 422:
            error_message = Client.parse_validation_error(resp)
            raise DemistoException(error_message)

        if status in HTTP_ERRORS:
            raise DemistoException(HTTP_ERRORS[status])
        else:
            resp.raise_for_status()

    @staticmethod
    def parse_validation_error(resp) -> str:
        """
        Parse 422 validation error response and return a meaningful error message.

        :param resp: HTTP response object.

        :return: Formatted error message string.
        """
        try:
            error_data = resp.json()
            errors = error_data.get("errors", [])

            if errors:
                error_messages = []
                for error in errors:
                    loc = error.get("loc", [])
                    # Get the parameter name (last element in loc array)
                    param_name = loc[-1] if loc else "unknown"
                    msg = error.get("msg", "validation failed")
                    input_value = error.get("input", "")

                    if input_value:
                        error_messages.append(f"{param_name}: {msg} (input: {input_value})")
                    else:
                        error_messages.append(f"{param_name}: {msg}")

                return f"Validation Error [422]: {'; '.join(error_messages)}"

            # Fallback to detail message if no errors array
            return f"Validation Error [422]: {error_data}"

        except Exception:
            return HTTP_ERRORS[422]


""" HELPER FUNCTIONS """


def remove_space_from_args(args):
    """
    Remove space from args.

    :param args: Arguments.

    :return: Argument"s dictionary without spaces.
    """
    for key in args:
        if isinstance(args[key], str):
            args[key] = args[key].strip()
    return args


def validate_params(params: dict):
    """
    Validate the parameters.

    :param params: Params to validate.
    """
    if not params.get("url"):
        raise DemistoException(MESSAGES["NO_PARAM_PROVIDED"].format("Server URL"))
    if not str(params.get("credentials", {}).get("password", "")).strip():
        raise DemistoException(MESSAGES["NO_PARAM_PROVIDED"].format("API Key"))


def convert_types_to_ioc_types(types_list: list[str]) -> str:
    """
    Convert old type values to v2 ioc_types format.

    :param types_list: List of types from configuration.

    :return: Comma-separated string of ioc_types.
    """
    if not types_list:
        return ""

    ioc_types = []
    for t in types_list:
        t_lower = t.lower()
        if t_lower in IOC_TYPE_MAPPING:
            ioc_types.append(IOC_TYPE_MAPPING[t_lower])

    return ",".join(ioc_types)


def validate_get_indicators_args(args: dict) -> dict:
    """
    Validate the argument list for get indicators.

    :param args: Dictionary of arguments.

    :return: Updated dictionary of arguments for v2 API.
    """
    cidr_range = args.get("cidr_range")
    min_score = args.get("min_severity_level")
    max_score = args.get("max_severity_level")
    validated_min, validated_max = validate_score_params(min_score, max_score)
    mitre_attack_ids = argToList(args.get("mitre_attack_ids", []))
    tags = argToList(args.get("tags", []))
    actor_tags = argToList(args.get("actor_tags", []))
    malware_tags = argToList(args.get("malware_tags", []))
    source_tags = argToList(args.get("source_tags", []))

    fetch_params = assign_params(
        cidr_range=cidr_range,
        min_score=validated_min,
        max_score=validated_max,
        mitre_attack_ids=",".join(mitre_attack_ids),
        tags=",".join(tags),
        actors=",".join(actor_tags),
        malware=",".join(malware_tags),
        sources=",".join(source_tags),
        embed="all",
        sort=DEFAULT_SORT_ORDER,
    )

    _from = arg_to_number(args.get("from", 0))
    if _from < 0:  # type: ignore
        raise ValueError(MESSAGES["FROM_ERROR"].format(_from))
    fetch_params["from"] = _from

    limit = arg_to_number(args.get("limit", LIMIT))
    if limit < 1 or limit > MAX_FETCH:  # type: ignore
        raise ValueError(MESSAGES["LIMIT_ERROR"].format(limit, MAX_FETCH))
    fetch_params["size"] = limit

    # Convert types to ioc_types for v2 API
    types = args.get("types", "")
    if types:
        types_list = argToList(types)
        fetch_params["ioc_types"] = convert_types_to_ioc_types(types_list)  # type: ignore

        if types_list and not fetch_params.get("ioc_types"):
            raise ValueError(MESSAGES["INVALID_TYPES"].format(types_list))

    first_fetch = arg_to_datetime(args.get("updated_since", DEFAULT_FIRST_FETCH))
    fetch_params["modified_after"] = first_fetch.strftime(DATE_FORMAT)  # type: ignore

    remove_nulls_from_dictionary(fetch_params)

    return fetch_params


def prepare_hr_for_indicators(indicators: list) -> str:
    """
    Prepare human-readable response.

    :param indicators: List of indicators.

    :return: Indicators in human-readable format.
    """
    hr = []

    for indicator in indicators:
        raw_json = indicator.get("rawJSON", {})

        data = {
            "ID": f"[{raw_json.get('id', '')}]({raw_json.get('platform_urls', {}).get('ignite', '')})",
            "Indicator Type": raw_json.get("type", ""),
            "Indicator Value": raw_json.get("value", ""),
            "Score": raw_json.get("score", {}).get("value", ""),
            "Modified At": raw_json.get("modified_at", ""),
            "Created At": raw_json.get("created_at", ""),
            "Last Seen At": raw_json.get("last_seen_at", ""),
            "APT Description": raw_json.get("apt_description", ""),
            "MITRE Attack IDs": raw_json.get("mitre_attack_ids", ""),
            "Sightings": raw_json.get("sightings", ""),
            "External References": raw_json.get("external_references", ""),
            "Total Sightings": raw_json.get("total_sightings", ""),
        }
        hr.append(data)

    headers = [
        "ID",
        "Indicator Type",
        "Indicator Value",
        "Score",
        "Modified At",
        "Created At",
        "Last Seen At",
        "APT Description",
        "MITRE Attack IDs",
        "Sightings",
        "External References",
        "Total Sightings",
    ]

    return tableToMarkdown(
        name="Indicator(s)",
        t=hr,
        headers=headers,
        removeNull=True,
        json_transform_mapping={
            "MITRE Attack IDs": JsonTransformer(is_nested=True),
            "Sightings": JsonTransformer(is_nested=True),
            "External References": JsonTransformer(is_nested=True),
        },
    )


def validate_score_params(min_score: str | None, max_score: str | None) -> tuple[str | None, str | None]:
    """
    Validate and convert score parameters.

    :param min_score: Minimum score value.
    :param max_score: Maximum score value.

    :return: Tuple of validated (min_score, max_score) for API.
    """
    score_order = ["informational", "suspicious", "malicious"]

    validated_min = None
    validated_max = None

    if min_score:
        min_lower = min_score.lower()
        if min_lower not in SCORE_MAPPING:
            raise ValueError(MESSAGES["INVALID_SCORE"].format(min_score))
        validated_min = SCORE_MAPPING[min_lower]

    if max_score:
        max_lower = max_score.lower()
        if max_lower not in SCORE_MAPPING:
            raise ValueError(MESSAGES["INVALID_SCORE"].format(max_score))
        validated_max = SCORE_MAPPING[max_lower]

    # Validate that min_score is not greater than max_score
    if validated_min and validated_max and score_order.index(validated_min) > score_order.index(validated_max):
        raise ValueError(MESSAGES["INVALID_SCORE_RANGE"])

    return validated_min, validated_max


def validate_fetch_indicators_params(params: dict, last_run: dict[str, Any]) -> dict:
    """
    Validate the parameter list for fetch indicators.

    :param params: Dictionary of parameters.
    :param last_run: last run object obtained from demisto.getLastRun().

    :return: Updated dictionary of parameters for v2 API.
    """
    # Convert types to ioc_types
    types_list = params.get("types", [])
    ioc_types = convert_types_to_ioc_types(types_list) if types_list else ""

    if types_list and not ioc_types:
        raise ValueError(MESSAGES["INVALID_TYPES"].format(types_list))

    cidr_range = params.get("cidr_range")
    min_score = params.get("min_score")
    max_score = params.get("max_score")
    validated_min, validated_max = validate_score_params(min_score, max_score)
    mitre_attack_ids = argToList(params.get("mitre_attack_ids", []))
    tags = argToList(params.get("tags", []))
    actor_tags = argToList(params.get("actor_tags", []))
    malware_tags = argToList(params.get("malware_tags", []))
    source_tags = argToList(params.get("source_tags", []))

    first_fetch = arg_to_datetime(params.get("first_fetch", DEFAULT_FIRST_FETCH)).strftime(DATE_FORMAT)  # type: ignore
    # If available then take modified_after from last_run.
    modified_after = last_run.get("next_modified_after", first_fetch)

    current_time = arg_to_datetime(CURRENT_TIME).strftime(DATE_FORMAT)  # type: ignore
    # If available then take modified_before from last_run.
    modified_before = last_run.get("next_modified_before", current_time)

    offset = last_run.get("offset", DEFAULT_OFFSET)

    fetch_params = assign_params(
        size=MAX_FETCH,
        embed="all",
        ioc_types=ioc_types,
        cidr_range=cidr_range,
        min_score=validated_min,
        max_score=validated_max,
        mitre_attack_ids=",".join(mitre_attack_ids),
        tags=",".join(tags),
        actors=",".join(actor_tags),
        malware=",".join(malware_tags),
        sources=",".join(source_tags),
        modified_after=modified_after,
        modified_before=modified_before,
        sort=DEFAULT_SORT_ORDER,
    )

    fetch_params["from"] = offset

    remove_nulls_from_dictionary(fetch_params)

    return fetch_params


"""Command functions"""


def test_module(client: Client) -> str:
    """
    Tests the indicators from the feed.

    :param client: Client object.

    :return: "ok" if test passed, anything else will fail the test.
    """
    params = demisto.params()
    is_fetch = params.get("feed", False)
    if is_fetch:
        fetch_indicators_command(client=client, params=params, last_run={}, is_test=True)
    else:
        client.fetch_indicators(params={"size": 1})
    return "ok"


def fetch_indicators_command(client: Client, params: dict, last_run: dict[str, Any], is_test: bool = False) -> tuple[list, dict]:
    """
    Fetch the indicators from v2 API.

    :param client: Client object.
    :param params: Dictionary of parameters.
    :param last_run: last run object obtained from demisto.getLastRun().
    :param is_test: If test_module called fetch_incident.

    :return: List of indicators and Dict of last run object.
    """
    next_run: dict = {}

    fetch_params = validate_fetch_indicators_params(params=params, last_run=last_run)

    resp = client.fetch_indicators(params=fetch_params, resp_type="json")

    items = resp.get("items", [])
    items = remove_empty_elements(items)

    if is_test:
        return [], {}

    # Creating new last_run according to response.
    if len(items) < MAX_FETCH:
        # Updating modified_after equal to previous modified_before.
        next_run["next_modified_after"] = last_run.get("next_modified_before", fetch_params["modified_before"])
    else:
        next_run = last_run.copy()
        next_run["next_modified_after"] = fetch_params["modified_after"]
        next_run["next_modified_before"] = fetch_params["modified_before"]
        # Set only offset equal to previous offset + max_fetch.
        next_run["offset"] = next_run.get("offset", DEFAULT_OFFSET) + MAX_FETCH

    indicators = client.create_indicators_from_response(response=items, params=params)

    demisto.debug(f"Set the last Run for indicators: {next_run}")

    return indicators, next_run


def flashpoint_ignite_v2_get_indicators_command(client: Client, params: dict, args: dict) -> CommandResults:
    """
    Get limited number of indicators from v2 API.

    :param client: Client object.
    :param params: Dictionary of parameters.
    :param args: Dictionary of arguments.

    :return: Standard Command Result.
    """
    fetch_params = validate_get_indicators_args(args=args)

    response = client.fetch_indicators(params=fetch_params)

    items = response.get("items", [])
    items = remove_empty_elements(items)

    indicators = client.create_indicators_from_response(response=items, params=params)

    if not indicators:
        return CommandResults(readable_output=MESSAGES["NO_INDICATORS_FOUND"])

    readable_output = prepare_hr_for_indicators(indicators=indicators)
    return CommandResults(
        readable_output=readable_output,
        outputs=items,
        outputs_key_field="id",
        outputs_prefix="FlashpointIgniteFeedV2.Indicator",
        raw_response=indicators,
    )


"""Main Function"""


def main():
    """Parse params and runs command functions."""
    params = remove_space_from_args(demisto.params())
    remove_nulls_from_dictionary(params)

    # Get the service API url
    base_url = params.get("url", DEFAULT_API_PATH)

    api_key = str(params.get("credentials", {}).get("password", "")).strip()

    # Default configuration parameters for handling proxy and SSL Certificate validation.
    insecure = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f"[Ignite Feed V2] Command being called is {command}")

    try:
        validate_params(params=params)
        headers: dict = {
            "Authorization": f"Bearer {api_key}",
            "X-FP-IntegrationPlatform": INTEGRATION_PLATFORM,
            "X-FP-IntegrationPlatformVersion": get_demisto_version_as_str(),
            "X-FP-IntegrationVersion": INTEGRATION_VERSION,
        }
        client = Client(verify=insecure, proxy=proxy, url=base_url, headers=headers)
        args = demisto.args()
        if command == "test-module":
            return_results(test_module(client=client))
        elif command == "fetch-indicators":
            last_run = demisto.getLastRun()
            indicators, next_run = fetch_indicators_command(client=client, params=params, last_run=last_run)
            demisto.setLastRun(next_run)
            demisto.createIndicators(indicators)
        elif command == "flashpoint-ignite-v2-get-indicators":
            return_results(flashpoint_ignite_v2_get_indicators_command(client=client, params=params, args=args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ["__main__", "builtin", "builtins"]:  # pragma: no cover
    main()

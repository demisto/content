import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import csv

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

BASE_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/"
EXPORT_FILE_NAME = "online.csv"
LAST_RUN_KEY = EXPORT_FILE_NAME
MIN_FETCH_INTERVAL_MINUTES = 5
REQUEST_TIMEOUT_SECONDS = 20
FEED_ENCODING = "latin-1"
COMMENT_PREFIX = "#"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# Refetch the full export at least this often, even when it is unchanged, so the indicators do not expire.
FULL_REFRESH_SECONDS = 43200  # 12 hours
CREATE_INDICATORS_BATCH_SIZE = 2000
DEFAULT_GET_INDICATORS_LIMIT = 50
FETCH_INTERVAL_VALIDATED_COMMANDS = ("test-module", "fetch-indicators")
FIELDNAMES = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]
FIELDS_MAPPING = {
    "Creation Date": "dateadded",
    "Value": "url",
    "State": "url_status",
    "Tags": "tags",
    "Download URL": "urlhaus_link",
    "Reported By": "reporter",
}


class Client(BaseClient):
    def __init__(self, auth_key: str, verify: bool, proxy: bool):
        super().__init__(base_url=BASE_URL, verify=verify, proxy=proxy)
        self._feed_url = build_feed_url(auth_key)

    def download_export(self, headers: dict | None = None, stream: bool = False) -> requests.Response:
        """Downloads the online URLs export. Returns the raw response, which may be 304 for a conditional request."""
        return self._http_request(
            "GET",
            full_url=self._feed_url,
            headers=headers,
            resp_type="response",
            timeout=REQUEST_TIMEOUT_SECONDS,
            stream=stream,
        )


def build_feed_url(auth_key: str) -> str:
    """Builds the v2 export URL. abuse.ch expects the Auth-Key as a path segment."""
    return f"{BASE_URL}{auth_key}/{EXPORT_FILE_NAME}"


def validate_fetch_interval(fetch_interval: Any) -> None:
    """Rejects a Feed Fetch Interval below the abuse.ch minimum (the dump is regenerated every 5 minutes).

    Raises:
        DemistoException: If the interval is lower than the minimum.
    """
    interval = arg_to_number(fetch_interval)
    if interval is not None and interval < MIN_FETCH_INTERVAL_MINUTES:
        raise DemistoException(
            f"The Feed Fetch Interval must be at least {MIN_FETCH_INTERVAL_MINUTES} minutes, as requested by abuse.ch. "
            f"Set it to {MIN_FETCH_INTERVAL_MINUTES} minutes or more in the instance configuration."
        )


def build_indicator(row: dict, tags: list[str], tlp_color: str | None, enrichment_excluded: bool) -> dict | None:
    """Builds a URL indicator from an export row. Returns None for a row without a URL."""
    raw_json = dict(row)
    value = raw_json.get("url")
    if not value:
        return None
    raw_json["value"] = value
    raw_json["type"] = FeedIndicatorType.URL

    fields: dict[str, Any] = {field: raw_json[column] for field, column in FIELDS_MAPPING.items() if raw_json.get(column)}
    fields["tags"] = tags
    if tlp_color:
        fields["trafficlightprotocol"] = tlp_color

    indicator = {"value": value, "type": FeedIndicatorType.URL, "rawJSON": raw_json, "fields": fields, "relationships": []}
    if enrichment_excluded:
        indicator["enrichmentExcluded"] = enrichment_excluded
    return indicator


def build_indicators(content: bytes, params: dict, enrichment_excluded: bool, limit: int = 0) -> list[dict]:
    """Parses the export CSV (skipping its commented header) into indicators. A limit of 0 means no limit."""
    lines = [line for line in content.decode(FEED_ENCODING).split("\n") if not line.startswith(COMMENT_PREFIX)]
    tags = argToList(params.get("feedTags"))
    tlp_color = params.get("tlp_color")

    indicators = []
    for row in csv.DictReader(lines, fieldnames=FIELDNAMES):
        indicator = build_indicator(row, tags, tlp_color, enrichment_excluded)
        if indicator:
            indicators.append(indicator)
            if limit and len(indicators) >= limit:
                break
    return indicators


def get_conditional_headers(last_run: dict) -> dict:
    """Builds the If-None-Match and If-Modified-Since headers, unless a full refresh is due."""
    state = last_run.get(LAST_RUN_KEY, {})
    last_updated = state.get("last_updated")
    if last_updated and has_passed_time_threshold(timestamp_str=last_updated, seconds_threshold=FULL_REFRESH_SECONDS):
        demisto.debug("The URLhaus export was not refetched for a long time, so it is fetched in full to keep indicators alive.")
        return {}

    headers = {}
    if state.get("etag"):
        headers["If-None-Match"] = state["etag"]
    if state.get("last_modified"):
        headers["If-Modified-Since"] = state["last_modified"]
    return headers


def build_last_run(response: requests.Response) -> dict:
    """Builds the lastRun from the response caching headers. Returns an empty dict if there are none."""
    etag = response.headers.get("ETag")
    last_modified = response.headers.get("Last-Modified")
    if not etag and not last_modified:
        return {}
    last_updated = datetime.now(timezone.utc).strftime(DATE_FORMAT)
    return {LAST_RUN_KEY: {"etag": etag, "last_modified": last_modified, "last_updated": last_updated}}


def test_module(client: Client) -> str:
    """Checks that the export can be downloaded, without reading the whole file."""
    response = client.download_export(stream=True)
    response.close()
    return "ok"


def fetch_indicators_command(client: Client, params: dict) -> None:
    response = client.download_export(headers=get_conditional_headers(demisto.getLastRun()))
    if response.status_code == 304:
        demisto.debug("The URLhaus export did not change since the last fetch.")
        demisto.createIndicators([], noUpdate=True)
        return

    indicators = build_indicators(response.content, params, params.get("enrichmentExcluded", False))
    demisto.debug(f"Fetched {len(indicators)} indicators from the URLhaus export.")
    if not indicators:
        demisto.createIndicators([], noUpdate=False)
    for indicators_batch in batch(indicators, batch_size=CREATE_INDICATORS_BATCH_SIZE):
        demisto.createIndicators(indicators_batch, noUpdate=False)

    # Set after the indicators are created, so a failed fetch is not skipped as unchanged next time.
    # Replacing the whole lastRun also drops entries saved by older versions under the request URL.
    demisto.setLastRun(build_last_run(response))


def get_indicators_command(client: Client, params: dict, args: dict) -> CommandResults:
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_INDICATORS_LIMIT
    enrichment_excluded = params.get("enrichmentExcluded", False) or (
        params.get("tlp_color") == "RED" and is_xsiam_or_xsoar_saas()
    )
    response = client.download_export()
    indicators = build_indicators(response.content, params, enrichment_excluded, limit)
    readable_output = tableToMarkdown("Indicators", indicators, headers=["value", "type", "fields"])
    return CommandResults(readable_output=readable_output, raw_response=indicators)


def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        auth_key = params.get("credentials", {}).get("password")
        if not auth_key:
            raise ValueError("Missing required parameter Auth Key. Please set this parameter in the instance configuration.")
        # The Auth-Key is part of the request URL, so mask it in any log or error message.
        add_sensitive_log_strs(auth_key)

        if command in FETCH_INTERVAL_VALIDATED_COMMANDS:
            validate_fetch_interval(params.get("feedFetchInterval"))

        client = Client(auth_key, verify=not params.get("insecure", False), proxy=params.get("proxy", False))
        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-indicators":
            fetch_indicators_command(client, params)
        elif command == "urlhaus-get-indicators":
            return_results(get_indicators_command(client, params, demisto.args()))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {e!s}")


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()

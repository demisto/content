import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from ContentClientApiModule import *  # noqa: F401,F403

import csv
import re
import traceback
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from itertools import islice

import httpx

BASE_URL = "https://netapi.com/api2/"
COMMAND_PREFIX = "netapi"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_TIMEOUT_SECONDS = 120
# Refetch the full list at least this often, even when it is unchanged, so the indicators do not expire.
FULL_REFRESH_SECONDS = 43200  # 12 hours
CREATE_INDICATORS_BATCH_SIZE = 2000
DEFAULT_GET_INDICATORS_LIMIT = 50

LIST_DOMAINS = "Compromised domains"
LIST_DOMAINS_NO_SINKHOLES = "Compromised domains without sinkholed malware domains"
LIST_IPS = "Honeypot attacker IPs"

LIST_QUERIES = {
    LIST_DOMAINS: {"method": "compromised", "dataset_type": "url", "format": "csv"},
    LIST_DOMAINS_NO_SINKHOLES: {"method": "compromised", "dataset_type": "url", "format": "csv", "sinkholes": "0"},
    LIST_IPS: {"method": "compromised", "dataset_type": "ip", "format": "csv"},
}

DOMAIN_COLUMNS = ["domain", "threat_type", "evidence", "first_seen", "last_seen"]
# Threat categories of the NetAPI threat types of the domain list.
DOMAIN_THREAT_CATEGORIES = {"cert-polska": "Phishing", "related-phishing": "Phishing", "sinkhole-ns": "Malware"}
IP_COLUMNS = ["ip", "first_seen", "last_seen", "category", "top_threat", "threats", "country", "asn", "as_name", "sensors"]

# The lists carry dates as YYYY-MM-DD (domains) or YYYY-MM-DDTHH:MM:SSZ (IP addresses), so no date parser is needed.
DATE_ONLY_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DATE_TIME_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class Client(ContentClient):
    def __init__(self, verify: bool, proxy: bool, timeout: int):
        super().__init__(base_url=BASE_URL, verify=verify, proxy=proxy, timeout=timeout, client_name="FeedNetAPI")

    def download_list(self, list_name: str, headers: dict | None = None) -> httpx.Response:
        """Downloads a list. The response is read in full, its status is 304 when the list did not change.

        A download that breaks off before the announced Content-Length raises an error (after the retries),
        so a cut list is never taken for a complete one.
        """
        response = self._http_request(
            "GET",
            params=LIST_QUERIES[list_name],
            headers=headers,
            ok_codes=(200, 304),
            resp_type="response",
            timeout=self.timeout,
        )
        # The client passes other 2xx answers too (for example 206), and only a full 200 answer is a whole list.
        if response.status_code not in (200, 304):
            raise DemistoException(f"Unexpected HTTP status {response.status_code} from NetAPI for the list {list_name}.")
        return response


def get_list_name(params: dict) -> str:
    """Returns the list chosen in the instance configuration, the compromised domains by default."""
    list_name = params.get("list") or LIST_DOMAINS
    if list_name not in LIST_QUERIES:
        raise DemistoException(f"Unknown list: {list_name}. Choose one of: {', '.join(LIST_QUERIES)}.")
    return list_name


def to_iso_date(value: str | None) -> str | None:
    """Converts a date of the lists to the format the server expects. Returns None for an empty or unexpected value."""
    if not value:
        return None
    if DATE_TIME_REGEX.match(value):
        return value
    if DATE_ONLY_REGEX.match(value):
        return f"{value}T00:00:00Z"
    return None


def remove_empty(fields: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in fields.items() if value}


def domain_fields(row: dict[str, str]) -> dict[str, Any]:
    """Maps a row of the domain list to indicator fields."""
    threat_type = row.get("threat_type")
    evidence = row.get("evidence")
    description = f"NetAPI threat type: {threat_type}." if threat_type else ""
    if evidence:
        description = f"{description} Evidence: {evidence}".strip()
    category = DOMAIN_THREAT_CATEGORIES.get(threat_type or "", threat_type)
    return remove_empty(
        {
            "threattypes": [{"threatcategory": category}] if category else None,
            "description": description,
            "firstseenbysource": to_iso_date(row.get("first_seen")),
            "lastseenbysource": to_iso_date(row.get("last_seen")),
        }
    )


def ip_fields(row: dict[str, str]) -> dict[str, Any]:
    """Maps a row of the IP address list to indicator fields."""
    top_threat = row.get("top_threat")
    threats = [threat for threat in (row.get("threats") or "").split("|") if threat]
    # The main attack type first, then the others in the order of the list.
    categories = list(dict.fromkeys(([top_threat] if top_threat else []) + threats))
    asn = row.get("asn")
    return remove_empty(
        {
            "threattypes": [{"threatcategory": category} for category in categories],
            "description": f"Attack types seen by NetAPI honeypot sensors: {', '.join(threats)}" if threats else None,
            "firstseenbysource": to_iso_date(row.get("first_seen")),
            "lastseenbysource": to_iso_date(row.get("last_seen")),
            "geocountry": row.get("country"),
            "asn": f"AS{asn}" if asn else None,
            "asowner": row.get("as_name"),
        }
    )


def build_indicator(row: dict[str, str], list_name: str, params: dict, enrichment_excluded: bool) -> dict | None:
    """Builds an indicator from a row of a list. Returns None for a row without a value."""
    is_ip_list = list_name == LIST_IPS
    value = (row.get("ip" if is_ip_list else "domain") or "").strip()
    if not value:
        return None
    indicator_type = FeedIndicatorType.IP if is_ip_list else FeedIndicatorType.Domain
    fields = ip_fields(row) if is_ip_list else domain_fields(row)
    fields["tags"] = argToList(params.get("feedTags"))
    if params.get("tlp_color"):
        fields["trafficlightprotocol"] = params["tlp_color"]

    # Cells beyond the header are stored by the CSV reader under the key None, they are left out.
    raw_json: dict[str, Any] = {key: cell for key, cell in row.items() if key is not None}
    raw_json.update({"value": value, "type": indicator_type})
    indicator: dict[str, Any] = {
        "value": value,
        "type": indicator_type,
        "rawJSON": raw_json,
        "fields": fields,
        "relationships": [],
    }
    if enrichment_excluded:
        indicator["enrichmentExcluded"] = enrichment_excluded
    return indicator


def iter_indicators(
    lines: Iterable[str], list_name: str, params: dict, enrichment_excluded: bool, limit: int = 0
) -> Iterator[dict]:
    """Parses the CSV lines of a list (the first line is the header) into indicators. A limit of 0 means no limit."""
    expected_columns = IP_COLUMNS if list_name == LIST_IPS else DOMAIN_COLUMNS
    reader = csv.DictReader(lines)
    if not reader.fieldnames:
        raise DemistoException("The NetAPI list is empty: no header line was received.")
    # Columns added at the end of the list later are ignored.
    if list(reader.fieldnames[: len(expected_columns)]) != expected_columns:
        raise DemistoException(f"Unexpected columns in the NetAPI list: {reader.fieldnames}. Expected: {expected_columns}.")
    count = 0
    for row in reader:
        indicator = build_indicator(row, list_name, params, enrichment_excluded)
        if not indicator:
            continue
        yield indicator
        count += 1
        if limit and count >= limit:
            return


def iter_batches(items: Iterable[dict], batch_size: int) -> Iterator[list[dict]]:
    """Yields lists of up to batch_size items from any iterable, without materializing it."""
    iterator = iter(items)
    while chunk := list(islice(iterator, batch_size)):
        yield chunk


def content_lines(content: bytes) -> list[str]:
    """Splits a whole downloaded list into lines. Only line feeds end a line, a trailing carriage return is removed."""
    text = content.decode("utf-8-sig")
    return [line.removesuffix("\r") for line in text.split("\n")]


def get_conditional_headers(last_run: dict, list_name: str) -> dict:
    """Builds the If-None-Match and If-Modified-Since headers, unless the list changed or a full refresh is due."""
    if last_run.get("list") != list_name:
        return {}
    last_updated = last_run.get("last_updated")
    if last_updated and has_passed_time_threshold(timestamp_str=last_updated, seconds_threshold=FULL_REFRESH_SECONDS):
        demisto.debug("The NetAPI list was not refetched for a long time, so it is fetched in full to keep indicators alive.")
        return {}
    headers = {}
    if last_run.get("etag"):
        headers["If-None-Match"] = last_run["etag"]
    if last_run.get("last_modified"):
        headers["If-Modified-Since"] = last_run["last_modified"]
    return headers


def build_last_run(response: httpx.Response, list_name: str) -> dict:
    """Builds the lastRun from the response caching headers. Returns an empty dict if there are none."""
    etag = response.headers.get("ETag")
    last_modified = response.headers.get("Last-Modified")
    if not etag and not last_modified:
        return {}
    last_updated = datetime.now(timezone.utc).strftime(DATE_FORMAT)
    return {"list": list_name, "etag": etag, "last_modified": last_modified, "last_updated": last_updated}


def is_enrichment_excluded(params: dict) -> bool:
    return params.get("enrichmentExcluded", False) or (params.get("tlp_color") == "RED" and is_xsiam_or_xsoar_saas())


def test_module(client: Client, list_name: str, params: dict) -> str:
    """Checks that the list can be downloaded and has the expected columns."""
    response = client.download_list(list_name)
    list(iter_indicators(content_lines(response.content), list_name, params, False, limit=1))
    return "ok"


def fetch_indicators_command(client: Client, list_name: str, params: dict) -> int:
    """Fetches the whole list and creates its indicators in batches. Returns the number of indicators created."""
    response = client.download_list(list_name, headers=get_conditional_headers(demisto.getLastRun(), list_name))
    if response.status_code == 304:
        demisto.debug(f"The NetAPI list {list_name} did not change since the last fetch.")
        demisto.createIndicators([], noUpdate=True)
        return 0

    # The whole list (about 20 MB) is downloaded before any indicator is created, so a download that breaks off
    # or a response without the header never replaces the indicators of the last complete fetch.
    lines = content_lines(response.content)

    total = 0
    indicators = iter_indicators(lines, list_name, params, is_enrichment_excluded(params))
    for indicators_batch in iter_batches(indicators, CREATE_INDICATORS_BATCH_SIZE):
        demisto.createIndicators(indicators_batch, noUpdate=False)
        total += len(indicators_batch)
    if not total:
        demisto.createIndicators([], noUpdate=False)

    demisto.debug(f"Fetched {total} indicators from the NetAPI list {list_name}.")
    # Set after the indicators are created, so a failed fetch is not skipped as unchanged next time.
    demisto.setLastRun(build_last_run(response, list_name))
    return total


def get_indicators_command(client: Client, list_name: str, params: dict, args: dict) -> CommandResults:
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_INDICATORS_LIMIT
    response = client.download_list(list_name)
    indicators = list(
        iter_indicators(content_lines(response.content), list_name, params, is_enrichment_excluded(params), limit=limit)
    )
    readable_output = tableToMarkdown("Indicators", indicators, headers=["value", "type", "fields"])
    return CommandResults(readable_output=readable_output, raw_response=indicators)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        list_name = get_list_name(params)
        timeout = arg_to_number(params.get("polling_timeout")) or DEFAULT_TIMEOUT_SECONDS
        client = Client(verify=not params.get("insecure", False), proxy=params.get("proxy", False), timeout=timeout)
        if command == "test-module":
            return_results(test_module(client, list_name, params))
        elif command == "fetch-indicators":
            fetch_indicators_command(client, list_name, params)
        elif command == f"{COMMAND_PREFIX}-get-indicators":
            return_results(get_indicators_command(client, list_name, params, demisto.args()))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        demisto.debug(traceback.format_exc())
        return_error(f"Failed to execute {command} command. Error: {e!s}", error=e)


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()

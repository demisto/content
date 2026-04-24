import http
import json
import math
from json import JSONDecodeError
from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *

urllib3.disable_warnings()

DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_INTERVAL = 30  # 30 minutes
DEFAULT_FIRST_FETCH = "3 days"
EXECUTION_TIMEOUT_SECONDS = 1200  # 20 minutes
MAX_LIMIT_SIZE_PER_EXEC = 100000
PAGE_SIZE = 5000
RETRIES = 3
BACKOFF_FACTOR = 5  # seconds: 5, 10, 20 between retries
STATUS_LIST_TO_RETRY = [429, 503]

IOC_TYPE_MAPPING = {
    "IP": "ipv4",
    "Domain": "domain",
    "URL": "url",
    "File": ["sha256", "sha1", "md5"],
}

ACTIVITY_MAPPING = {
    "malware_payload": "Malware",
    "cnc_server": "CnC Server",
    "infected_machine": "Compromised Host",
    "phishing_website": "Phishing",
    "payload_delivery": "Infecting URL",
    "cc_skimming": "Malicious",
    "botnet": "Botnet",
    "anonymization": "Anonymizer",
}

SEVERITY_MAP = {
    1: "Low",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
}


class Client(BaseClient):
    """
    Client to use in the Cyberint Premium Feed integration.
    """

    def __init__(
        self,
        base_url: str,
        access_token: str,
        verify: bool = False,
        proxy: bool = False,
    ):
        params = demisto.params()
        self._cookies = {"access_token": access_token}
        self._headers = {
            "X-Integration-Type": "XSOAR",
            "X-Integration-Instance-Name": demisto.integrationInstance(),
            "X-Integration-Instance-Id": "",
            "X-Integration-Customer-Name": params.get("client_name", ""),
            "X-Integration-Version": str(get_pack_version()),
        }
        super().__init__(base_url, verify=verify, proxy=proxy, headers=self._headers)

    @logger
    def fetch_feed_page(
        self,
        filters: dict[str, Any],
        limit: int,
        offset: int,
        sort_field: str = "last_seen",
        sort_direction: str = "desc",
    ) -> list[dict[str, Any]]:
        """
        Fetches a single page of indicators from the premium feed.

        Args:
            filters: Filter parameters for the API request.
            limit: The maximum number of entries to retrieve.
            offset: Pagination offset.
            sort_field: Field to sort by.
            sort_direction: Sort direction (asc/desc).

        Returns:
            A list of raw indicator dicts for this page.
        """
        return self.process_feed_response(filters, limit, offset, sort_field, sort_direction)

    def process_feed_response(
        self,
        filters: dict[str, Any],
        limit: int,
        offset: int,
        sort_field: str = "last_seen",
        sort_direction: str = "desc",
    ) -> list[dict[str, Any]]:
        """
        Makes the API request and processes the JSONL feed response.

        Args:
            filters: Filter parameters for the API request.
            limit: The maximum number of entries to retrieve per request.
            offset: The offset for pagination.
            sort_field: Field to sort by.
            sort_direction: Sort direction.

        Returns:
            A list of indicator dictionaries.
        """
        result: list[Any] = []
        response = self.retrieve_indicators_from_api(filters, limit, offset, sort_field, sort_direction)

        try:
            feeds = response.strip().split("\n")
            ioc_feeds = [json.loads(feed) for feed in feeds if feed.strip()]
        except JSONDecodeError as e:
            demisto.error(f"Failed to decode JSON: {e}")
            return result

        if not ioc_feeds:
            demisto.debug("No more indicators found")
            return result

        for indicator in ioc_feeds:
            ioc_value = indicator.get("indicator_value")
            if auto_detect_indicator_type(ioc_value):
                result.append(indicator)

        return result

    @logger
    def retrieve_indicators_from_api(
        self,
        filters: dict[str, Any],
        limit: int,
        offset: int,
        sort_field: str = "last_seen",
        sort_direction: str = "desc",
    ) -> str:
        """
        Makes a POST request to the premium feed JSONL endpoint.

        Args:
            filters: Filter parameters.
            limit: Number of results to return.
            offset: Pagination offset.
            sort_field: Field to sort by.
            sort_direction: Sort direction.

        Returns:
            Raw JSONL response text.
        """
        url_suffix = "/ioc-intel/feed-api/v1/feed/jsonl"
        body: dict[str, Any] = {
            "filters": filters,
            "pagination": {"limit": limit, "offset": offset},
            "sort": {"field": sort_field, "direction": sort_direction},
        }
        demisto.debug(f"URL to fetch premium indicators: {url_suffix}, body: {json.dumps(body)}")
        response = self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=body,
            cookies=self._cookies,
            resp_type="text",
            timeout=120,
            retries=RETRIES,
            status_list_to_retry=STATUS_LIST_TO_RETRY,
            backoff_factor=BACKOFF_FACTOR,
        )
        return response

    @logger
    def count_indicators(self, filters: dict[str, Any]) -> int:
        """
        Returns count of indicators matching the given filters.

        Args:
            filters: Filter parameters.

        Returns:
            Count of matching indicators.
        """
        url_suffix = "/ioc-intel/feed-api/v1/feed/count"
        demisto.debug(f"URL to count premium indicators: {url_suffix}")
        response = self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=filters,
            cookies=self._cookies,
            timeout=120,
            retries=RETRIES,
            status_list_to_retry=STATUS_LIST_TO_RETRY,
            backoff_factor=BACKOFF_FACTOR,
        )
        return response.get("count", 0)

    @logger
    def enrich_indicator(self, indicator_type: str, value: str) -> dict[str, Any]:
        """
        Enriches a single IOC via the enrichment API.

        Args:
            indicator_type: The IOC type (ipv4, domain, url, sha256, sha1, md5).
            value: The indicator value.

        Returns:
            Enriched IOC data.
        """
        url_suffix = "/ioc-intel/enrichment-api/v1/enrichment"
        body = {"type": indicator_type, "value": value}
        demisto.debug(f"Enriching indicator: {indicator_type}={value}")
        response = self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=body,
            cookies=self._cookies,
            timeout=120,
            retries=RETRIES,
            status_list_to_retry=STATUS_LIST_TO_RETRY,
            backoff_factor=BACKOFF_FACTOR,
        )
        return response


def test_module(client: Client) -> str:
    """
    Builds the iterator to check that the feed is accessible.

    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    try:
        client.fetch_feed_page(filters={}, limit=10, offset=0)
    except DemistoException as exc:
        if exc.res and (exc.res.status_code == http.HTTPStatus.UNAUTHORIZED or exc.res.status_code == http.HTTPStatus.FORBIDDEN):
            return "Authorization Error: invalid `API Token`"
        raise exc

    return "ok"


def build_filters(params: dict[str, Any]) -> dict[str, Any]:
    """
    Builds the filter dictionary from integration parameters.

    Args:
        params: Integration parameters.

    Returns:
        Filter dictionary for the API request.
    """
    filters: dict[str, Any] = {}

    indicator_types = argToList(params.get("indicator_type"))
    if indicator_types and "All" not in indicator_types:
        api_types = []
        for t in indicator_types:
            mapped = IOC_TYPE_MAPPING.get(t)
            if isinstance(mapped, list):
                api_types.extend(mapped)
            elif mapped:
                api_types.append(mapped)
        if api_types:
            filters["indicator_type"] = api_types

    activities = argToList(params.get("activity"))
    if activities and "All" not in activities:
        filters["activity"] = activities

    confidence_min = arg_to_number(params.get("confidence_min"))
    if confidence_min is not None:
        filters["confidence_min"] = confidence_min

    confidence_max = arg_to_number(params.get("confidence_max"))
    if confidence_max is not None:
        filters["confidence_max"] = confidence_max

    severity_min = arg_to_number(params.get("severity_min"))
    if severity_min is not None:
        filters["severity_min"] = severity_min

    severity_max = arg_to_number(params.get("severity_max"))
    if severity_max is not None:
        filters["severity_max"] = severity_max

    malicious = params.get("malicious")
    if malicious:
        filters["malicious"] = malicious

    is_blocking = params.get("is_blocking")
    if is_blocking is not None and is_blocking != "":
        filters["is_blocking"] = argToBoolean(is_blocking)

    is_unique = params.get("is_unique")
    if is_unique is not None and is_unique != "":
        filters["is_unique"] = argToBoolean(is_unique)

    has_cve = params.get("has_cve")
    if has_cve is not None and has_cve != "":
        filters["has_cve"] = argToBoolean(has_cve)

    has_campaign = params.get("has_campaign")
    if has_campaign is not None and has_campaign != "":
        filters["has_campaign"] = argToBoolean(has_campaign)

    malware_family = argToList(params.get("malware_family"))
    if malware_family:
        filters["malware_family"] = malware_family

    origin_country = argToList(params.get("origin_country"))
    if origin_country:
        filters["origin_country"] = origin_country

    targeted_country = argToList(params.get("targeted_country"))
    if targeted_country:
        filters["targeted_country"] = targeted_country

    targeted_sector = argToList(params.get("targeted_sector"))
    if targeted_sector:
        filters["targeted_sector"] = targeted_sector

    return filters


def build_filters_from_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Builds the filter dictionary from command arguments.

    Args:
        args: Command arguments.

    Returns:
        Filter dictionary for the API request.
    """
    filters: dict[str, Any] = {}

    indicator_types = argToList(args.get("indicator_type"))
    if indicator_types:
        filters["indicator_type"] = indicator_types

    activities = argToList(args.get("activity"))
    if activities:
        filters["activity"] = activities

    confidence_min = arg_to_number(args.get("confidence_min"))
    if confidence_min is not None:
        filters["confidence_min"] = confidence_min

    severity_min = arg_to_number(args.get("severity_min"))
    if severity_min is not None:
        filters["severity_min"] = severity_min

    malicious = args.get("malicious")
    if malicious:
        filters["malicious"] = malicious

    added_to_feed_after = args.get("added_to_feed_after")
    if added_to_feed_after:
        filters["added_to_feed_after"] = added_to_feed_after

    added_to_feed_before = args.get("added_to_feed_before")
    if added_to_feed_before:
        filters["added_to_feed_before"] = added_to_feed_before

    return filters


def raw_to_indicator(item: dict[str, Any], tlp_color: str, feed_tags: list) -> dict[str, Any] | None:
    """
    Converts a raw API item to an XSOAR indicator object.

    Args:
        item: Raw indicator dict from the API.
        tlp_color: TLP designation.
        feed_tags: Tags to assign.

    Returns:
        XSOAR indicator dict, or None if the value is not a valid indicator.
    """
    indicator_value = item.get("indicator_value")
    if not indicator_value:
        return None

    indicator_type = auto_detect_indicator_type(indicator_value)
    if not indicator_type:
        return None

    severity = item.get("severity", 1)

    indicator_obj = {
        "type": indicator_type,
        "value": indicator_value,
        "service": "Cyberint Premium Feed",
        "rawJSON": item,
        "fields": {
            "reportedby": "Cyberint",
            "firstseenbysource": item.get("first_seen"),
            "lastseenbysource": item.get("last_seen"),
            "activity": item.get("activity"),
            "confidence": item.get("confidence"),
            "severity": SEVERITY_MAP.get(severity, "Unknown"),
            "malicious": item.get("malicious"),
            "killchainphases": item.get("kill_chain_stage"),
            "indicatoridentification": item.get("indicator_type"),
            "isblocking": item.get("is_blocking"),
            "isunique": item.get("is_unique"),
            "malwaretypes": item.get("malware_types"),
            "hascve": item.get("has_cve"),
            "hascampaign": item.get("has_campaign"),
            "validuntil": item.get("valid_until"),
        },
    }

    if feed_tags:
        indicator_obj["fields"]["tags"] = feed_tags

    if tlp_color:
        indicator_obj["fields"]["trafficlightprotocol"] = tlp_color

    return indicator_obj


def fetch_indicators_with_publish(
    client: Client,
    tlp_color: str,
    filters: dict[str, Any],
    feed_tags: list,
) -> int:
    """
    Fetches indicators page by page and publishes each page immediately
    via demisto.createIndicators(), to avoid timeout on large feeds.

    Args:
        client: API Client.
        tlp_color: TLP designation.
        filters: Filter dictionary for the API request.
        feed_tags: Tags to assign fetched indicators.

    Returns:
        Total number of indicators published.
    """
    ctx = demisto.getIntegrationContext()
    offset = ctx.get("offset", 0)
    init_offset = offset
    total_published = 0
    execution_start_time = datetime.now()

    demisto.debug(f"Fetching premium indicators, starting offset {offset}, filters: {json.dumps(filters)}")

    while True:
        if offset >= init_offset + MAX_LIMIT_SIZE_PER_EXEC:
            demisto.debug(f"Reached max limit per execution at offset {offset}, saving for next run")
            ctx["offset"] = offset
            demisto.setIntegrationContext(ctx)
            break

        if is_execution_time_exceeded(start_time=execution_start_time):
            demisto.debug(f"Execution time exceeded at offset {offset}, saving for next run")
            ctx["offset"] = offset
            demisto.setIntegrationContext(ctx)
            break

        start_time = time.time()

        raw_indicators = client.fetch_feed_page(
            filters=filters,
            limit=PAGE_SIZE,
            offset=offset,
            sort_field="added_to_feed",
            sort_direction="desc",
        )

        if not raw_indicators:
            demisto.debug(f"No more indicators at offset {offset}, page complete")
            # All done — save timestamp for next incremental fetch and reset offset
            ctx["offset"] = 0
            ctx["last_fetch_time"] = execution_start_time.strftime(DATETIME_FORMAT)
            demisto.setIntegrationContext(ctx)
            break

        # Transform and publish this page immediately
        indicators = []
        for item in raw_indicators:
            indicator_obj = raw_to_indicator(item, tlp_color, feed_tags)
            if indicator_obj:
                indicators.append(indicator_obj)

        if indicators:
            demisto.debug(f"Publishing {len(indicators)} indicators from offset {offset}")
            demisto.createIndicators(indicators)
            total_published += len(indicators)

        duration = math.ceil(time.time() - start_time)
        demisto.debug(f"Page at offset {offset}: {len(raw_indicators)} raw, {len(indicators)} published in {duration}s")

        offset += PAGE_SIZE

    return total_published


def get_indicators_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Wrapper for retrieving indicators from the premium feed to the war-room.

    Args:
        client: Cyberint API Client.
        args: Command arguments.

    Returns:
        Outputs indicators.
    """
    limit = int(args.get("limit", 50))
    offset = int(args.get("offset", 0))

    filters = build_filters_from_args(args)

    indicators = client.process_feed_response(
        filters=filters,
        limit=limit,
        offset=offset,
        sort_field=args.get("sort_field", "last_seen"),
        sort_direction=args.get("sort_direction", "desc"),
    )

    human_readable = tableToMarkdown(
        "Indicators from Cyberint Premium Feed:",
        indicators,
        headers=[
            "indicator_type",
            "indicator_value",
            "activity",
            "confidence",
            "severity",
            "malicious",
            "kill_chain_stage",
            "first_seen",
            "last_seen",
            "added_to_feed",
        ],
        headerTransform=premium_header_transformer,
        removeNull=False,
    )

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="CyberintPremium.indicator",
        outputs_key_field="indicator_value",
        raw_response=indicators,
        outputs=indicators,
    )


def get_indicators_count_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Returns count of indicators matching the given filters.

    Args:
        client: Cyberint API Client.
        args: Command arguments.

    Returns:
        Count of matching indicators.
    """
    filters = build_filters_from_args(args)
    count = client.count_indicators(filters)

    return CommandResults(
        readable_output=f"Total indicators matching filters: {count}",
        outputs_prefix="CyberintPremium.count",
        outputs_key_field="count",
        raw_response={"count": count},
        outputs={"count": count},
    )


def enrich_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Enriches a single IOC indicator.

    Args:
        client: Cyberint API Client.
        args: Command arguments (type, value).

    Returns:
        Enrichment results.
    """
    indicator_type = args.get("type", "")
    value = args.get("value", "")

    data = client.enrich_indicator(indicator_type, value)

    enrichment = data.get("enrichment") or {}

    # Build base info table
    base_info = {
        "indicator_type": data.get("indicator_type"),
        "indicator_value": data.get("indicator_value"),
        "activity": data.get("activity"),
        "confidence": data.get("confidence"),
        "severity": data.get("severity"),
        "malicious": data.get("malicious"),
        "kill_chain_stage": data.get("kill_chain_stage"),
        "first_seen": data.get("first_seen"),
        "last_seen": data.get("last_seen"),
        "valid_until": data.get("valid_until"),
        "malware_family": data.get("malware_family"),
    }

    human_readable = tableToMarkdown(
        "Indicator Details",
        [base_info],
        headers=[
            "indicator_type",
            "indicator_value",
            "activity",
            "confidence",
            "severity",
            "malicious",
            "kill_chain_stage",
            "first_seen",
            "last_seen",
            "valid_until",
            "malware_family",
        ],
        headerTransform=premium_header_transformer,
        removeNull=True,
    )

    # Threat intelligence section
    threat_intel = {}
    for field in (
        "malware_types",
        "origin_countries",
        "targeted_countries",
        "targeted_sectors",
        "targeted_brands",
        "threat_actors",
        "campaigns",
        "cves",
        "tags",
    ):
        val = data.get(field)
        if val:
            threat_intel[field] = ", ".join(val) if isinstance(val, list) else val

    if threat_intel:
        human_readable += tableToMarkdown(
            "Threat Intelligence",
            [threat_intel],
            headerTransform=premium_header_transformer,
            removeNull=True,
        )

    # TTPs section
    ttps = data.get("ttps", [])
    if ttps:
        ttps_formatted = [{"mitre_id": t.get("mitre_id"), "title": t.get("title")} for t in ttps]
        human_readable += tableToMarkdown(
            "TTPs",
            ttps_formatted,
            headers=["mitre_id", "title"],
            headerTransform=premium_header_transformer,
            removeNull=True,
        )

    # Type-specific enrichment section
    if enrichment:
        if indicator_type == "ipv4":
            geo = enrichment.get("geo") or {}
            asn = enrichment.get("asn") or {}
            enrichment_formatted = {
                "country": geo.get("country"),
                "city": geo.get("city"),
                "asn_number": asn.get("number"),
                "asn_organization": asn.get("organization"),
            }
            human_readable += tableToMarkdown(
                "IPv4 Enrichment",
                [enrichment_formatted],
                headerTransform=premium_header_transformer,
                removeNull=True,
            )

        elif indicator_type == "domain":
            whois = enrichment.get("whois") or {}
            enrichment_formatted = {
                "ips": ", ".join(enrichment.get("ips", [])),
            }
            enrichment_formatted.update(whois)
            human_readable += tableToMarkdown(
                "Domain Enrichment",
                [enrichment_formatted],
                headerTransform=premium_header_transformer,
                removeNull=True,
            )

        elif indicator_type == "url":
            whois = enrichment.get("whois") or {}
            enrichment_formatted = {
                "ips": ", ".join(enrichment.get("ips", [])),
                "hostname": enrichment.get("hostname"),
                "domain": enrichment.get("domain"),
            }
            enrichment_formatted.update(whois)
            human_readable += tableToMarkdown(
                "URL Enrichment",
                [enrichment_formatted],
                headerTransform=premium_header_transformer,
                removeNull=True,
            )

        elif indicator_type in ("sha256", "sha1", "md5"):
            enrichment_formatted = {
                "filenames": ", ".join(enrichment.get("filenames", [])),
                "download_urls": ", ".join(enrichment.get("download_urls", [])),
            }
            human_readable += tableToMarkdown(
                "File Hash Enrichment",
                [enrichment_formatted],
                headerTransform=premium_header_transformer,
                removeNull=True,
            )

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="CyberintPremium.enrichment",
        outputs_key_field="indicator_value",
        raw_response=data,
        outputs=data,
    )


def fetch_indicators_command(
    client: Client,
    params: dict[str, Any],
) -> None:
    """
    Fetches indicators from the premium feed page by page,
    publishing each page immediately to avoid timeout.

    Uses incremental fetching: on first run, fetches indicators from the
    configured "First Fetch" window. On subsequent runs, only fetches
    indicators added since the last successful fetch.

    Args:
        client: Cyberint API Client.
        params: Integration parameters.
    """
    feed_enabled = params.get("feed", True)
    if not feed_enabled:
        demisto.debug("Feed is disabled, skipping fetch")
        return

    tlp_color = params.get("tlp_color", "")
    feed_tags = argToList(params.get("feedTags"))
    filters = build_filters(params)

    ctx = demisto.getIntegrationContext()
    last_fetch_time = ctx.get("last_fetch_time")

    if last_fetch_time:
        # Incremental fetch: only new indicators since last run
        filters["added_to_feed_after"] = last_fetch_time
        demisto.debug(f"Incremental fetch: added_to_feed_after={last_fetch_time}")
    else:
        # First fetch: use configured window
        first_fetch = params.get("first_fetch", DEFAULT_FIRST_FETCH)
        first_fetch_dt = dateparser.parse(f"{first_fetch} ago")
        if first_fetch_dt:
            filters["added_to_feed_after"] = first_fetch_dt.strftime(DATETIME_FORMAT)
            demisto.debug(f"First fetch: added_to_feed_after={filters['added_to_feed_after']}")

    total = fetch_indicators_with_publish(
        client=client,
        tlp_color=tlp_color,
        filters=filters,
        feed_tags=feed_tags,
    )
    demisto.debug(f"Fetch indicators completed, total published: {total}")


def premium_header_transformer(header: str) -> str:
    """
    Returns a correct header for premium feed fields.
    """
    header_map = {
        "indicator_type": "Indicator Type",
        "indicator_value": "Indicator Value",
        "activity": "Activity",
        "confidence": "Confidence",
        "severity": "Severity",
        "malicious": "Malicious",
        "kill_chain_stage": "Kill Chain Stage",
        "first_seen": "First Seen",
        "last_seen": "Last Seen",
        "added_to_feed": "Added to Feed",
        "valid_until": "Valid Until",
        "is_blocking": "Is Blocking",
        "prevention_valid_until": "Prevention Valid Until",
        "is_unique": "Is Unique",
        "malware_types": "Malware Types",
        "has_cve": "Has CVE",
        "has_campaign": "Has Campaign",
        "malware_family": "Malware Family",
        "origin_countries": "Origin Countries",
        "targeted_countries": "Targeted Countries",
        "targeted_sectors": "Targeted Sectors",
        "targeted_brands": "Targeted Brands",
        "threat_actors": "Threat Actors",
        "campaigns": "Campaigns",
        "cves": "CVEs",
        "tags": "Tags",
        "ttps": "TTPs",
        "mitre_id": "MITRE ID",
        "title": "Title",
        "ips": "IPs",
        "country": "Country",
        "city": "City",
        "asn_number": "ASN Number",
        "asn_organization": "ASN Organization",
        "hostname": "Hostname",
        "domain": "Domain",
        "filenames": "Filenames",
        "download_urls": "Download URLs",
        "registrant_name": "Registrant Name",
        "registrant_email": "Registrant Email",
        "registrant_organization": "Registrant Organization",
        "registrant_country": "Registrant Country",
        "registrant_telephone": "Registrant Telephone",
        "technical_contact_email": "Technical Contact Email",
        "technical_contact_name": "Technical Contact Name",
        "technical_contact_organization": "Technical Contact Organization",
        "registrar_name": "Registrar Name",
        "admin_contact_name": "Admin Contact Name",
        "admin_contact_organization": "Admin Contact Organization",
        "admin_contact_email": "Admin Contact Email",
        "created_date": "Created Date",
        "updated_date": "Updated Date",
        "expiration_date": "Expiration Date",
    }
    return header_map.get(header, string_to_table_header(header))


@logger
def is_execution_time_exceeded(start_time: datetime) -> bool:
    """
    Checks if the execution time so far exceeded the timeout limit.

    Args:
        start_time: the time when the execution started.

    Returns:
        bool: true, if execution passed timeout settings, false otherwise.
    """
    end_time = datetime.now()
    secs_from_beginning = (end_time - start_time).seconds
    demisto.debug(f"Execution duration is {secs_from_beginning} secs so far")
    return secs_from_beginning > EXECUTION_TIMEOUT_SECONDS


@logger
def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()

    base_url = params.get("url")
    access_token = params.get("access_token").get("password")
    insecure = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            access_token=access_token,
            verify=insecure,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "cyberint-premium-get-indicators":
            return_results(get_indicators_command(client, args))

        elif command == "cyberint-premium-get-indicators-count":
            return_results(get_indicators_count_command(client, args))

        elif command == "cyberint-premium-enrich":
            return_results(enrich_command(client, args))

        elif command == "fetch-indicators":
            fetch_indicators_command(client, params)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()

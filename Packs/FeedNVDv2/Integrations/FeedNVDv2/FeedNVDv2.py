# pylint: disable=invalid-name,protected-access,unused-wildcard-import,wildcard-import,wrong-import-order
"""
NVD Feed Integration to retrieve CVEs from NIST NVD and parse them
into a normalized XSOAR CVE indicator data structure
for threat intelligence management
"""

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from dateparser import parse

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

# NVD API severity parameters – mutually exclusive, only one per request.
CVSS_VERSION_TO_PARAM: dict[str, str] = {
    "CVSS v4": "cvssV4Severity",
    "CVSS v3": "cvssV3Severity",
    "CVSS v2": "cvssV2Severity",
}
NVD_API_MAX_RESULTS_PER_PAGE = 2000
NVD_API_MAX_DATE_RANGE_DAYS = 120  # NVD API rejects date-range queries spanning more than 120 days.
BASE_URL: str = "https://services.nvd.nist.gov"  # disable-secrets-detection

# Recommended max indicators per fetch based on NVD rate limits. (see https://nvd.nist.gov/developers/start-here#rateLimits)
MAX_INDICATORS_WITHOUT_API_KEY = 40000
MAX_INDICATORS_WITH_API_KEY = 200000
DEFAULT_MANUAL_LIMIT = 50
DEFAULT_MANUAL_HISTORY = "7 days"


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(
        self,
        base_url: str,
        proxy: bool,
        api_key: str,
        tlp_color: str,
        has_kev: bool,
        first_fetch: str,
        feed_tags: list[str],
        cvss_severity: list[str],
        keyword_search: str,
        max_indicators: int,
        cvss_versions: list[str] | None = None,
        include_rejected: bool = False,
    ):
        super().__init__(base_url=base_url, proxy=proxy)
        self._base_url = base_url
        self.tlp_color = tlp_color
        self.proxy = proxy
        self.api_key = api_key
        self.has_kev = has_kev
        self.feed_tags = feed_tags
        self.first_fetch = first_fetch
        self.cvss_severity = cvss_severity
        self.keyword_search = keyword_search
        self.cvss_versions = cvss_versions
        self.max_indicators = max_indicators
        self.include_rejected = include_rejected

    def get_cves(self, path: str, params: dict, severity_param: str = "", severity_value: str = ""):  # pragma: no cover
        """
        Perform a basic HTTP call using specified headers and parameters.

        Args:
            path: URL suffix for the API endpoint.
            params: Base query parameters.
            severity_param: Optional NVD severity parameter name
                (e.g. ``"cvssV3Severity"``).
            severity_value: Optional severity level value
                (e.g. ``"HIGH"``).
        """

        if self.api_key:
            headers = {"apiKey": self.api_key}
        else:
            headers = {}

        param_string = self.build_param_string(params, severity_param=severity_param, severity_value=severity_value)

        demisto.debug(f"Calling NIST NVD with the following parameters {param_string}")
        return self._http_request(
            "GET", url_suffix=path, headers=headers, params=param_string, resp_type="json", timeout=300, retries=3
        )

    def build_param_string(self, params: dict, severity_param: str = "", severity_value: str = "") -> str:
        """Builds a query-string from *params*, optionally adding a single
        CVSS severity filter.

        The NVD API's ``cvssV2Severity``, ``cvssV3Severity`` and
        ``cvssV4Severity`` parameters are **mutually exclusive** – only one
        may appear per request.  The caller is responsible for passing the
        correct *severity_param* name (e.g. ``"cvssV3Severity"``).

        Args:
            params: The base URL parameters.
            severity_param: The NVD severity query-parameter name
                (e.g. ``"cvssV3Severity"``).
            severity_value: The severity level value
                (e.g. ``"HIGH"``).

        Returns:
            The assembled query-string.
        """

        param_string: str = "&".join([f"{key}={value}" for key, value in params.items()])
        param_string = param_string.replace("noRejected=None", "noRejected")
        param_string = param_string.replace("hasKev=True", "hasKev")

        if severity_param and severity_value:
            param_string += f"&{severity_param}={severity_value}"

        return param_string


def _select_primary_cvss_entry(cvss_entries: list[dict]) -> dict:
    """Return the Primary (NIST/NVD) CVSS entry when available, otherwise the first.

    The NVD API marks NIST's own assessment as ``type: "Primary"`` and
    CNA/vendor assessments as ``type: "Secondary"``.  The API's severity
    filters operate on the Primary score, so we must prefer it to keep
    displayed scores consistent with the filter.
    """
    if not cvss_entries:
        return {}
    return next(
        (entry for entry in cvss_entries if entry.get("type") == "Primary"),
        cvss_entries[0],
    )


def _build_cvss_fields(metrics_data: dict, preferred_versions: list[str] | None) -> dict:
    """Resolve CVSS fields from *metrics_data* honouring *preferred_versions*.

    Args:
        metrics_data: The ``metrics`` dict from a raw NVD CVE object.
        preferred_versions: Ordered list of CVSS version labels the user
            prefers (e.g. ``["CVSS v3", "CVSS v4"]``).  ``None`` falls back
            to the default highest-available priority.

    Returns:
        A dict with keys ``cvssversion``, ``cvssscore``, ``cvssvector``,
        ``sourceoriginalseverity``, and ``cvsstable`` populated from the
        resolved CVSS entry, or an empty dict when no CVSS data is present.
    """
    cvss_version, score, _severity = get_cvss_version_and_score(metrics_data, preferred_versions=preferred_versions)
    if not cvss_version:
        return {}

    fields: dict = {
        "cvssversion": cvss_version,
        "cvssscore": score,
        "sourceoriginalseverity": score,
    }

    cvss_metric = _VERSION_STRING_TO_METRIC_KEY.get(cvss_version, "")
    table: list[dict] = []
    if cvss_metric:
        cvss_entry = _select_primary_cvss_entry(metrics_data.get(cvss_metric, []))
        cvss_data = cvss_entry.get("cvssData", {})
        fields["cvssvector"] = cvss_data.get("vectorString")
        for key, value in cvss_entry.items():
            if key == "cvssData":
                table.extend({"metrics": str(k), "value": v} for k, v in cvss_data.items())
            else:
                table.append({"metrics": str(key), "value": value})

    fields["cvsstable"] = table
    return fields


def build_indicators(client: Client, raw_cves: List[dict], preferred_versions: list[str] | None = None):
    """Iteratively processes the retrieved CVEs and parses them into XSOAR indicator dicts.

    Args:
        client: Integration client instance.
        raw_cves: CVEs retrieved using the retrieve_cves function.
        preferred_versions: Optional ordered list of CVSS version labels
            (e.g. ``["CVSS v3", "CVSS v4"]``) that controls which score is
            displayed.  When provided, the first version with available data
            wins.  Falls back to the default highest-available priority when
            none of the preferred versions have data.

    Returns:
        list: Parsed indicator dicts ready for XSOAR ingestion.
    """
    indicators = []

    for cve in raw_cves:
        raw_cve = cve.get("cve", {})
        cpes: list[dict] = []
        refs: list[dict] = []

        indicator: dict = {"value": raw_cve.get("id")}
        descriptions = raw_cve.get("descriptions", [])
        description = descriptions[0].get("value") if descriptions else ""
        fields: dict = {
            "description": description,
            "cvemodified": raw_cve.get("lastModified"),
            "published": raw_cve.get("published"),
            "updateddate": raw_cve.get("lastModified"),
            "vulnerabilities": raw_cve.get("weaknesses"),
        }

        for ref in raw_cve.get("references"):
            refs.append({"title": indicator["value"], "source": ref.get("source"), "link": ref.get("url")})
        fields["publications"] = refs

        for conf in raw_cve.get("configurations", []):
            for node in conf["nodes"]:
                if "cpeMatch" in node:
                    cpes.extend({"CPE": cpe["criteria"]} for cpe in node["cpeMatch"])
        fields["vulnerableproducts"] = cpes

        matched_version = cve.get("_matched_cvss_version")
        effective_preferred_versions = [matched_version] if matched_version else preferred_versions
        fields.update(_build_cvss_fields(raw_cve.get("metrics") or {}, effective_preferred_versions))

        if cpes:
            tags, relationships = parse_cpe_command([d["CPE"] for d in cpes], raw_cve.get("id"))
            if client.feed_tags:
                tags.append(str(client.feed_tags))
        else:
            tags = []
            relationships = []

        fields["tags"] = tags
        fields["trafficlightprotocol"] = client.tlp_color
        indicator["relationships"] = [relationship.to_indicator() for relationship in relationships]
        indicator["type"] = FeedIndicatorType.CVE
        indicator["rawJSON"] = raw_cve
        indicator["fields"] = fields
        indicator["score"] = calculate_dbotscore(fields.get("cvssscore", -1))
        indicators.append(indicator)

    return indicators


def calculate_dbotscore(cvss) -> int:
    """Returns the correct DBot score according to the CVSS Score

    Args:
        cvss (str): The CVE cvss score

    Returns:
        int: The Dbot score of the CVE
    """

    cvss = float(cvss)

    if cvss == -1:
        return 0
    elif cvss < 4.0:
        return 1
    elif cvss < 7.0:
        return 2
    else:
        return 3


def parse_cpe_command(cpes: list[str], cve_id: str) -> tuple[list[str], list[EntityRelationship]]:
    """
    Parses a CPE to return the correct tags and relationships needed for the CVE.

    Args:
        cpe: A list representing a single CPE, see
        "https://nvlpubs.nist.gov/nistpubs/legacy/ir/nistir7695.pdf" # disable-secrets-detection

    Returns:
        A tuple consisting of a list of tags and a list of EntityRelationships.

    """

    cpe_parts = {"a": "Application", "o": "Operating-System", "h": "Hardware"}

    vendors = set()
    products = set()
    parts = set()

    for cpe in cpes:
        cpe_split = re.split(r"(?<!\\):", cpe)

        try:
            parts.add(cpe_parts[cpe_split[2]])

            if vendor := cpe_split[3].capitalize().replace("\\", "").replace("_", " "):
                vendors.add(vendor)

            if product := cpe_split[4].capitalize().replace("\\", "").replace("_", " "):
                products.add(product)

        except IndexError:
            pass

    relationships = [
        EntityRelationship(name="targets", entity_a=cve_id, entity_a_type="cve", entity_b=vendor, entity_b_type="identity")
        for vendor in vendors
    ]

    relationships.extend(
        [
            EntityRelationship(name="targets", entity_a=cve_id, entity_a_type="cve", entity_b=product, entity_b_type="software")
            for product in products
        ]
    )

    demisto.debug(f"{len(relationships)} relationships found for {cve_id}")

    return list(vendors | products | parts), relationships


def cves_to_war_room(raw_cves: list[dict], preferred_versions: list[str] | None = None) -> CommandResults:
    """Output CVEs to war room based on nvd-get-indicators.

    Displays the score from the first preferred CVSS version that has data.
    When no preferred versions are specified, falls back to newest available (v4 > v3 > v2).

    Args:
        raw_cves: List of raw CVE dicts.
        preferred_versions: CVSS version labels to prefer for score display
            (e.g. ``["CVSS v3"]``). Should match the versions used for filtering
            so the displayed score is consistent with the filter.
    """

    output_list: list[dict] = []

    for raw_cve in raw_cves:
        if not raw_cve:
            continue

        cve = raw_cve.get("cve")
        if not cve:
            continue
        descriptions = cve.get("descriptions", [])
        fields: dict[str, Any] = {"Description": descriptions[0].get("value") if descriptions else ""}
        fields["Modified"] = cve.get("lastModified")
        fields["Published"] = cve.get("published")
        fields["ID"] = cve.get("id")
        fields["CVSS"] = 0
        try:
            matched_version = raw_cve.get("_matched_cvss_version")
            effective_preferred_versions = [matched_version] if matched_version else preferred_versions
            fields["CVSSVersion"], fields["CVSS"], fields["Severity"] = get_cvss_version_and_score(
                cve.get("metrics") or {},
                preferred_versions=effective_preferred_versions,
            )
        except Exception as e:
            demisto.debug(f"Cant find CVSS score for {raw_cve}: {e}")

        output_list.append(fields)

    if not output_list:
        return CommandResults(
            readable_output="No CVE indicators were found for the given parameters.",
            raw_response=raw_cves,
        )

    return CommandResults(
        outputs=output_list,
        outputs_prefix="NistNVDv2.Indicators",
        readable_output=tableToMarkdown(
            f"CVEs ({len(output_list):,} results)",
            [
                {
                    "ID": cve["ID"].replace("-", "\u2011"),
                    "CVSS Version": cve.get("CVSSVersion", ""),
                    "Severity": cve.get("Severity", ""),
                    "Score": cve["CVSS"],
                    "Published": cve.get("Published", "")[:10],
                    "Last Modified": cve.get("Modified", "")[:10],
                    "Description": cve["Description"],
                }
                for cve in output_list
            ],
            headers=["ID", "CVSS Version", "Severity", "Score", "Published", "Last Modified", "Description"],
        ),
        outputs_key_field="ID",
        raw_response=raw_cves,
    )


# Maps CVSS version labels (as used in the config/args) to NVD metric keys.
CVSS_VERSION_TO_METRIC_KEYS: dict[str, list[str]] = {
    "CVSS v4": ["cvssMetricV40"],
    "CVSS v3": ["cvssMetricV31", "cvssMetricV30"],
    "CVSS v2": ["cvssMetricV2"],
}

# Default priority when no preferred versions are specified.
_DEFAULT_METRIC_KEY_ORDER = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]

# Reverse mapping: CVSS version string (as returned by cvssData.version) → NVD metric key.
_VERSION_STRING_TO_METRIC_KEY: dict[str, str] = {
    "4.0": "cvssMetricV40",
    "3.1": "cvssMetricV31",
    "3.0": "cvssMetricV30",
    "2.0": "cvssMetricV2",
}


def get_cvss_version_and_score(
    metrics: dict,
    preferred_versions: list[str] | None = None,
) -> tuple[str, Any, str]:
    """Return ``(version_string, base_score, severity)`` from *metrics*.

    When *preferred_versions* is provided (e.g. ``["CVSS v3", "CVSS v2"]``),
    the function looks for scores in those versions first (in order).
    Falls back to the default highest-available priority if none of the
    preferred versions have data.
    """
    # Build ordered list of metric keys to try.
    ordered_keys: list[str] = []
    if preferred_versions:
        for label in preferred_versions:
            ordered_keys.extend(CVSS_VERSION_TO_METRIC_KEYS.get(label, []))
    # Append remaining keys as fallback (preserving default priority).
    for key in _DEFAULT_METRIC_KEY_ORDER:
        if key not in ordered_keys:
            ordered_keys.append(key)

    for key in ordered_keys:
        cvss_metrics = metrics.get(key)
        cvss_entry = _select_primary_cvss_entry(cvss_metrics) if cvss_metrics else {}
        if cvss_entry:
            cvss_data = cvss_entry.get("cvssData", {})
            if cvss_data:
                # For CVSS v2, baseSeverity is at the metric entry root, not inside cvssData.
                severity = cvss_data.get("baseSeverity") or cvss_entry.get("baseSeverity", "")
                return cvss_data["version"], cvss_data["baseScore"], severity

    return "", "", ""


def test_module(client: Client) -> None:
    """
    Performs a simple API call to the NVD endpoint

    Args:
        client: An instance of the BaseClient connection class
        params: A dictionary containing HTTP parameters

    Returns:
        'ok' if a successful HTTP 200 message is returned

    """
    try:
        interval = parse_date_range("1 day", DATE_FORMAT)
        parse_date_range(client.first_fetch, DATE_FORMAT)
        client.get_cves("/rest/json/cves/2.0/", params={"pubStartDate": interval[0], "pubEndDate": interval[1]})

        if client.max_indicators is not None:
            if client.max_indicators <= 0:
                return_error("Max Indicators Per Fetch must be a positive integer.")

            cap = MAX_INDICATORS_WITH_API_KEY if client.api_key else MAX_INDICATORS_WITHOUT_API_KEY
            if client.max_indicators > cap:
                mode = "with an API key" if client.api_key else "without an API key"
                return_error(
                    f"Max Indicators Per Fetch ({client.max_indicators:,}) exceeds the recommended "
                    f"maximum of {cap:,} {mode}.\n\n"
                    f"NVD API rate limits:\n"
                    f"  • Without API key: 5 requests per 30 seconds (recommended max: {MAX_INDICATORS_WITHOUT_API_KEY:,})\n"
                    f"  • With API key: 50 requests per 30 seconds (recommended max: {MAX_INDICATORS_WITH_API_KEY:,})\n\n"
                    f"See: https://nvd.nist.gov/developers/start-here#rateLimits"
                )

        return_results("ok")

    except Exception as e:  # pylint: disable=broad-except
        return_error("Invalid API key specified in integration instance configuration" + "\nError Message: " + str(e))


def _retrieve_cves_single_query(
    client: Client,
    start_date: Any,
    end_date: Any,
    use_pub_date: bool = False,
    severity_param: str = "",
    severity_value: str = "",
    remaining_calls: list[int] | None = None,
) -> list[dict]:
    """Fetch CVE pages for a single NVD API query.

    Args:
        client: Integration client instance.
        start_date: Window start.
        end_date: Window end.
        use_pub_date: When ``True`` query by publish-date
            (``pubStartDate``/``pubEndDate``), otherwise by
            last-modified date.  First-fetch and manual commands use
            publish-date; incremental runs use last-modified.
        severity_param: Optional NVD severity parameter name
            (e.g. ``"cvssV3Severity"``).
        severity_value: Optional severity level value
            (e.g. ``"HIGH"``).
        remaining_calls: A mutable single-element list ``[n]`` that
            tracks how many API calls are still allowed in this fetch
            round.  Each call decrements ``remaining_calls[0]``.
            When it reaches 0 pagination stops.  ``None`` means
            unlimited.

    Returns:
        A list of raw CVE vulnerability dicts.
    """
    url_suffix = "/rest/json/cves/2.0/"
    results_per_page = NVD_API_MAX_RESULTS_PER_PAGE
    param: dict[str, str | int] = {"startIndex": 0, "resultsPerPage": results_per_page}
    if not client.include_rejected:
        param["noRejected"] = ""
    raw_cves: list[dict] = []
    more_to_process = True

    if use_pub_date:
        param["pubStartDate"] = start_date.strftime(DATE_FORMAT)
        param["pubEndDate"] = end_date.strftime(DATE_FORMAT)
    else:
        param["lastModStartDate"] = start_date.strftime(DATE_FORMAT)
        param["lastModEndDate"] = end_date.strftime(DATE_FORMAT)

    if client.has_kev:
        param["hasKev"] = True

    if client.keyword_search:
        param["keywordSearch"] = client.keyword_search

    while more_to_process:
        # Check call budget before making the request.
        if remaining_calls is not None and remaining_calls[0] <= 0:
            demisto.debug(f"API call budget exhausted ({remaining_calls[0]}), stopping pagination.")
            break

        try:
            res = client.get_cves(url_suffix, param, severity_param=severity_param, severity_value=severity_value)

            total_results = res.get("totalResults", 0)

            # Only count API calls that returned data toward the budget.
            # Empty responses (totalResults == 0) are lightweight probes
            # and should not consume the limited call allowance — this is
            # critical for sparse datasets (e.g. KEV filter) where most
            # 120-day windows are empty.
            if remaining_calls is not None and total_results > 0:
                remaining_calls[0] -= 1

            if total_results:
                demisto.debug(
                    f'Fetching {param["startIndex"]}-{int(param["startIndex"]) + results_per_page} '
                    f'out of {total_results} results.'
                )
                raw_cves += res.get("vulnerabilities") or []
                param["startIndex"] += int(results_per_page)  # type: ignore

            if param["startIndex"] >= total_results:
                more_to_process = False

        except Exception as e:  # pylint: disable=broad-except
            demisto.debug(f"Error fetching CVEs (startIndex={param['startIndex']}): {e}")
            raise

    return raw_cves


def retrieve_cves(
    client: Client,
    start_date: Any,
    end_date: Any,
    use_pub_date: bool = False,
    remaining_calls: list[int] | None = None,
) -> list[dict]:
    """Retrieve CVEs from NVD, querying each selected CVSS version
    separately when a severity filter is active (the NVD severity
    parameters are mutually exclusive).  Results are deduplicated by
    CVE ID.

    Args:
        client: An instance of the Client class.
        start_date: The start of the date window.
        end_date: The end of the date window.
        use_pub_date: When ``True`` query by publish-date, otherwise
            by last-modified date.
        remaining_calls: Mutable ``[n]`` counter shared across the
            entire fetch round.  See
            :func:`_retrieve_cves_single_query`.

    Returns:
        A list of raw CVE vulnerability dicts.
    """
    demisto.debug(f"cvss_severity={client.cvss_severity}, cvss_versions={client.cvss_versions}")

    if not client.cvss_severity:
        # No severity filter – single query, no severity param needed.
        return _retrieve_cves_single_query(
            client, start_date, end_date, use_pub_date=use_pub_date, remaining_calls=remaining_calls
        )

    # Severity filter is set – query each (CVSS version, severity value)
    # combination separately because the NVD API only allows one
    # cvss*Severity param per request AND one severity value per param.
    seen_ids: set[str] = set()
    deduplicated: list[dict] = []

    versions_to_query = client.cvss_versions or list(CVSS_VERSION_TO_PARAM.keys())
    for version_label in versions_to_query:
        # Stop early if the call budget is exhausted.
        if remaining_calls is not None and remaining_calls[0] <= 0:
            break
        severity_param = CVSS_VERSION_TO_PARAM.get(version_label, "")
        if not severity_param:
            demisto.debug(f"Unknown CVSS version label '{version_label}', skipping.")
            continue

        for sev_value in client.cvss_severity:
            if remaining_calls is not None and remaining_calls[0] <= 0:
                break
            demisto.debug(f"Querying NVD: {severity_param}={sev_value} (version={version_label})")

            cves = _retrieve_cves_single_query(
                client,
                start_date,
                end_date,
                use_pub_date=use_pub_date,
                severity_param=severity_param,
                severity_value=sev_value,
                remaining_calls=remaining_calls,
            )

            for cve in cves:
                cve_id = cve.get("cve", {}).get("id", "")
                if cve_id and cve_id not in seen_ids:
                    seen_ids.add(cve_id)
                    cve["_matched_cvss_version"] = version_label
                    cve["_matched_cvss_severity"] = sev_value
                    deduplicated.append(cve)

    # Sort by last-modified date for consistent ordering.
    deduplicated.sort(key=lambda cve: cve.get("cve", {}).get("lastModified", ""))

    demisto.debug(
        f"Total deduplicated CVEs after querying "
        f"{len(client.cvss_versions or [])} CVSS versions x {len(client.cvss_severity)} severity levels: "
        f"{len(deduplicated)}"
    )
    return deduplicated


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure *dt* is timezone-aware (UTC).

    ``dateparser.parse`` may return naive datetimes.  Since the rest
    of the code uses ``datetime.now(timezone.utc)`` we must ensure
    consistency to avoid *"can't subtract offset-naive and
    offset-aware datetimes"* errors.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _resolve_auto_fetch_window(client: Client) -> tuple[datetime, bool]:
    """Determine the start date and query mode for the automated fetch.

    Returns:
        A tuple of ``(start_date, use_pub_date)``.  ``use_pub_date``
        is ``True`` for first-fetch (query by publish date) and
        ``False`` for incremental runs (query by last-modified date).
    """
    last_run_data = demisto.getLastRun()
    if last_run_data:
        resume_date = last_run_data.get("resumeFrom")
        if resume_date:
            use_pub_date = last_run_data.get("usePubDate", False)
            demisto.debug(f"Resuming previous fetch from {resume_date}")
            return _ensure_utc(parse(resume_date)), use_pub_date  # type: ignore[arg-type]
        return _ensure_utc(parse(last_run_data.get("lastRun", ""))), False  # type: ignore[arg-type]

    # First run
    first_fetch: tuple[Any, Any] = parse_date_range(client.first_fetch, DATE_FORMAT)
    start_date: datetime = _ensure_utc(parse(first_fetch[0]))  # type: ignore[arg-type]
    demisto.debug(f"Running Feed NVD for the first time catching CVEs since {first_fetch}")
    return start_date, True


def _ingest_batch(
    client: Client,
    raw_cves: list[dict],
) -> int:
    """Build indicators from *raw_cves* and push them into XSOAR via
    ``createIndicators``.

    Args:
        client: Integration client instance.
        raw_cves: Raw CVE dicts returned by :func:`retrieve_cves`.

    Returns:
        The number of indicators created.
    """
    if not raw_cves:
        return 0

    indicators = build_indicators(client, raw_cves, preferred_versions=client.cvss_versions)

    demisto.debug(f'Creating {len(indicators)} using "createIndicators"')
    for chunk in batch(indicators, batch_size=NVD_API_MAX_RESULTS_PER_PAGE):
        demisto.createIndicators(chunk)

    return len(indicators)


def _fetch_cves_in_windows(
    client: Client,
    start_date: datetime,
    end_date: datetime,
    use_pub_date: bool,
    max_results: int,
) -> tuple[list[dict], datetime, bool]:
    """Fetch CVEs from NVD across 120-day windows.

    This is the shared core that both the automated ``fetch-indicators``
    and the manual ``nvd-get-indicators`` paths call.

    Args:
        client: Integration client instance.
        start_date: Beginning of the fetch window.
        end_date: End of the fetch window (usually *now*).
        use_pub_date: ``True`` → ``pubStartDate``; ``False`` →
            ``lastModStartDate``.
        max_results: Stop fetching once this many CVEs have been
            collected.

    Returns:
        ``(all_raw_cves, last_completed_end, limit_reached)``
    """
    all_raw_cves: list[dict] = []
    window_start: datetime | None = start_date
    last_completed_end: datetime = start_date
    limit_reached = False

    while window_start:
        delta = (end_date - window_start).days
        if delta > NVD_API_MAX_DATE_RANGE_DAYS:
            demisto.debug(f"Fetching CVEs over a span of {delta} days, will run in 120 days batches")
            window_end = window_start + timedelta(days=NVD_API_MAX_DATE_RANGE_DAYS)
        else:
            window_end = end_date

        demisto.debug(f"Fetching CVEs from {window_start:%Y-%m-%d} to {window_end:%Y-%m-%d}")
        raw_cves = retrieve_cves(client, window_start, window_end, use_pub_date=use_pub_date)
        all_raw_cves.extend(raw_cves)
        demisto.debug(f"Retrieved {len(raw_cves)} CVEs in current window (total so far: {len(all_raw_cves)})")

        last_completed_end = window_end

        if len(all_raw_cves) >= max_results:
            all_raw_cves = all_raw_cves[:max_results]
            limit_reached = True
            break

        if window_end >= end_date:
            break

        window_start = window_end

    return all_raw_cves, last_completed_end, limit_reached


def fetch_indicators_command(client: Client) -> None:
    """Automated ``fetch-indicators`` handler.

    Resolves the fetch window from ``lastRun`` / ``first_fetch``,
    retrieves CVEs in 120-day batches, creates XSOAR indicators, and
    persists progress so the next interval resumes where this one
    stopped.

    ``max_indicators`` is divided by ``NVD_API_MAX_RESULTS_PER_PAGE``
    to determine the total number of API calls allowed per fetch
    interval.  A shared mutable counter is passed through all
    layers so every ``get_cves`` call decrements it, regardless
    of which 120-day window or severity sub-query triggered it.
    """
    start_date, use_pub_date = _resolve_auto_fetch_window(client)
    demisto.debug(f"Auto-fetch: start_date={start_date}, use_pub_date={use_pub_date}, max_indicators={client.max_indicators}")
    end_date = datetime.now(timezone.utc)

    # Compute the global API-call budget for this fetch round.
    max_calls = client.max_indicators // NVD_API_MAX_RESULTS_PER_PAGE
    if max_calls < 1:
        max_calls = 1
    remaining_calls: list[int] = [max_calls]
    demisto.debug(f"max_indicators={client.max_indicators}, page_size={NVD_API_MAX_RESULTS_PER_PAGE}, max_calls={max_calls}")

    total_created = 0
    last_completed_end: datetime = start_date
    last_raw_cves: list[dict] = []
    window_start: datetime | None = start_date

    while window_start:
        # Stop if the call budget is already exhausted.
        if remaining_calls[0] <= 0:
            demisto.debug("API call budget exhausted before starting next window.")
            break

        delta = (end_date - window_start).days
        if delta > NVD_API_MAX_DATE_RANGE_DAYS:
            demisto.debug(f"Fetching CVEs over a span of {delta} days, will run in 120 days batches")
            window_end = window_start + timedelta(days=NVD_API_MAX_DATE_RANGE_DAYS)
        else:
            window_end = end_date

        demisto.debug(
            f"Fetching CVEs from {window_start:%Y-%m-%d} to {window_end:%Y-%m-%d} " f"(remaining_calls={remaining_calls[0]})"
        )
        raw_cves = retrieve_cves(client, window_start, window_end, use_pub_date=use_pub_date, remaining_calls=remaining_calls)

        created = _ingest_batch(client, raw_cves)
        total_created += created
        last_raw_cves = raw_cves
        last_completed_end = window_end

        if remaining_calls[0] <= 0:
            demisto.debug(f"API call budget exhausted ({max_calls} calls). " f"Stopping after {total_created} indicators.")
            break

        if window_end >= end_date:
            break

        window_start = window_end

    # Persist progress
    if remaining_calls[0] <= 0:
        # Resume from the last CVE's date to ensure continuity.
        # For publication-based queries (first-fetch), we use the last CVE's
        # 'published' date to avoid skipping entries. For incremental
        # updates, we use 'lastModified' to avoid re-processing.
        resume_point = last_completed_end.strftime(DATE_FORMAT)
        if last_raw_cves:
            last_cve = last_raw_cves[-1].get("cve", {})
            if use_pub_date:
                cve_date = last_cve.get("published", "")
            else:
                cve_date = last_cve.get("lastModified", "")
            if cve_date:
                resume_point = cve_date
        set_feed_last_run(
            {
                "lastRun": resume_point,
                "resumeFrom": resume_point,
                "usePubDate": use_pub_date,
            }
        )
        demisto.debug(
            f"Fetch limit reached after {total_created} indicators. " f"Will resume from {resume_point} on next interval."
        )
    else:
        set_feed_last_run({"lastRun": end_date.strftime(DATE_FORMAT)})

    demisto.debug(
        f"({start_date.strftime(DATE_FORMAT)})-({end_date.strftime(DATE_FORMAT)}), " f"Fetched {total_created} indicators."
    )


def manual_get_indicators_command(client: Client) -> CommandResults:
    """Manual ``nvd-get-indicators`` handler.

    Reads command arguments, optionally overrides the client's CVSS
    filters, fetches CVEs, and returns raw dicts for War Room display.
    No state is persisted.
    """
    # --- Read command arguments ---
    history_arg = demisto.getArg("history") or DEFAULT_MANUAL_HISTORY
    keyword = demisto.getArg("keyword") or ""
    limit = arg_to_number(demisto.getArg("limit")) or DEFAULT_MANUAL_LIMIT

    # Override CVSS filters if provided as command args
    severity_override = argToList(demisto.getArg("cvss_severity"))
    versions_override = argToList(demisto.getArg("cvss_versions"))

    if severity_override:
        client.cvss_severity = severity_override
    if versions_override:
        client.cvss_versions = versions_override

    client.keyword_search = keyword

    # Compute date window
    history = parse_date_range(history_arg, DATE_FORMAT)
    start_date: datetime = _ensure_utc(parse(history[0]))  # type: ignore[arg-type] # history[0] is guaranteed to be a string by parse_date_range
    end_date = datetime.now(timezone.utc)

    demisto.debug(
        f"Manual fetch: history={history_arg}, start_date={start_date}, "
        f"limit={limit}, severity={client.cvss_severity}, versions={client.cvss_versions}"
    )

    all_raw_cves, _, _ = _fetch_cves_in_windows(
        client,
        start_date,
        end_date,
        use_pub_date=True,
        max_results=limit,
    )

    demisto.debug(f"Manual fetch complete: {len(all_raw_cves)} CVEs returned")
    return cves_to_war_room(all_raw_cves, preferred_versions=client.cvss_versions)


def main():  # pragma: no cover
    """Main integration entry point."""

    params = demisto.params()
    proxy = argToBoolean(params.get("proxy", False))
    api_key = params.get("apiKey", {}).get("password", "")
    tlp_color = params.get("tlp_color", "")
    has_kev = argToBoolean(params.get("hasKev", False))
    first_fetch = params.get("first_fetch", "")
    feed_tags = params.get("feedTags", [])
    max_indicators = arg_to_number(params.get("max_indicators"))
    if max_indicators is None or max_indicators <= 0:
        max_indicators = MAX_INDICATORS_WITH_API_KEY if api_key else MAX_INDICATORS_WITHOUT_API_KEY
    cvss_versions_raw = argToList(params.get("cvss_versions", ""))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=BASE_URL,
            proxy=proxy,
            api_key=api_key,
            tlp_color=tlp_color,
            has_kev=has_kev,
            first_fetch=first_fetch,
            feed_tags=feed_tags,
            cvss_severity=argToList(params.get("cvss_severity", [])),
            keyword_search=params.get("keyword_search", ""),
            cvss_versions=cvss_versions_raw or None,
            max_indicators=max_indicators,
            include_rejected=argToBoolean(params.get("include_rejected", False)),
        )

        if command == "test-module":
            test_module(client)
        elif command == "fetch-indicators":
            fetch_indicators_command(client)
        elif command == "nvd-get-indicators":
            return_results(manual_get_indicators_command(client))

    except Exception as e:  # pylint: disable=broad-except
        return_error(f"Failed to execute {demisto.command()} command.\nError: \n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

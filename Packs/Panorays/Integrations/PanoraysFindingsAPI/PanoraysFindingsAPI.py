import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
import json
import time
from typing import Any
from datetime import UTC, timedelta

urllib3.disable_warnings()

SUPPLIER_FIELDS = [
    "id",
    "name",
    "primary_domain",
    "business_impact",
    "combined_score",
    "posture_score",
    "risk",
    "tags",
]

# The Panorays API allows 150 requests per minute and blocks the caller for a full hour on breach,
# so the default is deliberately below the ceiling.
DEFAULT_RATE_LIMIT = 120
SUPPLIER_PAGE_SIZE = 100
FINDING_PAGE_SIZE = 200
SUPPLIER_CACHE_KEY = "supplier_cache"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# The ledger must span a whole multi-run pass, not just one run.
SEEN_IDS_LIMIT = 20000


class Client(BaseClient):
    """Panorays PAPI v2 client.

    The API is cursor paginated: every list response carries ``has_next`` and a ``next`` token that
    must be echoed back as ``next_token``. Offset pagination (``page``/``skip``) is not supported.
    """

    def __init__(self, *args, rate_limit: int = DEFAULT_RATE_LIMIT, **kwargs):
        super().__init__(*args, **kwargs)
        self._min_interval = 60.0 / rate_limit if rate_limit > 0 else 0.0
        self._last_request_ts = 0.0

    def _throttle(self) -> None:
        """Space out requests so a fetch across a large portfolio cannot trip the hourly block."""
        if not self._min_interval:
            return
        elapsed = time.time() - self._last_request_ts
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request_ts = time.time()

    def _get(self, url_suffix: str, params: dict[str, Any]) -> dict[str, Any]:
        self._throttle()
        clean = {k: v for k, v in params.items() if v not in (None, "", [])}
        return self._http_request(method="GET", url_suffix=url_suffix, params=clean)

    def _paginate(self, url_suffix: str, params: dict[str, Any], page_size: int, limit: int | None) -> list[dict[str, Any]]:
        """Walk the cursor until exhausted, or until ``limit`` records have been collected."""
        results: list[dict[str, Any]] = []
        next_token = None
        while True:
            page_params = dict(params)
            page_params["limit"] = page_size if limit is None else min(page_size, limit - len(results))
            page_params["next_token"] = next_token
            response = self._get(url_suffix, page_params)
            results.extend(response.get("data") or [])
            next_token = response.get("next")
            if not response.get("has_next") or not next_token:
                break
            if limit is not None and len(results) >= limit:
                break
        return results[:limit] if limit is not None else results

    def get_company_findings(self, limit: int | None = None, next_token: str | None = None, **filters) -> dict[str, Any]:
        params = {"limit": min(limit or FINDING_PAGE_SIZE, FINDING_PAGE_SIZE), "next_token": next_token, **filters}
        return self._get("/v2/findings", params)

    def list_company_findings(self, limit: int | None = None, **filters) -> list[dict[str, Any]]:
        return self._paginate("/v2/findings", filters, FINDING_PAGE_SIZE, limit)

    def list_suppliers(self, limit: int | None = None, **filters) -> list[dict[str, Any]]:
        params = {"fields": SUPPLIER_FIELDS, **filters}
        return self._paginate("/v2/suppliers", params, SUPPLIER_PAGE_SIZE, limit)

    def list_supplier_findings(self, supplier_id: str, limit: int | None = None, **filters) -> list[dict[str, Any]]:
        return self._paginate(f"/v2/suppliers/{supplier_id}/findings", filters, FINDING_PAGE_SIZE, limit)


def verify_module(client: Client) -> str:
    try:
        client._get("/v2/findings", {"limit": 1})
        return "ok"
    except Exception as e:
        message = str(e)
        if "Unauthorized" in message or "Forbidden" in message:
            raise DemistoException("Authorization Error: check your API Key.") from e
        if "Too Many Requests" in message or "429" in message:
            raise DemistoException(
                "Rate limit reached. The Panorays API blocks callers for one hour after 150 requests per minute; "
                "wait for the block to expire and lower the 'Maximum API requests per minute' setting."
            ) from e
        raise


def _make_aware(dt):
    """Ensure a datetime is timezone-aware (UTC). Returns None if dt is None."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _csv_arg(args: dict[str, Any], key: str) -> list[str] | None:
    value = args.get(key)
    return argToList(value) if value else None


def _severity_matches(finding_severity: Any, wanted: list[str] | None) -> bool:
    """Compare severities case-insensitively; Panorays returns upper-case values such as CRITICAL."""
    if not wanted:
        return True
    return str(finding_severity or "").strip().upper() in {str(w).strip().upper() for w in wanted}


def _finding_custom_fields(finding: dict[str, Any]) -> dict[str, Any]:
    cves = finding.get("cves")
    return {
        "panoraysfindingid": finding.get("id"),
        "panoraysfindingseverity": finding.get("severity"),
        "panoraysfindingstatus": finding.get("status"),
        "panoraysfindingcategory": finding.get("category"),
        "panoraysfindingsubcategory": finding.get("sub_category"),
        "panoraysfindingassetname": finding.get("asset_name"),
        "panoraysfindingcves": ", ".join(cves) if isinstance(cves, list) else cves,
        "panoraysfindingdescription": finding.get("description"),
        "panoraysfindingfindingtext": finding.get("finding_text"),
        "panoraysfindinginsertts": finding.get("insert_ts"),
        "panoraysfindingupdatets": finding.get("update_ts"),
        "panoraysfindingstestname": finding.get("test_name"),
    }


def _supplier_custom_fields(supplier: dict[str, Any]) -> dict[str, Any]:
    tags = supplier.get("tags")
    return {
        "panorayssupplierid": supplier.get("id"),
        "panorayssuppliername": supplier.get("name"),
        "panorayssupplierdomain": supplier.get("primary_domain"),
        "panorayssupplierbusinessimpact": supplier.get("business_impact"),
        "panorayssuppliercombinedscore": supplier.get("combined_score"),
        "panorayssupplierposturescore": supplier.get("posture_score"),
        "panorayssupplierrisk": supplier.get("risk"),
        "panorayssuppliertags": ", ".join(str(t) for t in tags) if isinstance(tags, list) else tags,
    }


def finding_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get("limit")) or 50
    findings = client.list_company_findings(
        limit=limit,
        severity=_csv_arg(args, "severity"),
        status=_csv_arg(args, "status"),
        asset_name=_csv_arg(args, "asset_name"),
    )

    markdown_data = [
        {
            "Finding ID": f.get("id"),
            "Category": f.get("category"),
            "Affected Asset": f.get("asset_name"),
            "Risk Level": f.get("severity"),
            "State": f.get("status"),
        }
        for f in findings
    ]

    return CommandResults(
        readable_output=tableToMarkdown("Panorays Findings", markdown_data, removeNull=True),
        outputs_prefix="Panorays.Finding",
        outputs_key_field="id",
        outputs=findings,
        raw_response=findings,
    )


def supplier_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get("limit")) or 50
    suppliers = client.list_suppliers(
        limit=limit,
        names=_csv_arg(args, "names"),
        ids=_csv_arg(args, "ids"),
        tags=_csv_arg(args, "tags"),
        segment_ids=_csv_arg(args, "segment_ids"),
    )

    markdown_data = [
        {
            "Supplier ID": s.get("id"),
            "Name": s.get("name"),
            "Primary Domain": s.get("primary_domain"),
            "Business Impact": s.get("business_impact"),
            "Combined Score": s.get("combined_score"),
            "Risk": s.get("risk"),
        }
        for s in suppliers
    ]

    return CommandResults(
        readable_output=tableToMarkdown("Panorays Suppliers", markdown_data, removeNull=True),
        outputs_prefix="Panorays.Supplier",
        outputs_key_field="id",
        outputs=suppliers,
        raw_response=suppliers,
    )


def supplier_finding_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    supplier_id = args.get("supplier_id")
    if not supplier_id:
        raise DemistoException("The 'supplier_id' argument is required.")

    limit = arg_to_number(args.get("limit")) or 50
    findings = client.list_supplier_findings(
        supplier_id=supplier_id,
        limit=limit,
        severity=_csv_arg(args, "severity"),
        status=_csv_arg(args, "status"),
        asset_name=_csv_arg(args, "asset_name"),
        date_field=args.get("date_field"),
        date_range_from=args.get("date_range_from"),
        date_range_to=args.get("date_range_to"),
    )

    for finding in findings:
        finding["supplier_id"] = supplier_id

    markdown_data = [
        {
            "Finding ID": f.get("id"),
            "Category": f.get("category"),
            "Affected Asset": f.get("asset_name"),
            "Risk Level": f.get("severity"),
            "State": f.get("status"),
        }
        for f in findings
    ]

    return CommandResults(
        readable_output=tableToMarkdown(f"Panorays Findings for Supplier {supplier_id}", markdown_data, removeNull=True),
        outputs_prefix="Panorays.SupplierFinding",
        outputs_key_field="id",
        outputs=findings,
        raw_response=findings,
    )


def get_cached_suppliers(client: Client, cache_ttl_hours: int, segment_ids: list[str] | None, tags: list[str] | None):
    """Return the supplier portfolio, reusing the cached copy until it goes stale.

    Enumerating suppliers costs one request per 100 suppliers on every fetch, which is pure overhead
    against the rate limit given that portfolios change rarely.
    """
    context = demisto.getIntegrationContext() or {}
    cache = context.get(SUPPLIER_CACHE_KEY) or {}
    cached_at = _make_aware(arg_to_datetime(cache.get("cached_at"))) if cache.get("cached_at") else None
    now = datetime.now(UTC)

    if cached_at and cache.get("suppliers") and (now - cached_at) < timedelta(hours=cache_ttl_hours):
        demisto.debug(f"Panorays: using cached supplier list ({len(cache['suppliers'])} suppliers).")
        return cache["suppliers"]

    suppliers = client.list_suppliers(segment_ids=segment_ids, tags=tags)
    demisto.debug(f"Panorays: refreshed supplier list ({len(suppliers)} suppliers).")
    context[SUPPLIER_CACHE_KEY] = {"cached_at": now.strftime(DATE_FORMAT), "suppliers": suppliers}
    demisto.setIntegrationContext(context)
    return suppliers


def fetch_incidents_command(client: Client, last_run: dict, first_fetch_time: str, max_fetch: int) -> tuple[dict, list[dict]]:
    """Fetch the organization's own findings (unchanged behavior)."""
    last_fetch = last_run.get("last_fetch")
    last_fetch_time = _make_aware(arg_to_datetime(last_fetch or first_fetch_time))

    findings = client.list_company_findings(limit=max_fetch)

    incidents = []
    latest_created_time = last_fetch_time

    for finding in findings:
        finding_time = _make_aware(arg_to_datetime(finding.get("insert_ts")))

        if last_fetch_time and finding_time and finding_time <= last_fetch_time:
            continue

        incidents.append(
            {
                "name": f"Panorays Finding: {finding.get('asset_name', 'Unknown')}",
                "details": finding.get("finding_text", ""),
                "occurred": finding.get("insert_ts"),
                "rawJSON": json.dumps(finding),
                "CustomFields": _finding_custom_fields(finding),
            }
        )

        if finding_time and (not latest_created_time or finding_time > latest_created_time):
            latest_created_time = finding_time

    next_run = {"last_fetch": latest_created_time.strftime(DATE_FORMAT) if latest_created_time else last_fetch}
    return next_run, incidents


def fetch_supplier_incidents_command(
    client: Client,
    last_run: dict,
    first_fetch_time: str,
    max_fetch: int,
    severities: list[str] | None,
    statuses: list[str] | None,
    date_field: str,
    cache_ttl_hours: int,
    segment_ids: list[str] | None,
    tags: list[str] | None,
) -> tuple[dict, list[dict]]:
    """Fetch findings across the supplier portfolio and raise one incident per finding.

    The portfolio is walked with a resumable cursor: if ``max_fetch`` is reached part-way through,
    the run stops at that supplier and resumes there next time. ``last_fetch`` only advances once a
    full pass completes, so no supplier can be skipped.
    """
    last_fetch = last_run.get("last_fetch")
    last_fetch_time = _make_aware(arg_to_datetime(last_fetch or first_fetch_time))
    seen_ids = set(last_run.get("seen_ids") or [])
    start_index = last_run.get("supplier_index") or 0

    suppliers = get_cached_suppliers(client, cache_ttl_hours, segment_ids, tags)
    if not suppliers:
        demisto.debug("Panorays: no suppliers returned; nothing to fetch.")
        return {"last_fetch": last_fetch, "seen_ids": list(seen_ids), "supplier_index": 0}, []

    if start_index >= len(suppliers):
        start_index = 0

    # date_range_from is day-granular, so pull from the start of the day and filter precisely below.
    date_from = last_fetch_time.strftime("%Y-%m-%d") if last_fetch_time else None

    incidents: list[dict] = []
    latest_created_time = last_fetch_time
    new_seen: set[str] = set()
    index = start_index
    completed_pass = True

    while index < len(suppliers):
        if len(incidents) >= max_fetch:
            completed_pass = False
            break

        supplier = suppliers[index]
        supplier_id = supplier.get("id")
        if not supplier_id:
            index += 1
            continue

        try:
            findings = client.list_supplier_findings(
                supplier_id=supplier_id,
                severity=severities,
                status=statuses,
                date_field=date_field,
                date_range_from=date_from,
            )
        except Exception as e:
            # One bad supplier must not sink the whole fetch cycle.
            demisto.error(f"Panorays: failed fetching findings for supplier {supplier_id}: {e}")
            index += 1
            continue

        supplier_fields = _supplier_custom_fields(supplier)
        supplier_name = supplier.get("name") or supplier_id

        for finding in findings:
            finding_id = str(finding.get("id"))
            # The API filters by severity server-side, but re-check in case the tenant ignores the filter.
            if not _severity_matches(finding.get("severity"), severities):
                continue

            # date_range_from is day-granular, so the server re-returns findings already ingested earlier
            # today. The id ledger is what actually guarantees exactly-once creation.
            if finding_id in new_seen or finding_id in seen_ids:
                continue

            finding_time = _make_aware(arg_to_datetime(finding.get(date_field) or finding.get("insert_ts")))

            enriched = dict(finding)
            enriched["supplier_id"] = supplier_id
            enriched["supplier_name"] = supplier.get("name")

            incidents.append(
                {
                    "name": f"Panorays Supplier Finding: {supplier_name} - {finding.get('asset_name', 'Unknown')}",
                    "details": finding.get("finding_text", ""),
                    "occurred": finding.get("insert_ts"),
                    "rawJSON": json.dumps(enriched),
                    "CustomFields": {**_finding_custom_fields(finding), **supplier_fields},
                }
            )
            new_seen.add(finding_id)

            if finding_time and (not latest_created_time or finding_time > latest_created_time):
                latest_created_time = finding_time

            if len(incidents) >= max_fetch:
                break
        else:
            # Every finding for this supplier was processed, so move on to the next one.
            index += 1
            continue

        # max_fetch was reached part-way through this supplier. Hold the cursor ON this supplier rather
        # than advancing past it: the next run re-reads it and the seen-id ledger skips what was already
        # ingested, so the cap stays honest and no finding is dropped.
        completed_pass = False
        break

    if completed_pass and index >= len(suppliers):
        next_index = 0
        next_last_fetch = latest_created_time.strftime(DATE_FORMAT) if latest_created_time else last_fetch
    else:
        # Mid-portfolio: hold the cursor so the remaining suppliers are covered on the next run, and
        # freeze the window start. Without this, a first run resolves "first_fetch" afresh on every
        # resumed run, so the window slides forward mid-pass and findings in the gap are never fetched.
        next_index = index
        next_last_fetch = last_fetch or (last_fetch_time.strftime(DATE_FORMAT) if last_fetch_time else None)

    next_run = {
        "last_fetch": next_last_fetch,
        "supplier_index": next_index,
        "seen_ids": list(seen_ids | new_seen)[-SEEN_IDS_LIMIT:],
    }
    return next_run, incidents


def main() -> None:
    try:
        params = demisto.params()
        command = demisto.command()

        api_key = (params.get("apikey") or {}).get("password", "")
        base_url = params.get("url", "https://api.panoraysapp.com")

        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        verify_certificate = not bool(params.get("insecure", False))
        proxy = bool(params.get("proxy", False))
        rate_limit = arg_to_number(params.get("rate_limit")) or DEFAULT_RATE_LIMIT

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers,
            rate_limit=rate_limit,
        )

        if command == "test-module":
            return_results(verify_module(client))
        elif command == "panorays-finding-list":
            return_results(finding_list_command(client, demisto.args()))
        elif command == "panorays-supplier-list":
            return_results(supplier_list_command(client, demisto.args()))
        elif command == "panorays-supplier-finding-list":
            return_results(supplier_finding_list_command(client, demisto.args()))
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            first_fetch_time = params.get("first_fetch", "3 days")
            max_fetch = arg_to_number(params.get("max_fetch")) or 50
            scope = params.get("findings_scope") or "Company Findings"

            if scope == "Supplier Findings":
                next_run, incidents = fetch_supplier_incidents_command(
                    client=client,
                    last_run=last_run,
                    first_fetch_time=first_fetch_time,
                    max_fetch=max_fetch,
                    severities=argToList(params.get("supplier_finding_severity")) or None,
                    statuses=argToList(params.get("supplier_finding_status")) or None,
                    date_field=params.get("date_field") or "update_ts",
                    cache_ttl_hours=arg_to_number(params.get("supplier_cache_ttl")) or 12,
                    segment_ids=argToList(params.get("segment_ids")) or None,
                    tags=argToList(params.get("supplier_tags")) or None,
                )
            else:
                next_run, incidents = fetch_incidents_command(client, last_run, first_fetch_time, max_fetch)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

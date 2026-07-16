"""Demisto Integration for Axonius."""

import json
import requests
from axonius_api_client.api.assets.devices import Devices
from axonius_api_client.api.assets.users import Users
from axonius_api_client.connect import Connect
from axonius_api_client.tools import dt_parse, strip_left
from CommonServerPython import *

# Added ignore RemovedInMarshmallow4Warning in Axonius_test file.


MAX_ROWS: int = 50
"""Maximum number of assets to allow user to fetch."""
SKIPS: List[str] = ["specific_data.data.image", "view"]
"""Fields to remove from each asset if found."""
FIELDS_TIME: List[str] = ["seen", "fetch", "time", "date"]
"""Fields to try and convert to date time if they have these words in them."""
AXONIUS_ID = "internal_axon_id"
V2_PAGE_SIZE_DEFAULT: int = 50
"""Default page size for v2 API pagination."""
V2_PAGE_SIZE_ALL_PAGES: int = 100
"""Page size used when fetching all pages."""
MAX_PAGES: int = 200
"""Maximum number of pages to fetch in a single paginated request (infinite-loop guard)."""
REQUEST_TIMEOUT: int = 30
"""HTTP request timeout in seconds to prevent silent hangs in Playbooks."""


def get_int_arg(
    key: str,
    required: Optional[bool] = False,
    default: Optional[int] = None,
) -> int:
    """Get a key from a command arg and convert it into an int."""
    args: dict = demisto.args()
    value: int = args.get(key, default)

    if value is None and required:
        raise ValueError(f"No value supplied for argument {key!r}")

    try:
        return int(value)
    except Exception:
        raise ValueError(f"Supplied value {value!r} for argument {key!r} is not an integer.")


def get_csv_arg(
    key: str,
    required: Optional[bool] = False,
    default: Optional[str] = "",
) -> List[str]:
    """Get string values from CSV."""
    args: dict = demisto.args()
    value: List[str] = argToList(arg=args.get(key, default))
    value = [x for x in value if x]

    if not value and required:
        raise ValueError(f"No value supplied for argument {key!r}")

    return value


def test_module(client: Connect) -> str:
    """Tests Axonius API Client connectivity."""
    client.start()
    return "ok"


def parse_kv(key: str, value: Any) -> Any:
    """Parse time stamp into required format."""
    for word in FIELDS_TIME:
        if word in key:
            try:
                return dt_parse(value).isoformat()
            except Exception:
                return value
    return value


def parse_key(key: str) -> str:
    """Parse fields into required format."""
    if key.startswith("specific_data.data."):
        key = strip_left(obj=key, fix="specific_data.data.")
        key = f"aggregated_{key}"
    if key.startswith("adapters_data."):
        key = strip_left(obj=key, fix="adapters_data.")
    key = key.replace(".", "_")
    return key


def parse_asset(asset: dict) -> dict:
    """Initiate field format correction on assets."""
    return {parse_key(key=k): parse_kv(key=k, value=v) for k, v in asset.items() if k not in SKIPS}


def get_saved_queries(client: Connect, args: dict) -> CommandResults:  # noqa: F821, F405
    """Get assets with their defined fields returned by a saved query."""
    api_obj = client.devices if args["type"] == "devices" else client.users
    saved_queries = api_obj.saved_query.get()
    return parse_assets(
        assets=saved_queries,
        api_obj=api_obj,
        outputs_key_field="",
        extension="saved_queries",
        exclude_raw=True,
    )


def make_api_call(
    endpoint: str,
    payload: dict = None,
    method: str = "POST",
    query_params: dict = None,
) -> requests.Response | None:
    """Make an authenticated HTTP API call to the Axonius instance.

    Args:
        endpoint: API endpoint path (appended to the base URL).
        payload: JSON body for POST/DELETE requests.
        method: HTTP method — GET, POST, or DELETE (default: POST).
        query_params: URL query parameters for GET requests.

    Returns:
        The HTTP response, or None if no URL is configured.
    """
    params: dict = demisto.params()
    url: str | None = params.get("ax_url")
    key: str = params.get("credentials", {}).get("identifier")
    secret: str = params.get("credentials", {}).get("password")
    certverify: bool = not params.get("insecure", False)

    if not url:
        return None

    url = url + "/" if url[-1] != "/" else url
    url = url + endpoint

    headers: dict = {
        "accept": "application/json",
        "api-key": key,
        "api-secret": secret,
        "content-type": "application/json",
    }

    method = method.upper()
    if method == "GET":
        return requests.get(url, headers=headers, params=query_params, verify=certverify, timeout=REQUEST_TIMEOUT)
    elif method == "DELETE":
        return requests.delete(url, json=payload, headers=headers, verify=certverify, timeout=REQUEST_TIMEOUT)
    else:
        return requests.post(url, json=payload, headers=headers, verify=certverify, timeout=REQUEST_TIMEOUT)


def _handle_api_response(response: Optional[requests.Response], endpoint: str) -> dict:
    """Validate an API response and return parsed JSON.

    Raises:
        DemistoException: on missing URL, non-2xx status, or invalid JSON.
    """
    if response is None:
        raise DemistoException("No URL configured for the Axonius instance.")

    if not response.ok:
        raise DemistoException(f"API call to '{endpoint}' failed with HTTP {response.status_code}: {response.text[:1000]}")

    if not response.content:
        return {}

    try:
        return response.json()
    except ValueError as exc:
        raise DemistoException(f"Failed to parse response from '{endpoint}' as JSON: {exc}") from exc


def add_note(client: Connect, args: dict) -> CommandResults:
    """Add notes to assets."""
    note: str = args["note"]
    asset_type: str = args["type"]
    internal_axon_id_arr: list = args["ids"]
    success_count: int = 0
    if isinstance(internal_axon_id_arr, str):
        internal_axon_id_arr = argToList(internal_axon_id_arr, separator=",")

    payload: dict = {
        "meta": None,
        "data": {
            "attributes": {
                "note": note,
            },
            "type": "notes_schema",
        },
    }

    for id in internal_axon_id_arr:
        response = make_api_call(endpoint=f"api/{asset_type}/{id}/notes", payload=payload)
        if response and response.status_code == 200:
            success_count += 1

    readable_output = f"{success_count} {asset_type}(s) updated."
    return CommandResults(
        outputs_prefix="Axonius.asset.updates",
        readable_output=readable_output,
        outputs=success_count,
        raw_response=success_count,
    )


def get_tags(client: Connect, args: dict) -> CommandResults:  # noqa: F821, F405
    """Get assets with their defined fields returned by a saved query."""
    api_obj = client.devices if args["type"] == "devices" else client.users
    tags = api_obj.labels.get()
    return CommandResults(
        outputs_prefix=f"Axonius.tags.{args['type']}",
        readable_output=",".join(tags),
        outputs=tags,
        raw_response=tags,
    )


def update_tags(client: Connect, args: dict, method_name: str) -> CommandResults:  # noqa: F821, F405
    tag_name: str = args["tag_name"]
    internal_axon_id_arr: list = args["ids"]
    if isinstance(internal_axon_id_arr, str):
        internal_axon_id_arr = argToList(internal_axon_id_arr, separator=",")
    api_obj = client.devices if args["type"] == "devices" else client.users
    api_name = api_obj.__class__.__name__

    if method_name == "add":
        res = api_obj.labels.add(rows=internal_axon_id_arr, labels=[tag_name])
    else:
        res = api_obj.labels.remove(rows=internal_axon_id_arr, labels=[tag_name])

    # res is count of rows included in the output, regardless of success.
    readable_output = f"{res} {api_name}(s) updated."
    return CommandResults(
        outputs_prefix=f"Axonius.asset.updates.{args['type']}",
        readable_output=readable_output,
        outputs=res,
        raw_response=res,
    )


def get_by_sq(api_obj: Union[Users, Devices], args: dict) -> CommandResults:  # noqa: F821, F405
    """Get assets with their defined fields returned by a saved query."""
    name: str = args["saved_query_name"]
    fields: List[str] = get_csv_arg(key="fields", required=False)
    max_rows: int = get_int_arg(key="max_results", required=False, default=MAX_ROWS)
    assets = api_obj.get_by_saved_query(name=name, max_rows=max_rows, fields=fields)
    return parse_assets(assets=assets, api_obj=api_obj)


def get_by_value(
    api_obj: Union[Users, Devices],
    args: dict,
    method_name: str,
) -> CommandResults:  # noqa: F821, F405
    """Get assets by a value using a api_obj.get_by_{method_name}."""
    api_name = api_obj.__class__.__name__
    value: str = args["value"]
    fields: List[str] = get_csv_arg(key="fields", required=False)
    max_rows: int = get_int_arg(key="max_results", required=False, default=MAX_ROWS)

    api_method_name = f"get_by_{method_name}"
    if not hasattr(api_obj, api_method_name):
        valid = []

        for x in dir(api_obj):
            if not x.startswith("get_by_") or x.endswith("s"):
                continue

            valid.append(x.replace("get_by_", ""))

        valid = ", ".join(valid)
        raise Exception(f"Invalid get by {method_name} for {api_name}, valid: {valid}")

    method = getattr(api_obj, api_method_name)
    assets = method(value=value, max_rows=max_rows, fields=fields)
    return parse_assets(assets=assets, api_obj=api_obj)


def get(
    api_obj: Union[Users, Devices],
    args: dict,
) -> CommandResults:
    """Get assets by a query using a api_obj.get."""
    query: str = args["query"]
    fields: List[str] = get_csv_arg(key="fields", required=False)
    max_rows: int = get_int_arg(key="max_results", required=False, default=MAX_ROWS)
    assets = api_obj.get(query=query, max_rows=max_rows, fields=fields)
    return parse_assets(assets=assets, api_obj=api_obj)


def parse_assets(
    assets: List[dict],
    api_obj: Union[Users, Devices],
    outputs_key_field=AXONIUS_ID,
    extension="",
    exclude_raw=False,
) -> CommandResults:  # noqa: F821, F405
    """Parse assets into CommandResults."""
    api_name = api_obj.__class__.__name__
    aql = api_obj.LAST_GET.get("filter")
    results = [parse_asset(asset=asset) for asset in assets]

    readable_output: Optional[str] = None
    outputs: Union[List[dict], dict] = results

    if not results:
        readable_output = f"No {api_name} assets found using AQL: {aql}"

    if len(results) == 1:
        outputs = results[0]

    outputs_prefix = f"Axonius.{api_name}"
    if extension:
        outputs_prefix += f".{extension}"
    raw_response = None if exclude_raw else assets

    return CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field=outputs_key_field,
        readable_output=readable_output,
        outputs=outputs,
        raw_response=raw_response,
    )  # noqa: F821, F405


# ---------------------------------------------------------------------------
# v2 API helpers
# ---------------------------------------------------------------------------


def _build_v2_page(limit: int, cursor: Optional[str] = None) -> dict:
    """Build a v2 API page object."""
    page: dict = {"limit": limit}
    if cursor:
        page["cursor"] = cursor
    return page


# ---------------------------------------------------------------------------
# axonius-get-assets
# ---------------------------------------------------------------------------


def get_assets(args: dict) -> CommandResults:
    """Fetch assets of any type via POST /api/v2/assets/{asset_type}.

    Supports all asset types including alert_findings and
    vulnerability_instances. Returns a single page of results together with a
    cursor (next_page) for subsequent calls.

    Note on large payloads: when a response exceeds ~10 MB, XSOAR automatically
    stores the data as a downloadable file instead of writing it to the context.
    Use the page_limit argument to keep responses within manageable bounds.
    """
    asset_type: str = args.get("asset_type", "devices")
    query: Optional[str] = args.get("query") or None
    fields: List[str] = get_csv_arg(key="fields")
    fields_to_exclude: List[str] = get_csv_arg(key="fields_to_exclude")
    page_limit: int = get_int_arg(key="page_limit", default=V2_PAGE_SIZE_DEFAULT)
    next_page: Optional[str] = args.get("next_page") or None
    include_metadata: bool = argToBoolean(args.get("include_metadata", False))
    include_details: bool = argToBoolean(args.get("include_details", False))
    use_cache_entry: bool = argToBoolean(args.get("use_cache_entry", False))

    payload: dict = {"page": _build_v2_page(limit=page_limit, cursor=next_page)}
    if query:
        payload["query"] = query
    if fields:
        payload["fields"] = fields
    if fields_to_exclude:
        payload["fields_to_exclude"] = fields_to_exclude
    if include_metadata:
        payload["include_metadata"] = True
    if include_details:
        payload["include_details"] = True
    if use_cache_entry:
        payload["use_cache_entry"] = True

    endpoint = f"api/v2/assets/{asset_type}"
    response = make_api_call(endpoint=endpoint, payload=payload, method="POST")
    data = _handle_api_response(response=response, endpoint=endpoint)

    assets: List[dict] = data.get("assets") or []
    meta: dict = data.get("meta") or {}
    next_cursor: Optional[str] = meta.get("next_page")
    page_meta: dict = meta.get("page") or {}
    total_count: Optional[int] = page_meta.get("totalResources")

    if not assets:
        readable_output = f"No {asset_type} assets found."
    else:
        readable_output = tableToMarkdown(
            f"Axonius Assets — {asset_type} ({len(assets)} returned)",
            assets,
            removeNull=True,
        )

    outputs: dict = {
        "asset_type": asset_type,
        "assets": assets,
        "count": len(assets),
    }
    if total_count is not None:
        outputs["total_count"] = total_count
    if next_cursor:
        outputs["next_page"] = next_cursor

    return CommandResults(
        outputs_prefix="Axonius.Assets",
        outputs_key_field="asset_type",
        readable_output=readable_output,
        outputs=outputs,
        raw_response=data,
    )


# ---------------------------------------------------------------------------
# axonius-get-asset-types
# ---------------------------------------------------------------------------


def get_asset_types() -> CommandResults:
    """Return available asset types via GET /api/v2/assets/asset_types."""
    endpoint = "api/v2/assets/asset_types"
    response = make_api_call(endpoint=endpoint, method="GET")
    data = _handle_api_response(response=response, endpoint=endpoint)

    asset_types: list = data.get("asset_types") or []

    readable_output = tableToMarkdown(
        "Axonius Asset Types",
        [{"asset_type": t} for t in asset_types]
        if isinstance(asset_types, list) and asset_types and not isinstance(asset_types[0], dict)
        else asset_types,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="Axonius.AssetTypes",
        readable_output=readable_output,
        outputs=asset_types,
        raw_response=data,
    )


# ---------------------------------------------------------------------------
# Custom Data Management
# ---------------------------------------------------------------------------


def get_custom_data(args: dict) -> CommandResults:
    """List custom data entries via GET /api/v2/custom_data_management."""
    limit: int = get_int_arg(key="limit", default=50)
    offset: int = get_int_arg(key="offset", default=0)
    endpoint = "api/v2/custom_data_management"
    response = make_api_call(
        endpoint=endpoint,
        method="GET",
        query_params={"limit": limit, "offset": offset},
    )
    data = _handle_api_response(response=response, endpoint=endpoint)

    entries: list = data.get("custom_fields") or []

    readable_output = tableToMarkdown(
        "Axonius Custom Data",
        entries,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="Axonius.CustomData",
        readable_output=readable_output,
        outputs=entries,
        raw_response=data,
    )


def create_custom_data(args: dict) -> CommandResults:
    """Create a custom data entry via POST /api/v2/custom_data_management."""
    payload_str: Optional[str] = args.get("payload")
    if not payload_str:
        raise DemistoException("The 'payload' argument is required for axonius-create-custom-data.")
    try:
        payload: dict = json.loads(payload_str)
    except (ValueError, TypeError) as exc:
        raise DemistoException(f"Invalid JSON in 'payload' argument: {exc}") from exc

    endpoint = "api/v2/custom_data_management"
    response = make_api_call(endpoint=endpoint, payload=payload, method="POST")
    data = _handle_api_response(response=response, endpoint=endpoint)

    return CommandResults(
        outputs_prefix="Axonius.CustomData",
        readable_output="Custom data entry created successfully.",
        outputs=data,
        raw_response=data,
    )


def delete_custom_data(args: dict) -> CommandResults:
    """Delete a custom data entry via DELETE /api/v2/custom_data_management/{id}."""
    entry_id: str = args.get("id", "")
    if not entry_id:
        raise DemistoException("The 'id' argument is required for axonius-delete-custom-data.")

    endpoint = f"api/v2/custom_data_management/{entry_id}"
    response = make_api_call(endpoint=endpoint, method="DELETE")
    _handle_api_response(response=response, endpoint=endpoint)

    return CommandResults(
        outputs_prefix="Axonius.CustomData",
        readable_output=f"Custom data entry '{entry_id}' deleted successfully.",
        outputs={"id": entry_id, "deleted": True},
    )


# ---------------------------------------------------------------------------
# Enforcements
# ---------------------------------------------------------------------------


def get_enforcements(args: dict) -> CommandResults:
    """List enforcements via GET /api/v2/enforcements."""
    limit: int = get_int_arg(key="limit", default=50)
    offset: int = get_int_arg(key="offset", default=0)
    endpoint = "api/v2/enforcements"
    response = make_api_call(
        endpoint=endpoint,
        method="GET",
        query_params={"limit": limit, "offset": offset},
    )
    data = _handle_api_response(response=response, endpoint=endpoint)

    enforcements: list = data.get("enforcements") or []

    readable_output = tableToMarkdown(
        "Axonius Enforcements",
        enforcements,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="Axonius.Enforcements",
        outputs_key_field="uuid",
        readable_output=readable_output,
        outputs=enforcements,
        raw_response=data,
    )


def run_enforcement(args: dict) -> CommandResults:
    """Trigger an enforcement run via POST /api/v2/enforcements/{id}/run."""
    enforcement_id: str = args.get("enforcement_id", "")
    if not enforcement_id:
        raise DemistoException("The 'enforcement_id' argument is required for axonius-run-enforcement.")

    endpoint = f"api/v2/enforcements/{enforcement_id}/run"
    response = make_api_call(endpoint=endpoint, method="POST")
    data = _handle_api_response(response=response, endpoint=endpoint)

    return CommandResults(
        outputs_prefix="Axonius.Enforcements",
        readable_output=f"Enforcement '{enforcement_id}' triggered successfully.",
        outputs={"enforcement_id": enforcement_id, "triggered": True, "response": data},
        raw_response=data,
    )


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def get_queries(args: dict) -> CommandResults:
    """List saved queries via GET /api/v2/queries."""
    asset_type: Optional[str] = args.get("asset_type") or None
    limit: int = get_int_arg(key="limit", default=50)
    offset: int = get_int_arg(key="offset", default=0)
    endpoint = "api/v2/queries"
    qp: dict = {"limit": limit, "offset": offset}
    if asset_type:
        qp["asset_type"] = asset_type
    response = make_api_call(endpoint=endpoint, method="GET", query_params=qp)
    data = _handle_api_response(response=response, endpoint=endpoint)

    queries: list = data.get("queries") or []

    readable_output = tableToMarkdown(
        "Axonius Queries",
        queries,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="Axonius.Queries",
        outputs_key_field="uuid",
        readable_output=readable_output,
        outputs=queries,
        raw_response=data,
    )


def create_query(args: dict) -> CommandResults:
    """Create a saved query via POST /api/v2/queries."""
    name: str = args.get("name", "")
    query: str = args.get("query", "")
    asset_type: str = args.get("asset_type", "devices")
    description: Optional[str] = args.get("description") or None

    if not name:
        raise DemistoException("The 'name' argument is required for axonius-create-query.")
    if not query:
        raise DemistoException("The 'query' argument is required for axonius-create-query.")

    payload: dict = {"name": name, "query": query, "asset_type": asset_type}
    if description:
        payload["description"] = description

    endpoint = "api/v2/queries"
    response = make_api_call(endpoint=endpoint, payload=payload, method="POST")
    data = _handle_api_response(response=response, endpoint=endpoint)

    return CommandResults(
        outputs_prefix="Axonius.Queries",
        outputs_key_field="uuid",
        readable_output=f"Query '{name}' created successfully.",
        outputs=data,
        raw_response=data,
    )


def delete_query(args: dict) -> CommandResults:
    """Delete a saved query via DELETE /api/v2/queries/{query_id}."""
    query_id: str = args.get("query_id", "")
    if not query_id:
        raise DemistoException("The 'query_id' argument is required for axonius-delete-query.")

    endpoint = f"api/v2/queries/{query_id}"
    response = make_api_call(endpoint=endpoint, method="DELETE")
    _handle_api_response(response=response, endpoint=endpoint)

    return CommandResults(
        outputs_prefix="Axonius.Queries",
        readable_output=f"Query '{query_id}' deleted successfully.",
        outputs={"query_id": query_id, "deleted": True},
    )


# ---------------------------------------------------------------------------
# Grouped Vulnerabilities
# ---------------------------------------------------------------------------


def _fetch_all_pages(asset_type: str, query: Optional[str] = None, page_size: int = V2_PAGE_SIZE_ALL_PAGES) -> List[dict]:
    """Fetch all pages of an asset type from the v2 API.

    Args:
        asset_type: Axonius asset type (e.g. 'vulnerability_instances').
        query: Optional AQL filter string.
        page_size: Number of records per page request.

    Returns:
        Flat list of all asset records across all pages.
    """
    all_assets: List[dict] = []
    cursor: Optional[str] = None
    endpoint = f"api/v2/assets/{asset_type}"
    page_count: int = 0

    while True:
        payload: dict = {"page": _build_v2_page(limit=page_size, cursor=cursor)}
        if query:
            payload["query"] = query

        response = make_api_call(endpoint=endpoint, payload=payload, method="POST")
        data = _handle_api_response(response=response, endpoint=endpoint)

        page_assets: List[dict] = data.get("assets") or []
        all_assets.extend(page_assets)
        page_count += 1

        meta: dict = data.get("meta") or {}
        cursor = meta.get("next_page")

        if not cursor or not page_assets or page_count >= MAX_PAGES:
            if page_count >= MAX_PAGES and cursor:
                demisto.debug(
                    f"_fetch_all_pages: reached MAX_PAGES ({MAX_PAGES}) for '{asset_type}'; "
                    f"stopping pagination early with {len(all_assets)} records collected."
                )
            break

    return all_assets


def _flatten_instance(instance: dict) -> dict:
    """Flatten single-element lists in a vulnerability instance dict."""
    flattened: dict = {}
    for key, value in instance.items():
        if isinstance(value, list) and len(value) == 1:
            flattened[key] = value[0]
        else:
            flattened[key] = value
    return flattened


def _safe_float(value: Any) -> Optional[float]:
    """Convert value to float, returning None on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def get_grouped_vulnerabilities(args: dict) -> CommandResults:
    """Fetch all vulnerability instances and group them by CVE ID.

    Fetches all pages of /v2/assets/vulnerability_instances, flattens each
    instance, groups by cve_id, counts affected hosts, averages CVSS scores,
    and returns the Top N CVEs sorted by affected_hosts_count descending.
    """
    query: Optional[str] = args.get("query") or None
    team_name: Optional[str] = args.get("team_name") or None
    urgent: Optional[str] = args.get("urgent") or None
    top_n: int = get_int_arg(key="top_n", default=10)
    page_size: int = get_int_arg(key="page_size", default=V2_PAGE_SIZE_ALL_PAGES)

    # Build composite query filter
    query_parts: List[str] = []
    if query:
        query_parts.append(query)
    if team_name:
        query_parts.append(f'(specific_data.data.team_name == "{team_name}")')
    if urgent is not None:
        urgent_bool = "true" if argToBoolean(urgent) else "false"
        query_parts.append(f"(specific_data.data.urgent == {urgent_bool})")
    final_query = " and ".join(query_parts) if query_parts else None

    instances = _fetch_all_pages(asset_type="vulnerability_instances", query=final_query, page_size=page_size)

    if not instances:
        return CommandResults(
            outputs_prefix="Axonius.GroupedVulnerabilities",
            outputs_key_field="cve_id",
            readable_output="No vulnerability instances found.",
            outputs=[],
        )

    # Group by CVE ID
    grouped: dict = {}
    for raw in instances:
        inst = _flatten_instance(raw)
        cve_id = inst.get("cve_id") or inst.get("specific_data.data.cve_id")
        if not cve_id:
            continue

        if cve_id not in grouped:
            grouped[cve_id] = {"affected_hosts_count": 0, "cvss_scores": []}

        grouped[cve_id]["affected_hosts_count"] += 1
        cvss = _safe_float(inst.get("cvss_score") or inst.get("specific_data.data.cvss_score"))
        if cvss is not None:
            grouped[cve_id]["cvss_scores"].append(cvss)

    # Build sorted output
    results: List[dict] = []
    for cve_id, group_data in grouped.items():
        scores = group_data["cvss_scores"]
        avg_cvss = round(sum(scores) / len(scores), 2) if scores else None
        results.append(
            {
                "cve_id": cve_id,
                "affected_hosts_count": group_data["affected_hosts_count"],
                "average_cvss_score": avg_cvss,
            }
        )

    results.sort(key=lambda x: x["affected_hosts_count"], reverse=True)
    top_results = results[:top_n]

    readable_output = tableToMarkdown(
        f"Top {top_n} CVEs by Affected Hosts",
        top_results,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="Axonius.GroupedVulnerabilities",
        outputs_key_field="cve_id",
        readable_output=readable_output,
        outputs=top_results,
        raw_response=top_results,
    )


def run_command(client: Connect, args: dict, command: str):
    results: Union[CommandResults, str, None] = None

    if command == "test-module":
        results = test_module(client=client)

    elif command == "axonius-get-devices-by-savedquery":
        results = get_by_sq(api_obj=client.devices, args=args)

    elif command == "axonius-get-users-by-savedquery":
        results = get_by_sq(api_obj=client.users, args=args)

    elif command == "axonius-get-devices-by-aql":
        results = get(api_obj=client.devices, args=args)

    elif command == "axonius-get-users-by-aql":
        results = get(api_obj=client.users, args=args)

    elif command == "axonius-get-users-by-mail":
        results = get_by_value(api_obj=client.users, args=args, method_name="mail")

    elif command == "axonius-get-users-by-mail-regex":
        results = get_by_value(api_obj=client.users, args=args, method_name="mail_regex")

    elif command == "axonius-get-users-by-username":
        results = get_by_value(api_obj=client.users, args=args, method_name="username")

    elif command == "axonius-get-users-by-username-regex":
        results = get_by_value(api_obj=client.users, args=args, method_name="username_regex")

    elif command == "axonius-get-devices-by-hostname":
        results = get_by_value(api_obj=client.devices, args=args, method_name="hostname")

    elif command == "axonius-get-devices-by-hostname-regex":
        results = get_by_value(api_obj=client.devices, args=args, method_name="hostname_regex")

    elif command == "axonius-get-devices-by-ip":
        results = get_by_value(api_obj=client.devices, args=args, method_name="ip")

    elif command == "axonius-get-devices-by-ip-regex":
        results = get_by_value(api_obj=client.devices, args=args, method_name="ip_regex")

    elif command == "axonius-get-devices-by-mac":
        results = get_by_value(api_obj=client.devices, args=args, method_name="mac")

    elif command == "axonius-get-devices-by-mac-regex":
        results = get_by_value(api_obj=client.devices, args=args, method_name="mac_regex")

    elif command == "axonius-get-saved-queries":
        results = get_saved_queries(client=client, args=args)

    elif command == "axonius-get-tags":
        results = get_tags(client=client, args=args)

    elif command == "axonius-add-note":
        results = add_note(client=client, args=args)

    elif command == "axonius-add-tag":
        results = update_tags(client=client, args=args, method_name="add")

    elif command == "axonius-remove-tag":
        results = update_tags(client=client, args=args, method_name="remove")

    # v2 API commands
    elif command == "axonius-get-assets":
        results = get_assets(args=args)

    elif command == "axonius-get-asset-types":
        results = get_asset_types()

    elif command == "axonius-get-custom-data":
        results = get_custom_data(args=args)

    elif command == "axonius-create-custom-data":
        results = create_custom_data(args=args)

    elif command == "axonius-delete-custom-data":
        results = delete_custom_data(args=args)

    elif command == "axonius-get-enforcements":
        results = get_enforcements(args=args)

    elif command == "axonius-run-enforcement":
        results = run_enforcement(args=args)

    elif command == "axonius-get-queries":
        results = get_queries(args=args)

    elif command == "axonius-create-query":
        results = create_query(args=args)

    elif command == "axonius-delete-query":
        results = delete_query(args=args)

    elif command == "axonius-get-grouped-vulnerabilities":
        results = get_grouped_vulnerabilities(args=args)

    return results


def main():
    """PARSE AND VALIDATE INTEGRATION PARAMS."""
    params: dict = demisto.params()
    command: str = demisto.command()

    url: str = params["ax_url"]
    key: str = params.get("credentials", {}).get("identifier")
    secret: str = params.get("credentials", {}).get("password")
    certverify: bool = not params.get("insecure", False)

    proxies: dict = handle_proxy()  # noqa: F821, F405
    demisto.debug(f"Attempting to connect via proxy with: {proxies}")

    demisto.debug(f"Command being called is {command}")
    args: dict = demisto.args()

    try:
        client = Connect(
            url=url,
            key=key,
            secret=secret,
            certverify=certverify,
            certwarn=False,
            proxy=proxies.get("https") or proxies.get("http"),
        )
        return_results(run_command(client, args, command))  # noqa: F821, F405

    except Exception as exc:
        demisto.error(traceback.format_exc())
        msg: List[str] = [f"Failed to execute {command} command", "Error:", str(exc)]
        return_error("\n".join(msg))  # noqa: F821, F405


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

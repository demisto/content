"""CYFIRMA integration for Cortex XSOAR.

Fetches alerts (Attack Surface, Brand Intelligence, Data Breach/Web Monitoring,
Social/Public Exposure) as incidents and exposes take-down and alert-parsing commands.
"""

import json
import uuid
from datetime import datetime, UTC
from typing import Any

import dateparser
import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
DEFAULT_MAX_FETCH = 100
DEFAULT_FIRST_FETCH = "90 days"
DATEPARSER_SETTINGS = {"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True}

_BASE_PREFIX_PATH = "/api/ex/v3/da"
_TEST_PATH = "/foo/ping"

_TAKE_DOWN_LIST_API_PATH = "/td/list"
_TAKE_DOWN_CREATE_API_PATH = "/td/create"

_API_PATHS = {
    "AS": "/al/as",
    "BI": "/al/bi",
    "DW": "/al/dbwm",
    "SP": "/al/spe",
}

_FETCH_PARAMS = {
    "fetchAttackSurface": ("AS",),
    "fetchBrandExposure": ("BI",),
    "fetchDataBreachWebMonitor": ("DW",),
    "fetchSocialPublicExposure": ("SP",),
}

_SKIP_FIELDS = frozenset(
    {
        "alertDetails",
        "networkAttributes",
        "portDetails",
        "certificateDetails",
        "configurationDetails",
        "ipDomainReputationDetails",
        "assetDetails",
        "vulnerabilities",
        "additionalDetails",
        "hasActive",
        "isSafe",
        "category",
        "categoryLabel",
        "subCategory",
        "subCategoryLabel",
        "compromisedDetails",
        "user",
    }
)


""" HELPERS """


def _kv_fields(data: dict, skip: frozenset | set = frozenset()) -> list[dict]:
    """Convert a dict into the XSOAR grid format.

    Args:
        data: Source dictionary.
        skip: Keys to exclude from the result.

    Returns:
        A list of ``{"fields": <Capitalized key>, "values": <value>}`` rows.
    """
    return [{"fields": key.capitalize(), "values": value} for key, value in data.items() if key not in skip]


def _safe_join(value: Any, sep: str = ",") -> str:
    """Join an iterable into a string without failing on non-string or missing values.

    Args:
        value: A list/tuple/set (joined), None (returned as empty string) or any scalar (stringified).
        sep: Separator placed between items.

    Returns:
        The joined string.
    """
    if isinstance(value, (list, tuple, set)):
        return sep.join(str(v) for v in value)
    return "" if value is None else str(value)


def _get_severity(risk_score) -> int:
    """Map a CYFIRMA exposure score to an XSOAR incident severity.

    Args:
        risk_score: Numeric (or numeric string) exposure score; invalid values are treated as unknown.

    Returns:
        An ``IncidentSeverity`` value: >8 critical, >5 high, >=3 medium, >=1 low, otherwise unknown.
    """
    try:
        score = float(risk_score)
    except (TypeError, ValueError):
        return IncidentSeverity.UNKNOWN
    if score > 8:
        return IncidentSeverity.CRITICAL
    if score > 5:
        return IncidentSeverity.HIGH
    if score >= 3:
        return IncidentSeverity.MEDIUM
    if score >= 1:
        return IncidentSeverity.LOW
    return IncidentSeverity.UNKNOWN


def _parse_date(value: str | None):
    """Parse a date string or relative expression (e.g. '90 days') as a UTC-aware datetime.

    Args:
        value: Date string, relative time expression, or None.

    Returns:
        A timezone-aware ``datetime``, or None if the value is empty or unparsable.
    """
    return dateparser.parse(value, settings=DATEPARSER_SETTINGS) if value else None


class Client(BaseClient):
    """HTTP client for the CYFIRMA API."""

    def call_api(self, end_point: str, params: dict | None = None) -> dict:
        """Perform a GET request with retries on transient gateway errors.

        Args:
            end_point: URL suffix appended to the client's base URL.
            params: Optional query-string parameters.

        Returns:
            The decoded JSON body, or an empty dict if the response has no content.

        Raises:
            DemistoException: On HTTP errors (after retrying 502/503/504 up to 3 times).
        """
        response = self._http_request(
            url_suffix=end_point,
            params=params,
            resp_type="response",
            method="GET",
            retries=3,
            status_list_to_retry=(502, 503, 504),
            raise_on_status=True,
        )
        if response.status_code == 200 and response.content:
            return response.json()
        return {}

    # ---- incident building ----
    def _populate_custom_fields(self, data: dict) -> dict:
        """Build the incident custom fields (grid fields) for an alert.

        Compromised-account alerts produce a single grid; all other alerts produce alert details,
        network attributes, digital footprints and, when present, deepfake and vulnerability grids.

        Args:
            data: A single alert as returned by the API.

        Returns:
            A dict mapping custom-field names to grid rows.
        """
        event_details = data.get("alertDetails", data)
        base = [
            {"fields": "Subcategory", "values": data.get("subCategoryLabel", "")},
            {"fields": "Category", "values": data.get("categoryLabel", "")},
        ]
        generic = _kv_fields(event_details, _SKIP_FIELDS)
        sub_category = data.get("subCategory", "")
        result = {
            "cyfirmaalertdetails": base
            + [
                {"fields": "Alertid", "values": data.get("alertId", "")},
                {"fields": "Objectid", "values": event_details.get("uid", "")},
            ]
            + generic,
            "cyfirmanetworkattributes": _kv_fields(event_details.get("networkAttributes", {})),
            "cyfirmadigitalfootprints": self._build_sub_category_data_fields(event_details, sub_category),
        }

        deep_fake_details = event_details.get("deepFakeDetails")
        if deep_fake_details:
            result["cyfirmadeepfakedetails"] = _kv_fields(deep_fake_details)

        if sub_category == "DOMAIN_IP_VULNERABILITY":
            result["cyfirmavulnerabilities"] = self._vulnerability_fields(event_details.get("vulnerabilities", []))
        return result

    def _build_sub_category_data_fields(self, alert_details: dict, sub_category: str) -> list:
        """Build the 'digital footprints' grid based on the alert's sub-category.

        Args:
            alert_details: The alert's details dict.
            sub_category: Sub-category code (OPEN_PORTS, CERTIFICATES, CONFIGURATION,
                IP_DOMAIN_REPUTATION or anything else for generic asset details).

        Returns:
            A list of ``{"fields": ..., "values": ...}`` rows.
        """
        if sub_category == "OPEN_PORTS":
            ports = [str(p["port"]) for p in alert_details.get("portDetails", []) if "port" in p]
            return [{"fields": "Open Ports", "values": ",".join(ports)}]

        if sub_category == "CERTIFICATES":
            return self._details_fields(alert_details.get("certificateDetails", {}), join_keys={"issuer"})

        if sub_category == "CONFIGURATION":
            return self._details_fields(
                alert_details.get("configurationDetails", {}),
                join_keys={"missingEppCodes"},
            )

        if sub_category == "IP_DOMAIN_REPUTATION":
            return self._details_fields(
                alert_details.get("ipDomainReputationDetails", {}),
                join_keys={"reportedCategories"},
                only_keys={"reportedCategories"},
            )

        return _kv_fields(alert_details.get("assetDetails", {}))

    @staticmethod
    def _vulnerability_fields(vulnerabilities: list) -> list:
        """Build the vulnerabilities grid.

        Args:
            vulnerabilities: List of vulnerability dicts from the alert.

        Returns:
            A list of rows with ``cve``, ``cvssscore``, ``kev`` and ``products`` keys.
        """
        return [
            {
                "cve": v.get("cveNo", ""),
                "cvssscore": v.get("cvssScore", ""),
                "kev": str(v.get("isKev", False)),
                "products": _safe_join(v.get("products", []), ", "),
            }
            for v in vulnerabilities
        ]

    @staticmethod
    def _details_fields(details: dict, join_keys: set, only_keys: set | None = None) -> list:
        """Convert a details dict into grid rows, optionally filtering and joining list values.

        Args:
            details: Source dictionary.
            join_keys: Keys whose list values should be joined into a comma-separated string.
            only_keys: If given, only these keys are included.

        Returns:
            A list of ``{"fields": key, "values": value}`` rows (keys are not capitalized).
        """
        result = []
        for key, value in details.items():
            if only_keys is not None and key not in only_keys:
                continue
            if key in join_keys:
                value = _safe_join(value)
            result.append({"fields": key, "values": value})
        return result

    def _build_incident_json(self, event: dict) -> dict[str, Any]:
        """Convert a CYFIRMA alert into an XSOAR incident dict.

        Args:
            event: A single alert as returned by the API.

        Returns:
            The incident dict (type, name, occurred, severity, rawJSON, custom fields, etc.).
        """
        occurred_date = _parse_date(event.get("alertCreatedDate") or event.get("lastModifiedDate"))
        alert_details = event.get("alertDetails", event)

        return {
            "type": event.get("categoryLabel", ""),
            "name": event.get("title", ""),
            "occurred": occurred_date.strftime(DATE_FORMAT) if occurred_date else None,
            "severity": _get_severity(alert_details.get("exposureScore", 0)),
            "rawJSON": json.dumps(event),
            "category": event.get("category", ""),
            "subcategory": event.get("subCategory", ""),
            "dbotMirrorId": str(event.get("alertId") or alert_details.get("uid") or ""),
            "sourceBrand": "CYFIRMA",
            "labels": [],
            "CustomFields": self._populate_custom_fields(data=event),
        }

    def get_incidents(self, params: dict, alerts_to_fetch: dict) -> list:
        """Fetch all pages of alerts for every enabled alert type and build incidents.

        Args:
            params: Base query parameters (size, after, includeThirdParty, ...).
            alerts_to_fetch: Mapping of alert-type code (AS, BI, DW, SP) to
                a boolean indicating whether that type should be fetched.

        Returns:
            A list of XSOAR incident dicts.
        """
        incidents: list = []

        for alert_type in (t for t, enabled in alerts_to_fetch.items() if enabled):
            request_params = {**params, "page": 0}
            end_point = _API_PATHS[alert_type]
            self._headers["X-Request-Id"] = str(uuid.uuid4())  # type: ignore[index]

            while True:
                response = self.call_api(end_point=end_point, params=request_params)
                incidents.extend(self._build_incident_json(event) for event in response.get("data", []))
                if response.get("metaData", {}).get("isLast", True):
                    break
                request_params["page"] += 1

        return incidents

    def initiate_take_down(self, alert_id: str, comment: str = "") -> dict:
        """Create a take-down request for an alert.

        Args:
            alert_id: ID of the alert to take down.
            comment: Optional comment sent along with the request.

        Returns:
            The raw API response (expected to contain a ``response`` or ``error`` key).
        """
        params = {"alertId": alert_id}
        if comment:
            params["comment"] = comment
        return self.call_api(_TAKE_DOWN_CREATE_API_PATH, params)

    def take_down_list_data(self, sub_category: str, page: str, size: str) -> list:
        """Retrieve a page of existing take-down tickets.

        Args:
            sub_category: Optional sub-category filter; empty string means all.
            page: Zero-based page number.
            size: Number of records per page.

        Returns:
            A list of take-down ticket dicts (empty if none were returned).
        """
        params = {"page": page, "size": size}
        if sub_category:
            params["subCategory"] = sub_category
        res = self.call_api(_TAKE_DOWN_LIST_API_PATH, params)
        return res.get("data", []) if isinstance(res, dict) else []


def test_module(client: Client) -> str:
    """Validate connectivity, credentials and that the organization/company is active.

    Args:
        client: Configured API client.

    Returns:
        "ok" on success, otherwise a message describing the authorization problem.

    Raises:
        DemistoException: For errors other than authorization failures.
    """
    try:
        res = client.call_api(_TEST_PATH)
    except DemistoException as e:
        if "Forbidden" in str(e) or "Unauthorized" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        raise

    if not res or not res.get("isOrgActive", False):
        return "Not Authorized"
    if "isCompanyActive" in res and not res.get("isCompanyActive", False):
        return "Not Authorized"
    return "ok"


def take_down_list_command_results(data: list, title: str) -> CommandResults:
    """Format take-down tickets as a markdown table and context outputs.

    Args:
        data: List of take-down ticket dicts from the API.
        title: Title of the markdown table.

    Returns:
        CommandResults with readable output and ``Cyfirma.TakeDownList`` context
        (or a "no data"/"unexpected format" message).
    """
    if not data:
        return CommandResults(readable_output="No data found for current request.")
    if not isinstance(data, list):
        return CommandResults(readable_output="Unexpected response format.")

    table_data, outputs = [], []
    for da in data:
        table_data.append(
            {
                "Ticket Id": da.get("ticket_name", ""),
                "URL Status Updated By": da.get("url_status_updated_by", ""),
                "URL Status": da.get("url_status", ""),
                "Domain": da.get("domain", ""),
                "Sub Category": da.get("sub_category", ""),
                "Category": da.get("category", ""),
                "Status": da.get("status", ""),
                "Created Date": da.get("created_date", ""),
                "Modified Date": da.get("modified_date", ""),
                "Created By": da.get("created_by", ""),
                "Modified By": da.get("modified_by", ""),
            }
        )
        outputs.append(
            {
                "ticket_id": da.get("ticket_name", ""),
                "sub_category": da.get("sub_category", ""),
                "created_date": da.get("created_date", ""),
                "modified_date": da.get("modified_date", ""),
                "status": da.get("status", ""),
                "domain": da.get("domain", ""),
                "created_by": da.get("created_by", ""),
                "modified_by": da.get("modified_by", ""),
            }
        )

    return CommandResults(
        readable_output=tableToMarkdown(title, table_data, removeNull=True),
        outputs_prefix="Cyfirma.TakeDownList",
        outputs_key_field="ticket_id",
        outputs=outputs,
        raw_response=data,
    )


def initiate_take_down_request(client: Client) -> CommandResults:
    """Command ``cyfirma-takedown-initiate``: create a take-down request for an alert.

    Command args:
        alert_id (required): ID of the alert.
        comment (optional): Comment for the request.

    Args:
        client: Configured API client.

    Returns:
        CommandResults with ``Cyfirma.InitiateTakeDown`` context containing the ticket ID and message.

    Raises:
        DemistoException: If ``alert_id`` is not provided.
    """
    args = demisto.args()
    alert_id = args.get("alert_id")
    if not alert_id:
        raise DemistoException("alert_id is required.")

    data = client.initiate_take_down(alert_id, args.get("comment", ""))

    ticket_id = ""
    if not data:
        msg = "No data found for current request."
    elif data.get("error"):
        msg = "Error in creating take down request."
    elif not data.get("response"):
        msg = "Error in creating take down request."
    else:
        ticket_id = data["response"].get("ticketName", "")
        msg = f"Take Down Request Created Successfully - Ticket ID: {ticket_id}"

    return CommandResults(
        readable_output=msg,
        outputs_prefix="Cyfirma.InitiateTakeDown",
        outputs_key_field="ticket_id",
        outputs={"ticket_id": ticket_id, "message": msg},
        raw_response=data,
    )


def get_take_down_list(client: Client) -> CommandResults:
    """Command ``cyfirma-takedown-list``: list take-down tickets.

    Command args:
        sub_category (optional): Filter by sub-category; defaults to all.
        size (optional): Page size; defaults to "50".
        page (optional): Zero-based page number; defaults to "0".

    Args:
        client: Configured API client.

    Returns:
        CommandResults built by ``take_down_list_command_results``.
    """
    args = demisto.args()
    sub_category = args.get("sub_category", "")
    size = args.get("size", "50")
    page = args.get("page", "0")

    res_data = client.take_down_list_data(sub_category, page, size)
    return take_down_list_command_results(
        res_data,
        f"CYFIRMA Take Down List - Sub Category: {sub_category or 'All'}, Page: {page}, Size: {size}",
    )


def fetch_incidents(client: Client, first_fetch: str, max_fetch: int) -> None:
    """Fetch new alerts since the last run and push them to XSOAR as incidents.

    The last-run timestamp is captured *before* querying the API (in UTC) so alerts
    created while the fetch is running are picked up on the next run.

    Args:
        client: Configured API client.
        first_fetch: Relative or absolute start time used on the first run (e.g. "90 days").
        max_fetch: Page size used when querying alerts.

    Raises:
        DemistoException: If ``first_fetch`` cannot be parsed.
    """
    params = demisto.params()
    last_run = demisto.getLastRun() or {}

    alerts_to_fetch = {
        alert_type: argToBoolean(params.get(param, False))
        for param, alert_types in _FETCH_PARAMS.items()
        for alert_type in alert_types
    }

    start_fetch = _parse_date(last_run.get("last_fetch") or first_fetch)
    if start_fetch is None:
        raise DemistoException(f"Invalid 'First fetch' value: {first_fetch!r}")

    # Capture BEFORE calling the API so alerts created mid-fetch aren't skipped.
    # Original used naive local datetime.now() but labeled it as UTC ('Z').
    fetch_started = datetime.now(UTC)

    request_params = {
        "page": 0,
        "size": max_fetch,
        "after": int(start_fetch.timestamp() * 1000),
        "includeThirdParty": argToBoolean(params.get("includeThirdParty", False)),
    }
    incidents = client.get_incidents(params=request_params, alerts_to_fetch=alerts_to_fetch)

    demisto.incidents(incidents)
    demisto.setLastRun({"last_fetch": fetch_started.strftime(DATE_FORMAT)})


def command_alertdetailextraction() -> None:
    """Command ``cyfirma-alert-parser``: flatten the incident's alert-details grid into context.

    Reads the ``cyfirmaalertdetails`` custom field of the current incident and writes it
    to ``Cyfirma.Alert`` as a ``{field: value}`` dict. Exits with an error if the grid is empty.
    """
    rows = (demisto.incident().get("CustomFields") or {}).get("cyfirmaalertdetails") or []
    if not rows:
        return_error("cyfirmaalertdetails is empty on this incident")

    result = {row["fields"]: row.get("values") for row in rows if row.get("fields")}
    return_results(
        CommandResults(
            outputs_prefix="Cyfirma.Alert",
            outputs=result,
            readable_output=f"Parsed alert {result}",
        )
    )


def main() -> None:
    """Read integration parameters, build the client and dispatch the invoked command."""
    params = demisto.params()
    command = demisto.command()

    api_url = params.get("url", "").rstrip("/")
    api_key = (params.get("api_key") or {}).get("password")
    if not api_url or not api_key:
        return_error("Server URL and API Key are required.")

    max_fetch = int(params.get("max_fetch") or DEFAULT_MAX_FETCH)
    first_fetch = (params.get("first_fetch") or DEFAULT_FIRST_FETCH).strip()
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    demisto.info(f"Command being called is {command}")

    try:
        client = Client(
            base_url=urljoin(api_url, _BASE_PREFIX_PATH),
            verify=verify_certificate,
            headers={"X-Api-Key": api_key, "X-App-Name": "PALO_ALTO_XSOAR_V2_AL"},
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-incidents":
            fetch_incidents(client, first_fetch, max_fetch)
        elif command == "cyfirma-takedown-initiate":
            return_results(initiate_take_down_request(client))
        elif command == "cyfirma-takedown-list":
            return_results(get_take_down_list(client))
        elif command == "cyfirma-alert-parser":
            command_alertdetailextraction()
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        if "Forbidden" in str(e):
            return_error("Authorization Error: make sure API Key is correctly set")
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()

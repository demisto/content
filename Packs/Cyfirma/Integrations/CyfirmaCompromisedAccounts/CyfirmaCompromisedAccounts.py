"""CYFIRMA Compromised Accounts integration for Cortex XSOAR.

Fetches customer-account, compromised-employee and public-account leak as incidents.
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

_DD_COM_ACC_PATH = "/dd/dbwm/ca"

_API_PATHS = {
    "CUS": f"{_DD_COM_ACC_PATH}/customer-accounts",
    "EMP": f"{_DD_COM_ACC_PATH}/compromised-employees",
    "PUB": f"{_DD_COM_ACC_PATH}/public-accounts-leaks",
}

_SKIP_FIELDS = frozenset(
    {
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


def _kv_fields(data: dict, skip: frozenset | set = frozenset()) -> list[dict[str, Any]]:
    """Convert a dict into the XSOAR grid format.

    Args:
        data: Source dictionary.
        skip: Keys to exclude.

    Returns:
        A list of ``{"fields": <Capitalized key>, "values": <value>}`` rows.
    """
    return [{"fields": key.capitalize(), "values": value} for key, value in data.items() if key not in skip]


def _parse_date(value: str | None):
    """Parse a date string or relative expression (e.g. '90 days') as a UTC-aware datetime.

    Args:
        value: Date string, relative time expression, or None.

    Returns:
        A timezone-aware ``datetime``, or None if the value is empty or unparsable.
    """
    return dateparser.parse(value, settings=DATEPARSER_SETTINGS) if value else None


class Client(BaseClient):
    """HTTP client for the CYFIRMA DeCYFIR compromised-accounts API."""

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

    def _populate_custom_fields(self, data: dict) -> dict:
        """Build the compromised-account grid custom field for an alert.

        Args:
            data: A single alert as returned by the API.

        Returns:
            ``{"cyfirmacompromisedaccountdetails": [rows]}`` containing the sub-category and
            category labels, the remaining top-level alert fields and the ``compromisedDetails`` fields.
        """
        rows = (
            [
                {"fields": "Subcategory", "values": data.get("subCategoryLabel", "")},
                {"fields": "Category", "values": data.get("categoryLabel", "")},
            ]
            + _kv_fields(data, _SKIP_FIELDS)
            # "or {}" protects against an explicit null in the API response
            + _kv_fields(data.get("compromisedDetails") or {})
        )
        return {"cyfirmacompromisedaccountdetails": rows}

    def _build_incident_json(self, event: dict) -> dict[str, Any]:
        """Convert an alert into an XSOAR incident dict.

        Args:
            event: A single alert as returned by the API.

        Returns:
            The incident dict. Severity is always critical (compromised credentials).
        """

        occurred_date = _parse_date(event.get("lastModifiedDate") or event.get("createdDate"))

        return {
            "type": event.get("categoryLabel", ""),
            "name": event.get("title", ""),
            "occurred": occurred_date.strftime(DATE_FORMAT) if occurred_date else None,
            "severity": IncidentSeverity.CRITICAL,
            "rawJSON": json.dumps(event),
            "category": event.get("category", ""),
            "subcategory": event.get("subCategory", ""),
            "dbotMirrorId": event.get("uid", ""),
            "sourceBrand": "CYFIRMA",
            "labels": [],
            "CustomFields": self._populate_custom_fields(data=event),
        }

    def get_incidents(self, params: dict) -> list:
        """Fetch every page of every compromised-account endpoint and build incidents.

        Args:
            params: Base query parameters (size, after, includeThirdParty, ...). Not modified.

        Returns:
            A list of XSOAR incident dicts.
        """
        incidents: list = []

        for api_path in _API_PATHS.values():
            request_params = {**params, "page": 0}
            self._headers["X-Request-Id"] = str(uuid.uuid4())  # type: ignore[index]

            while True:
                response = self.call_api(end_point=api_path, params=request_params)
                incidents.extend(self._build_incident_json(event) for event in response.get("data", []))
                if response.get("metaData", {}).get("isLast", True):
                    break
                request_params["page"] += 1

        return incidents


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


def fetch_incidents(client: Client, first_fetch: str, max_fetch: int) -> None:
    """Fetch new alerts since the last run and push them to XSOAR as incidents.

    The last-run timestamp is captured in UTC *before* querying the API so alerts created
    while the fetch is running are picked up next time. (The original saved naive local time
    labelled as UTC, taken after the fetch.)

    Args:
        client: Configured API client.
        first_fetch: Relative or absolute start time used on the first run (e.g. "90 days").
        max_fetch: Page size used when querying alerts.

    Raises:
        DemistoException: If ``first_fetch`` cannot be parsed.
    """
    params = demisto.params()
    last_run = demisto.getLastRun() or {}

    start_fetch = _parse_date(last_run.get("last_fetch") or first_fetch)
    if start_fetch is None:
        raise DemistoException(f"Invalid 'First fetch' value: {first_fetch!r}")

    fetch_started = datetime.now(UTC)

    request_params = {
        "page": 0,
        "size": max_fetch,
        "after": int(start_fetch.timestamp() * 1000),
        "includeThirdParty": argToBoolean(params.get("includeThirdPartyCompromisedAccounts", False)),
    }
    incidents = client.get_incidents(params=request_params)

    demisto.incidents(incidents)
    demisto.setLastRun({"last_fetch": fetch_started.strftime(DATE_FORMAT)})


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
            headers={"X-Api-Key": api_key, "X-App-Name": "PALO_ALTO_XSOAR_V2_CA"},
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-incidents":
            fetch_incidents(client, first_fetch, max_fetch)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        if "Forbidden" in str(e):
            return_error("Authorization Error: make sure API Key is correctly set")
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()

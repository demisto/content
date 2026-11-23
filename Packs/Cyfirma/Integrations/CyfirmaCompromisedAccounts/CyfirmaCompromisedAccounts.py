"""CYFIRMA Compromised Accounts integration for Cortex XSOAR.

Fetches customer-account, compromised-employee and public-account leak as incidents.
"""

import json
import uuid
from typing import Any

import dateparser
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from ContentClientApiModule import *


""" CONSTANTS """


DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
DEFAULT_MAX_FETCH = 100
DEFAULT_FIRST_FETCH = "60 days"

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


def kv_fields(data: dict, skip: frozenset | set = frozenset()) -> list[dict[str, Any]]:
    """Convert a dict into the XSOAR grid format.

    Args:
        data: Source dictionary.
        skip: Keys to exclude.

    Returns:
        A list of ``{"fields": <Capitalized key>, "values": <value>}`` rows.
    """
    return [{"fields": key.capitalize(), "values": value} for key, value in data.items() if key not in skip]


def parse_date(value: str | None):
    """Parse a date string into a timezone-aware datetime object."""
    return dateparser.parse(value) if value else None


class Client(ContentClient):
    """HTTP client for the CYFIRMA DeCYFIR compromised-accounts API."""

    def populate_custom_fields(self, data: dict) -> dict:
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
            + kv_fields(data, _SKIP_FIELDS)
            # "or {}" protects against an explicit null in the API response
            + kv_fields(data.get("compromisedDetails") or {})
        )
        return {"cyfirmacompromisedaccountdetails": rows}

    def build_incident_json(self, event: dict) -> dict[str, Any]:
        """Convert an alert into an XSOAR incident dict.

        Args:
            event: A single alert as returned by the API.

        Returns:
            The incident dict. Severity is always critical (compromised credentials).
        """

        occurred_date = parse_date(event.get("lastModifiedDate") or event.get("createdDate"))
        breach_date = parse_date(event.get("compromisedDetails", {}).get("breachDate", ""))

        return {
            "type": event.get("categoryLabel", ""),
            "name": event.get("title", ""),
            "occurred": occurred_date.strftime(DATE_FORMAT) if occurred_date else None,
            "datetimeofthebreach": breach_date.strftime(DATE_FORMAT) if breach_date else None,
            "severity": IncidentSeverity.CRITICAL,
            "rawJSON": json.dumps(event),
            "category": event.get("category", ""),
            "subCategory": event.get("subCategory", ""),
            "dbotMirrorId": event.get("uid", ""),
            "sourceBrand": "CYFIRMA",
            "labels": [],
            "CustomFields": self.populate_custom_fields(data=event),
        }

    def get_incidents(self, req_params: dict) -> list:
        """Fetch every page of every compromised-account endpoint and build incidents.

        Args:
            req_params: Base query parameters (size, after, includeThirdParty, ...). Not modified.

        Returns:
            A list of XSOAR incident dicts.
        """
        incidents: list = []
        req_size = req_params.get("size", 0)
        req_params["page"] = 0

        for api_path in _API_PATHS.values():
            headers = {"X-Request-ID": str(uuid.uuid4())}
            remaining = req_size - len(incidents)

            if remaining <= 0:
                break

            while remaining > 0 and req_params["page"] < req_size:
                response = self.get(api_path, params=req_params, headers=headers)
                events = response.get("data") or []
                meta_data = response.get("metaData") or {}

                incidents.extend(self.build_incident_json(event) for event in events[:remaining])
                remaining = req_size - len(incidents)

                total_pages = meta_data.get("totalPages")
                next_page = req_params["page"] + 1
                if not events or meta_data.get("isLast", True) or (total_pages is not None and next_page >= total_pages):
                    break

                req_params["page"] = next_page

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
        res = client.get(_TEST_PATH)
    except DemistoException as e:
        if "Forbidden" in str(e) or "Unauthorized" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        raise

    if not res or not res.get("isOrgActive", False):
        return "Not Authorized"
    if "isCompanyActive" in res and not res.get("isCompanyActive", False):
        return "Not Authorized"
    return "ok"


def fetch_incidents(client: Client, first_fetch: str, max_fetch: int, params: dict, last_run: dict) -> None:
    """Fetch new alerts since the last run and push them to XSOAR as incidents.

    The last-run timestamp is captured in UTC *before* querying the API so alerts created
    while the fetch is running are picked up next time. (The original saved naive local time
    labelled as UTC, taken after the fetch.)

    Args:
        client: Configured API client.
        first_fetch: Relative or absolute start time used on the first run (e.g. "90 days").
        max_fetch: Page size used when querying alerts.
        params: Integration parameters.

    Raises:
        DemistoException: If ``first_fetch`` cannot be parsed.
    """
    after = parse_date(last_run.get("last_fetch") or first_fetch)
    if after is None:
        raise DemistoException(f"Invalid 'First fetch' value: {first_fetch!r}")

    next_run_from = datetime.now(timezone.utc)

    request_params = {
        "size": max_fetch,
        "after": int(after.timestamp() * 1000),
        "includeThirdParty": argToBoolean(params.get("includeThirdPartyCompromisedAccounts", False)),
    }
    incidents = client.get_incidents(req_params=request_params)

    demisto.incidents(incidents)
    demisto.setLastRun({"last_fetch": next_run_from.strftime(DATE_FORMAT)})


def main() -> None:
    """Read integration parameters, build the client and dispatch the invoked command."""
    params = demisto.params()
    command = demisto.command()
    last_run = demisto.getLastRun() or {}

    api_url = params.get("url", "").rstrip("/")
    api_key = ((params.get("api_key") or {}).get("password") or "").strip()
    if not api_url or not api_key:
        return_error("Server URL and API Key are required.")

    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
    first_fetch = (params.get("first_fetch") or DEFAULT_FIRST_FETCH).strip()
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    demisto.info(f"Command being called is {command}")

    try:
        api_path = urljoin(f"{api_url}/{_BASE_PREFIX_PATH.lstrip('/')}")
        client = Client(
            base_url=api_path,
            verify=verify_certificate,
            proxy=proxy,
            headers={"X-App-Name": "PALO_ALTO_XSOAR_V2_AL"},
            auth_handler=APIKeyAuthHandler(key=api_key, header_name="X-Api-Key"),
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-incidents":
            fetch_incidents(client, first_fetch, max_fetch, params, last_run)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.debug(traceback.format_exc())
        if "Forbidden" in str(e):
            return_error("Authorization Error: make sure API Key is correctly set")
        return_error(f"Failed to execute {command} command.\nError:\n{e}", error=str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()

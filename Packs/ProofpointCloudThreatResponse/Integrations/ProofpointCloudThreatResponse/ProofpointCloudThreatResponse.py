"""Proofpoint Cloud Threat Response integration.

Fetches Proofpoint Cloud Threat Response (CTR) incidents into Cortex XSOAR
and exposes commands to list and retrieve incident details. Authentication is
performed via OAuth2 client_credentials against ``https://auth.proofpoint.com/v1/token``.
"""

from collections.abc import Iterable
from typing import Any

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings - users can opt-in via the insecure parameter.
urllib3.disable_warnings()

# ----------------------------------------------------------------------------- #
# Constants
# ----------------------------------------------------------------------------- #
AUTH_URL = "https://auth.proofpoint.com/v1/token"
INTEGRATION_NAME = "Proofpoint Cloud Threat Response"
INTEGRATION_CONTEXT_KEY = "access_token"
INTEGRATION_CONTEXT_EXPIRES_KEY = "token_expires_at"
TOKEN_EXPIRY_BUFFER_SEC = 60
DATE_FORMAT_API = "%Y-%m-%d %H:%M:%S"
DEFAULT_FETCH_LIMIT = 50
MAX_PAGE_SIZE = 200
SOURCE_FILTERS_ALLOWED = {"abuse_mailbox", "tap", "smart_search", "message_csv_upload"}
OTHER_FILTERS_ALLOWED = {"open_incidents", "closed_incidents", "vap"}
VERDICT_FILTERS_ALLOWED = {
    "verdict_failed",
    "verdict_low_risk",
    "verdict_manual_review",
    "verdict_threat",
}
DISPOSITION_ALLOWED = {
    "bulk",
    "clean",
    "impostor",
    "in_progress",
    "internal",
    "low_risk",
    "malware",
    "manual_review",
    "not_set",
    "phish",
    "scam",
    "simulated_phish",
    "spam",
    "suspicious",
    "tap_false_positive",
    "toad",
    "vendor",
}
CONFIDENCE_FILTERS_ALLOWED = {"confidence_high", "confidence_medium", "confidence_low"}
OUTPUT_PREFIX = "ProofPointCloud.Incident"

# ----------------------------------------------------------------------------- #
# Client
# ----------------------------------------------------------------------------- #


class Client(BaseClient):
    """HTTP client for Proofpoint Cloud Threat Response APIs."""

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        verify: bool = True,
        proxy: bool = False,
    ) -> None:
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._client_id = client_id
        self._client_secret = client_secret

    # ------------------------------------------------------------------ auth
    def _get_token(self) -> str:
        """Return a valid Bearer token, using ``integration_context`` cache.

        A new token is requested when the cached one is missing or about to
        expire (``TOKEN_EXPIRY_BUFFER_SEC`` seconds margin).
        """
        context = get_integration_context() or {}
        cached_token = context.get(INTEGRATION_CONTEXT_KEY)
        expires_at = context.get(INTEGRATION_CONTEXT_EXPIRES_KEY, 0)
        now = int(time.time())
        if cached_token and now < int(expires_at) - TOKEN_EXPIRY_BUFFER_SEC:
            return cached_token

        demisto.debug("Proofpoint CTR: requesting a new access token")
        response = self._http_request(
            method="POST",
            full_url=AUTH_URL,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            timeout=30,
        )
        token = response.get("access_token")
        if not token:
            raise DemistoException("Failed to retrieve an access token from Proofpoint auth endpoint.")
        expires_in = int(response.get("expires_in", 3600))
        set_integration_context(
            {
                INTEGRATION_CONTEXT_KEY: token,
                INTEGRATION_CONTEXT_EXPIRES_KEY: now + expires_in,
            }
        )
        return token

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------ api
    def list_incidents(self, body: dict[str, Any]) -> dict[str, Any]:
        """Call ``POST /api/v1/tric/incidents`` with the supplied body."""
        return self._http_request(
            method="POST",
            url_suffix="/api/v1/tric/incidents",
            headers=self._auth_headers(),
            json_data=body,
            timeout=60,
        )

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Call ``GET /api/v1/tric/incidents/<incident_id>``."""
        return self._http_request(
            method="GET",
            url_suffix=f"/api/v1/tric/incidents/{incident_id}",
            headers=self._auth_headers(),
            timeout=60,
        )


# ----------------------------------------------------------------------------- #
# Helpers
# ----------------------------------------------------------------------------- #


def format_ctr_date(value: datetime) -> str:
    """Format a datetime as ``YYYY-MM-DD HH:MM:SS`` (UTC, no timezone suffix)."""
    if value.tzinfo is not None:
        value = value.astimezone(tz=None).replace(tzinfo=None)
    return value.strftime(DATE_FORMAT_API)


def parse_ctr_date(value: str | None) -> datetime | None:
    """Parse a date string from arguments or last-run into a UTC ``datetime``."""
    if not value:
        return None
    parsed = dateparser.parse(value, settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": False})
    if not parsed:
        raise DemistoException(f"Could not parse date value: {value!r}")
    return parsed


def _validate_allowed(values: list[str], allowed: set[str], arg_name: str) -> list[str]:
    """Raise if any item in ``values`` is not part of ``allowed``."""
    invalid = [v for v in values if v not in allowed]
    if invalid:
        raise DemistoException(
            f"Invalid value(s) for {arg_name!r}: {invalid}. Allowed: {sorted(allowed)}."
        )
    return values


def build_filters_body(
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    incident_id_filters: list[str] | None = None,
    source_filters: list[str] | None = None,
    other_filters: list[str] | None = None,
    verdict_filters: list[str] | None = None,
    disposition: list[str] | None = None,
    confidence_filters: list[str] | None = None,
    start_row: int = 0,
    end_row: int = DEFAULT_FETCH_LIMIT,
    sort_col: str = "createdAt",
    sort_dir: str = "desc",
) -> dict[str, Any]:
    """Build a request body for ``POST /api/v1/tric/incidents``.

    Empty/None filter lists are omitted to mirror the design's expected shape.
    """
    filters: dict[str, Any] = {}
    if start_time and end_time:
        filters["time_range_filter"] = {
            "start": format_ctr_date(start_time),
            "end": format_ctr_date(end_time),
        }
    if incident_id_filters:
        filters["incident_id_filters"] = list(incident_id_filters)
    if source_filters:
        filters["source_filters"] = _validate_allowed(
            list(source_filters), SOURCE_FILTERS_ALLOWED, "source_filters"
        )
    if other_filters:
        filters["other_filters"] = _validate_allowed(
            list(other_filters), OTHER_FILTERS_ALLOWED, "other_filters"
        )
    if verdict_filters:
        filters["verdict_filters"] = _validate_allowed(
            list(verdict_filters), VERDICT_FILTERS_ALLOWED, "verdict_filters"
        )
    if disposition:
        filters["disposition"] = _validate_allowed(
            list(disposition), DISPOSITION_ALLOWED, "disposition"
        )
    if confidence_filters:
        filters["confidence_filters"] = _validate_allowed(
            list(confidence_filters), CONFIDENCE_FILTERS_ALLOWED, "confidence_filters"
        )

    return {
        "filters": filters,
        "endRow": end_row,
        "startRow": start_row,
        "sortParams": [{"sort": sort_dir, "colId": sort_col}],
    }


def _coerce_int_arg(value: Any, default: int, name: str) -> int:
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise DemistoException(f"Argument {name!r} must be an integer.") from exc


# ----------------------------------------------------------------------------- #
# Commands
# ----------------------------------------------------------------------------- #


def test_module(client: Client, params: dict[str, Any]) -> str:
    """Validate connectivity and (when fetching) the configured state filter."""
    if argToBoolean(params.get("isFetch", False)):
        states = argToList(params.get("fetch_states") or [])
        if not states:
            return (
                "When 'Fetch incidents' is enabled you must select at least one value in "
                "'Fetch incidents with specific states'."
            )
        if "open_incidents" in states and "closed_incidents" in states:
            return (
                "Selecting both 'open_incidents' and 'closed_incidents' in 'Fetch incidents "
                "with specific states' returns an empty result from the Proofpoint API. "
                "Please choose only one of them."
            )

    # Hit the API with a minimal one-minute window to validate auth + connectivity.
    end = datetime.utcnow()
    start = end - timedelta(minutes=1)
    body = build_filters_body(start_time=start, end_time=end, start_row=0, end_row=1)
    client.list_incidents(body)
    return "ok"


def proofpoint_ctr_incidents_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List CTR incidents based on the supplied filter arguments."""
    start_dt = parse_ctr_date(args.get("start_time"))
    end_dt = parse_ctr_date(args.get("end_time"))
    if start_dt and not end_dt:
        end_dt = datetime.utcnow()

    limit = _coerce_int_arg(args.get("limit"), DEFAULT_FETCH_LIMIT, "limit")
    if limit < 1:
        raise DemistoException("Argument 'limit' must be a positive integer.")
    end_row = max(0, limit - 1)

    body = build_filters_body(
        start_time=start_dt,
        end_time=end_dt,
        incident_id_filters=argToList(args.get("incident_id_filters")),
        source_filters=argToList(args.get("source_filters")),
        other_filters=argToList(args.get("other_filters")),
        verdict_filters=argToList(args.get("verdict_filters")),
        disposition=argToList(args.get("disposition")),
        confidence_filters=argToList(args.get("confidence_filters")),
        start_row=0,
        end_row=end_row,
    )

    response = client.list_incidents(body)
    incidents = response.get("incidents") or []

    hr_rows = [
        {
            "ID": inc.get("id"),
            "Display ID": inc.get("displayId"),
            "Title": inc.get("title"),
            "State": inc.get("state"),
            "Created At": inc.get("createdAt"),
            "Message Count": inc.get("messageCount"),
            "Assigned Team Name": inc.get("assignedTeamName"),
            "Source Types": inc.get("sourceTypes"),
            "Type": (inc.get("sourcesData") or [{}])[0].get("type"),
        }
        for inc in incidents
    ]
    readable = tableToMarkdown(
        f"{INTEGRATION_NAME} Incidents",
        hr_rows,
        headers=[
            "ID",
            "Display ID",
            "Created At",
            "Type",
            "State",
            "Message Count",
            "Assigned Team Name",
            "Title",
            "Source Types",
        ],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=incidents,
        readable_output=readable,
        raw_response=response,
    )


def proofpoint_ctr_incident_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve full details for one or more CTR incidents."""
    incident_ids = argToList(args.get("incident_id"))
    if not incident_ids:
        raise DemistoException("Argument 'incident_id' is required.")

    results: list[dict[str, Any]] = []
    hr_rows: list[dict[str, Any]] = []
    for inc_id in incident_ids:
        response = client.get_incident(inc_id)
        results.append(response)
        summary = response.get("summary") or {}
        hr_rows.append(
            {
                "ID": summary.get("id") or inc_id,
                "Display ID": summary.get("displayId"),
                "Created At": summary.get("createdAt"),
                "State": summary.get("state"),
                "Message Count": summary.get("messageCount"),
                "Assigned Team Name": summary.get("assignedTeamName"),
                "Title": summary.get("title"),
            }
        )

    readable = tableToMarkdown(
        f"{INTEGRATION_NAME} Incident",
        hr_rows,
        headers=[
            "ID",
            "Display ID",
            "Created At",
            "State",
            "Message Count",
            "Assigned Team Name",
            "Title",
        ],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX,
        outputs_key_field="summary.id",
        outputs=results,
        readable_output=readable,
        raw_response=results,
    )


# ----------------------------------------------------------------------------- #
# Fetch
# ----------------------------------------------------------------------------- #


def _build_incident(enriched: dict[str, Any], list_entry: dict[str, Any]) -> dict[str, Any]:
    """Construct an XSOAR incident dict from a CTR incident payload."""
    summary = enriched.get("summary") or list_entry
    occurred_raw = summary.get("createdAt") or list_entry.get("createdAt")
    occurred = occurred_raw
    parsed_occurred = parse_ctr_date(occurred_raw) if occurred_raw else None
    if parsed_occurred is not None:
        occurred = parsed_occurred.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "name": f"Proofpoint CTR Incident {summary.get('displayId') or summary.get('id')}",
        "occurred": occurred,
        "rawJSON": json.dumps({**list_entry, **enriched}),
        "dbotMirrorId": str(summary.get("id") or list_entry.get("id") or ""),
    }


def _filter_new_incidents(
    incidents: list[dict[str, Any]],
    last_fetched_ids: Iterable[str],
) -> list[dict[str, Any]]:
    """Drop incidents whose ``id`` was already ingested in the previous run."""
    seen = set(last_fetched_ids)
    return [inc for inc in incidents if inc.get("id") not in seen]


def fetch_incidents(
    client: Client,
    params: dict[str, Any],
    last_run: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch CTR incidents using a sliding time window.

    The function returns a tuple ``(next_last_run, incidents)``. ``incidents``
    is the list of XSOAR incident dicts to pass to :func:`demisto.incidents`.
    """
    fetch_delta_minutes = _coerce_int_arg(params.get("fetch_delta"), 1, "fetch_delta")
    max_fetch = _coerce_int_arg(params.get("max_fetch"), DEFAULT_FETCH_LIMIT, "max_fetch")
    max_fetch = min(max_fetch, MAX_PAGE_SIZE)
    fetch_states = argToList(params.get("fetch_states") or [])
    if "open_incidents" in fetch_states and "closed_incidents" in fetch_states:
        raise DemistoException(
            "Selecting both 'open_incidents' and 'closed_incidents' in 'Fetch incidents "
            "with specific states' returns an empty result from the Proofpoint API."
        )

    now = datetime.utcnow()
    last_fetch_iso = last_run.get("last_fetch")
    if last_fetch_iso:
        start = parse_ctr_date(last_fetch_iso) or now
    else:
        first_fetch_param = params.get("first_fetch") or "3 days"
        first_fetch = dateparser.parse(
            first_fetch_param,
            settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": False},
        )
        if not first_fetch:
            raise DemistoException(f"Invalid 'First fetch timestamp' value: {first_fetch_param!r}")
        start = first_fetch

    # Apply the configured delta buffer to mitigate clock drift.
    start = start - timedelta(minutes=fetch_delta_minutes)
    if start >= now:
        start = now - timedelta(minutes=fetch_delta_minutes)

    body = build_filters_body(
        start_time=start,
        end_time=now,
        other_filters=fetch_states or None,
        start_row=0,
        end_row=max(0, max_fetch - 1),
        sort_dir="asc",
    )
    response = client.list_incidents(body)
    raw_incidents: list[dict[str, Any]] = response.get("incidents") or []

    last_fetched_ids = last_run.get("last_fetched_ids") or []
    new_incidents = _filter_new_incidents(raw_incidents, last_fetched_ids)

    xsoar_incidents: list[dict[str, Any]] = []
    processed_ids: list[str] = list(last_fetched_ids)
    latest_created_at: datetime | None = parse_ctr_date(last_fetch_iso) if last_fetch_iso else None

    for inc in new_incidents[:max_fetch]:
        inc_id = inc.get("id")
        if not inc_id:
            continue
        try:
            enriched = client.get_incident(inc_id)
        except Exception as exc:  # noqa: BLE001
            demisto.error(f"Proofpoint CTR: failed to enrich incident {inc_id}: {exc}")
            enriched = {}
        xsoar_incidents.append(_build_incident(enriched, inc))
        processed_ids.append(inc_id)
        created_at = parse_ctr_date(inc.get("createdAt"))
        if created_at and (latest_created_at is None or created_at > latest_created_at):
            latest_created_at = created_at

    if latest_created_at is None:
        latest_created_at = parse_ctr_date(last_fetch_iso) or start

    # Persist only IDs that share the latest second to keep the dedupe set small.
    cutoff_iso = format_ctr_date(latest_created_at)
    next_last_fetched_ids = [
        inc.get("id")
        for inc in raw_incidents
        if inc.get("id") and inc.get("createdAt") and inc.get("createdAt").startswith(cutoff_iso)
    ]
    if not next_last_fetched_ids:
        next_last_fetched_ids = processed_ids[-MAX_PAGE_SIZE:]

    next_last_run = {
        "last_fetch": format_ctr_date(latest_created_at),
        "last_fetched_ids": next_last_fetched_ids,
    }
    return next_last_run, xsoar_incidents


# ----------------------------------------------------------------------------- #
# Entrypoint
# ----------------------------------------------------------------------------- #


def main() -> None:  # pragma: no cover - exercised indirectly by tests
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    credentials = params.get("credentials") or {}
    client_id = credentials.get("identifier") or ""
    client_secret = credentials.get("password") or ""
    base_url = (params.get("url") or "").rstrip("/")
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    if not client_id or not client_secret:
        return_error("Client ID and Client Secret must be provided.")

    client = Client(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        verify=verify,
        proxy=proxy,
    )

    demisto.debug(f"Proofpoint CTR: command={command}")
    try:
        if command == "test-module":
            return_results(test_module(client, params))
        elif command == "fetch-incidents":
            next_last_run, incidents = fetch_incidents(client, params, demisto.getLastRun() or {})
            demisto.setLastRun(next_last_run)
            demisto.incidents(incidents)
        elif command == "proofpoint-ctr-incidents-list":
            return_results(proofpoint_ctr_incidents_list_command(client, args))
        elif command == "proofpoint-ctr-incident-get":
            return_results(proofpoint_ctr_incident_get_command(client, args))
        else:
            raise NotImplementedError(f"Command {command!r} is not implemented.")
    except Exception as exc:  # noqa: BLE001
        return_error(f"Failed to execute {command!r}. Error: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()

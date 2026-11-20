import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import json
import re
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
import dateutil.parser

from collections.abc import Callable
from typing import Any

ENTRY_TYPE_USER = "ENTRY_TYPE_USER"
ENTRY_TYPE_IDENTITY = "ENTRY_TYPE_IDENTITY"

LABEL_STATUS_ACTIVE = "LABEL_STATUS_ACTIVE"

RISKY_USER = "Risky User"

LEAVING_ORG_USER = "Leaving Org User"

ENTRY_TYPE_EVENT = "ENTRY_TYPE_EVENT"

LABEL_STATUS_RESOLVED = "LABEL_STATUS_RESOLVED"

FILTER_RELATIONSHIP_AND = "FILTER_RELATIONSHIP_AND"
PAGE_SIZE = 1000
MAX_PAGES = 1000  # hard cap on _paginate_all iterations; guards against an unbounded loop

DEMISTO_OCCURRED_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
RECO_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEMISTO_INFORMATIONAL = 0.5
RECO_API_TIMEOUT_IN_SECONDS = 180
RECO_ACTIVE_INCIDENTS_VIEW = "active_incidents_view"
RATE_LIMIT_MAX_RETRIES = 3
RATE_LIMIT_RETRY_BASE_DELAY = 2  # seconds; doubles on each attempt
ALERT_VIEW_WITH_SHARED_STATUS = "ALERT_VIEW_WITH_SHARED_STATUS"
RECO_TIMELINE_EVENT_TYPE = "TIMELINE_EVENT_TYPE_USER_COMMENT"
CREATED_AT_FIELD = "created_at"
STEP_FETCH = "fetch"
STEP_INIT = "init"

# Base path for the Reco external API (relative to /api/v1)
EXTERNAL_API_BASE = "/external-api"

# Maps numeric or string risk level values to the severity name expected by the external API.
RISK_LEVEL_TO_SEVERITY_NAME: dict[str, str] = {
    "10": "LOW",
    "LOW": "LOW",
    "low": "LOW",
    "20": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "medium": "MEDIUM",
    "30": "HIGH",
    "HIGH": "HIGH",
    "high": "HIGH",
    "40": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "critical": "CRITICAL",
}

# Ascending severity order, used to expand a minimum risk level into "that level and above".
SEVERITY_ORDER: list[str] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def parse_minimum_risk_level(risk_level_param: str | None) -> list[str] | None:
    """Parse a single risk_level value into the list of severity names at or above it.

    Accepts a numeric value (10/20/30/40) or a name (LOW/MEDIUM/HIGH/CRITICAL).
    Example: "MEDIUM" -> ["MEDIUM", "HIGH", "CRITICAL"] (fetches medium severity and higher).
    """
    if not risk_level_param:
        return None
    value = str(risk_level_param).strip()
    severity_name = RISK_LEVEL_TO_SEVERITY_NAME.get(value) or RISK_LEVEL_TO_SEVERITY_NAME.get(value.upper())
    if not severity_name:
        demisto.debug(f"Unknown risk level value '{value}', using upper-cased as-is")
        return [value.upper()]
    min_index = SEVERITY_ORDER.index(severity_name)
    return SEVERITY_ORDER[min_index:]


# Alert statuses an analyst can filter on (short name -> API enum). ALERT_STATUS_PREVIEW is never
# offered: Preview-state alerts are always excluded from every alert query in this pack.
ALERT_STATUS_PREFIX = "ALERT_STATUS_"
ALERT_STATUSES: list[str] = ["NEW", "IN_PROGRESS", "CLOSED"]

# Caps for the on-demand alert commands.
# Statuses the External API accepts on a threat alert (POST /external-api/alerts/{id}/status).
THREAT_ALERT_STATUSES: list[str] = [f"{ALERT_STATUS_PREFIX}{name}" for name in ALERT_STATUSES]
# HTTP codes on which change_alert_status retries on the internal endpoint: 404 (not a threat alert) and
# 403 (the External API needs PERM_ALERTS_WRITE; the internal one also accepts PERM_POSTURES_UPDATE).
EXTERNAL_STATUS_FALLBACK_CODES = (403, 404)

# Entity types the External API accepts on labels/add and labels/remove.
ENTITY_LABEL_TYPES: list[str] = ["account", "app", "identity", "posture", "saas-to-saas", "ip-address", "ai-agent", "device"]

LIST_ALERTS_DEFAULT_LIMIT = 50
FETCH_ALERTS_PAGE_SIZE = 500  # reco-fetch-alerts enriches every alert with one detail call each, so it works in pages


@dataclass
class AlertFilterOptions:
    """Source-side alert filters, sent to the Reco API as part of the SCIM `filters` query.

    All lists are OR-ed within themselves and AND-ed with every other filter.
    """

    saas_platforms: list[str] = field(default_factory=list)  # matched against the app instance name
    statuses: list[str] = field(default_factory=list)  # ALERT_STATUS_* enum names
    include_labels: list[str] = field(default_factory=list)  # alert must carry at least one of these labels
    exclude_labels: list[str] = field(default_factory=list)  # alert must carry none of these labels
    custom_filter: str = ""  # raw SCIM expression, for AND / OR / NOT combinations not covered above


def _scim_quote(value: str) -> str:
    """Quote a value as a SCIM string literal, escaping backslashes and double quotes."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _scim_or_group(clauses: list[str]) -> str:
    """Join clauses with `or`, parenthesized when there is more than one."""
    return f"({' or '.join(clauses)})" if len(clauses) > 1 else clauses[0]


def build_alerts_scim_filter(
    risk_levels: list[str] | None = None,
    source: str | None = None,
    before: datetime | None = None,
    after: datetime | None = None,
    filter_options: AlertFilterOptions | None = None,
) -> str:
    """Build the SCIM filter for `alerts/list`. Single source of truth for fetch-incidents,
    the Test button and the on-demand alert commands, so they always send the same query.

    Every OR group (and the raw user expression) is parenthesized before being AND-ed, so a
    value can never change the meaning of a neighbouring clause. Preview-state alerts are
    always excluded.
    """
    options = filter_options or AlertFilterOptions()
    filter_parts: list[str] = [f'status ne "{ALERT_STATUS_PREFIX}PREVIEW"']

    if risk_levels:
        # `eq` clauses joined with `or` work on every Reco version; older ones reject the SCIM `in` operator (HTTP 500).
        filter_parts.append(_scim_or_group([f"severity eq {_scim_quote(r)}" for r in risk_levels]))
    if options.statuses:
        filter_parts.append(_scim_or_group([f"status eq {_scim_quote(s)}" for s in options.statuses]))
    if source:
        filter_parts.append(f"apps co {_scim_quote(source)}")
    if options.saas_platforms:
        filter_parts.append(_scim_or_group([f"instance.appName co {_scim_quote(p)}" for p in options.saas_platforms]))
    if options.include_labels:
        filter_parts.append(_scim_or_group([f"customLabels eq {_scim_quote(label)}" for label in options.include_labels]))
    if options.exclude_labels:
        excluded = " or ".join(f"customLabels eq {_scim_quote(label)}" for label in options.exclude_labels)
        filter_parts.append(f"not ({excluded})")
    if after:
        filter_parts.append(f'createdAt gt "{after.strftime(DEMISTO_OCCURRED_FORMAT)}"')
    if before:
        filter_parts.append(f'createdAt lt "{before.strftime(DEMISTO_OCCURRED_FORMAT)}"')
    if options.custom_filter.strip():
        filter_parts.append(f"({options.custom_filter.strip()})")

    return " and ".join(filter_parts)


def parse_risk_levels(value: str | list[str] | None) -> list[str] | None:
    """Parse an explicit list of risk levels (e.g. "HIGH,CRITICAL" or "30,40") into severity names.

    Unlike parse_minimum_risk_level this does not expand to "and above", and unknown values raise.
    """
    names: list[str] = []
    for item in argToList(value):
        name = RISK_LEVEL_TO_SEVERITY_NAME.get(item.strip()) or RISK_LEVEL_TO_SEVERITY_NAME.get(item.strip().upper())
        if not name:
            raise ValueError(f"Unknown risk level '{item}'. Valid values: LOW, MEDIUM, HIGH, CRITICAL (or 10, 20, 30, 40).")
        if name not in names:
            names.append(name)
    return names or None


def parse_alert_statuses(value: str | list[str] | None) -> list[str]:
    """Parse alert statuses ("new", "In Progress", "ALERT_STATUS_CLOSED") into ALERT_STATUS_* enum names."""
    statuses: list[str] = []
    for item in argToList(value):
        short = item.strip().upper().replace(" ", "_").replace("-", "_").removeprefix(ALERT_STATUS_PREFIX)
        if short not in ALERT_STATUSES:
            raise ValueError(f"Unknown alert status '{item}'. Valid values: {', '.join(ALERT_STATUSES)}.")
        if ALERT_STATUS_PREFIX + short not in statuses:
            statuses.append(ALERT_STATUS_PREFIX + short)
    return statuses


DATE_ONLY_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def parse_date_param(value: str | None, name: str, include_whole_day: bool = False) -> datetime | None:
    """Parse a user-supplied date (ISO 8601 or relative like "3 days ago") into a UTC datetime.

    Values with a UTC offset are converted to UTC. With include_whole_day, a date-only value
    (e.g. "2026-10-31") is moved to the start of the next day, so that using it as an exclusive
    upper bound includes the whole day. Raises if the value can't be parsed.
    """
    if not value:
        return None
    parsed = dateparser.parse(str(value), settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True})
    if not parsed:
        raise ValueError(f"Could not parse '{name}' value '{value}' as a date.")
    parsed = parsed.astimezone(UTC)
    if include_whole_day and DATE_ONLY_PATTERN.match(str(value).strip()):
        parsed += timedelta(days=1)
    return parsed


def build_filter_options(
    saas_platform: str | list[str] | None = None,
    status: str | list[str] | None = None,
    include_labels: str | list[str] | None = None,
    exclude_labels: str | list[str] | None = None,
    custom_filter: str | None = None,
) -> AlertFilterOptions:
    """Build AlertFilterOptions from comma-separated integration parameters / command arguments."""
    return AlertFilterOptions(
        saas_platforms=argToList(saas_platform),
        statuses=parse_alert_statuses(status),
        include_labels=argToList(include_labels),
        exclude_labels=argToList(exclude_labels),
        custom_filter=custom_filter or "",
    )


def extract_response(response: Any) -> list[dict[str, Any]]:
    if response.get("getTableResponse") is None:
        demisto.error(f"got bad response, {response}")
        raise Exception(f"got bad response, {response}")
    else:
        demisto.info(f"Count of entities: {response.get('getTableResponse').get('totalNumberOfResults')}")
        entities = response.get("getTableResponse", {}).get("data", {}).get("rows", [])
        demisto.info(f"Got {len(entities)} entities")
        return entities


class RecoClient(BaseClient):
    def __init__(self, api_token: str, base_url: str, verify: bool, proxy):
        super().__init__(
            base_url,
            verify=verify,
            proxy=proxy,
            headers={
                "Authorization": f"Bearer {api_token}",
                "User-Agent": f"xsoar/{get_pack_version()}",
            },
        )

    # --- External API helpers ---

    def _rate_limited_request(self, method: str, url_suffix: str, **kwargs) -> dict[str, Any]:
        """Wrap _http_request with automatic 429 retry and exponential backoff.

        Respects a Retry-After header when present; otherwise backs off
        RATE_LIMIT_RETRY_BASE_DELAY * 2^attempt seconds between attempts.
        Raises on the last attempt or on any non-429 error.
        """
        for attempt in range(RATE_LIMIT_MAX_RETRIES):
            try:
                return self._http_request(method=method, url_suffix=url_suffix, **kwargs)
            except DemistoException as exc:
                is_rate_limited = exc.res is not None and getattr(exc.res, "status_code", None) == 429
                if is_rate_limited and attempt < RATE_LIMIT_MAX_RETRIES - 1:
                    retry_after = int(
                        exc.res.headers.get(  # type: ignore[union-attr]
                            "Retry-After",
                            RATE_LIMIT_RETRY_BASE_DELAY * (2**attempt),
                        )
                    )
                    demisto.debug(
                        f"Rate limited (429) on {url_suffix}, "
                        f"retrying in {retry_after}s (attempt {attempt + 1}/{RATE_LIMIT_MAX_RETRIES})"
                    )
                    time.sleep(retry_after)  # pylint: disable=E9003
                else:
                    raise
        raise DemistoException(f"Max retries ({RATE_LIMIT_MAX_RETRIES}) exceeded for {url_suffix}")

    def _external_api_list(
        self,
        endpoint: str,
        filters: str = "",
        count: int = PAGE_SIZE,
        start_index: int = 0,
        sort_by: str = "",
        sort_order: str = "",
    ) -> dict[str, Any]:
        """GET /external-api/{endpoint} with SCIM filter, sort, and pagination params."""
        params: dict[str, Any] = {"count": count, "startIndex": start_index}
        if filters:
            params["filters"] = filters
        if sort_by:
            params["sortBy"] = sort_by
        if sort_order:
            params["sortOrder"] = sort_order
        return self._rate_limited_request(
            method="GET",
            url_suffix=f"{EXTERNAL_API_BASE}/{endpoint}",
            params=params,
            timeout=RECO_API_TIMEOUT_IN_SECONDS,
        )

    def _external_api_post(self, endpoint: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST /external-api/{endpoint}."""
        return self._rate_limited_request(
            method="POST",
            url_suffix=f"{EXTERNAL_API_BASE}/{endpoint}",
            data=json.dumps(body),
            timeout=RECO_API_TIMEOUT_IN_SECONDS,
        )

    def _external_api_put(self, url_suffix: str, body: dict[str, Any]) -> dict[str, Any]:
        """PUT to an arbitrary external-api path suffix."""
        return self._rate_limited_request(
            method="PUT",
            url_suffix=url_suffix,
            data=json.dumps(body),
            timeout=RECO_API_TIMEOUT_IN_SECONDS,
        )

    def _paginate_all(
        self,
        endpoint: str,
        item_key: str,
        filters: str = "",
        page_size: int = 1000,
    ) -> list[dict[str, Any]]:
        """Fetch every page from a list endpoint, returning all items combined.

        Uses the `totalResults` field in the response to know when to stop.
        Stops early if an empty page is returned (defensive guard against
        totalResults being stale or the server having fewer items than reported).
        Capped at MAX_PAGES to guard against an unbounded loop if the server
        never reports totalResults or an empty page.

        The External API treats `startIndex` as 1-based although its docs say 0-based, so with
        0-based offsets each page repeats the previous page's last item. Items are therefore
        de-duplicated by `id`, which keeps this correct whichever way the API counts.
        """
        all_items: list[dict[str, Any]] = []
        seen_ids: set[Any] = set()
        start_index = 0
        for _page in range(MAX_PAGES):
            response = self._external_api_list(
                endpoint,
                filters=filters,
                count=page_size,
                start_index=start_index,
            )
            page_items = response.get(item_key, [])
            if not page_items:
                break
            for item in page_items:
                item_id = item.get("id")
                if item_id is not None:
                    if item_id in seen_ids:
                        continue
                    seen_ids.add(item_id)
                all_items.append(item)
            total = int(response.get("totalResults", 0) or response.get("total_results", 0) or 0)
            demisto.debug(f"_paginate_all {endpoint}: fetched {len(all_items)}/{total}")
            if total and len(all_items) >= total:
                break
            start_index += len(page_items)
        else:
            demisto.debug(f"_paginate_all {endpoint}: reached MAX_PAGES ({MAX_PAGES}) cap, stopping")
        return all_items

    # --- Alerts (external API) ---

    def get_alerts(
        self,
        risk_levels: list[str] | None = None,
        source: str | None = None,
        before: datetime | None = None,
        after: datetime | None = None,
        limit: int = PAGE_SIZE,
        start_index: int = 0,
        filter_options: AlertFilterOptions | None = None,
        sort_order: str = "ascending",
    ) -> list[dict[str, Any]]:
        """List threat alerts via the external API (oldest first by default).

        risk_levels: list of severity names, e.g. ["HIGH", "CRITICAL"].  Multiple
        values are combined with OR so a single call fetches all matching severities.
        filter_options: further source-side filters (platform, status, labels, raw SCIM);
        see build_alerts_scim_filter. They are all evaluated by the Reco API, not after retrieval.

        API errors are raised rather than swallowed, so a failed call is never mistaken
        for "no new alerts" and shows up as a failure in XSOAR.

        Sorted ascending by createdAt (rather than the API's default descending order) so
        that fetch_incidents can page through a burst via `start_index` without ever
        skipping alerts, regardless of how many share the same fetch window. Only the
        on-demand commands pass sort_order="descending".

        Preview-state alerts are always excluded: a Policy in Preview state is explicitly
        meant to stay out of the customer's SOAR/ticketing systems while it's being
        evaluated (the webhook and share-service paths already enforce this upstream).
        """
        scim_filter = build_alerts_scim_filter(risk_levels, source, before, after, filter_options)
        demisto.debug(f"get_alerts SCIM filter: {scim_filter!r}")

        response = self._external_api_list(
            "alerts/list",
            filters=scim_filter,
            count=limit,
            start_index=start_index,
            sort_by="createdAt",
            sort_order=sort_order,
        )
        alerts = response.get("alerts", [])
        demisto.info(f"get_alerts: fetched {len(alerts)} alerts (total={response.get('totalResults', '?')})")
        return alerts

    def get_single_alert(self, alert_id: str) -> dict[str, Any]:
        """Get full alert detail including policy violations via the external API."""
        try:
            response = self._rate_limited_request(
                method="GET",
                url_suffix=f"{EXTERNAL_API_BASE}/alert-details/{alert_id}",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
            )
            return response.get("alert", {})
        except Exception as e:
            demisto.error(f"get_single_alert({alert_id}) error: {str(e)}")
            raise

    def get_alert_ai_summary(self, alert_id: str) -> dict[str, Any]:  # pragma: no cover
        """Get alert AI summary (internal API - no external equivalent yet)."""
        try:
            return self._http_request(
                method="GET",
                url_suffix=f"/alert/summarize/{alert_id}",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
            )
        except Exception as e:
            demisto.error(f"get_alert_ai_summary error: {str(e)}")
            raise

    def change_alert_status(self, alert_id: str, status: str) -> Any:
        """Change an alert's status.

        Threat-alert statuses (new / in progress / closed) go through the External API, which also
        records the change in the audit log and emits the webhook event. The previous internal
        endpoint is kept as a fallback for what the External API cannot do: posture statuses, posture
        issue IDs (404), and tokens that hold PERM_POSTURES_UPDATE but not PERM_ALERTS_WRITE (403),
        both of which the internal endpoint accepts.
        """
        try:
            if status in THREAT_ALERT_STATUSES:
                try:
                    return self._external_api_post(f"alerts/{alert_id}/status", {"status": status})
                except DemistoException as exc:
                    if getattr(exc.res, "status_code", None) not in EXTERNAL_STATUS_FALLBACK_CODES:
                        raise
                    demisto.debug(
                        f"External status update for {alert_id} returned {exc.res.status_code}; "  # type: ignore[union-attr]
                        "falling back to the internal status endpoint"
                    )
            return self._http_request(
                method="PUT",
                url_suffix=f"/policy-subsystem/alert-inbox/{alert_id}/status/{status}",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
            )
        except Exception as e:
            demisto.error(f"change_alert_status error: {str(e)}")
            demisto.debug(traceback.format_exc())
            raise

    def update_reco_incident_timeline(self, incident_id: str, comment: str) -> Any:
        """Add a comment to an alert entity via the external API."""
        body: dict[str, Any] = {
            "entityId": incident_id,
            "entityType": "alert",
            "content": comment,
        }
        try:
            return self._external_api_post("comments/create", body)
        except Exception as e:
            demisto.error(f"update_reco_incident_timeline error: {str(e)}")
            raise

    # --- Labels (external API) ---

    def _entity_label_request(
        self,
        endpoint: str,
        entity_id: str,
        entity_type: str,
        label_name: str,
        instance_id: str = "",
    ) -> Any:
        body: dict[str, Any] = {
            "entityId": entity_id,
            "entityType": entity_type,
            "labelName": label_name,
        }
        if instance_id:
            body["instanceId"] = instance_id
        try:
            return self._external_api_post(endpoint, body)
        except Exception as e:
            demisto.error(f"{endpoint} error: {str(e)}")
            demisto.debug(traceback.format_exc())
            raise

    def add_entity_label(
        self,
        entity_id: str,
        entity_type: str,
        label_name: str,
        instance_id: str = "",
    ) -> Any:
        """Add a label to any Reco entity via the external API.

        entity_type: "account", "identity", "app", "posture", "saas-to-saas",
                     "ip-address", "ai-agent", "device"
        The label must already exist in the tenant's label catalog.
        """
        return self._entity_label_request("labels/add", entity_id, entity_type, label_name, instance_id)

    def remove_entity_label(
        self,
        entity_id: str,
        entity_type: str,
        label_name: str,
        instance_id: str = "",
    ) -> Any:
        """Remove a label from any Reco entity via the external API (same entity types as add_entity_label)."""
        return self._entity_label_request("labels/remove", entity_id, entity_type, label_name, instance_id)

    def update_alert_severity(self, alert_id: str, severity: str) -> dict[str, Any]:
        """Set a threat alert's severity (LOW, MEDIUM, HIGH, CRITICAL) via the external API; returns the updated alert."""
        try:
            response = self._external_api_post(f"alerts/{alert_id}/severity", {"severity": severity})
            return response.get("alert", {})
        except Exception as e:
            demisto.error(f"update_alert_severity error: {str(e)}")
            demisto.debug(traceback.format_exc())
            raise

    def resolve_visibility_event(self, entity_id: str, label_name: str) -> Any:
        """Resolve a visibility event (internal API - no external equivalent)."""
        try:
            return self._http_request(
                method="PUT",
                url_suffix="/set-label-status",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(
                    {
                        "labelsRelationStatusUpdate": [
                            {
                                "labelName": label_name,
                                "entryId": f"{entity_id}_visibility",
                                "entryType": ENTRY_TYPE_EVENT,
                                "newStatus": LABEL_STATUS_RESOLVED,
                                "oldStatus": LABEL_STATUS_ACTIVE,
                                "comment": "Resolved by XSOAR Automation",
                            }
                        ]
                    }
                ),
            )
        except Exception as e:
            demisto.error(f"resolve_visibility_event error: {str(e)}")
            raise

    # --- Identities / Users (external API) ---

    def get_identities(self, email_address: Optional[str] = None, label: Optional[str] = None) -> list[dict[str, Any]]:
        """List identities from the external API, optionally filtered by email."""
        filter_parts: list[str] = []
        if email_address:
            filter_parts.append(f"email co {_scim_quote(email_address)}")
        # label filter is handled separately via get_risky_users (ListAccounts)
        scim_filter = " and ".join(filter_parts)
        try:
            response = self._external_api_list("users/list", filters=scim_filter, count=PAGE_SIZE)
            return response.get("users", [])
        except Exception as e:
            demisto.error(f"get_identities error: {str(e)}")
            raise

    def get_risky_users(self) -> list[dict[str, Any]]:
        """List ALL accounts flagged as risky via the external API (auto-paginated)."""
        try:
            return self._paginate_all("accounts/list", "accounts", filters="isRiskyUser eq true")
        except Exception as e:
            demisto.error(f"get_risky_users error: {str(e)}")
            raise

    def get_user_context_by_email_address(self, email_address: str) -> list[dict[str, Any]]:
        """Get identity context for an email address via the external API."""
        try:
            response = self._external_api_list(
                "users/list",
                filters=f"email co {_scim_quote(email_address)}",
                count=10,
            )
            return response.get("users", [])
        except Exception as e:
            demisto.error(f"get_user_context_by_email_address error: {str(e)}")
            raise

    # --- Apps (external API) ---

    def get_app_discovery(
        self,
        before: datetime | None = None,
        after: datetime | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """List discovered apps via the external API. Auto-paginates all results when limit is None."""
        filter_parts: list[str] = []
        if after:
            filter_parts.append(f'lastSeen gt "{after.strftime(DEMISTO_OCCURRED_FORMAT)}"')
        if before:
            filter_parts.append(f'lastSeen lt "{before.strftime(DEMISTO_OCCURRED_FORMAT)}"')
        scim_filter = " and ".join(filter_parts)
        try:
            if limit is None:
                return self._paginate_all("apps/list", "apps", filters=scim_filter)
            response = self._external_api_list("apps/list", filters=scim_filter, count=limit)
            return response.get("apps", [])
        except Exception as e:
            demisto.error(f"get_app_discovery error: {str(e)}")
            raise

    def set_app_authorization_status(self, app_id: str, authorization_status: str, app_type: str = "") -> Any:
        """Update app authorization status via the external API.

        app_type (APP_ENTITY_TYPE_*) selects the app inventory; the API defaults to app discovery.
        """
        body: dict[str, Any] = {"authorizationStatus": authorization_status}
        if app_type:
            body["appType"] = app_type
        try:
            return self._external_api_put(f"{EXTERNAL_API_BASE}/apps/{app_id}/auth-status", body)
        except Exception as e:
            demisto.error(f"set_app_authorization_status error: {str(e)}")
            raise

    # --- Files / Assets (external API) ---

    def get_sensitive_assets_information(
        self, asset_name: str | None, asset_id: str | None, sensitive_only: bool, regex_search: bool
    ) -> list[dict[str, Any]]:
        """List files from the external API, optionally filtered by name or id (auto-paginated)."""
        filter_parts: list[str] = []
        if asset_name:
            op = "co" if regex_search else "eq"
            filter_parts.append(f"name {op} {_scim_quote(asset_name)}")
        elif asset_id:
            filter_parts.append(f"id eq {_scim_quote(asset_id)}")
        if sensitive_only:
            filter_parts.append('sensitivityLevel in ["30","40"]')
        scim_filter = " and ".join(filter_parts)
        try:
            return self._paginate_all("files/list", "files", filters=scim_filter)
        except Exception as e:
            demisto.error(f"get_sensitive_assets_information error: {str(e)}")
            raise

    # --- Internal API methods (data risk management - no external equivalent) ---

    def get_exposed_publicly_files_at_risk(self) -> list[dict[str, Any]]:
        """Get exposed publicly files at risk (internal API)."""
        params: Dict[str, Any] = {
            "getTableRequest": {
                "tableName": "DATA_RISK_MANAGEMENT_VIEW_BREAKDOWN_EXPOSED_PUBLICLY",
                "pageSize": PAGE_SIZE,
                "fieldSorts": {"sorts": [{"sortBy": "last_access_date", "sortDirection": "SORT_DIRECTION_DESC"}]},
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_OR",
                    "filters": {"filters": [{"field": "data_category", "stringEquals": {"value": "ALL"}}]},
                },
            }
        }
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/risk-management/get-data-risk-management-table",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"get_exposed_publicly_files_at_risk error: {str(e)}")
            raise

    def get_files_exposed_to_email(self, email_account) -> list[dict[str, Any]]:
        """Get files exposed to an email account (internal API)."""
        params = {
            "getTableRequest": {
                "tableName": "data_posture_view_files_by_emails_slider",
                "pageSize": PAGE_SIZE,
                "fieldSorts": {"sorts": [{"sortBy": "last_access_date", "sortDirection": "SORT_DIRECTION_DESC"}]},
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": [
                            {
                                "relationship": "FILTER_RELATIONSHIP_AND",
                                "fieldFilterGroups": {
                                    "fieldFilters": [
                                        {
                                            "relationship": "FILTER_RELATIONSHIP_AND",
                                            "filters": {
                                                "filters": [
                                                    {"field": "email_account", "stringEquals": {"value": f"{email_account}"}}
                                                ]
                                            },
                                        }
                                    ]
                                },
                                "forceEstimateSize": True,
                            }
                        ]
                    },
                    "forceEstimateSize": True,
                },
            }
        }
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/risk-management/get-data-risk-management-table",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"get_files_exposed_to_email error: {str(e)}")
            raise

    def get_list_of_private_emails_with_access(self) -> list[dict[str, Any]]:
        """Get private email addresses with file access (internal API)."""
        params = {
            "getTableRequest": {
                "tableName": "data_posture_view_private_email_with_access",
                "pageSize": PAGE_SIZE,
                "fieldSorts": {"sorts": [{"sortBy": "files_num", "sortDirection": "SORT_DIRECTION_DESC"}]},
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {"fieldFilters": []},
                    "forceEstimateSize": True,
                },
            }
        }
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/risk-management/get-data-risk-management-table",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"get_list_of_private_emails_with_access error: {str(e)}")
            raise

    @staticmethod
    def get_date_time_before_days_formatted(last_interaction_time_before_in_days: int) -> str:
        thirty_days_ago = datetime.utcnow() - timedelta(days=last_interaction_time_before_in_days)
        return thirty_days_ago.strftime("%Y-%m-%dT%H:%M:%S.999Z")

    def get_3rd_parties_risk_list(self, last_interaction_time_before_in_days: int) -> list[dict[str, Any]]:
        """Get 3rd party domains with file access (internal API)."""
        formatted_date = self.get_date_time_before_days_formatted(last_interaction_time_before_in_days)
        params = {
            "getTableRequest": {
                "tableName": "data_posture_view_3rd_parties_domain",
                "pageSize": PAGE_SIZE,
                "fieldSorts": {"sorts": [{"sortBy": "files_num", "sortDirection": "SORT_DIRECTION_DESC"}]},
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": [
                            {
                                "relationship": "FILTER_RELATIONSHIP_AND",
                                "fieldFilterGroups": {
                                    "fieldFilters": [
                                        {
                                            "relationship": "FILTER_RELATIONSHIP_AND",
                                            "filters": {
                                                "filters": [{"field": "last_activity", "before": {"value": f"{formatted_date}"}}]
                                            },
                                        }
                                    ]
                                },
                            }
                        ]
                    },
                    "forceEstimateSize": True,
                },
            }
        }
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/risk-management/get-data-risk-management-table",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"get_3rd_parties_risk_list error: {str(e)}")
            raise

    def get_files_shared_with_3rd_parties(self, domain: str, last_interaction_time_before_in_days: int) -> list[dict[str, Any]]:
        """Get files shared with a specific 3rd party domain (internal API)."""
        formatted_date = self.get_date_time_before_days_formatted(last_interaction_time_before_in_days)
        params = {
            "getTableRequest": {
                "tableName": "data_posture_view_files_by_domain_slider",
                "pageSize": PAGE_SIZE,
                "fieldSorts": {"sorts": [{"sortBy": "last_access_date", "sortDirection": "SORT_DIRECTION_ASC"}]},
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": [
                            {
                                "relationship": "FILTER_RELATIONSHIP_AND",
                                "filters": {
                                    "filters": [
                                        {"field": "domain", "regexCaseInsensitive": {"value": f"{domain}"}},
                                        {"field": "last_access_date", "before": {"value": f"{formatted_date}"}},
                                    ]
                                },
                            }
                        ]
                    },
                    "forceEstimateSize": True,
                },
            }
        }
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/risk-management/get-data-risk-management-table",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"get_files_shared_with_3rd_parties error: {str(e)}")
            raise

    def get_assets_user_has_access(self, email_address: str, only_sensitive: bool) -> list[dict[str, Any]]:
        """Get assets a user has access to (internal API)."""
        params: dict[str, Any] = {
            "getTableRequest": {
                "tableName": "files_view",
                "pageSize": PAGE_SIZE,
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": [
                            {
                                "relationship": "FILTER_RELATIONSHIP_OR",
                                "filters": {
                                    "filters": [
                                        {
                                            "field": "currently_permitted_users",
                                            "regexCaseInsensitive": {"value": email_address},
                                        }
                                    ]
                                },
                            }
                        ]
                    },
                },
            }
        }
        if only_sensitive is True:
            params["getTableRequest"]["fieldFilters"]["fieldFilterGroups"]["fieldFilters"].append(
                {
                    "relationship": "FILTER_RELATIONSHIP_OR",
                    "filters": {
                        "filters": [
                            {"field": "sensitivity_level", "stringEquals": {"value": "30"}},
                            {"field": "sensitivity_level", "stringEquals": {"value": "40"}},
                        ]
                    },
                }
            )
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/asset-management/query",
                timeout=RECO_API_TIMEOUT_IN_SECONDS * 2,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"get_assets_user_has_access error: {str(e)}")
            raise

    def get_assets_shared_externally(self, email_address: str) -> list[dict[str, Any]]:
        """Get assets an owner has shared externally (internal API)."""
        params: dict[str, Any] = {
            "getTableRequest": {
                "tableName": "files_view",
                "pageSize": PAGE_SIZE,
                "fieldSorts": {"sorts": [{"sortBy": "last_access_date", "sortDirection": "SORT_DIRECTION_DESC"}]},
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": [
                            {
                                "relationship": "FILTER_RELATIONSHIP_OR",
                                "filters": {
                                    "filters": [
                                        {
                                            "field": "permission_visibility",
                                            "stringEquals": {"value": "PERMISSION_TYPE_SHARED_EXTERNALLY"},
                                        }
                                    ]
                                },
                            },
                            {
                                "relationship": "FILTER_RELATIONSHIP_OR",
                                "filters": {
                                    "filters": [{"field": "file_owner", "stringContains": {"value": f"{email_address}"}}]
                                },
                            },
                        ]
                    },
                    "forceEstimateSize": True,
                },
            }
        }
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/asset-management/query",
                timeout=RECO_API_TIMEOUT_IN_SECONDS * 2,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"get_assets_shared_externally error: {str(e)}")
            raise

    def get_link_to_user_overview_page(self, link_type: str, entity_id: str) -> str:
        """Get a magic link to a Reco UI overview page (internal API)."""
        try:
            response = self._http_request(
                method="GET",
                url_suffix=f"/risk-management/risk-management/link?link_type={link_type}&param={entity_id}",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
            )
            link = response.get("link", None)
        except Exception as e:
            demisto.error(f"get_link_to_user_overview_page error: {str(e)}")
            raise
        return link  # type: ignore[return-value]

    def add_exclusion_filter(self, key_to_add: str, values_to_add: list[str]):
        """Add exclusion filter values (internal API)."""
        body = {"environmentName": "string", "keyToAddTo": key_to_add, "valuesToAdd": values_to_add}
        try:
            return self._http_request(
                method="POST",
                url_suffix="/algo/add_values_to_data_type_exclude_analyzer",
                timeout=RECO_API_TIMEOUT_IN_SECONDS * 2,
                data=json.dumps(body),
            )
        except Exception as e:
            demisto.error(f"add_exclusion_filter error: {str(e)}")
            raise

    # --- New external API list methods ---

    def list_events(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List SaaS events via the external API."""
        return self._external_api_list("events/list", filters=filters, count=count)

    def list_posture_issues(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List posture issues via the external API."""
        return self._external_api_list("posture-issues/list", filters=filters, count=count)

    def list_accounts(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List accounts via the external API."""
        return self._external_api_list("accounts/list", filters=filters, count=count)

    def list_devices(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List devices via the external API."""
        return self._external_api_list("devices/list", filters=filters, count=count)

    def list_ai_agents(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List AI agents via the external API."""
        return self._external_api_list("ai-agents/list", filters=filters, count=count)

    def list_integrations(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List connected integrations via the external API."""
        return self._external_api_list("integrations/list", filters=filters, count=count)

    def list_groups(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List SaaS groups via the external API."""
        return self._external_api_list("groups/list", filters=filters, count=count)

    def list_saas_to_saas(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List SaaS-to-SaaS grants via the external API."""
        return self._external_api_list("saas-to-saas/list", filters=filters, count=count)

    def list_ip_addresses(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List observed IP addresses via the external API."""
        return self._external_api_list("ip-addresses/list", filters=filters, count=count)

    def list_business_units(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List external business units via the external API."""
        return self._external_api_list("business-units/list", filters=filters, count=count)

    def list_audit_logs(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List platform audit logs via the external API."""
        return self._external_api_list("audit-logs/list", filters=filters, count=count)

    def list_posture_checks(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List posture check definitions via the external API."""
        return self._external_api_list("posture-checks/list", filters=filters, count=count)

    def list_threat_detection_policies(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List threat detection policies via the external API."""
        return self._external_api_list("policies/list", filters=filters, count=count)

    def list_exclusions(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List alert suppression exclusion rules via the external API."""
        return self._external_api_list("exclusions/list", filters=filters, count=count)

    def list_app_instances(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List integrated app instances (portfolio) via the external API."""
        return self._external_api_list("app-instances/list", filters=filters, count=count)

    def list_labeled_netapp_files(self, filters: str = "", count: int = PAGE_SIZE) -> dict[str, Any]:
        """List NetApp files carrying an active label via the external API."""
        return self._external_api_list("labeled-netapp-files/list", filters=filters, count=count)

    # --- API key validation ---

    def validate_api_key(
        self,
        risk_levels: list[str] | None = None,
        source: str | None = None,
        before: datetime | None = None,
        after: datetime | None = None,
        filter_options: AlertFilterOptions | None = None,
    ) -> str:
        """Validate the API token with the same alerts query fetch-incidents sends.

        Going through get_alerts (rather than an unfiltered call) means a filter the API
        rejects fails the Test button instead of only surfacing later during fetch.
        """
        try:
            self.get_alerts(risk_levels, source, before, after, limit=1, filter_options=filter_options)
            return "ok"
        except Exception as e:
            demisto.error(f"validate_api_key error: {str(e)}")
            raise


# --- Helpers ---


def add_legacy_output_aliases(items: list[dict[str, Any]], aliases: dict[str, str]) -> list[dict[str, Any]]:
    """Copy renamed External API fields back onto their pre-migration key names, in place.

    Restores backward compatibility for playbooks/automations built against the old
    internal-API field names, alongside the new camelCase External API fields.
    """
    for item in items:
        for old_key, new_key in aliases.items():
            if new_key in item:
                item[old_key] = item[new_key]
    return items


def parse_table_row_to_dict(alert: list[dict[str, Any]]) -> dict[str, Any]:
    """Decode a table row returned by Reco's internal Table API (base64-encoded cells)."""
    if alert is None:
        return {}
    alert_as_dict = {}
    for obj in alert:
        key = obj.get("key", None)
        value = obj.get("value", None)
        if key is None or value is None:
            continue
        obj[key] = base64.b64decode(value).decode("utf-8")
        if key != "labels":
            obj[key] = obj[key].replace('"', "")
        if key in ["updated_at", "created_at", "event_time"]:
            try:
                parsed_time = datetime.strptime(obj[key], RECO_TIME_FORMAT)
            except Exception:
                parsed_time = datetime.strptime(obj[key], DEMISTO_OCCURRED_FORMAT)
            if parsed_time:
                obj[key] = parsed_time.strftime(DEMISTO_OCCURRED_FORMAT)
        if key == "risk_level":
            try:
                obj[key] = int(obj[key])
            except Exception:
                pass
        if key in ["group", "job_title", "departments", "labels"]:
            try:
                obj[key] = json.loads(obj[key])
            except Exception:
                pass
        alert_as_dict[key] = obj[key]
    return alert_as_dict


# --- Alert fetching ---


def normalize_policy_violations(detail: dict[str, Any]) -> dict[str, Any]:
    """Parse each policy violation's `jsonData` (a JSON string, not base64, in the external API) in place."""
    for violation in detail.get("policyViolations", []):
        json_data = violation.get("jsonData", "{}")
        if isinstance(json_data, str):
            try:
                parsed = json.loads(json_data)
                parsed.pop("violation", None)
                violation["jsonData"] = parsed
            except json.JSONDecodeError:
                pass
    return detail


def get_alerts(
    reco_client: RecoClient,
    risk_levels: list[str] | None = None,
    source: str | None = None,
    before: datetime | None = None,
    after: datetime | None = None,
    limit: int = PAGE_SIZE,
    start_index: int = 0,
    filter_options: AlertFilterOptions | None = None,
    sort_order: str = "ascending",
) -> tuple[list[Any], int]:
    """Fetch alert summaries then enrich each with full detail (policy violations).

    Returns the enriched ThreatAlertDetail dicts alongside the raw page size, so callers
    can tell whether the page was truncated by `limit` (more alerts may remain).
    """
    raw_alerts = reco_client.get_alerts(
        risk_levels, source, before, after, limit, start_index, filter_options=filter_options, sort_order=sort_order
    )
    alerts_data: list[Any] = []

    for raw in raw_alerts:
        alert_id = raw.get("id")
        if not alert_id:
            demisto.debug(f"Alert without id: {raw}")
            continue
        try:
            detail = reco_client.get_single_alert(alert_id)
            if not detail:
                continue
            alerts_data.append(normalize_policy_violations(detail))
        except Exception as e:
            demisto.error(f"Failed to enrich alert {alert_id}: {str(e)}")

    demisto.info(f"get_alerts: enriched {len(alerts_data)}/{len(raw_alerts)} alerts")
    return alerts_data, len(raw_alerts)


# --- Score mapping ---


def map_reco_score_to_demisto_score(reco_score: int) -> int | float:
    demisto_informational = 0.5
    demisto_medium = 2
    demisto_high = 3
    demisto_critical = 4
    MAPPING = {40: demisto_critical, 30: demisto_high, 20: demisto_medium, 10: demisto_informational, 0: demisto_informational}
    tier = min(40, max(0, (reco_score // 10) * 10))
    return MAPPING.get(tier, demisto_informational)


def map_reco_alert_score_to_demisto_score(reco_score: str) -> int | float:
    demisto_informational = 0.5
    demisto_medium = 2
    demisto_high = 3
    demisto_critical = 4
    MAPPING = {"CRITICAL": demisto_critical, "HIGH": demisto_high, "MEDIUM": demisto_medium, "LOW": demisto_informational}
    return MAPPING.get(reco_score, demisto_informational)


def _reco_risk_to_demisto_severity(raw_risk: Any) -> int | float:
    """Normalize Reco risk level to XSOAR severity. Handles int, numeric str, or name str."""
    if raw_risk is None:
        return map_reco_score_to_demisto_score(10)
    if isinstance(raw_risk, int):
        return map_reco_score_to_demisto_score(min(40, max(10, raw_risk)))
    if isinstance(raw_risk, str):
        stripped = raw_risk.strip().upper()
        if stripped in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return map_reco_alert_score_to_demisto_score(stripped)
        try:
            return map_reco_score_to_demisto_score(min(40, max(10, int(raw_risk))))
        except (TypeError, ValueError):
            pass
    try:
        return map_reco_score_to_demisto_score(min(40, max(10, int(raw_risk))))
    except (TypeError, ValueError):
        return map_reco_score_to_demisto_score(10)


# --- Incident parsing ---


def parse_alerts_to_incidents(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert ThreatAlertDetail dicts (external API) to XSOAR incident format.

    Also handles the legacy internal-API shape (cells[]) for backward compatibility.
    """
    incidents = []
    for alert in alerts:
        # Support legacy row format (cells[]) and modern external API dicts
        alert_dict = parse_table_row_to_dict(alert.get("cells", {})) if alert.get("cells") else alert
        occurred = alert_dict.get("created_at") or alert_dict.get("createdAt", "")
        raw_risk = alert_dict.get("risk_level") or alert_dict.get("riskLevel") or alert_dict.get("severity")
        incident = {
            "name": alert_dict.get("description", ""),
            "occurred": occurred,
            "dbotMirrorId": alert_dict.get("id", ""),
            "rawJSON": json.dumps(alert),
            "severity": _reco_risk_to_demisto_severity(raw_risk),
        }
        incidents.append(incident)
    return incidents


def get_max_fetch(max_fetch: int) -> int:
    return min(max_fetch, 500)


# --- Fetch incidents ---


def fetch_incidents(
    reco_client: RecoClient,
    last_run: dict[str, Any],
    max_fetch: int,
    risk_levels: list[str] | None = None,
    source: str | None = None,
    before: datetime | None = None,
    after: datetime | None = None,
    filter_options: AlertFilterOptions | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    demisto.info(f"fetch-incidents called {max_fetch=}")
    next_run: dict[str, Any] = {}

    last_run_time = last_run.get("lastRun", None)
    if last_run_time is not None:
        after = dateutil.parser.parse(last_run_time)
    start_index = last_run.get("startIndex", 0)

    alerts, raw_page_size = get_alerts(
        reco_client, risk_levels, source, before, after, max_fetch, start_index, filter_options=filter_options
    )
    incidents = parse_alerts_to_incidents(alerts)

    existing_incidents = last_run.get("incident_ids", [])
    incidents = [
        incident
        for incident in incidents
        if (incident.get("severity", 0) > DEMISTO_INFORMATIONAL)
        and (incident.get("dbotMirrorId", None) not in existing_incidents)
    ]

    if raw_page_size < max_fetch:
        # The window is fully drained - safe to advance the timestamp cursor.
        incidents_sorted = sorted(incidents, key=lambda k: k["occurred"])
        if incidents_sorted:
            last_occurred_dt = dateutil.parser.parse(incidents_sorted[-1]["occurred"])
            next_run["lastRun"] = (last_occurred_dt + timedelta(seconds=1)).strftime(DEMISTO_OCCURRED_FORMAT)
        else:
            next_run["lastRun"] = last_run_time
        next_run["startIndex"] = 0
    else:
        # The page was full - more alerts may remain in this window. Keep lastRun in place
        # and resume from start_index next cycle, so a burst larger than max_fetch is
        # drained over multiple cycles instead of the excess being permanently skipped.
        next_run["lastRun"] = last_run_time
        next_run["startIndex"] = start_index + raw_page_size

    next_run["incident_ids"] = existing_incidents + [inc["dbotMirrorId"] for inc in incidents]

    return next_run, incidents


# --- Fetch filters shared by fetch-incidents and the Test button ---


def get_fetch_filters(params: dict[str, Any]) -> dict[str, Any]:
    """Translate integration parameters into the alert-query keyword arguments.

    fetch-incidents and test-module both call this and pass the result straight through, so the
    Test button always exercises exactly the query that fetch will send.
    """
    after = parse_date_param(params.get("after"), "after") or parse_date_param(params.get("first_fetch"), "first_fetch")
    return {
        # risk_level accepts a single value; alerts at or above it are fetched (PRO-303)
        "risk_levels": parse_minimum_risk_level(params.get("risk_level")),
        "source": params.get("source") or None,
        "before": parse_date_param(params.get("before"), "before", include_whole_day=True),
        "after": after,
        "filter_options": build_filter_options(
            saas_platform=params.get("saas_platform"),
            status=params.get("alert_status"),
            include_labels=params.get("include_labels"),
            exclude_labels=params.get("exclude_labels"),
            custom_filter=params.get("custom_filter"),
        ),
    }


# --- Command functions ---


def get_risky_users_from_reco(reco_client: RecoClient) -> CommandResults:
    """Return accounts flagged as risky."""
    accounts = reco_client.get_risky_users()
    return CommandResults(
        readable_output=tableToMarkdown(
            "Risky Users",
            accounts,
            headers=["id", "name", "accountEmail", "permissions", "openAlerts", "roles", "isAdmin", "lastSeen"],
        ),
        outputs_prefix="Reco.RiskyUsers",
        outputs_key_field="accountEmail",
        outputs=accounts,
        raw_response=accounts,
    )


def add_risky_user_label(reco_client: RecoClient, email_address: str) -> CommandResults:
    """Tag an identity as risky via the external API labels endpoint."""
    identities = reco_client.get_identities(email_address=email_address)
    if not identities:
        return CommandResults(readable_output=f"No identity found for {email_address}")
    raw_response = None
    for identity in identities:
        identity_id = identity.get("id")
        if identity_id:
            raw_response = reco_client.add_entity_label(identity_id, "identity", RISKY_USER)
    return CommandResults(
        raw_response=raw_response,
        readable_output=f"User {email_address} labeled as risky",
    )


def add_leaving_org_user(reco_client: RecoClient, email_address: str) -> CommandResults:  # pragma: no cover
    """Tag an identity as a leaving-org user via the external API labels endpoint."""
    identities = reco_client.get_identities(email_address=email_address)
    if not identities:
        return CommandResults(readable_output=f"No identity found for {email_address}")
    raw_response = None
    for identity in identities:
        identity_id = identity.get("id")
        if identity_id:
            raw_response = reco_client.add_entity_label(identity_id, "identity", LEAVING_ORG_USER)
    return CommandResults(
        raw_response=raw_response,
        readable_output=f"User {email_address} labeled as leaving org user",
    )


def get_alert_ai_summary(reco_client: RecoClient, alert_id: str) -> CommandResults:
    response = reco_client.get_alert_ai_summary(alert_id)
    content = str(response.get("markdown")) if response.get("markdown") else json.dumps(response)
    return CommandResults(
        readable_output=content,
        outputs_prefix="Reco.AlertSummary",
        outputs_key_field="alert_id",
        outputs=response,
        raw_response=response,
    )


def get_assets_user_has_access(reco_client: RecoClient, email_address: str, only_sensitive: bool) -> CommandResults:
    assets = reco_client.get_assets_user_has_access(email_address, only_sensitive)
    assets_list = [parse_table_row_to_dict(a.get("cells", {})) for a in assets]
    return CommandResults(
        readable_output=tableToMarkdown(
            "Assets",
            assets_list,
            headers=["file_name", "file_owner", "file_url", "currently_permitted_users", "visibility", "location", "source"],
        ),
        outputs_prefix="Reco.Assets",
        outputs_key_field="asset_value",
        outputs=assets_list,
        raw_response=assets,
    )


def get_sensitive_assets_shared_with_public_link(reco_client: RecoClient) -> CommandResults:
    assets = reco_client.get_exposed_publicly_files_at_risk()
    assets_list = [parse_table_row_to_dict(a.get("cells", {})) for a in assets]
    return CommandResults(
        readable_output=tableToMarkdown(
            "Assets",
            assets_list,
            headers=["asset_id", "asset", "data_category", "data_categories", "last_access_date", "visibility", "location"],
        ),
        outputs_prefix="Reco.Assets",
        outputs_key_field="asset_id",
        outputs=assets_list,
        raw_response=assets,
    )


def get_assets_shared_externally_command(reco_client: RecoClient, email_address: str) -> CommandResults:
    assets = reco_client.get_assets_shared_externally(email_address)
    assets_list = [parse_table_row_to_dict(a.get("cells", {})) for a in assets]
    return CommandResults(
        readable_output=tableToMarkdown(
            "Assets",
            assets_list,
            headers=[
                "asset_id",
                "asset",
                "data_category",
                "data_categories",
                "last_access_date",
                "visibility",
                "location",
                "file_owner",
            ],
        ),
        outputs_prefix="Reco.Assets",
        outputs_key_field="asset_id",
        outputs=assets_list,
        raw_response=assets,
    )


def get_files_exposed_to_email_command(reco_client: RecoClient, email_account: str) -> CommandResults:
    assets = reco_client.get_files_exposed_to_email(email_account)
    assets_list = [parse_table_row_to_dict(a.get("cells", {})) for a in assets]
    return CommandResults(
        readable_output=tableToMarkdown(
            "Assets",
            assets_list,
            headers=[
                "asset_id",
                "asset",
                "data_category",
                "data_categories",
                "last_access_date",
                "visibility",
                "location",
                "email_account",
                "file_owner",
            ],
        ),
        outputs_prefix="Reco.Assets",
        outputs_key_field="asset_id",
        outputs=assets_list,
        raw_response=assets,
    )


def get_3rd_parties_list(reco_client: RecoClient, last_interaction_time_in_days: int) -> CommandResults:
    domains = reco_client.get_3rd_parties_risk_list(last_interaction_time_in_days)
    domains_list = [parse_table_row_to_dict(d.get("cells", {})) for d in domains]
    return CommandResults(
        readable_output=tableToMarkdown(
            "Domains",
            domains_list,
            headers=["domain", "last_activity", "files_num", "users_with_access_num"],
        ),
        outputs_prefix="Reco.Domains",
        outputs_key_field="domain",
        outputs=domains_list,
        raw_response=domains,
    )


def get_files_shared_with_3rd_parties(
    reco_client: RecoClient, domain: str, last_interaction_time_before_in_days: int
) -> CommandResults:
    files = reco_client.get_files_shared_with_3rd_parties(domain, last_interaction_time_before_in_days)
    files_list = [parse_table_row_to_dict(f.get("cells", {})) for f in files]
    return CommandResults(
        readable_output=tableToMarkdown(
            "Files",
            files_list,
            headers=["domain", "location", "users", "file_owner", "data_category", "asset", "last_access_date", "asset_id"],
        ),
        outputs_prefix="Reco.Assets",
        outputs_key_field="asset_id",
        outputs=files_list,
        raw_response=files,
    )


LEGACY_ASSET_FIELD_ALIASES = {
    "file_name": "name",
    "file_owner": "owner",
    "file_url": "url",
    "sensitivity_level": "sensitivityLevel",
    "visibility": "permissionVisibility",
}


def assets_to_command_result(files: list[dict[str, Any]]) -> CommandResults:
    """Convert File objects (external API) to CommandResults for asset commands."""
    add_legacy_output_aliases(files, LEGACY_ASSET_FIELD_ALIASES)
    return CommandResults(
        readable_output=tableToMarkdown(
            "Assets",
            files,
            headers=["id", "name", "owner", "url", "sensitivityLevel", "permissionVisibility", "location", "dataCategories"],
        ),
        outputs_prefix="Reco.SensitiveAssets",
        outputs_key_field="id",
        outputs=files,
        raw_response=files,
    )


def get_sensitive_assets_by_name(reco_client: RecoClient, asset_name: str, regex_search: bool) -> CommandResults:
    files = reco_client.get_sensitive_assets_information(asset_name, None, True, regex_search)
    return assets_to_command_result(files)


def get_assets_by_id(reco_client: RecoClient, asset_id: str) -> CommandResults:
    files = reco_client.get_sensitive_assets_information(None, asset_id, False, False)
    return assets_to_command_result(files)


def get_sensitive_assets_by_id(reco_client: RecoClient, asset_id: str) -> CommandResults:
    files = reco_client.get_sensitive_assets_information(None, asset_id, True, False)
    return assets_to_command_result(files)


LEGACY_USER_FIELD_ALIASES = {
    "email_account": "email",
    "full_name": "name",
    "job_titles": "jobTitles",
}


def get_user_context_by_email_address(reco_client: RecoClient, email_address: str) -> CommandResults:
    """Return identity context for an email address (external API)."""
    users = reco_client.get_user_context_by_email_address(email_address)
    user_data = users[0] if users else None
    if user_data:
        add_legacy_output_aliases([user_data], LEGACY_USER_FIELD_ALIASES)
        # "category" has no direct External API field; approximate from isInternal, matching
        # the old values ("internal"/"external"). "groups" and "labels" have no equivalent
        # data in the External API and are not populated.
        if "isInternal" in user_data:
            user_data["category"] = "internal" if user_data["isInternal"] else "external"
    return CommandResults(
        readable_output=tableToMarkdown("User", user_data, headers=list(user_data.keys()) if user_data else []),
        outputs_prefix="Reco.User",
        outputs_key_field="email",
        outputs=user_data,
        raw_response=users,
    )


def add_exclusion_filter(reco_client: RecoClient, key_to_add: str, values: list[str]) -> CommandResults:  # pragma: no cover
    response = reco_client.add_exclusion_filter(key_to_add, values)
    return CommandResults(raw_response=response, readable_output="Exclusion filter added successfully")


def change_alert_status(reco_client: RecoClient, alert_id: str, status: str) -> CommandResults:  # pragma: no cover
    response = reco_client.change_alert_status(alert_id, status)
    return CommandResults(raw_response=response, readable_output=f"Alert {alert_id} status changed successfully to {status}")


def get_private_email_list_with_access(reco_client: RecoClient) -> CommandResults:
    result = reco_client.get_list_of_private_emails_with_access()
    identities_list = [parse_table_row_to_dict(i.get("cells", {})) for i in result]
    return CommandResults(
        readable_output=tableToMarkdown(
            "PrivateEmails",
            identities_list,
            headers=["email_account", "primary_email", "files_num", "user_category"],
        ),
        outputs_prefix="Reco.privateEmails",
        outputs_key_field="email_account",
        outputs=identities_list,
        raw_response=result,
    )


def get_link_to_user_overview_page(reco_client: RecoClient, entity: str, link_type: str) -> CommandResults:
    link = reco_client.get_link_to_user_overview_page(link_type, entity)
    return CommandResults(outputs_prefix="Reco.Link", outputs={"link": link}, raw_response=link)


LEGACY_APP_FIELD_ALIASES = {
    "app_id": "id",
    "app_name": "name",
    "users_count": "usersCount",
    "created_at": "firstSeen",
}


def get_apps_command(
    reco_client: RecoClient, before: datetime | None = None, after: datetime | None = None, limit: int = PAGE_SIZE
) -> CommandResults:
    """List discovered apps from the external API."""
    apps = reco_client.get_app_discovery(before=before, after=after, limit=limit)
    # "risk_score", "data_access", "status", and "updated_at" have no equivalent field in the
    # External API and are not populated.
    add_legacy_output_aliases(apps, LEGACY_APP_FIELD_ALIASES)
    headers = ["id", "name", "category", "usersCount", "authorization", "isUsingAi", "vendorGrade", "aiCapability", "lastSeen"]
    return CommandResults(
        readable_output=tableToMarkdown("App Discovery", apps, headers=headers),
        outputs_prefix="Reco.Apps",
        outputs_key_field="id",
        outputs=apps,
        raw_response=apps,
    )


def set_app_authorization_status_command(
    reco_client: RecoClient, app_id: str, authorization_status: str, app_type: str = ""
) -> CommandResults:
    """Update app authorization status via the external API."""
    reco_client.set_app_authorization_status(app_id, authorization_status, app_type)
    return CommandResults(
        readable_output=f"App {app_id} authorization status updated to {authorization_status}",
        outputs_prefix="Reco.AppAuthorization",
        outputs={"app_id": app_id, "authorization_status": authorization_status, "updated": True},
    )


# --- On-demand alert commands (never read or write the fetch-incidents last-run) ---

ALERT_TABLE_HEADERS = ["id", "description", "severity", "status", "createdAt", "apps", "instanceName", "customLabels"]


def _alert_query_from_args(args: dict[str, Any]) -> dict[str, Any]:
    """Parse the shared alert filter arguments of reco-list-alerts / reco-fetch-alerts."""
    return {
        "risk_levels": parse_risk_levels(args.get("risk_level")),
        "source": args.get("source") or None,
        "after": parse_date_param(args.get("after"), "after"),
        "before": parse_date_param(args.get("before"), "before", include_whole_day=True),
        "filter_options": build_filter_options(
            saas_platform=args.get("saas_platform"),
            status=args.get("status"),
            include_labels=args.get("labels"),
            exclude_labels=args.get("exclude_labels"),
            custom_filter=args.get("filters"),
        ),
    }


def _parse_limit(args: dict[str, Any]) -> int:
    raw_limit = arg_to_number(args.get("limit"), arg_name="limit")
    limit = LIST_ALERTS_DEFAULT_LIMIT if raw_limit is None else int(raw_limit)
    if limit < 1:
        raise ValueError("limit must be a positive number.")
    return limit


def _parse_sort_order(args: dict[str, Any], default: str) -> str:
    sort_order = str(args.get("sort_order") or default).lower()
    if sort_order not in ("ascending", "descending"):
        raise ValueError("sort_order must be 'ascending' or 'descending'.")
    return sort_order


def _alerts_to_command_results(title: str, alerts: list[dict[str, Any]]) -> CommandResults:
    rows = [{**alert, "instanceName": (alert.get("instance") or {}).get("appName", "")} for alert in alerts]
    return CommandResults(
        readable_output=tableToMarkdown(title, rows, headers=ALERT_TABLE_HEADERS, removeNull=True),
        outputs_prefix="Reco.Alerts",
        outputs_key_field="id",
        outputs=alerts,
    )


def _collect_alert_pages(
    fetch_page: Callable[[int, int], tuple[list[dict[str, Any]], int]], limit: int, max_page_size: int
) -> list[dict[str, Any]]:
    """Collect up to `limit` alerts by paging. fetch_page(page_size, offset) returns (alerts, raw page size).

    A new alert arriving between pages shifts the offsets, so an alert is never returned twice, and paging
    stops on a short page or a page with nothing new.
    """
    alerts: list[dict[str, Any]] = []
    seen_ids: set[str | None] = set()
    offset = 0
    while len(alerts) < limit:
        page_size = min(max_page_size, limit - len(alerts))
        page, raw_page_size = fetch_page(page_size, offset)
        offset += raw_page_size
        new_alerts = [alert for alert in page if alert.get("id") not in seen_ids]
        seen_ids.update(alert.get("id") for alert in new_alerts)
        alerts.extend(new_alerts)
        if raw_page_size < page_size or not new_alerts:
            break
    return alerts


def list_alerts_command(reco_client: RecoClient, args: dict[str, Any]) -> CommandResults:
    """List alert summaries for an analyst-defined window and filters. One list call per page, no per-alert detail calls.

    Deliberately independent of fetch-incidents: it never reads or writes the last-run, so it
    cannot move the production fetch cursor.
    """
    query = _alert_query_from_args(args)
    limit = _parse_limit(args)
    sort_order = _parse_sort_order(args, default="descending")

    def fetch_page(page_size: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        page = reco_client.get_alerts(**query, limit=page_size, start_index=offset, sort_order=sort_order)
        return page, len(page)

    alerts = _collect_alert_pages(fetch_page, limit, PAGE_SIZE)
    return _alerts_to_command_results("Reco Alerts", alerts)


def fetch_alerts_command(reco_client: RecoClient, args: dict[str, Any]) -> CommandResults:
    """Retrieve enriched alerts (full detail incl. policy violations - the same shape fetch-incidents
    ingests) for a historical window, for investigations, mapping tests and controlled backfills.

    It returns the alerts to the war room / context only: it does not create incidents, and it never
    reads or writes the fetch-incidents last-run.
    """
    query = _alert_query_from_args(args)
    limit = _parse_limit(args)
    sort_order = _parse_sort_order(args, default="ascending")

    def fetch_page(page_size: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        return get_alerts(reco_client, limit=page_size, start_index=offset, sort_order=sort_order, **query)

    alerts = _collect_alert_pages(fetch_page, limit, FETCH_ALERTS_PAGE_SIZE)
    return _alerts_to_command_results("Reco Alerts (detailed)", alerts)


def get_alert_command(reco_client: RecoClient, alert_id: str) -> CommandResults:
    """Retrieve one alert, with its policy violations, by ID."""
    detail = reco_client.get_single_alert(alert_id)
    if not detail:
        raise DemistoException(f"Alert {alert_id} was not found.")
    return _alerts_to_command_results(f"Reco Alert {alert_id}", [normalize_policy_violations(detail)])


# --- Alert severity and entity label commands (external API) ---


def update_alert_severity_command(reco_client: RecoClient, alert_id: str, severity: str) -> CommandResults:
    """Set the severity of a threat alert."""
    severities = parse_risk_levels(severity) or []
    if len(severities) != 1:
        raise ValueError("severity must be exactly one of LOW, MEDIUM, HIGH, CRITICAL (or 10, 20, 30, 40).")
    alert = reco_client.update_alert_severity(alert_id, severities[0])
    return CommandResults(
        readable_output=f"Alert {alert_id} severity updated to {severities[0]}",
        outputs_prefix="Reco.Alerts",
        outputs_key_field="id",
        outputs=normalize_policy_violations(alert),
        raw_response=alert,
    )


def _validated_entity_type(entity_type: str) -> str:
    normalized = entity_type.strip().lower()
    if normalized not in ENTITY_LABEL_TYPES:
        raise ValueError(f"Unknown entity_type '{entity_type}'. Valid values: {', '.join(ENTITY_LABEL_TYPES)}.")
    return normalized


def add_entity_label_command(reco_client: RecoClient, args: dict[str, Any]) -> CommandResults:
    """Add an existing catalog label to an entity."""
    entity_type = _validated_entity_type(args["entity_type"])
    response = reco_client.add_entity_label(args["entity_id"], entity_type, args["label_name"], args.get("instance_id", ""))
    return CommandResults(
        readable_output=f"Label '{args['label_name']}' added to {entity_type} {args['entity_id']}",
        raw_response=response,
    )


def remove_entity_label_command(reco_client: RecoClient, args: dict[str, Any]) -> CommandResults:
    """Remove a label from an entity."""
    entity_type = _validated_entity_type(args["entity_type"])
    response = reco_client.remove_entity_label(args["entity_id"], entity_type, args["label_name"], args.get("instance_id", ""))
    return CommandResults(
        readable_output=f"Label '{args['label_name']}' removed from {entity_type} {args['entity_id']}",
        raw_response=response,
    )


# --- New command functions (external API) ---


def list_events_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List SaaS events from the external API."""
    response = reco_client.list_events(filters=filters, count=limit)
    events = response.get("events", [])
    flat: list[dict[str, Any]] = []
    for e in events:
        row = dict(e)
        actor = e.get("actor") or {}
        row["actorEmail"] = actor.get("email", "")
        row["actorName"] = actor.get("name", "")
        flat.append(row)
    return CommandResults(
        readable_output=tableToMarkdown(
            "Events",
            flat,
            headers=["id", "eventType", "formattedEventType", "application", "actorEmail", "eventTime", "outcomeString"],
        ),
        outputs_prefix="Reco.Events",
        outputs_key_field="id",
        outputs=events,
        raw_response=response,
    )


def list_posture_issues_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List posture issues from the external API."""
    response = reco_client.list_posture_issues(filters=filters, count=limit)
    issues = response.get("issues", [])
    return CommandResults(
        readable_output=tableToMarkdown(
            "Posture Issues",
            issues,
            headers=["id", "name", "severity", "checkStatus", "scorePercentage", "checkedInstance", "url"],
        ),
        outputs_prefix="Reco.PostureIssues",
        outputs_key_field="id",
        outputs=issues,
        raw_response=response,
    )


def list_accounts_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List accounts from the external API."""
    response = reco_client.list_accounts(filters=filters, count=limit)
    accounts = response.get("accounts", [])
    return CommandResults(
        readable_output=tableToMarkdown(
            "Accounts",
            accounts,
            headers=["id", "name", "accountEmail", "permissions", "hasMfa", "openAlerts", "isAdmin", "isRiskyUser", "lastSeen"],
        ),
        outputs_prefix="Reco.Accounts",
        outputs_key_field="id",
        outputs=accounts,
        raw_response=response,
    )


def list_devices_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List devices from the external API."""
    response = reco_client.list_devices(filters=filters, count=limit)
    devices = response.get("devices", [])
    return CommandResults(
        readable_output=tableToMarkdown(
            "Devices",
            devices,
            headers=["id", "name", "devicePlatform", "os", "osVersion", "isUnmanaged", "hasNonCompliant", "lastSeen"],
        ),
        outputs_prefix="Reco.Devices",
        outputs_key_field="id",
        outputs=devices,
        raw_response=response,
    )


def list_ai_agents_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List AI agents from the external API."""
    response = reco_client.list_ai_agents(filters=filters, count=limit)
    agents = response.get("aiAgents", [])
    return CommandResults(
        readable_output=tableToMarkdown(
            "AI Agents",
            agents,
            headers=["id", "name", "vendor", "type", "authorization", "agentStatus", "risk", "lastUsage"],
        ),
        outputs_prefix="Reco.AiAgents",
        outputs_key_field="id",
        outputs=agents,
        raw_response=response,
    )


def list_groups_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List SaaS groups from the external API."""
    response = reco_client.list_groups(filters=filters, count=limit)
    groups = response.get("groups", [])
    return CommandResults(
        readable_output=tableToMarkdown(
            "Groups",
            groups,
            headers=["id", "name", "email", "membersCount", "appsCount"],
        ),
        outputs_prefix="Reco.Groups",
        outputs_key_field="id",
        outputs=groups,
        raw_response=response,
    )


def list_saas_to_saas_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List SaaS-to-SaaS grants from the external API."""
    response = reco_client.list_saas_to_saas(filters=filters, count=limit)
    grants = response.get("saasToSaas", [])
    return CommandResults(
        readable_output=tableToMarkdown(
            "SaaS-to-SaaS Grants",
            grants,
            headers=["id", "plugin", "authorization", "permissionRisk", "accounts", "aiCapability", "lastSeen"],
        ),
        outputs_prefix="Reco.SaasToSaas",
        outputs_key_field="id",
        outputs=grants,
        raw_response=response,
    )


def list_ip_addresses_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List observed IP addresses from the external API."""
    response = reco_client.list_ip_addresses(filters=filters, count=limit)
    ips = response.get("ipAddresses", [])
    return CommandResults(
        readable_output=tableToMarkdown(
            "IP Addresses",
            ips,
            headers=["ipAddress", "country", "asnName", "eventsCount", "usersCount", "hasVpn", "hasProxy", "lastEventTime"],
        ),
        outputs_prefix="Reco.IpAddresses",
        outputs_key_field="ipAddress",
        outputs=ips,
        raw_response=response,
    )


def list_business_units_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List external business units from the external API."""
    response = reco_client.list_business_units(filters=filters, count=limit)
    bus = response.get("businessUnits", [])
    return CommandResults(
        readable_output=tableToMarkdown(
            "Business Units",
            bus,
            headers=["id", "name", "manager", "createdAt"],
        ),
        outputs_prefix="Reco.BusinessUnits",
        outputs_key_field="id",
        outputs=bus,
        raw_response=response,
    )


def list_audit_logs_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List platform audit logs from the external API."""
    response = reco_client.list_audit_logs(filters=filters, count=limit)
    logs = response.get("auditLogs", [])
    return CommandResults(
        readable_output=tableToMarkdown(
            "Audit Logs",
            logs,
            headers=["id", "userEmail", "module", "action", "objectName", "timestamp", "remoteAddr"],
        ),
        outputs_prefix="Reco.AuditLogs",
        outputs_key_field="id",
        outputs=logs,
        raw_response=response,
    )


def list_posture_checks_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List posture check definitions from the external API."""
    response = reco_client.list_posture_checks(filters=filters, count=limit)
    checks = response.get("postureChecks", [])
    return CommandResults(
        readable_output=tableToMarkdown(
            "Posture Checks",
            checks,
            headers=["id", "name", "severity", "policyType", "apps", "type"],
        ),
        outputs_prefix="Reco.PostureChecks",
        outputs_key_field="id",
        outputs=checks,
        raw_response=response,
    )


def list_threat_detection_policies_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List threat detection policies from the external API."""
    response = reco_client.list_threat_detection_policies(filters=filters, count=limit)
    policies = response.get("policies", [])
    return CommandResults(
        readable_output=tableToMarkdown(
            "Threat Detection Policies",
            policies,
            headers=["id", "name", "severity", "status", "apps", "openAlerts", "type"],
        ),
        outputs_prefix="Reco.ThreatDetectionPolicies",
        outputs_key_field="id",
        outputs=policies,
        raw_response=response,
    )


def list_exclusions_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List alert suppression exclusion rules from the external API."""
    response = reco_client.list_exclusions(filters=filters, count=limit)
    exclusions = response.get("exclusions", [])
    return CommandResults(
        readable_output=tableToMarkdown(
            "Exclusions",
            exclusions,
            headers=["id", "name", "policyName", "apps", "createdBy", "createdAt"],
        ),
        outputs_prefix="Reco.Exclusions",
        outputs_key_field="id",
        outputs=exclusions,
        raw_response=response,
    )


def list_app_instances_command(reco_client: RecoClient, filters: str = "", limit: int = PAGE_SIZE) -> CommandResults:
    """List integrated app instances (portfolio) from the external API."""
    response = reco_client.list_app_instances(filters=filters, count=limit)
    instances = response.get("appInstances", [])
    return CommandResults(
        readable_output=tableToMarkdown(
            "App Instances",
            instances,
            headers=["id", "name", "instanceType", "accountsCount", "isUsingAi", "saasToSaasCount", "filesCount"],
        ),
        outputs_prefix="Reco.AppInstances",
        outputs_key_field="id",
        outputs=instances,
        raw_response=response,
    )


# --- Main ---


def main() -> None:  # pragma: no cover
    try:
        command = demisto.command()
        demisto.debug(f"Reco Command being called is {command}")
        params = demisto.params()
        args = demisto.args()
        api_url = params.get("url")
        api_token = params.get("api_token")
        verify_certificate = not params.get("insecure", False)
        proxy = params.get("proxy", False)

        if not api_url:
            raise ValueError("Server URL is required")
        if not api_token:
            raise ValueError("API Token is required")

        max_fetch = get_max_fetch(int(params.get("max_fetch", "200")))

        reco_client = RecoClient(
            api_token=api_token,
            base_url=api_url,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "fetch-incidents":
            next_run, incidents = fetch_incidents(
                reco_client,
                last_run=demisto.getLastRun(),
                max_fetch=max_fetch,
                **get_fetch_filters(params),
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == "reco-add-comment-to-alert":
            incident_id = args["alert_id"]
            response = reco_client.update_reco_incident_timeline(
                incident_id=incident_id,
                comment=args["comment"],
            )
            return_results(CommandResults(raw_response=response, readable_output=f"Comment added to alert {incident_id}"))

        elif command == "reco-update-incident-timeline":
            incident_id = args["incident_id"]
            response = reco_client.update_reco_incident_timeline(
                incident_id=incident_id,
                comment=args["comment"],
            )
            return_results(CommandResults(raw_response=response, readable_output=f"Timeline updated for incident {incident_id}"))

        elif command == "reco-resolve-visibility-event":
            entity_id = args["entity_id"]
            label_name = args["label_name"]
            response = reco_client.resolve_visibility_event(entity_id=entity_id, label_name=label_name)
            return_results(CommandResults(raw_response=response, readable_output=f"Visibility event {entity_id} resolved"))

        elif command == "test-module":
            return_results(reco_client.validate_api_key(**get_fetch_filters(params)))

        elif command == "reco-list-alerts":
            return_results(list_alerts_command(reco_client, args))

        elif command == "reco-fetch-alerts":
            return_results(fetch_alerts_command(reco_client, args))

        elif command == "reco-get-alert":
            return_results(get_alert_command(reco_client, args["alert_id"]))

        elif command == "reco-update-alert-severity":
            return_results(update_alert_severity_command(reco_client, args["alert_id"], args["severity"]))

        elif command == "reco-add-entity-label":
            return_results(add_entity_label_command(reco_client, args))

        elif command == "reco-remove-entity-label":
            return_results(remove_entity_label_command(reco_client, args))

        elif command == "reco-get-risky-users":
            return_results(get_risky_users_from_reco(reco_client))

        elif command == "reco-add-risky-user-label":
            return_results(add_risky_user_label(reco_client, args["email_address"]))

        elif command == "reco-add-leaving-org-user-label":
            return_results(add_leaving_org_user(reco_client, args["email_address"]))

        elif command == "reco-get-assets-user-has-access-to":
            return_results(
                get_assets_user_has_access(
                    reco_client,
                    args["email_address"],
                    args.get("only_sensitive", False),
                )
            )

        elif command == "reco-get-sensitive-assets-by-name":
            return_results(
                get_sensitive_assets_by_name(
                    reco_client,
                    args["asset_name"],
                    args.get("regex_search", False),
                )
            )

        elif command == "reco-get-sensitive-assets-by-id":
            return_results(get_sensitive_assets_by_id(reco_client, args["asset_id"]))

        elif command == "reco-get-link-to-user-overview-page":
            return_results(get_link_to_user_overview_page(reco_client, args["entity"], args["param"]))

        elif command == "reco-get-sensitive-assets-with-public-link":
            return_results(get_sensitive_assets_shared_with_public_link(reco_client))

        elif command == "reco-get-3rd-parties-accessible-to-data-list":
            return_results(get_3rd_parties_list(reco_client, int(args["last_interaction_time_in_days"])))

        elif command == "reco-get-files-shared-with-3rd-parties":
            return_results(
                get_files_shared_with_3rd_parties(
                    reco_client,
                    args["domain"],
                    int(args["last_interaction_time_in_days"]),
                )
            )

        elif command == "reco-add-exclusion-filter":
            return_results(add_exclusion_filter(reco_client, args["key_to_add"], argToList(args["values_to_add"])))

        elif command == "reco-change-alert-status":
            return_results(change_alert_status(reco_client, args["alert_id"], args["status"]))

        elif command == "reco-get-user-context-by-email-address":
            return_results(get_user_context_by_email_address(reco_client, args["email_address"]))

        elif command == "reco-get-files-exposed-to-email-address":
            return_results(get_files_exposed_to_email_command(reco_client, args["email_address"]))

        elif command == "reco-get-assets-shared-externally":
            return_results(get_assets_shared_externally_command(reco_client, args["email_address"]))

        elif command == "reco-get-private-email-list-with-access":
            return_results(get_private_email_list_with_access(reco_client))

        elif command == "reco-get-assets-by-id":
            return_results(get_assets_by_id(reco_client, args["asset_id"]))

        elif command == "reco-get-alert-ai-summary":
            return_results(get_alert_ai_summary(reco_client, args.get("alert_id", "")))

        elif command == "reco-get-apps":
            before_dt = dateparser.parse(args["before"]) if args.get("before") else None
            after_dt = dateparser.parse(args["after"]) if args.get("after") else None
            return_results(
                get_apps_command(reco_client, before=before_dt, after=after_dt, limit=int(args.get("limit") or PAGE_SIZE))
            )

        elif command == "reco-set-app-authorization-status":
            return_results(
                set_app_authorization_status_command(
                    reco_client, args["app_id"], args["authorization_status"], args.get("app_type", "")
                )
            )

        elif command == "reco-list-events":
            return_results(
                list_events_command(reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE))
            )

        elif command == "reco-list-posture-issues":
            return_results(
                list_posture_issues_command(
                    reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE)
                )
            )

        elif command == "reco-list-accounts":
            return_results(
                list_accounts_command(reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE))
            )

        elif command == "reco-list-devices":
            return_results(
                list_devices_command(reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE))
            )

        elif command == "reco-list-ai-agents":
            return_results(
                list_ai_agents_command(reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE))
            )

        elif command == "reco-list-groups":
            return_results(
                list_groups_command(reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE))
            )

        elif command == "reco-list-saas-to-saas":
            return_results(
                list_saas_to_saas_command(reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE))
            )

        elif command == "reco-list-ip-addresses":
            return_results(
                list_ip_addresses_command(reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE))
            )

        elif command == "reco-list-business-units":
            return_results(
                list_business_units_command(
                    reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE)
                )
            )

        elif command == "reco-list-audit-logs":
            return_results(
                list_audit_logs_command(reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE))
            )

        elif command == "reco-list-posture-checks":
            return_results(
                list_posture_checks_command(
                    reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE)
                )
            )

        elif command == "reco-list-threat-detection-policies":
            return_results(
                list_threat_detection_policies_command(
                    reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE)
                )
            )

        elif command == "reco-list-exclusions":
            return_results(
                list_exclusions_command(reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE))
            )

        elif command == "reco-list-app-instances":
            return_results(
                list_app_instances_command(
                    reco_client, filters=args.get("filters", ""), limit=int(args.get("limit") or PAGE_SIZE)
                )
            )

        else:
            raise NotImplementedError(f"{command} is not an existing reco command")

    except Exception as e:
        demisto.error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

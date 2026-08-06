import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
VENDOR = "orca"
PRODUCT = "security"
DEFAULT_PAGE_SIZE = 100  # Serving Layer API default page size (SQL LIMIT)
TEST_MODULE_LIMIT = 1  # Minimal page size for the connectivity test

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, server_url: str, headers: dict, proxy: bool = False, verify: bool = False):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)

    def get_alerts_request(self, page_size: int, start_index: int, last_fetch: str, end_time: str) -> dict:
        """Retrieve a single page of alerts using the Serving Layer API.

        The Serving Layer API uses offset-based pagination: ``start_at_index`` is a plain
        0-based SQL OFFSET (not a cursor/token) and ``limit`` maps to SQL LIMIT. The caller
        is responsible for advancing ``start_index`` between pages and detecting the end of
        results (a page returning fewer rows than ``page_size`` or an empty ``data`` array).

        Events are filtered and ordered by ``LastUpdated`` (the sync timestamp), which is
        monotonic under Orca's eventual consistency - unlike ``CreatedAt``. The window is
        two-sided: ``LastUpdated >= last_fetch AND LastUpdated < end_time``. The ``end_time``
        upper bound is fixed at the start of the run so events synced mid-run are not
        half-fetched (they are picked up whole on the next run). ``gte``/``lt`` operators are
        used without ``value_type`` for second-level precision (per Orca guidance).

        Args:
            page_size: int - Maximum number of records to return in this page (SQL LIMIT).
            start_index: int - 0-based offset for this page (SQL OFFSET).
            last_fetch: str - Inclusive lower bound for ``LastUpdated`` (ISO 8601).
                             **MUST be a valid ISO 8601 string (e.g., "2023-10-27T10:00:00Z").**
                             The API is very strict about this format.
            end_time: str - Exclusive upper bound for ``LastUpdated`` (ISO 8601), fixed at run start.
        Returns:
            A dictionary with the alerts details (keys: ``status``, ``data``, ``from_cache``).
        """
        payload = {
            "query": {
                "models": ["Alert"],
                "type": "object_set",
                "with": {
                    "type": "operation",
                    "operator": "and",
                    "values": [
                        {
                            "key": "LastUpdated",
                            "values": [last_fetch],
                            "type": "datetime",
                            "operator": "gte",
                        },
                        {
                            "key": "LastUpdated",
                            "values": [end_time],
                            "type": "datetime",
                            "operator": "lt",
                        },
                    ],
                },
            },
            "limit": page_size,
            "start_at_index": start_index,
            "order_by[]": ["LastUpdated"],
            "select": [
                "AlertId",
                "AlertType",
                "OrcaScore",
                "RiskLevel",
                "RuleSource",
                "ScoreVector",
                "Category",
                "Inventory.Name",
                "CloudAccount.Name",
                "CloudAccount.CloudProvider",
                "Source",
                "Status",
                "CreatedAt",
                "LastUpdated",
                "LastSeen",
                "Labels",
            ],
        }

        demisto.debug(f"In get_alerts (Serving Layer API) request payload: {json.dumps(payload)}")

        return self._http_request(method="POST", url_suffix="/serving-layer/query", json_data=payload)


""" HELPER FUNCTIONS """


def add_time_key_to_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Adds the _time key to the alerts with improved logging and clarity.
    This function mutates the 'alerts' list in place and also returns it.

    ``_time`` is set from the alert's ``LastUpdated`` (the sync timestamp), so updated alerts
    re-land in XSIAM at their update time. If ``LastUpdated`` is missing/unparseable, we fall
    back to ``CreatedAt``, and finally to the current time.

    Args:
        alerts: A list of alert dictionaries to process.

    Returns:
        The mutated list of alerts, now including the '_time' key.
    """
    now_utc = datetime.now(timezone.utc)
    fallback_time_str = now_utc.strftime(DATE_FORMAT)

    if not alerts:
        return alerts

    for alert in alerts:
        alert_data = alert.get("data", {})
        alert_id = alert_data.get("AlertId", {}).get("value") or alert.get("id", "UNKNOWN_ID")
        last_updated_str = alert_data.get("LastUpdated", {}).get("value")
        create_time_str = alert_data.get("CreatedAt", {}).get("value")

        # Prefer LastUpdated (sync time); fall back to CreatedAt if it is missing/unparseable.
        event_time = None
        for field_name, raw_value in (("LastUpdated", last_updated_str), ("CreatedAt", create_time_str)):
            if not raw_value:
                continue
            try:
                event_time = arg_to_datetime(arg=raw_value)
                if event_time:
                    break
            except Exception as e:
                demisto.debug(
                    f"arg_to_datetime failed unexpectedly while parsing '{field_name}' for AlertId: {alert_id} "
                    f"with value '{raw_value}'. Error: {e}"
                )

        if event_time:
            alert["_time"] = event_time.strftime(DATE_FORMAT)
        else:
            demisto.info(
                f"Could not parse or find 'LastUpdated'/'CreatedAt' value for AlertId: {alert_id}. "
                f"Raw values were LastUpdated='{last_updated_str}', CreatedAt='{create_time_str}'. "
                f"Setting '_time' to {fallback_time_str}."
            )
            alert["_time"] = fallback_time_str

        demisto.debug(f"Processed AlertId: {alert_id}, final _time: {alert.get('_time')}")

    return alerts


def add_entry_status_to_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Adds the ``_ENTRY_STATUS`` key to each alert, classifying whether it is new or updated.
    This function mutates the 'alerts' list in place and also returns it.

    Logic:
        - "new"     when ``LastUpdated`` == ``CreatedAt`` (never modified since creation),
                    or when either timestamp is missing/unparseable (safe default).
        - "updated" when ``LastUpdated`` > ``CreatedAt`` (modified after creation).

    Args:
        alerts: A list of alert dictionaries to process.

    Returns:
        The mutated list of alerts, now including the '_ENTRY_STATUS' key.
    """
    if not alerts:
        return alerts

    for alert in alerts:
        alert_data = alert.get("data", {})
        alert_id = alert_data.get("AlertId", {}).get("value") or alert.get("id", "UNKNOWN_ID")
        created_time = arg_to_datetime(arg=alert_data.get("CreatedAt", {}).get("value"))
        last_updated_time = arg_to_datetime(arg=alert_data.get("LastUpdated", {}).get("value"))

        if created_time and last_updated_time and last_updated_time > created_time:
            alert["_ENTRY_STATUS"] = "updated"
        else:
            alert["_ENTRY_STATUS"] = "new"

        demisto.debug(f"Processed AlertId: {alert_id}, _ENTRY_STATUS: {alert.get('_ENTRY_STATUS')}")

    return alerts


""" COMMAND FUNCTIONS """


def orca_test_module(client: Client, last_fetch: str, end_time: str) -> str:
    """Test the connection to Orca Security.
    Args:
        client: client - An Orca client.
        last_fetch: str - The time and date of the last fetch alert.
        end_time: str - The exclusive upper bound for the fetch window (run start).
    Returns:
        'ok' if the connection was successful, else throws exception.
    """
    try:
        client.get_alerts_request(TEST_MODULE_LIMIT, 0, last_fetch, end_time)
        return "ok"
    except DemistoException as e:
        if "Error in API call [404] - Not Found" in e.message:
            raise Exception('Error in API call [404] - Not Found\n{"error": "URL is invalid"}')
        else:
            raise Exception(e.message)


def get_alerts(client: Client, max_fetch: int, last_fetch: str, end_time: str, page_size: int = DEFAULT_PAGE_SIZE) -> list:
    """Retrieve alerts, paginating through all available pages for the given window.

    The Serving Layer API is offset-based: there is no next-page token. We start at
    ``start_at_index`` = 0 and, after each page, advance the offset by the number of rows
    actually returned (not blindly by ``page_size``). Pagination stops when a page returns
    fewer rows than ``page_size`` (or an empty ``data`` array) - the normal end-of-results
    signal - or when we reach ``max_fetch`` total events for this run.

    The fetch window is two-sided on ``LastUpdated``: ``>= last_fetch AND < end_time``.

    Args:
        client: client - An Orca client.
        max_fetch: int - The maximum number of events to collect in this run (across all pages).
        last_fetch: str - Inclusive lower bound for ``LastUpdated``.
        end_time: str - Exclusive upper bound for ``LastUpdated`` (fixed at run start).
        page_size: int - The maximum number of events to request per page.
    Returns:
        A list of alerts (at most ``max_fetch`` items).
    """
    alerts: list = []
    start_index = 0
    pages_fetched = 0

    while len(alerts) < max_fetch:
        # Don't request more than we still need for this run.
        current_page_size = min(page_size, max_fetch - len(alerts))
        response = client.get_alerts_request(current_page_size, start_index, last_fetch, end_time)
        page = response.get("data", [])
        demisto.debug(f"Get Alerts page: {start_index=} , {current_page_size=} , returned={len(page)}")

        if not page:
            # Empty page - no more results.
            break

        pages_fetched += 1
        alerts.extend(page)
        # Advance the SQL OFFSET by the number of rows actually returned.
        start_index += len(page)

        if len(page) < current_page_size:
            # Short page - this was the last page of results.
            break

    # Summary line: confirms pagination is looping (vs the old single-page behavior).
    demisto.debug(f"Get Alerts summary: fetched {len(alerts)} event(s) across {pages_fetched} page(s)")
    # If we stopped because we hit max_fetch (rather than exhausting the window), a backlog
    # remains for the next run. This is the key signal to watch during the tenant catch-up:
    # it means the window still has more events than max_fetch could carry this cycle.
    if len(alerts) >= max_fetch:
        demisto.info(
            f"Get Alerts reached max_fetch cap ({max_fetch}); more events remain in the window "
            f"[LastUpdated >= {last_fetch} AND < {end_time}]. They will be collected on the next run."
        )
    return alerts


def dedup_alerts(alerts: List[Dict[str, Any]], seen_ids: List[str], boundary_time: Optional[str]) -> List[Dict[str, Any]]:
    """Remove alerts already returned at the previous window's upper boundary.

    Because the lower bound is inclusive (``LastUpdated >= last_fetch``), any alert whose
    ``LastUpdated`` equals the previous run's boundary second would be re-fetched. We drop
    exactly those alerts whose ``AlertId`` was already emitted at that boundary second.

    Args:
        alerts: Alerts fetched this run (ordered by ``LastUpdated`` ascending).
        seen_ids: AlertIds emitted at ``boundary_time`` on the previous run.
        boundary_time: The previous run's boundary ``LastUpdated`` value (== this run's ``last_fetch``).
    Returns:
        The alerts list with boundary-second duplicates removed.
    """
    if not alerts or not seen_ids or not boundary_time:
        return alerts

    seen = set(seen_ids)
    deduped = [
        alert
        for alert in alerts
        if not (
            alert.get("data", {}).get("LastUpdated", {}).get("value") == boundary_time
            and alert.get("data", {}).get("AlertId", {}).get("value") in seen
        )
    ]
    demisto.debug(f"Dedup removed {len(alerts) - len(deduped)} boundary duplicate(s) at {boundary_time}")
    return deduped


def get_boundary_ids(alerts: List[Dict[str, Any]], boundary_time: str) -> List[str]:
    """Collect AlertIds whose ``LastUpdated`` equals the given boundary second.

    These IDs are persisted so the next run can skip them (see :func:`dedup_alerts`).

    Args:
        alerts: Alerts emitted this run.
        boundary_time: The newest ``LastUpdated`` value (this run's boundary).
    Returns:
        A list of AlertIds sharing ``boundary_time`` as their ``LastUpdated``.
    """
    return [
        alert_id
        for alert in alerts
        if alert.get("data", {}).get("LastUpdated", {}).get("value") == boundary_time
        and (alert_id := alert.get("data", {}).get("AlertId", {}).get("value"))
    ]


""" MAIN FUNCTION """


def main() -> None:
    command = demisto.command()
    api_token = demisto.params().get("credentials", {}).get("password")
    server_url = f"{demisto.params().get('server_url')}/api"
    first_fetch = demisto.params().get("first_fetch") or "3 days"
    max_fetch = arg_to_number(demisto.params().get("max_fetch")) or 1000
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(arg=first_fetch, arg_name="First fetch time", required=True)
    first_fetch_time = first_fetch_time.strftime(DATE_FORMAT) if first_fetch_time else ""
    # Fixed exclusive upper bound for this run, so events synced mid-run aren't half-fetched.
    end_time = datetime.now(timezone.utc).strftime(DATE_FORMAT)
    demisto.debug(f"{first_fetch_time=} {end_time=}")
    demisto.info(f"Orca Security. Command being called is {command}")
    try:
        headers: dict = {"Authorization": f"Token {api_token}"}

        client = Client(server_url=server_url, verify=verify_certificate, headers=headers, proxy=proxy)

        last_run = demisto.getLastRun()
        if not last_run:
            demisto.debug(f"first run {last_run=}")
            last_fetch = first_fetch_time
            last_run_ids: list = []
        else:
            last_fetch = last_run.get("lastRun")
            last_run_ids = last_run.get("lastRunIds", [])
            demisto.debug(f"Isn't the first run {last_fetch=} {last_run_ids=}")

        if command == "test-module":
            return_results(orca_test_module(client, last_fetch, end_time))
        elif command in ("fetch-events", "orca-security-get-events"):
            # Explicit fetch window for this run (lower inclusive -> upper exclusive), for diagnostics.
            demisto.debug(f"Fetch window: LastUpdated >= {last_fetch} AND < {end_time} ({max_fetch=})")
            alerts = get_alerts(client, max_fetch, last_fetch, end_time)

            if command == "fetch-events":
                should_push_events = True
                # Dedup only applies to the stateful fetch cycle: drop alerts already emitted at
                # the previous run's boundary second (the lower bound is inclusive). The manual
                # get-events command is stateless and must not dedup against fetch state.
                alerts = dedup_alerts(alerts, last_run_ids, last_fetch)

            else:  # command == 'orca-security-get-events'
                should_push_events = argToBoolean(demisto.args().get("should_push_events", False))
                return_results(
                    CommandResults(
                        readable_output=tableToMarkdown(t=alerts, name=f"{VENDOR} - {PRODUCT} events", removeNull=True),
                        raw_response=alerts,
                    )
                )

            if should_push_events and alerts:
                alerts = add_time_key_to_alerts(alerts)
                alerts = add_entry_status_to_alerts(alerts)
                # Distribution of new vs updated: proves the LastUpdated cursor now captures updates.
                updated_count = sum(1 for alert in alerts if alert.get("_ENTRY_STATUS") == "updated")
                demisto.debug(
                    f"Entry status distribution: new={len(alerts) - updated_count}, updated={updated_count}, total={len(alerts)}"
                )
                demisto.debug(f"before send_events_to_xsiam {VENDOR=} {PRODUCT=} {alerts=}")
                send_events_to_xsiam(alerts, VENDOR, PRODUCT)
                demisto.debug(f"after send_events_to_xsiam {VENDOR=} {PRODUCT=} {alerts=}")

            # Only the scheduled fetch-events run may advance the cursor. The manual
            # orca-security-get-events command is a debug tool and must never touch lastRun,
            # otherwise running it would skip events on the next scheduled fetch.
            if command == "fetch-events":
                # Alerts are ordered by LastUpdated ascending, so the last item is the newest.
                # Advance lastRun to the newest event's LastUpdated; otherwise keep the previous value.
                last_updated_str = alerts[-1].get("data", {}).get("LastUpdated", {}).get("value") if alerts else None
                last_updated = arg_to_datetime(arg=last_updated_str)
                new_last_fetch = last_updated.strftime(DATE_FORMAT) if last_updated else last_fetch
                # Persist AlertIds sharing the new boundary second so the next run can skip them.
                new_last_run_ids = get_boundary_ids(alerts, new_last_fetch) if last_updated else last_run_ids
                current_last_run = {"lastRun": new_last_fetch, "lastRunIds": new_last_run_ids}

                demisto.setLastRun(current_last_run)
                demisto.debug(
                    f"Persisted lastRun={new_last_fetch} with {len(new_last_run_ids)} boundary id(s) for next-run dedup"
                )
                demisto.debug(f"{current_last_run=}")

        else:
            raise NotImplementedError("This command is not implemented yet.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

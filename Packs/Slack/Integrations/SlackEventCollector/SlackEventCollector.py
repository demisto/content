import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

urllib3.disable_warnings()

VENDOR = "slack"
PRODUCT = "slack"

# Recommended page size by Slack for the Audit Logs API.
API_PAGE_SIZE = 200
# Default maximum time range (in seconds) to fetch in a single run to avoid
# timeouts / out-of-memory when a very large backlog needs to be collected.
DEFAULT_MAX_FETCH_WINDOW = 24 * 60 * 60  # 1 day
# Maximum number of forward windows a single fetch run may walk. This bounds the run's
# duration / number of API calls when a large backlog needs to be backfilled; the remaining
# windows are covered by subsequent runs.
MAX_WINDOWS_PER_RUN = 10
# Sentinel used to mark the first pagination iteration (no cursor yet).
FIRST_PAGE = "__first_page__"


def get_now_timestamp() -> int:
    """Returns the current time as a unix timestamp (seconds). Wrapped for testability."""
    return int(datetime.utcnow().timestamp())


def arg_to_timestamp(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if datetime_obj := arg_to_datetime(value):
        return int(datetime_obj.timestamp())
    return None


def prepare_query_params(params: dict) -> dict:
    """
    Parses the given inputs into Slack Audit Logs API expected format.
    """
    query_params = {
        "limit": arg_to_number(params.get("limit") or 1000),
        "oldest": arg_to_timestamp(params.get("oldest")),
        "latest": arg_to_timestamp(params.get("latest")),
        "action": params.get("action"),
        "actor": params.get("actor"),
        "entity": params.get("entity"),
        "cursor": params.get("cursor"),
    }
    return query_params


class Client(BaseClient):
    def get_logs(self, query_params: dict) -> tuple[dict, list, str | None]:
        demisto.debug(f"{query_params=}")
        raw_response = self._http_request(
            method="GET",
            url_suffix="logs",
            params=query_params,
            retries=2,
        )
        demisto.debug(f"{raw_response=}")
        events = raw_response.get("entries", [])
        cursor = raw_response.get("response_metadata", {}).get("next_cursor")

        return raw_response, events, cursor

    def get_all_logs_in_window(self, oldest: int | None, latest: int | None, extra_params: dict) -> list[dict]:
        """
        Retrieves ALL events in the time window [oldest, latest] using cursor-based pagination.

        Slack returns events newest-first. Since the window is bounded on both ends
        (by `latest` on the top and `oldest` on the bottom), the number of events is
        naturally limited by the caller-chosen window size, which protects against
        timeouts / out-of-memory on large backlogs.

        Args:
            oldest: lower time boundary (inclusive), unix timestamp.
            latest: upper time boundary (inclusive), unix timestamp.
            extra_params: additional API filters (action, actor, entity).

        Returns:
            All events in the window (as returned by the API, i.e. newest-first).
        """
        base_params: dict = {k: v for k, v in extra_params.items() if v is not None}
        base_params["limit"] = API_PAGE_SIZE
        if oldest is not None:
            base_params["oldest"] = oldest
        if latest is not None:
            base_params["latest"] = latest

        aggregated: list[dict] = []
        # `cursor` drives the loop: FIRST_PAGE means "no cursor yet", None means "no more pages".
        cursor: str | None = FIRST_PAGE
        while cursor:
            query_params = dict(base_params)
            if cursor != FIRST_PAGE:
                query_params["cursor"] = cursor
            try:
                _, events, cursor = self.get_logs(query_params)
            except Exception as e:
                # If the very first page fails we have nothing to keep -> re-raise so the caller
                # does NOT advance lastRun and the same window is retried next run (no data loss).
                if not aggregated:
                    raise
                # A later page failed: keep what we already collected and stop paginating. The
                # caller persists progress up to the newest collected event and resumes next run.
                # This is a recoverable, expected condition, so it is logged at debug level.
                demisto.debug(
                    f"Failed to fetch a later page in window [{oldest}, {latest}]; "
                    f"keeping {len(aggregated)} events collected so far. Error: {e}"
                )
                break
            aggregated.extend(events)
        demisto.debug(f"Collected {len(aggregated)} events in window [{oldest}, {latest}].")
        return aggregated


def compute_window_start(params: dict, last_run: dict, now: int) -> int:
    """
    Computes the lower bound of the first window to fetch in this run: the oldest point we
    have not fully collected yet (`last_fetched_time`, or the configured first-fetch `oldest`
    on the first run). The run then walks forward in DEFAULT_MAX_FETCH_WINDOW-sized windows.
    """
    window_start = last_run.get("last_fetched_time")
    if window_start is None:
        window_start = arg_to_timestamp(params.get("oldest")) or now
    return window_start


def filter_already_fetched(events: list[dict], last_run: dict) -> list[dict]:
    """
    Removes events that were already sent to XSIAM on a previous run.

    Slack's `oldest` filter is inclusive, so events recorded exactly at
    `last_fetched_time` may be returned again; they are identified and dropped
    by matching their ids against `last_fetched_ids`.

    NOTE: This runs BEFORE the user-defined limit is applied, so the limit is always
    filled with genuinely-new events and we send as many new events as possible.
    """
    boundary_time = last_run.get("last_fetched_time")
    boundary_ids = set(last_run.get("last_fetched_ids") or [])
    if boundary_time is None or not boundary_ids:
        return events
    return [e for e in events if not (e.get("date_create") == boundary_time and e.get("id") in boundary_ids)]


def sort_events_oldest_first(events: list[dict]) -> list[dict]:
    """Sorts events ascending by (date_create, id) so the oldest events come first."""
    return sorted(events, key=lambda e: (e.get("date_create", 0), str(e.get("id", ""))))


def update_last_run(last_run: dict, sent_events: list[dict], window_end: int, reached_limit: bool, caught_up: bool) -> None:
    """
    Updates the lastRun object after sending events to XSIAM.

    The window was fully drained UNLESS `reached_limit` is True (in which case there are
    still more events at/after the last sent event). The low-water mark advances as follows:

    - reached_limit: mark = the newest SENT event, so the next run resumes mid-window and
      keeps walking forward. `last_fetched_ids` holds every id at that timestamp to dedup
      the inclusive boundary next run.
    - drained the window while still backfilling (window_end below 'now'): mark advances to
      `window_end`. This is provably safe (the API returned all events up to window_end),
      speeds up the backfill, and avoids re-querying the trailing gap of the window. No dedup
      ids are needed because there are no events exactly at window_end.
    - drained the window and caught up (window_end reached 'now'): mark = the newest SENT
      event (we cannot safely advance past 'now'); `last_fetched_ids` dedups the boundary.
    - empty window while still backfilling: mark advances to `window_end` so the next run
      moves on and we never get stuck re-querying an empty window.

    When the newest sent event is at the SAME timestamp as the previous high-water mark, the
    new boundary ids are MERGED with the previous ones (not replaced) so events already sent at
    that timestamp on earlier runs are still deduped and never re-sent.
    """
    if sent_events and (reached_limit or caught_up):
        newest_time = sent_events[-1].get("date_create")
        ids_at_newest = [e.get("id") for e in sent_events if e.get("date_create") == newest_time]
        if newest_time == last_run.get("last_fetched_time"):
            # High-water mark didn't move -> merge with the ids we already remembered.
            ids_at_newest = list(set(last_run.get("last_fetched_ids") or []) | set(ids_at_newest))
        last_run["last_fetched_time"] = newest_time
        last_run["last_fetched_ids"] = ids_at_newest
    elif not caught_up and window_end > (last_run.get("last_fetched_time") or 0):
        # Drained (or empty) window still below 'now' -> jump straight to the window end.
        last_run["last_fetched_time"] = window_end
        last_run["last_fetched_ids"] = []


def test_module_command(client: Client, params: dict) -> str:
    """
    Tests connection to Slack by performing a single, lightweight logs API call
    to verify the provided credentials are valid.

    Args:
        client (Client): the client implementing the API to Slack.
        params (dict): the instance configuration.

    Returns:
        (str) 'ok' if success.
    """
    client.get_logs({"limit": 1})
    return "ok"


def fetch_slack_events(client: Client, params: dict, last_run: dict) -> list[dict]:
    """
    Core Slack event collection cycle, shared by both `fetch-events` and `slack-get-events`.

    Because Slack returns events newest-first, we fetch ALL events in a bounded,
    forward-moving time window, sort them oldest-first, and return the oldest events
    up to the user-defined limit. Any surplus (beyond the limit) is collected in the
    following runs, which resume from where we stopped and keep walking forward until
    the present time is reached (steady state).

    The window is capped at DEFAULT_MAX_FETCH_WINDOW seconds to avoid timeouts / out-of-memory
    when a large backlog needs to be collected.

    This function MUTATES `last_run` in place to reflect progress. Callers that must not
    persist progress (e.g. the manual `slack-get-events` command) should pass a COPY.

    Args:
        client (Client): the client implementing the API to Slack.
        params (dict): the instance configuration / command arguments.
        last_run (dict): the lastRun object, holding information from the previous run.

    Returns:
        (list) the events to send (oldest-first, up to the limit).
    """
    if last_run is None:
        last_run = {}
    limit = arg_to_number(params.get("limit")) or 1000
    now = get_now_timestamp()
    extra_params = {
        "action": params.get("action"),
        "actor": params.get("actor"),
        "entity": params.get("entity"),
    }

    # Walk forward through bounded windows within this single run, so a sparse backlog is
    # drained quickly instead of advancing only one window per fetch interval. We stop as
    # soon as we either reach 'now' (caught up), fill the limit, or hit the per-run window cap
    # (which bounds the run's duration / number of API calls on very large backfills).
    window_start = compute_window_start(params, last_run, now)
    collected: list[dict] = []

    # `keep_walking` drives the loop: we always fetch at least the boundary window (even when
    # window_start == now, so events at the current second are collected), then keep walking
    # forward window-by-window until we catch up to 'now', fill the limit, or hit the cap.
    keep_walking = True
    windows_walked = 0
    while keep_walking:
        window_end = min(window_start + DEFAULT_MAX_FETCH_WINDOW, now)
        caught_up = window_end >= now
        demisto.debug(f"Fetch window: [{window_start}, {window_end}] (now={now}, limit={limit})")

        all_events = client.get_all_logs_in_window(window_start, window_end, extra_params)
        # Dedup BEFORE slicing to the limit so the limit is filled with new events only.
        new_events = filter_already_fetched(all_events, last_run)
        collected = sort_events_oldest_first(collected + new_events)
        windows_walked += 1

        # `have_enough` (at least the limit) means we have a full batch and stop walking further
        # windows. When we stop mid-backlog like this we MUST resume from the last SENT event
        # (not the window end), otherwise events between the last sent event and the window end
        # that we never sent would be skipped - a data-loss bug. `update_last_run` uses this
        # flag to store the last sent event as the resume point.
        have_enough = len(collected) >= limit
        events_to_send = collected[:limit]

        # When caught up (window reached 'now') and there is nothing new, keep the state as-is
        # so no event recorded at the boundary can be skipped. Otherwise update normally.
        if not (caught_up and not events_to_send):
            update_last_run(last_run, events_to_send, window_end, reached_limit=have_enough, caught_up=caught_up)

        # Stop once we caught up to 'now', have a full batch, or reached the per-run window cap;
        # otherwise walk to the next window. Any remaining windows are covered by the next run.
        hit_window_cap = windows_walked >= MAX_WINDOWS_PER_RUN
        if hit_window_cap and not (have_enough or caught_up):
            demisto.debug(f"Reached the per-run window cap ({MAX_WINDOWS_PER_RUN}); resuming next run.")
        keep_walking = not (have_enough or caught_up or hit_window_cap)
        window_start = window_end

    events_to_send = sort_events_oldest_first(collected)[:limit]
    demisto.debug(f"Collected {len(events_to_send)} events across the run.")
    return events_to_send


def get_events_command(client: Client, args: dict) -> tuple[list, CommandResults]:
    """
    Manual `slack-get-events` command.

    Runs the exact same collection cycle as the automated `fetch-events` collector
    (forward-moving window, oldest-first, deduped, limited) so the customer can preview
    precisely what a fetch would deliver - BUT it does NOT change the persisted lastRun.
    A copy of the current lastRun is used, so running this command has no side effects on
    the collector's state.

    Args:
        client (Client): the client implementing the API to Slack.
        args (dict): the command arguments.

    Returns:
        (list) the events retrieved (oldest-first, up to the limit).
        (CommandResults) the CommandResults object holding the collected logs information.
    """
    # Use a copy of the last run so the manual command never mutates the collector state.
    last_run_copy = dict(demisto.getLastRun() or {})
    events = fetch_slack_events(client, args, last_run_copy)
    results = CommandResults(
        readable_output=tableToMarkdown(
            "Slack Audit Logs",
            events,
            date_fields=["date_create"],
        ),
        raw_response={"entries": events},
    )
    return events, results


def fetch_events_command(client: Client, params: dict, last_run: dict) -> tuple[list, dict]:
    """
    Collects log events from Slack for the automated `fetch-events` collector and
    updates the lastRun object so subsequent runs continue where this one stopped.

    Args:
        client (Client): the client implementing the API to Slack.
        params (dict): the instance configuration.
        last_run (dict): the lastRun object, holding information from the previous run.

    Returns:
        (list) the events to send to XSIAM (oldest-first, up to the limit).
        (dict) the updated lastRun object.
    """
    if last_run is None:
        last_run = {}
    events_to_send = fetch_slack_events(client, params, last_run)
    return events_to_send, last_run


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            base_url=params.get("url"),
            verify=not params.get("insecure"),
            proxy=params.get("proxy"),
            headers={"Accept": "application/json", "Authorization": f'Bearer {params.pop("user_token", {}).get("password")}'},
        )

        if command == "test-module":
            return_results(test_module_command(client, params))

        elif command == "slack-get-events":
            events, results = get_events_command(client, args)
            return_results(results)

            if argToBoolean(args.get("should_push_events", "true")):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            demisto.debug(f"last run is: {last_run}")

            events, last_run = fetch_events_command(client, params, last_run)

            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(last_run)
            demisto.debug(f"Last run set to: {last_run}")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

urllib3.disable_warnings()

VENDOR = "slack"
PRODUCT = "slack"


class Config:
    """Global static configuration."""

    # Recommended page size by Slack for the Audit Logs API.
    API_PAGE_SIZE = 200
    # The maximum time range (in seconds) to fetch in a single run to avoid
    # timeouts / out-of-memory when a very large backlog needs to be collected.
    DEFAULT_MAX_FETCH_WINDOW = 24 * 60 * 60  # 1 day
    # Maximum number of forward windows a single fetch run may walk. This bounds the run's
    # duration / number of API calls when a large backlog needs to be backfilled; the remaining
    # windows are covered by subsequent runs.
    MAX_WINDOWS_PER_RUN = 10
    # Sentinel used to mark the first pagination iteration (no cursor yet).
    FIRST_PAGE = "__first_page__"
    # Default lookback for the FIRST fetch when no `oldest` is configured. Mirrors the
    # `oldest` parameter's default value in the integration YAML.
    DEFAULT_FIRST_FETCH = "10 minutes ago"


def get_now_timestamp() -> int:
    """Returns the current time as a unix timestamp (seconds). Wrapped for testability."""
    return int(time.time())


def arg_to_timestamp(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if datetime_obj := arg_to_datetime(value):
        return int(datetime_obj.timestamp())
    return None


def add_time_to_events(events: list[dict]) -> None:
    """Adds `_time` to each event, derived from `date_create` (epoch seconds, UTC)."""
    for event in events:
        if (date_create := event.get("date_create")) is not None:
            event["_time"] = timestamp_to_datestring(int(date_create) * 1000, is_utc=True)
        else:
            demisto.debug(f"Event {event.get('id')} has no date_create; '_time' not set.")


class Client(BaseClient):
    def get_logs(self, query_params: dict) -> tuple[dict, list, str | None]:
        demisto.debug(f"{query_params=}")
        raw_response = self._http_request(
            method="GET",
            url_suffix="logs",
            params=query_params,
            retries=3,
            status_list_to_retry=[429, 500, 502, 503, 504],
            backoff_factor=2,
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
        base_params["limit"] = Config.API_PAGE_SIZE
        if oldest is not None:
            base_params["oldest"] = oldest
        if latest is not None:
            base_params["latest"] = latest

        aggregated: list[dict] = []
        # `cursor` drives the loop: FIRST_PAGE means "no cursor yet", None means "no more pages".
        cursor: str | None = Config.FIRST_PAGE
        while cursor:
            query_params = dict(base_params)
            if cursor != Config.FIRST_PAGE:
                query_params["cursor"] = cursor
            try:
                _, events, cursor = self.get_logs(query_params)
            except DemistoException as e:
                # If the very first page fails we have nothing to keep -> re-raise so the caller
                # does NOT advance lastRun and the same window is retried next run (no data loss).
                if not aggregated:
                    raise
                # A later page failed after retries were exhausted (e.g. persistent 429): keep what
                # we already collected and stop paginating. The caller persists progress up to the
                # newest collected event and resumes next run. This is a partial-collection failure,
                # so it is logged at ERROR level to stay visible to operators.
                demisto.error(
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

    On the very first fetch, if no `oldest` is configured, the start falls back to
    Config.DEFAULT_FIRST_FETCH ("10 minutes ago", matching the YAML default) rather than
    exactly 'now', so events recorded around startup are not missed. An explicitly configured
    `oldest` always takes precedence.
    """
    window_start = last_run.get("last_fetched_time")
    if window_start is None:
        # DEFAULT_FIRST_FETCH is a fixed, always-parseable string, so this default is never None.
        default_first_fetch = cast(int, arg_to_timestamp(Config.DEFAULT_FIRST_FETCH))
        window_start = arg_to_timestamp(params.get("oldest")) or default_first_fetch
        demisto.debug(f"No last_fetched_time in last run; computed window start from first-fetch config: {window_start}")
    else:
        demisto.debug(f"Resuming from last_fetched_time; window start: {window_start}")
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
    filtered = [e for e in events if not (e.get("date_create") == boundary_time and e.get("id") in boundary_ids)]
    demisto.debug(
        f"Deduplication: filtered out {len(events) - len(filtered)} already-fetched events "
        f"at boundary_time={boundary_time}; {len(filtered)} new events remain."
    )
    return filtered


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
      speeds up the backfill, and avoids re-querying the trailing gap of the window.
      `last_fetched_ids` is set to the ids of any SENT events recorded exactly at `window_end`
      (Slack's `oldest`/`latest` bounds are inclusive), so those boundary events are deduped and
      not re-ingested when the next run re-queries starting at `window_end`.
    - drained the window and caught up (window_end reached 'now'): mark = the newest SENT
      event (we cannot safely advance past 'now'); `last_fetched_ids` dedups the boundary.
    - empty window while still backfilling: mark advances to `window_end` so the next run
      moves on and we never get stuck re-querying an empty window.

    When the newest sent event is at the SAME timestamp as the previous high-water mark, the
    new boundary ids are MERGED with the previous ones (not replaced) so events already sent at
    that timestamp on earlier runs are still deduped and never re-sent.
    """
    demisto.debug(
        f"Updating last run: sent_events={len(sent_events)}, window_end={window_end}, "
        f"reached_limit={reached_limit}, caught_up={caught_up}"
    )
    if sent_events and (reached_limit or caught_up):
        newest_time = sent_events[-1].get("date_create")
        ids_at_newest = [e.get("id") for e in sent_events if e.get("date_create") == newest_time]
        if newest_time == last_run.get("last_fetched_time"):
            # High-water mark didn't move -> merge with the ids we already remembered.
            ids_at_newest = list(set(last_run.get("last_fetched_ids") or []) | set(ids_at_newest))
        last_run["last_fetched_time"] = newest_time
        last_run["last_fetched_ids"] = ids_at_newest
        demisto.debug(f"Advanced last_fetched_time to newest sent event: {newest_time}")
    elif not caught_up and window_end > (last_run.get("last_fetched_time") or 0):
        # Drained (or empty) window still below 'now' -> jump straight to the window end.
        # `latest` is inclusive, so events recorded exactly at window_end were already sent in
        # this window; remember their ids so the next run (which re-queries from window_end,
        # inclusive) dedups them instead of re-ingesting duplicates.
        ids_at_window_end = [e.get("id") for e in sent_events if e.get("date_create") == window_end]
        last_run["last_fetched_time"] = window_end
        last_run["last_fetched_ids"] = ids_at_window_end
        demisto.debug(
            f"Drained window below 'now'; advanced last_fetched_time to window_end: {window_end} "
            f"(boundary ids kept for dedup: {ids_at_window_end})"
        )


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
    demisto.debug("test-module succeeded.")
    return "ok"


def fetch_slack_events(client: Client, params: dict, last_run: dict) -> list[dict]:
    """
    Core Slack event collection cycle, shared by both `fetch-events` and `slack-get-events`.

    Because Slack returns events newest-first, we fetch ALL events in a bounded,
    forward-moving time window, sort them oldest-first, and return the oldest events
    up to the user-defined limit. Any surplus (beyond the limit) is collected in the
    following runs, which resume from where we stopped and keep walking forward until
    the upper time bound is reached (steady state).

    The upper time bound of the walk is the `latest` value in `params` when supplied (used by the
    manual `slack-get-events` command to collect a fixed [oldest, latest] range), and the current
    time otherwise (used by the automated `fetch-events` collector).

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
    upper_bound = arg_to_timestamp(params.get("latest")) or get_now_timestamp()

    oldest_ts = arg_to_timestamp(params.get("oldest"))
    if oldest_ts is not None and oldest_ts > upper_bound:
        return_error("The 'oldest' argument must be earlier than or equal to the 'latest' argument.")

    demisto.debug(f"Starting Slack event collection cycle. limit={limit}, upper_bound={upper_bound}, last_run={last_run}")
    extra_params = {
        "action": params.get("action"),
        "actor": params.get("actor"),
        "entity": params.get("entity"),
    }

    # Walk forward through bounded windows within this single run, so a sparse backlog is
    # drained quickly instead of advancing only one window per fetch interval. We stop as
    # soon as we either reach the upper bound (caught up), fill the limit, or hit the per-run
    # window cap (which bounds the run's duration / number of API calls on very large backfills).
    window_start = compute_window_start(params, last_run, upper_bound)
    collected: list[dict] = []

    # `keep_walking` drives the loop: we always fetch at least the boundary window (even when
    # window_start == upper_bound, so events at that second are collected), then keep walking
    # forward window-by-window until we reach the upper bound, fill the limit, or hit the cap.
    keep_walking = True
    windows_walked = 0
    while keep_walking:
        window_end = min(window_start + Config.DEFAULT_MAX_FETCH_WINDOW, upper_bound)
        caught_up = window_end >= upper_bound
        demisto.debug(f"Fetch window: [{window_start}, {window_end}] (upper_bound={upper_bound}, limit={limit})")

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

        # The API returned zero events for this window: there is nothing more to collect right
        # now, so stop walking and let the next scheduled run resume from the advanced mark.
        window_returned_no_events = len(all_events) == 0

        # When caught up (window reached the upper bound) and there is nothing new, keep the state
        # as-is so no event recorded at the boundary can be skipped. Otherwise update normally.
        if not (caught_up and not events_to_send):
            update_last_run(last_run, events_to_send, window_end, reached_limit=have_enough, caught_up=caught_up)

        # Stop once we reached the upper bound, have a full batch, the window returned no events, or
        # reached the per-run window cap (hard upper bound); otherwise walk to the next window.
        # Any remaining windows are covered by the next run.
        hit_window_cap = windows_walked >= Config.MAX_WINDOWS_PER_RUN
        if hit_window_cap and not (have_enough or caught_up or window_returned_no_events):
            demisto.debug(f"Reached the per-run window cap ({Config.MAX_WINDOWS_PER_RUN}); resuming next run.")
        keep_walking = not (have_enough or caught_up or window_returned_no_events or hit_window_cap)
        window_start = window_end

    events_to_send = sort_events_oldest_first(collected)[:limit]
    add_time_to_events(events_to_send)
    demisto.debug(f"Collected {len(events_to_send)} events across the run.")
    return events_to_send


def get_events_command(client: Client, args: dict) -> tuple[list, CommandResults]:
    """
    Manual `slack-get-events` command.

    Runs the same collection cycle as the automated `fetch-events` collector (forward-moving
    window, oldest-first, deduped, limited to the `limit` argument), driven purely by the
    command arguments: `oldest` sets the window start and `latest` sets the upper bound of the
    range to collect. It uses a fresh, empty run state, so the command is independent of the
    collector's persisted state and has no side effects on it.

    Args:
        client (Client): the client implementing the API to Slack.
        args (dict): the command arguments.

    Returns:
        (list) the events retrieved (oldest-first, up to the limit).
        (CommandResults) the CommandResults object holding the collected logs information.
    """
    # Drive the cycle purely from the command arguments with a fresh run state, keeping the
    # command independent of the collector's persisted state and free of side effects on it.
    run_state: dict = {}
    demisto.debug("slack-get-events invoked; running an argument-driven collection cycle with a fresh run state.")
    events = fetch_slack_events(client, args, run_state)
    demisto.debug(f"slack-get-events retrieved {len(events)} events.")
    results = CommandResults(
        readable_output=tableToMarkdown(
            "Slack Audit Logs",
            events,
            date_fields=["date_create"],
        ),
        outputs_prefix="Slack.AuditLogs",
        outputs_key_field="id",
        outputs=events,
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

    except Exception as error:
        error_msg = f"Failed to execute {command}. Error: {error!s}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

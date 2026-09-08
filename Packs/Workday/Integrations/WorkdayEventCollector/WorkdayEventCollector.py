import math

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

# BUILD_MARKER: bump this string on every hotfix build so the exact deployed version can be
# identified from the tenant integration logs (search for "WORKDAY_EC_BUILD" in GCP Logs Explorer).
# This is what lets us confirm the fix is actually running on the client tenant after upload.
BUILD_MARKER = "WORKDAY_EC_BUILD=XSUP-75678-fix-todate-lag-60s"

# XSUP-75678 FIX: never query up to "now". Workday publishes a minute's events with a short lag
# (measured via the freshness-lag audit: counts settle within ~30s of a minute closing). Querying
# to_date=now therefore captured an incomplete tail of the newest minute, and the monotonic cursor
# then advanced past the not-yet-published events -> permanent loss. We cap to_date at now - this many
# seconds so every queried range is already fully settled. Clamped to never be earlier than from_date.
FETCH_TO_DATE_LAG_SECONDS = 60

# Freshness-lag audit (read-only diagnostic for XSUP-75678). The real fetch queries up to `to_date=now`,
# but Workday publishes an event minute's tail with a short lag, so the freshest events are not yet
# returned when we read them; the checkpoint then advances past them and they are lost permanently.
# The previous audit only observed each minute at 90s+ (already published) so it saw grew_by=0 and
# MISSED the loss. This audit instead re-counts the SAME fixed minute at several YOUNG ages spanning
# the freshness zone (AUDIT_PROBE_AGES_SECONDS). The count growing from the youngest age to the oldest
# is direct proof of Workday's publishing lag AND measures its magnitude (to size the fix's safety lag).
# Note: this measures the pure Workday API lag with NO XSIAM pipeline involvement (unlike _insert_time).
# The audit only COUNTS events via the API - it never ingests them - so it cannot cause duplication or loss.
AUDIT_LOG_TAG = "WORKDAY_FRESHNESS_LAG_AUDIT"
# Tag for the dedup-value proof: quantifies, each cycle, the duplicates the identity-based fix
# prevented from being re-ingested, and the boundary-second events it KEPT that the OLD
# position-based code would have silently dropped. Greppable in tenant logs to show the fix's value.
DEDUP_VALUE_LOG_TAG = "WORKDAY_DEDUP_VALUE"
# Tag for the capture-gap proof (Problem B consequence): each cycle, once a recently-fetched minute
# has settled (past the publishing lag), we re-count via the API how many events that minute REALLY
# has, and compare to how many the real fetch actually captured for it. A positive gap is the live,
# per-cycle version of the dataset shortfall - direct proof that to_date=now skips freshly-published
# events. Read-only: it only COUNTS via the API and never ingests, so it cannot cause loss/duplication.
CAPTURE_GAP_LOG_TAG = "WORKDAY_CAPTURE_GAP"
# A minute is considered "settled" (publishing lag elapsed) this many seconds after it closes; the
# capture-gap probe compares captured-vs-available only once a minute is at least this old.
CAPTURE_GAP_SETTLE_SECONDS = 300
# Ages (seconds after a minute closes) at which the audit re-counts the SAME minute to build a
# publishing-lag curve. The youngest age (~10s) mirrors where the real fetch reads (to_date=now);
# the oldest (~300s) is well past the lag so it represents the "complete" count. One read-only,
# non-paginated API call is made per cycle (for whichever probe age is due), so at most one extra call.
AUDIT_PROBE_AGES_SECONDS = (10, 30, 60, 120, 300)

DEFAULT_MAX_FETCH = 3000
MAX_PAGE_SIZE = 1000
VENDOR = "Workday"
PRODUCT = "Activity"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
# Millisecond-precision format used for the persisted checkpoint. Workday's `from`/`to` query
# params only accept whole seconds (see get_activity_logging_request), so we keep DATE_FORMAT for
# the request, but we persist the checkpoint with milliseconds to dedup precisely and avoid loss.
DATE_FORMAT_WITH_MS = "%Y-%m-%dT%H:%M:%S.%fZ"
# Fields that together uniquely identify a single Workday activity logging event. Used to build a
# stable identity for deduplication that does NOT depend on API result ordering (unlike the previous
# position-based approach, which silently dropped new events that sorted before the stored checkpoint).
EVENT_IDENTITY_FIELDS = ("taskId", "requestTime", "sessionId", "systemAccount", "activityAction", "ipAddress")

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls to the Saas Security platform, and does not contain any XSOAR logic.
    Handles the token retrieval.

    :param base_url (str): Workday server url.
    :param client_id (str): Workday client id.
    :param client_secret (str): Workday client_secret.
    :param token_url (str): Workday token url.
    :param refresh_token (str): Workday refresh token.
    :param verify (bool): specifies whether to verify the SSL certificate or not.
    :param proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url, token_url, verify, proxy, headers, client_id, client_secret, refresh_token, max_fetch):
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers)
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.token_url = token_url
        self.max_fetch = max_fetch
        self.access_token = self.get_access_token()

    def get_access_token(self):  # pragma: no cover
        """
        Getting access token from Workday API.
        """
        demisto.debug("Fetching access token from Workday API.")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"grant_type": "refresh_token", "refresh_token": self.refresh_token}

        workday_resp_token = self._http_request(
            method="POST", full_url=self.token_url, headers=headers, data=data, auth=(self.client_id, self.client_secret)
        )
        if workday_resp_token:
            return workday_resp_token.get("access_token")
        return None

    def http_request(
        self, method: str, url_suffix: str = "", params: dict = None, json_data: dict = None, retries: int = 0
    ) -> dict:  # pragma: no cover
        """
        Overriding BaseClient http request in order to use the access token.
        """
        headers = self._headers
        headers["Authorization"] = f"Bearer {self.access_token}"
        return self._http_request(
            method=method, url_suffix=url_suffix, params=params, json_data=json_data, headers=headers, retries=retries
        )

    def get_activity_logging_request(
        self,
        from_date: str,
        to_date: str,
        offset: Optional[int] = 0,
        user_activity_entry_count: bool = False,
        limit: Optional[int] = 1000,
    ) -> list:
        """Returns a simple python dict with the information provided
        Args:
            offset: The zero-based index of the first object in a response collection.
            limit: The maximum number of loggings to return.
            to_date: date to fetch events from.
            from_date: date to fetch events to.
            user_activity_entry_count: If true, returns only the total count of user activity instances for the params.

        Returns:
            activity loggings returned from Workday API.
        """
        instance_returned = math.ceil(self.max_fetch / 10000)
        params = {
            "from": from_date,
            "to": to_date,
            "limit": limit,
            "instancesReturned": instance_returned,
            "offset": offset,
            "returnUserActivityEntryCount": user_activity_entry_count,
            "type": "userActivity",
        }
        demisto.debug(f"params sent to Workday API are {params!s}")
        res = self.http_request(method="GET", url_suffix="/activityLogging", params=params, retries=3)
        return res.get("data", [])


""" HELPER FUNCTIONS """


def resolve_max_fetch(params: dict) -> int:
    """
    Resolves the max_fetch value from the integration params, falling back to DEFAULT_MAX_FETCH
    when the parameter is missing, empty, or evaluates to a falsy value.

    Args:
        params: The integration parameters.

    Returns:
        The resolved max_fetch value.
    """
    return arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH


def get_max_fetch_activity_logging(client: Client, logging_to_fetch: int, from_date: str, to_date: str):
    """
    Fetches up to logging_to_fetch activity logging avaiable from Workday.
    Args:
        client: Client object.
        logging_to_fetch: limit of logging to fetch from Workday.
        from_date: loggings from time.
        to_date: loggings to time.

    Returns:
        Activity loggings fetched from Workday.
    """
    activity_loggings: list = []
    offset = 0
    while logging_to_fetch > 0:
        limit = min(MAX_PAGE_SIZE, logging_to_fetch)
        res = client.get_activity_logging_request(from_date=from_date, to_date=to_date, offset=offset, limit=limit)
        demisto.debug(f"Fetched {len(res)} activity loggings.")
        activity_loggings.extend(res)
        offset += len(res)
        logging_to_fetch -= len(res)
        if not res:
            break
        demisto.debug(f"{logging_to_fetch} loggings left to fetch.")
    demisto.debug(f"Found {len(activity_loggings)} activity loggings.")
    return activity_loggings


def count_activity_logging_for_window(client: Client, from_date: str, to_date: str) -> tuple[int, bool]:
    """
    Read-only helper for the late-arrival audit: counts (without ingesting) how many activity
    loggings the Workday API returns *right now* for a given [from_date, to_date) window.

    To strictly bound API cost, this performs EXACTLY ONE non-paginated request (limit=MAX_PAGE_SIZE),
    regardless of how many events the window contains. For the audited 1-minute windows this is
    effectively always the full count. If a minute ever exceeds MAX_PAGE_SIZE events, the count is
    reported as MAX_PAGE_SIZE with capped=True (still sufficient to demonstrate a growing count).

    Args:
        client: Client object.
        from_date: window start (whole-second string).
        to_date: window end (whole-second string).

    Returns:
        (count, capped) - capped is True if the window may contain more than MAX_PAGE_SIZE events.
    """
    page = client.get_activity_logging_request(from_date=from_date, to_date=to_date, offset=0, limit=MAX_PAGE_SIZE)
    count = len(page)
    capped = count >= MAX_PAGE_SIZE
    return count, capped


def _elapsed_minute_window(now: datetime, delay_seconds: int) -> tuple[str, str]:
    """Returns the (from, to) whole-second strings for the 1-minute window that ended `delay_seconds`
    ago, floored to whole minutes."""
    end_dt = (now - timedelta(seconds=delay_seconds)).replace(second=0, microsecond=0)
    start_dt = end_dt - timedelta(minutes=1)
    return start_dt.strftime(DATE_FORMAT), end_dt.strftime(DATE_FORMAT)


def run_late_arrival_audit(client: Client, last_run: dict) -> dict:
    """
    Freshness-lag diagnostic for XSUP-75678 (read-only; ingests nothing).

    The real fetch reads up to `to_date=now`, but Workday publishes an event minute's tail with a
    short lag, so the freshest events are not yet returned at read time and are then skipped forever
    once the checkpoint advances. To measure that lag directly, this re-counts the SAME fixed minute
    at several increasing YOUNG ages (AUDIT_PROBE_AGES_SECONDS). Each cycle it issues at most ONE
    read-only, non-paginated API call for whichever probe age is currently due for the target minute,
    recording the count into `audit_history[minute][age]`. When the oldest probe age is reached, it
    logs the full lag curve and the growth from the youngest age to the oldest.

      growth = count(oldest_age) - count(youngest_age)

    A positive growth is direct proof of Workday's publishing lag (the cause of the residual gap),
    and its magnitude tells us how large a safety lag the fix must apply. This is the pure Workday API
    lag with NO XSIAM pipeline involvement (unlike _insert_time, which also includes pipeline delay).

    Args:
        client: Client object.
        last_run: the last run object (never mutated; a copy is returned via the caller).

    Returns:
        The updated audit_history dict to persist in last_run. Shape:
        { "<minute_from_str>": { "<age_seconds_str>": count, ... }, ... }
    """
    audit_history: dict = {minute: dict(ages) for minute, ages in last_run.get("audit_history", {}).items()}
    now = datetime.now(tz=timezone.utc)
    youngest_age = AUDIT_PROBE_AGES_SECONDS[0]
    oldest_age = AUDIT_PROBE_AGES_SECONDS[-1]

    # Each probe age targets the minute that closed `age` seconds ago (a DIFFERENT minute per age).
    # We measure every age whose target minute hasn't been measured yet this cycle, so each fixed
    # minute accumulates all its age-samples over successive cycles and its curve reliably completes.
    # At most len(AUDIT_PROBE_AGES_SECONDS) small non-paginated read-only calls per cycle (typically
    # far fewer, since most ages are already recorded), and never any ingestion.
    for age in AUDIT_PROBE_AGES_SECONDS:
        probe_from, probe_to = _elapsed_minute_window(now, age)
        minute_ages = audit_history.setdefault(probe_from, {})
        age_key = str(age)
        if age_key in minute_ages:
            continue  # already measured this minute at this age
        try:
            count, capped = count_activity_logging_for_window(client, from_date=probe_from, to_date=probe_to)
            minute_ages[age_key] = count
            demisto.info(
                f"{AUDIT_LOG_TAG} phase=probe window=[{probe_from},{probe_to}) "
                f"age_seconds={age} api_count={count}{' (capped)' if capped else ''}"
            )
            # When we have just taken the OLDEST-age measurement, emit the full lag curve + growth.
            if age == oldest_age and str(youngest_age) in minute_ages:
                curve = {a: minute_ages[a] for a in (str(x) for x in AUDIT_PROBE_AGES_SECONDS) if a in minute_ages}
                young_count = minute_ages[str(youngest_age)]
                old_count = minute_ages[str(oldest_age)]
                grew_by = old_count - young_count
                pct = (100.0 * grew_by / old_count) if old_count else 0.0
                demisto.info(
                    f"{AUDIT_LOG_TAG} phase=curve window=[{probe_from},{probe_to}) "
                    f"lag_curve={curve} young_age={youngest_age}s young_count={young_count} "
                    f"old_age={oldest_age}s old_count={old_count} grew_by={grew_by} "
                    f"late_publish_pct={pct:.1f} PUBLISH_LAG_DETECTED={grew_by > 0}"
                )
        except Exception as e:  # never let the diagnostic break the fetch
            demisto.debug(f"{AUDIT_LOG_TAG} probe query failed (non-fatal) age={age}: {e!s}")

    # Prune audit_history: keep only minutes still within the oldest probe age + 30 min buffer.
    cutoff, _ = _elapsed_minute_window(now, oldest_age + 1800)
    audit_history = {k: v for k, v in audit_history.items() if k >= cutoff}
    return audit_history


def run_capture_gap_probe(client: Client, last_run: dict, captured_per_minute: dict) -> dict:
    """
    Capture-gap proof for XSUP-75678 Problem B (read-only; ingests nothing).

    For a minute that has now SETTLED (closed at least CAPTURE_GAP_SETTLE_SECONDS ago, so Workday has
    finished publishing it), this re-counts via the API how many events that minute REALLY has, and
    compares it to how many the real scheduled fetch actually CAPTURED for that same minute. A
    positive gap = events that were available from the API but never ingested, i.e. the live,
    per-cycle version of the dataset shortfall. This makes Problem B's consequence explicit in logs.

    Read-only: performs at most ONE non-paginated API count per cycle and never ingests anything.

    Args:
        client: Client object.
        last_run: last run (never mutated here).
        captured_per_minute: {minute_from_str: captured_count} the real fetch has ingested so far.

    Returns:
        The captured_per_minute map with settled+reported minutes pruned out.
    """
    captured = dict(captured_per_minute)
    now = datetime.now(tz=timezone.utc)
    settled_from, settled_to = _elapsed_minute_window(now, CAPTURE_GAP_SETTLE_SECONDS)
    captured_count = captured.get(settled_from)
    if captured_count is not None:
        try:
            api_count, capped = count_activity_logging_for_window(client, from_date=settled_from, to_date=settled_to)
            gap = api_count - captured_count
            pct = (100.0 * gap / api_count) if api_count else 0.0
            demisto.info(
                f"{CAPTURE_GAP_LOG_TAG} window=[{settled_from},{settled_to}) "
                f"captured_by_fetch={captured_count} api_has_now={api_count}{' (capped)' if capped else ''} "
                f"missing={gap} missing_pct={pct:.1f} settle_seconds={CAPTURE_GAP_SETTLE_SECONDS} "
                f"CAPTURE_GAP_DETECTED={gap > 0}"
            )
            # This minute has been reported; drop it so the map stays small.
            captured.pop(settled_from, None)
        except Exception as e:  # never let the diagnostic break the fetch
            demisto.debug(f"{CAPTURE_GAP_LOG_TAG} probe query failed (non-fatal): {e!s}")

    # Prune any minutes older than the settle window (already reported or missed) to keep last_run small.
    cutoff, _ = _elapsed_minute_window(now, CAPTURE_GAP_SETTLE_SECONDS + 600)
    captured = {k: v for k, v in captured.items() if k >= cutoff}
    return captured


def accumulate_captured_per_minute(events_to_ingest: list, previous_captured: dict) -> dict:
    """
    Adds the events ingested this cycle into a per-minute captured-count map (keyed by the whole-minute
    `from` string of each event's requestTime), used by run_capture_gap_probe to compare captured vs
    available. Purely additive bookkeeping - does not affect ingestion.
    """
    captured = dict(previous_captured)
    for logging in events_to_ingest:
        request_time = str(logging.get("requestTime", ""))
        if len(request_time) < 16:
            continue
        minute_from = request_time[:16] + ":00Z"  # e.g. "2026-08-31T07:29:00Z"
        captured[minute_from] = captured.get(minute_from, 0) + 1
    return captured


def get_event_identity(activity_logging: dict) -> str:
    """
    Builds a stable, order-independent identity for a single activity logging event.

    This is the key to correct deduplication: instead of relying on the *position* of a
    previously-seen event in the new result set (which silently dropped new events that sorted
    before the checkpoint), we identify each event by its own content. Only events whose identity
    was already ingested in the previous cycle are treated as duplicates.

    Args:
        activity_logging: a single activity logging event returned by the Workday API.

    Returns:
        A string uniquely identifying the event.
    """
    return "|".join(str(activity_logging.get(field, "")) for field in EVENT_IDENTITY_FIELDS)


def remove_duplications(activity_loggings: list, last_run: dict) -> list:
    """
    Removes activity loggings that were already ingested in the previous fetch cycle.

    Because the checkpoint (`from_date`) is truncated to whole seconds for the Workday request, the
    boundary second is intentionally re-requested every cycle. Previously this function trimmed the
    *head* of the batch by the index of the stored `last_log`, assuming everything before it was a
    duplicate. When the API returned events of the boundary second in a different order (or returned
    a new event that sorts before the stored `last_log`), those new events were silently dropped
    (XSUP-75678). It could also re-ingest the whole second as duplicates when the exact object was
    not re-found.

    This implementation deduplicates by *event identity*: any event whose identity was seen in the
    previous cycle is dropped; every other event (including new events in the boundary second) is
    kept, regardless of API ordering.

    Args:
        activity_loggings: activity loggings fetched from Workday.
        last_run: Last run object. May contain `previous_event_ids` (identities ingested last cycle).

    Returns:
        The activity loggings with previously-ingested events removed.
    """
    demisto.debug("Started removing duplications (identity-based).")
    previous_event_ids = set(last_run.get("previous_event_ids", []))
    if not previous_event_ids:
        demisto.debug("No previous_event_ids in last_run, returning everything.")
        demisto.info(
            f"{DEDUP_VALUE_LOG_TAG} received={len(activity_loggings)} duplicates_prevented=0 "
            f"kept={len(activity_loggings)} would_have_been_dropped_by_old_code=0 (first cycle / no checkpoint)"
        )
        return activity_loggings

    deduped = [logging for logging in activity_loggings if get_event_identity(logging) not in previous_event_ids]
    removed = len(activity_loggings) - len(deduped)
    demisto.debug(
        f"Identity-based dedup: received {len(activity_loggings)} loggings, "
        f"removed {removed} already-ingested duplicates, keeping {len(deduped)}."
    )

    # ---- Proof of the previous fix's value (logged, does not change behavior) --------------------
    # 1) duplicates_prevented: real duplicates the OLD code often FAILED to detect (exact-dict match),
    #    which would have been RE-INGESTED into the dataset. The new identity dedup removes them.
    # 2) would_have_been_dropped_by_old_code: KEPT (non-duplicate) events whose requestTime sorts
    #    BEFORE the previous checkpoint. The OLD position-based code trimmed everything before the
    #    stored last_log's position, so these brand-new events would have been SILENTLY LOST.
    previous_checkpoint = last_run.get("latest_request_time", "")
    would_have_been_dropped = 0
    if previous_checkpoint:
        would_have_been_dropped = sum(1 for logging in deduped if str(logging.get("requestTime", "")) < previous_checkpoint)
    demisto.info(
        f"{DEDUP_VALUE_LOG_TAG} received={len(activity_loggings)} duplicates_prevented={removed} "
        f"kept={len(deduped)} would_have_been_dropped_by_old_code={would_have_been_dropped} "
        f"previous_checkpoint={previous_checkpoint or 'n/a'} "
        f"OLD_CODE_WOULD_HAVE_MISHANDLED={removed + would_have_been_dropped}"
    )
    # ---------------------------------------------------------------------------------------------
    return deduped


def remove_milliseconds_from_time_of_logging(activity_logging: dict) -> str:
    """
    Converts a logging's requestTime to the whole-second format Workday's `from`/`to` params accept.

    Note: Workday's query params only accept whole seconds, so this is used ONLY when building the
    request. The persisted checkpoint keeps milliseconds (see get_checkpoint_time_with_ms).

    Args:
        activity_logging: activity logging

    Returns:
        The requestTime string truncated to whole seconds (DATE_FORMAT).
    """
    demisto.debug("Changing timestamp of loggings to match whole-second date format.")
    request_time_date_obj = datetime.strptime(activity_logging.get("requestTime"), DATE_FORMAT_WITH_MS)  # type: ignore
    # replace() returns a NEW datetime; must reassign (the previous code discarded the result).
    request_time_date_obj = request_time_date_obj.replace(microsecond=0)
    return datetime.strftime(request_time_date_obj, DATE_FORMAT)


""" COMMAND FUNCTIONS """


def get_activity_logging_command(
    client: Client, from_date: str, to_date: str, limit: Optional[int], offset: Optional[int]
) -> tuple[list, CommandResults]:
    """

    Args:
        offset: The zero-based index of the first object in a response collection.
        limit: The maximum number of loggings to return.
        to_date: date to fetch events from.
        from_date: date to fetch events to.
        client: Client object.

    Returns:
        Activity loggings from Workday.
    """

    activity_loggings = client.get_activity_logging_request(to_date=to_date, from_date=from_date, limit=limit, offset=offset)
    readable_output = tableToMarkdown(
        "Activity Logging List:",
        activity_loggings,
        removeNull=True,
        headerTransform=lambda x: string_to_table_header(camel_case_to_underscore(x)),
    )

    return activity_loggings, CommandResults(readable_output=readable_output)


def build_next_last_run(activity_loggings: list, previous_last_run: dict) -> dict:
    """
    Builds the next last_run object after deduplication.

    The next `last_fetch_time` (used to build the next Workday request) is the whole-second floor of
    the latest event's requestTime, because Workday's `from` param only accepts whole seconds. To
    avoid losing or re-ingesting events in that re-requested boundary second, we also persist
    `previous_event_ids`: the identities of every event we ingested whose requestTime falls in the
    latest whole second. On the next cycle, remove_duplications uses this set to drop only genuine
    duplicates while keeping any newly-arrived events in that same second.

    Args:
        activity_loggings: the deduped events ingested this cycle.
        previous_last_run: the last_run from the current cycle (used as a fallback when empty).

    Returns:
        The next last_run dict.
    """
    if not activity_loggings:
        demisto.debug("No new activity loggings this cycle, preserving previous last_run.")
        return previous_last_run

    # Determine the latest requestTime across the ingested events (do NOT assume API ordering).
    latest_logging = max(activity_loggings, key=lambda logging: logging.get("requestTime", ""))
    latest_request_time = latest_logging.get("requestTime", "")
    # Whole-second checkpoint for the next request (Workday `from` accepts whole seconds only).
    next_from_date = remove_milliseconds_from_time_of_logging(latest_logging)
    # The whole-second prefix (e.g. "2026-08-18T07:29:33") that will be re-requested next cycle.
    latest_second_prefix = latest_request_time[:19]

    # Persist identities of every ingested event in that boundary second so the next cycle can
    # filter genuine duplicates by identity (order-independent) instead of by position.
    previous_event_ids = [
        get_event_identity(logging)
        for logging in activity_loggings
        if str(logging.get("requestTime", ""))[:19] == latest_second_prefix
    ]
    demisto.debug(
        f"Next checkpoint: last_fetch_time={next_from_date}, latest_request_time={latest_request_time}, "
        f"tracking {len(previous_event_ids)} event id(s) in boundary second {latest_second_prefix} for dedup."
    )
    return {
        "last_fetch_time": next_from_date,
        "last_log": latest_logging,  # kept for backward compatibility / observability
        "latest_request_time": latest_request_time,
        "previous_event_ids": previous_event_ids,
    }


def fetch_activity_logging(client: Client, max_fetch: int, first_fetch: datetime, last_run: dict):
    """
    Fetches activity loggings from Workday.
    Args:
        first_fetch: first fetch date.
        client: Client object.
        max_fetch: max loggings to fetch set by customer.
        last_run: last run object.

    Returns:
        Activity loggings from Workday.

    """
    demisto.debug(f"{BUILD_MARKER} | fetch_activity_logging started.")
    from_date = last_run.get("last_fetch_time", first_fetch.strftime(DATE_FORMAT))
    # XSUP-75678 FIX: never query up to "now" - cap to_date at (now - FETCH_TO_DATE_LAG_SECONDS) so we
    # only ever request minutes Workday has already fully published (freshness audit shows counts settle
    # within ~30s). Clamp so to_date is never earlier than from_date (e.g. after a long outage/backfill,
    # where from_date is already older than the lagged now - in that case we still fetch up to now-lag,
    # but never invert the window).
    now = datetime.now(tz=timezone.utc)
    safe_to_dt = now - timedelta(seconds=FETCH_TO_DATE_LAG_SECONDS)
    from_dt = datetime.strptime(from_date, DATE_FORMAT).replace(tzinfo=timezone.utc)
    # If the lagged "now" would precede from_date (from_date is very recent), fall back to from_date so
    # the window is non-inverted; the next cycle will advance once enough time has elapsed.
    to_dt = safe_to_dt if safe_to_dt >= from_dt else from_dt
    to_date = to_dt.strftime(DATE_FORMAT)
    demisto.debug(
        f"Getting activity loggings {from_date=}, {to_date=} (to_date lagged by "
        f"{FETCH_TO_DATE_LAG_SECONDS}s from now={now.strftime(DATE_FORMAT)}). "
        f"Carrying {len(last_run.get('previous_event_ids', []))} previous event id(s) for dedup."
    )
    activity_loggings = get_max_fetch_activity_logging(
        client=client, logging_to_fetch=max_fetch, from_date=from_date, to_date=to_date
    )
    demisto.debug(f"Fetched {len(activity_loggings)} activity loggings from Workday before dedup.")

    activity_loggings = remove_duplications(activity_loggings=activity_loggings, last_run=last_run)
    demisto.debug(f"{len(activity_loggings)} activity loggings remain after dedup and will be sent to XSIAM.")

    # The list of events to ingest is now FINAL. Nothing below is allowed to modify it.
    events_to_ingest = activity_loggings

    next_last_run = build_next_last_run(events_to_ingest, last_run)

    # ---- Read-only diagnostics (XSUP-75678 dual proof) ------------------------------------------
    # SAFETY GUARANTEES (both probes):
    #   * They do NOT touch `events_to_ingest` (the only list ever sent to XSIAM) -> no duplicates.
    #   * They do NOT touch fetch checkpoint keys (last_fetch_time/previous_event_ids) -> no loss.
    #   * They only perform extra READ counts and add isolated keys (audit_history/captured_per_minute).
    #   * Any failure is swallowed -> cannot break the fetch.
    #
    # Problem A (boundary-second dedup) is proven live by the WORKDAY_DEDUP_VALUE log in
    # remove_duplications. Problem B (freshness/publishing lag) is proven two ways here:
    #   1) run_late_arrival_audit -> WORKDAY_FRESHNESS_LAG_AUDIT lag curve (API count grows with age).
    #   2) run_capture_gap_probe -> WORKDAY_CAPTURE_GAP (what the fetch captured vs what the API has
    #      once the minute settled) = the live per-cycle version of the dataset shortfall.
    try:
        next_last_run["audit_history"] = run_late_arrival_audit(client=client, last_run=last_run)
    except Exception as e:  # extra belt-and-suspenders; never affect ingestion
        demisto.debug(f"{AUDIT_LOG_TAG} skipped due to non-fatal error: {e!s}")

    try:
        captured = accumulate_captured_per_minute(events_to_ingest, last_run.get("captured_per_minute", {}))
        next_last_run["captured_per_minute"] = run_capture_gap_probe(
            client=client, last_run=last_run, captured_per_minute=captured
        )
    except Exception as e:  # extra belt-and-suspenders; never affect ingestion
        demisto.debug(f"{CAPTURE_GAP_LOG_TAG} skipped due to non-fatal error: {e!s}")
        next_last_run["captured_per_minute"] = last_run.get("captured_per_minute", {})
    # ---------------------------------------------------------------------------------------------

    return events_to_ingest, next_last_run


def test_module(client: Client) -> str:  # pragma: no cover
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    client.get_access_token()
    return "ok"


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions"""
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()

    base_url = params.get("base_url")
    token_url = params.get("token_url")
    client_id = params.get("credentials", {}).get("identifier")
    client_secret = params.get("credentials", {}).get("password")
    token = params.get("token", {}).get("password")

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_fetch = resolve_max_fetch(params)
    first_fetch = arg_to_datetime(arg=params.get("first_fetch", "3 days"), arg_name="First fetch time", required=True)

    demisto.debug(f"{BUILD_MARKER} | Command being called is {command}")
    try:
        client = Client(
            base_url=base_url,
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=token,
            verify=verify_certificate,
            proxy=proxy,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            max_fetch=max_fetch,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "workday-get-activity-logging":
            should_push_events = argToBoolean(args.get("should_push_events", "false"))
            activity_loggings, results = get_activity_logging_command(
                client=client,
                from_date=args.get("from_date"),
                to_date=args.get("to_date"),
                limit=arg_to_number(args.get("limit")),
                offset=arg_to_number(args.get("offset")),
            )
            return_results(results)
            if should_push_events:
                send_events_to_xsiam(activity_loggings, vendor=VENDOR, product=PRODUCT)
        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            activity_loggings, new_last_run = fetch_activity_logging(
                client=client,
                max_fetch=max_fetch,
                first_fetch=first_fetch,  # type: ignore
                last_run=last_run,
            )
            send_events_to_xsiam(activity_loggings, vendor=VENDOR, product=PRODUCT)
            if new_last_run:
                # saves next_run for the time fetch-events is invoked
                demisto.info(f"Setting new last_run to {new_last_run}")
                demisto.setLastRun(new_last_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

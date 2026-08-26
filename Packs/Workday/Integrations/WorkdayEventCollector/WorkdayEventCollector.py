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
BUILD_MARKER = "WORKDAY_EC_BUILD=XSUP-75678-dedup-fix-1"

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
        return activity_loggings

    deduped = [logging for logging in activity_loggings if get_event_identity(logging) not in previous_event_ids]
    removed = len(activity_loggings) - len(deduped)
    demisto.debug(
        f"Identity-based dedup: received {len(activity_loggings)} loggings, "
        f"removed {removed} already-ingested duplicates, keeping {len(deduped)}."
    )
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
    to_date = datetime.now(tz=timezone.utc).strftime(DATE_FORMAT)
    demisto.debug(
        f"Getting activity loggings {from_date=}, {to_date=}. "
        f"Carrying {len(last_run.get('previous_event_ids', []))} previous event id(s) for dedup."
    )
    activity_loggings = get_max_fetch_activity_logging(
        client=client, logging_to_fetch=max_fetch, from_date=from_date, to_date=to_date
    )
    demisto.debug(f"Fetched {len(activity_loggings)} activity loggings from Workday before dedup.")

    activity_loggings = remove_duplications(activity_loggings=activity_loggings, last_run=last_run)
    demisto.debug(f"{len(activity_loggings)} activity loggings remain after dedup and will be sent to XSIAM.")

    next_last_run = build_next_last_run(activity_loggings, last_run)

    return activity_loggings, next_last_run


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

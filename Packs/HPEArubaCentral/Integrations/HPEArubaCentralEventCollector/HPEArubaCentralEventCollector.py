import demistomock as demisto
from CommonServerPython import *
import urllib3
from datetime import timedelta

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "aruba"
PRODUCT = "central"
RATE_LIMIT_STATUS_CODE = 429
NUM_OF_RETRIES = 3
BACKOFF_FACTOR = 5  # Sleep for: {backoff_factor} * (2 ** ({number of retries} - 1)) seconds between retries.
MAX_GET_AUDIT_LIMIT = 100  # Maximum limit accepted by get audit events API
MAX_AUDIT_API_REQS = 10
MAX_GET_EVENTS_LIMIT = 1000  # Maximum limit accepted by get events API
MAX_EVENT_API_REQS = 5
AUDIT_TS = "ts"
NETWORKING_TS = "timestamp"
MASK_EDGE_LEN = 6  # Chars kept from each end when masking a secret for debug logs.


""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client class to interact with the Aruba Central API
    """

    def __init__(
        self,
        base_url,
        client_id,
        client_secret,
        user_name,
        user_password,
        customer_id,
        downloaded_token="",
        verify=True,
        proxy=False,
    ):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret
        self.user_name = user_name
        self.user_password = user_password
        self.customer_id = customer_id
        # Full Access Token JSON bundle from the Aruba Central UI. Used only to seed the context on
        # the first run; afterwards the rotating refresh token stored in the context is used.
        self.downloaded_token = downloaded_token

    @staticmethod
    def parse_download_token(downloaded_token: str) -> tuple[str, str, int]:
        """
        Parses the "Access Token" JSON bundle pasted from the Aruba Central UI.

        The expected value is the full JSON bundle downloaded from the UI, e.g.:
            {"access_token": "...", "refresh_token": "...", "expires_in": 7200, ...}

        Args:
            downloaded_token (str): The raw value from the Access Token parameter.

        Returns:
            tuple[str, str, int]: (refresh_token, access_token, expires_in) extracted from the bundle.

        Raises:
            DemistoException: If the value is empty, not valid JSON, or missing required fields.
        """
        raw = (downloaded_token or "").strip()
        if not raw:
            return "", "", 0

        try:
            bundle = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as e:
            raise DemistoException(
                "The Access Token is not valid JSON. In the Aruba Central UI, click the 'Download Token' "
                "button and paste the full token JSON."
            ) from e

        if not isinstance(bundle, dict) or not bundle.get("refresh_token"):
            raise DemistoException(
                "The Access Token JSON is missing the required 'refresh_token' field. In the Aruba Central UI, "
                "click the 'Download Token' button and paste the full token JSON."
            )

        refresh_token = bundle["refresh_token"]
        access_token = bundle.get("access_token", "")
        expires_in = arg_to_number(bundle.get("expires_in")) or 0
        return refresh_token, access_token, expires_in

    def get_access_token(self, use_cached_token=True) -> str:
        """
        Returns a valid access token for the Aruba Central API.

        Resolution order: a non-expired cached token, then a refresh using the stored refresh token,
        then (only for Username/Password auth) a full OAuth sequence. On the first run, the context is
        seeded from the pasted Access Token so refresh works without a username/password.

        Args:
            use_cached_token (bool): If False, skip the cache and force a refresh / new token.

        Returns:
            str: A valid access token.
        """
        integration_context = get_integration_context()
        access_token = integration_context.get("access_token")
        expiry_time = integration_context.get("expiry_time", 0)
        refresh_token = integration_context.get("refresh_token")

        now = int(time.time())
        demisto.debug(
            f"get_access_token: use_cached_token={use_cached_token}, has_cached_access_token={bool(access_token)}, "
            f"has_refresh_token={bool(refresh_token)}, seconds_until_expiry={expiry_time - now}, "
            f"has_downloaded_token={bool(self.downloaded_token)}, has_user_pass={bool(self.user_name and self.user_password)}"
        )

        # First run (or a newly pasted bundle): seed the context so we can refresh without user/password.
        if self.downloaded_token and integration_context.get("seeded_token") != self.downloaded_token:
            seeded_refresh_token, seeded_access_token, seeded_expires_in = self.parse_download_token(self.downloaded_token)
            refresh_token = seeded_refresh_token
            integration_context["seeded_token"] = self.downloaded_token
            integration_context["refresh_token"] = refresh_token
            # Reuse the bundle's access token if present, to avoid an immediate refresh on the first run.
            if seeded_access_token and seeded_expires_in:
                access_token = seeded_access_token
                expiry_time = now + seeded_expires_in
                integration_context["access_token"] = access_token
                integration_context["expiry_time"] = expiry_time
            demisto.debug(f"Seeded tokens from the Access Token bundle (had_access_token={bool(seeded_access_token)}).")
            # Persist now so the seed survives even if the cached token is returned below.
            set_integration_context(integration_context)

        if use_cached_token and access_token and expiry_time > now:
            demisto.debug(f"Auth path: using cached access token (valid for {expiry_time - now}s).")
            return access_token
        elif isinstance(refresh_token, str) and refresh_token:
            demisto.debug("Auth path: refreshing access token using the stored refresh token.")
            access_token, refresh_token, validity_duration = self.refresh_access_token(refresh_token)
        elif self.user_name and self.user_password:
            demisto.debug("Auth path: acquiring a new access token via the full OAuth sequence (username/password).")
            access_token, refresh_token, validity_duration = self.oauth_sequence()
        else:
            raise DemistoException(
                "Unable to authenticate: no valid token is stored and no credentials were provided. "
                "Either paste an Access Token (from the Aruba Central UI 'Download Token' button), or provide a "
                "Username and Password for the initial OAuth authentication."
            )

        new_expiry_time = now + validity_duration
        demisto.debug(f"Obtained new access token (validity_duration={validity_duration}s, new_expiry_time={new_expiry_time}).")
        integration_context.update({"access_token": access_token, "expiry_time": new_expiry_time, "refresh_token": refresh_token})
        set_integration_context(integration_context)

        return access_token

    def refresh_access_token(self, refresh_token: str) -> tuple[str, str, int]:
        """
        Refreshes the access token using the provided refresh token.

        Args:
            refresh_token (str): Refresh token to be used

        Returns:
            access_token (str): The new access token.
            refresh_token (str): The next refresh token.
            expires_in (int): The validity duration of the new access token in seconds.
        """
        headers = {"Content-Type": "application/json"}
        params = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": refresh_token,
        }

        try:
            token_resp = self._http_request(
                method="POST",
                url_suffix="/oauth2/token",
                headers=headers,
                params=params,
            )

        except DemistoException as e:
            if "Invalid refresh_token" in str(e):
                demisto.debug("Refresh token is invalid, acquiring new access token via oauth.")
                return self.oauth_sequence()

            raise e

        demisto.debug(
            f"Refresh access token succeeded: access_token={mask_secret(token_resp.get('access_token'))}, "
            f"refresh_token={mask_secret(token_resp.get('refresh_token'))}, expires_in={token_resp.get('expires_in')}"
        )
        return (
            token_resp["access_token"],
            token_resp["refresh_token"],
            token_resp["expires_in"],
        )

    def oauth_sequence(self) -> tuple[str, str, int]:
        """
        Performs the full OAuth sequence to obtain an access token for the Aruba Central API.

        Returns:
            access_token (str): The access token.
            refresh_token (str): The next refresh token.
            validity_duration (int): The validity duration of the access token in seconds.
        """
        csrf_token, session = self.request_login()
        auth_code = self.request_auth_code(csrf_token, session)
        return self.request_access_token(auth_code)

    def request_login(self) -> tuple[str, str]:
        """
        Perform login step in oauth sequence

        Returns:
            csrf_token (str): CSRF token obtained from the login request
            session (str): Session object obtained from login request
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        params = {
            "client_id": self.client_id,
        }
        json_data = {
            "username": self.user_name,
            "password": self.user_password,
        }
        response: requests.Response = self._http_request(
            method="POST",
            url_suffix="/oauth2/authorize/central/api/login",
            headers=headers,
            params=params,
            json_data=json_data,
            resp_type="response",
        )
        csrf_token = response.cookies.get("csrftoken")
        session = response.cookies.get("session")
        if not csrf_token or not session:
            raise DemistoException(
                "Failed to acquire CSRF token and session from login request. Check if the credentials are valid."
            )
        demisto.debug(f"Login request succeeded: csrf_token={mask_secret(csrf_token)}, session={mask_secret(session)}")
        return csrf_token, session

    def request_auth_code(self, csrf_token: str, session: str) -> str:
        """
        Perform auth code request step in oauth sequence

        Args:
            csrf_token (str): CSRF token obtained from the login request
            session (str): Session object obtained from login request

        Returns:
            auth_code (str): Authorization code obtained from the auth code request
        """
        headers = {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf_token,
            "Cookie": f"session={session}",
        }
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": "read",
        }
        json_data = {
            "customer_id": self.customer_id,
        }
        response = self._http_request(
            method="POST",
            url_suffix="/oauth2/authorize/central/api",
            headers=headers,
            params=params,
            json_data=json_data,
        )
        demisto.debug(f"Auth code request succeeded: auth_code={mask_secret(response.get('auth_code'))}")
        return response.get("auth_code")

    def request_access_token(self, auth_code: str) -> tuple[str, str, int]:
        """
        Perform access token request step in oauth sequence

        Args:
            auth_code (str): Authorization code obtained from the auth code request

        Returns:
            access_token (str): The access token obtained from the request
            refresh_token (str): The refresh token obtained from the request
            validity_duration (int): The validity duration of the access token in seconds
        """
        headers = {
            "Content-Type": "application/json",
        }
        json_data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": auth_code,
        }
        response = self._http_request(
            method="POST",
            url_suffix="/oauth2/token",
            headers=headers,
            json_data=json_data,
        )
        demisto.debug(
            f"Access token request succeeded: access_token={mask_secret(response.get('access_token'))}, "
            f"refresh_token={mask_secret(response.get('refresh_token'))}, expires_in={response.get('expires_in')}"
        )
        return (
            response.get("access_token"),
            response.get("refresh_token"),
            response.get("expires_in"),
        )

    def http_request(self, method: str, url_suffix: str = "", params: dict = {}):
        """
        Make an http request to the Aruba Central API with the provided parameters.

        Args:
            method (str): HTTP method to use (e.g., 'GET', 'POST')
            url_suffix (str): Suffix to be appended to the base URL
            params (dict): Query parameters to be included in the request

        Returns:
            Response from the Aruba Central API
        """
        headers = {
            "accept": "application/json",
            "authorization": f"Bearer {self.get_access_token()}",
        }

        try:
            response = self._http_request(
                method=method,
                url_suffix=url_suffix,
                params=params,
                headers=headers,
                retries=NUM_OF_RETRIES,
                status_list_to_retry=[RATE_LIMIT_STATUS_CODE],
                backoff_factor=BACKOFF_FACTOR,
            )
        except DemistoException as e:
            if "access token is invalid" in str(e):
                demisto.debug("Access token is invalid, refreshing and retrying the request")
                headers["authorization"] = f"Bearer {self.get_access_token(use_cached_token=False)}"
                response = self._http_request(
                    method=method,
                    url_suffix=url_suffix,
                    params=params,
                    headers=headers,
                    retries=NUM_OF_RETRIES,
                    status_list_to_retry=[RATE_LIMIT_STATUS_CODE],
                    backoff_factor=BACKOFF_FACTOR,
                )
            else:
                raise e

        return response

    def validate_access_token(self, access_token: str) -> None:
        """
        Validates the given access token via one lightweight API call, using it as-is (no refresh/rotation),
        so it is safe to run from the Test button. Raises on an invalid token.
        """
        self._http_request(
            method="GET",
            url_suffix="/auditlogs/v1/events",
            params={"limit": 1},
            headers={"accept": "application/json", "authorization": f"Bearer {access_token}"},
        )

    def fetch_audit_events(self, start_time: int, end_time: int, amount_to_fetch: int, last_run: dict) -> list[dict]:
        """
        Fetch audit events from Aruba Central API.

        Args:
            start_time (int): Unix timestamp in seconds for the start time of the events to fetch
            end_time (int): Unix timestamp in seconds for the end time of the events to fetch
            amount_to_fetch (int): Amount of events to fetch
            last_run (dict): Last run object for duplicates filtering

        Returns:
            events (list): list of audit events
        """
        if amount_to_fetch > MAX_AUDIT_API_REQS * MAX_GET_AUDIT_LIMIT:
            demisto.debug("API requests required to satisfy limit exceeded maximum allowed. Fetching up to the allowed max.")
            amount_to_fetch = MAX_AUDIT_API_REQS * MAX_GET_AUDIT_LIMIT
        events = []
        offset = 0

        demisto.debug(f"{amount_to_fetch=}")
        while amount_to_fetch > 0:
            response = self.http_request(
                method="GET",
                url_suffix="/auditlogs/v1/events",
                params={
                    "limit": MAX_GET_AUDIT_LIMIT,
                    "offset": offset,
                    "start_time": start_time,
                    "end_time": end_time,
                },
            )
            if response["total"] > amount_to_fetch + offset:
                # manually skip to the end since the API has no option for ascending sort
                demisto.debug("Total entries for timeframe are larger than amount to fetch, skipping to get the earliest ones")
                offset = response["total"] - amount_to_fetch
                continue

            response_events = response.get("events", [])
            filtered_events = filter_and_reverse_audit_events(response_events, last_run)
            filtered_events = filtered_events[:amount_to_fetch]  # filtered_events return in ascending order

            events.extend(filtered_events)
            offset += len(response_events)
            amount_to_fetch -= len(filtered_events)
            if not response.get("remaining_records"):
                break

        demisto.debug(f"[Fetch] Audit events fetched {len(events)} event(s).")
        return events

    def fetch_networking_events(self, start_time: int, end_time: int, amount_to_fetch: int, last_run: dict) -> list[dict]:
        """
        Fetch networking events from Aruba Central API.

        Args:
            start_time (int): Unix timestamp in seconds indicating the start of the fetch window
            end_time (int): Unix timestamp in seconds for the end time of the events to fetch
            amount_to_fetch (int): Amount of events to fetch
            last_run (dict): Last run object for duplicates filtering

        Returns:
            events (list): list of networking events
        """
        if amount_to_fetch > MAX_EVENT_API_REQS * MAX_GET_EVENTS_LIMIT:
            demisto.debug("API requests required to satisfy limit exceeded maximum allowed. Fetching up to the allowed max.")
            amount_to_fetch = MAX_EVENT_API_REQS * MAX_GET_EVENTS_LIMIT
        events = []
        offset = 0

        demisto.debug(f"[Fetch] Networking events: starting fetch with {amount_to_fetch=}")
        while amount_to_fetch > 0:
            response = self.http_request(
                method="GET",
                url_suffix="/monitoring/v2/events",
                params={
                    "limit": MAX_GET_EVENTS_LIMIT,
                    "offset": offset,
                    "from_timestamp": start_time,
                    "to_timestamp": end_time,
                    "sort": "+timestamp",
                },
            )
            response_events = response.get("events", [])
            filtered_events = filter_networking_events(response_events, last_run)
            filtered_events = filtered_events[:amount_to_fetch]

            events.extend(filtered_events)
            amount_to_fetch -= len(filtered_events)
            offset += len(response_events)
            if len(response_events) < MAX_GET_EVENTS_LIMIT:  # got the last events for this time frame
                break

        return events


""" HELPER FUNCTIONS """


def mask_secret(secret: str | None) -> str:
    """
    Masks a secret for safe debug logging: keeps a short prefix and suffix plus the length,
    e.g. "paf8bU…fDvu(32)". This is enough to correlate a value across log lines and confirm
    token rotation, without exposing a usable portion.

    Each non-usable case is distinguishable so the log tells you what actually happened:
        - None  -> "<none>"    (the value was never set)
        - ""    -> "<empty>"   (the value was set but is an empty string)
        - short -> "***(N)"    (too short to safely reveal any edge, only the length is shown)
    """
    if secret is None:
        return "<none>"
    if secret == "":
        return "<empty>"
    if len(secret) <= 2 * MASK_EDGE_LEN:
        return f"***({len(secret)})"
    return f"{secret[:MASK_EDGE_LEN]}…{secret[-MASK_EDGE_LEN:]}({len(secret)})"


def filter_and_reverse_audit_events(events: list[dict], last_run: dict) -> list[dict]:
    """
    Check if the audit events contain any of the previous fetch events that had the highest timestamp and filters them.

    Args:
        events (list[dict]): Newly fetched audit events, in descending timestamp order
        last_run (dict): last_run object containing candidate duplicate events from the previous fetch and their timestamp

    Returns:
        events (list[dict]): events list with filtered duplicates, in ascending timestamp order
    """
    last_audit_ts = int(last_run.get("last_audit_ts", 0))
    last_audit_ids = last_run.get("last_audit_event_ids", [])

    if not last_audit_ts or not last_audit_ids:
        return list(reversed(events))

    filtered_events: list[dict] = []
    for i, event in reversed(list(enumerate(events))):
        if event[AUDIT_TS] > last_audit_ts:
            filtered_events.extend(reversed(events[: i + 1]))
            break

        if event["id"] not in last_audit_ids:
            filtered_events.append(event)

    return filtered_events


def filter_networking_events(events: list[dict], last_run: dict) -> list[dict]:
    """
    Check if the network events contain any of the previous fetch events that had the highest timestamp and filters them.

    Args:
        events (list[dict]): Newly fetched audit events, in ascending timestamp order
        last_run (dict): last_run object containing candidate duplicate events from the previous fetch and their timestamp

    Returns:
        events (list[dict]): events list with filtered duplicates, in ascending timestamp order
    """
    last_event_ts_ms = int(last_run.get("last_networking_ts", 0)) * 1000
    last_event_ids = last_run.get("last_networking_event_ids", [])
    filtered_events = []
    for i, event in enumerate(events):
        if event[NETWORKING_TS] > last_event_ts_ms:
            filtered_events.extend(events[i:])
            break

        if event["event_uuid"] not in last_event_ids:
            filtered_events.append(event)

    return filtered_events


def create_next_run(audit_events: list[dict], networking_events: list[dict] | None, end_time: int) -> dict[str, str]:
    """
    Create the next run object based on the latest fetched events.

    Args:
        audit_events (list[dict]): List of the latest fetched audit events
        networking_events (list[dict] | None): List of the latest fetched networking events
        end_time (int): Unix timestamp in seconds for the end time used in the fetches

    Returns:
        next_run (dict[str, str]): Object containing the latest event timestamps and event IDs to be used for duplicate removals
                                    in the next run
    """
    next_run: dict[str, Any] = {}
    end_time_ms = end_time * 1000
    if audit_events:
        last_audit_ts = audit_events[-1].get(AUDIT_TS, end_time)
        next_run["last_audit_ts"] = str(last_audit_ts)
        last_audit_event_ids = []
        for event in reversed(audit_events):
            # Save all event IDs with the latest timestamp
            if event.get(AUDIT_TS, 0) < last_audit_ts:
                break

            last_audit_event_ids.append(event.get("id"))

        next_run["last_audit_event_ids"] = last_audit_event_ids

    else:
        next_run["last_audit_ts"] = str(end_time)

    if networking_events:
        last_networking_ts = int(networking_events[-1].get(NETWORKING_TS, end_time_ms) / 1000)
        next_run["last_networking_ts"] = str(last_networking_ts)
        last_networking_event_ids = []
        for event in reversed(networking_events):
            # Save all event IDs with the latest timestamp
            if event.get(NETWORKING_TS, 0) < last_networking_ts:
                break

            last_networking_event_ids.append(event.get("event_uuid"))

        next_run["last_networking_event_ids"] = last_networking_event_ids

    else:
        next_run["last_networking_ts"] = str(end_time)

    return next_run


def add_time_to_events(events: list[dict] | None, time_arg: str):
    """
    Adds the _time key to the events.

    Args:
        events: List[Dict] - list of events to add the _time key to.
        time_arg: str - the key to be used for time extraction.

    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get(time_arg))
            event["_time"] = create_time.strftime(DATE_FORMAT) if create_time else None


def push_events(audit_events: list | None, networking_events: list | None):
    """
    Push audit and networking events to XSIAM

    Args:
        audit_events (list): list of fetched audit events
        networking_events (list): list of fetched networking events
    """
    events_to_send = []
    if audit_events:
        add_time_to_events(audit_events, AUDIT_TS)
        events_to_send.extend(audit_events)

    if networking_events:
        add_time_to_events(networking_events, NETWORKING_TS)
        events_to_send.extend(networking_events)

    if events_to_send:
        send_events_to_xsiam(
            events_to_send,
            vendor=VENDOR,
            product=PRODUCT,
        )


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Validates the configuration when the user clicks "Test".

    Test-module can't persist tokens, so it avoids rotating the pasted Access Token's refresh token:
    validate with the bundle's own access token when present, otherwise fall back to a refresh.
    If the bundle's access token is present but expired, the raised error hints that it may be stale and
    can be refreshed via the 'aruba-auth-test' command (which is safe to rotate the refresh token).
    Username/Password can't be tested safely (would burn Aruba's 30-min new-token quota), so we point
    the user to the 'aruba-auth-test' command instead. Returns "ok" on success.
    """
    if client.downloaded_token:
        _, access_token, _ = client.parse_download_token(client.downloaded_token)
        if access_token:
            # Non-mutating: validate with the bundle's own access token, leaving the refresh token untouched.
            # The bundle's access token may already be expired (they are valid for only ~2 hours), while the
            # refresh token remains valid for up to 15 days. If validation fails, tell the user the access token
            # may be stale and can be refreshed - without rotating the refresh token here (test-module can't persist).
            try:
                client.validate_access_token(access_token)
            except DemistoException as e:
                demisto.debug(f"Validation with the bundle's access token failed: {e}")
                raise DemistoException(
                    "Failed to validate the pasted Access Token. Its access token may be expired (access tokens are "
                    "valid for ~2 hours), even though the refresh token can still be valid (up to 15 days). Run the "
                    "'aruba-auth-test' command to authenticate using the refresh token, or paste a freshly downloaded "
                    "Access Token JSON from the Aruba Central UI."
                ) from e
        else:
            # No access token in the bundle: a refresh is the only way to get one to validate with.
            demisto.debug("Access Token bundle has no access token; validating via refresh (may rotate the refresh token).")
            client.validate_access_token(client.get_access_token())
        return "ok"

    raise DemistoException(
        "Test button is not supported when authenticating with Username and Password due to Aruba's "
        "API limitation of one new access token every 30 minutes. Use the 'aruba-auth-test' command "
        "to validate this configuration, or paste an Access Token to enable the Test button."
    )


def aruba_auth_test(
    client: Client,
    first_fetch_time: int,
    fetch_networking_events: bool,
    max_audit_events_per_fetch: int,
    max_networking_events_per_fetch: int,
) -> CommandResults:
    """
    Executes the test module flow (since integration context can't be accessed during test_module)
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Aruba Central client to use.
        first_fetch_time(str): The first fetch time as configured in the integration params.
        fetch_networking_events (bool): Whether to fetch networking events, as configured in the integration params.
        max_audit_events_per_fetch: The maximum number of audit log events to retrieve in a single fetch cycle.
        max_networking_events_per_fetch: The maximum number of networking log events to retrieve in a single fetch cycle.
    Returns:
        CommandResults: CommandResults which contains an informative message if the Authentication was successful or not.
        Anything else will raise an exception and will fail the test.
    """

    if not max_audit_events_per_fetch or max_audit_events_per_fetch > MAX_AUDIT_API_REQS * MAX_GET_AUDIT_LIMIT:
        raise DemistoException(
            f"The maximum number of audit events per fetch should not exceed {MAX_AUDIT_API_REQS * MAX_GET_AUDIT_LIMIT}."
        )
    if not max_networking_events_per_fetch or max_networking_events_per_fetch > MAX_EVENT_API_REQS * MAX_GET_EVENTS_LIMIT:
        raise DemistoException(
            f"The maximum number of networking events per fetch should not exceed {MAX_EVENT_API_REQS * MAX_GET_EVENTS_LIMIT}."
        )

    try:
        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            num_audit_events_to_fetch=1,
            fetch_networking_events=fetch_networking_events,
            num_networking_events_to_fetch=1,
        )

    except Exception as e:
        if "Forbidden" in str(e) or "UNAUTHORIZED" in str(e):
            return CommandResults(readable_output="Authorization Error: make sure credentials are correctly set")
        else:
            raise e

    return CommandResults(readable_output="Authentication was successful.")


def get_events(
    client: Client, fetch_networking_events: bool, args: dict
) -> tuple[list[dict], list[dict] | None, list[CommandResults]]:
    """
    Get events from the Aruba Central API.

    Args:
        client (Client): Aruba Central client to use.
        fetch_networking_events (bool): Whether to fetch networking events, as configured in the integration params.
        args (dict): command arguments.

    Returns:
        audit_events (list[dict]): List of audit events fetched from Aruba Central API.
        networking_events (list[dict] | None): List of networking events fetched from Aruba Central API
        results (list[CommandResults]): List of CommandResults objects to be returned to the war-room.
    """
    limit = arg_to_number(args.get("limit"), required=True)
    max_limit = max(
        MAX_GET_AUDIT_LIMIT * MAX_AUDIT_API_REQS,
        MAX_GET_EVENTS_LIMIT * MAX_EVENT_API_REQS,
    )
    if not limit or limit > max_limit:
        raise DemistoException(f"Requested limit ({limit}) exceeds maximum allowed limit of {max_limit}")

    audit_limit = limit or MAX_GET_AUDIT_LIMIT * MAX_AUDIT_API_REQS
    networking_limit = limit or MAX_GET_EVENTS_LIMIT * MAX_EVENT_API_REQS
    if "from_date" in args:
        start_time = int(date_to_timestamp(arg_to_datetime(args.get("from_date"))) / 1000)
    else:
        start_time = int(time.time()) - timedelta(hours=3).seconds

    demisto.debug(f"Running get_events with {start_time=}")
    _, audit_events, networking_events = fetch_events(
        client=client,
        last_run={},
        first_fetch_time=start_time,
        num_audit_events_to_fetch=audit_limit,
        fetch_networking_events=fetch_networking_events,
        num_networking_events_to_fetch=networking_limit,
    )
    audit_hr = tableToMarkdown(name="Audit Events", t=audit_events)
    results = [CommandResults(readable_output=audit_hr)]
    if fetch_networking_events:
        networking_hr = tableToMarkdown(name="Networking Events", t=networking_events)
        results.append(CommandResults(readable_output=networking_hr))

    return audit_events, networking_events, results


def fetch_events(
    client: Client,
    last_run: dict,
    first_fetch_time: int,
    num_audit_events_to_fetch: int,
    fetch_networking_events: bool,
    num_networking_events_to_fetch: int,
) -> tuple[dict, list[dict], list[dict] | None]:
    """
    Fetches events from the Aruba Central API

    Args:
        client (Client): Aruba Central client to use.
        last_run (dict): A dict with a key containing the end time of the last successful fetch.
        first_fetch_time: If last_run is None (first time we are fetching), it contains the timestamp in
            seconds on when to start fetching events.
        num_audit_events_to_fetch (int): number of audit events to fetch.
        fetch_networking_events (bool): whether to fetch networking events in addition to audit events.
        num_networking_events_to_fetch (int): number of networking events to fetch.

    Returns:
        next_run(dict): Dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        audit_events(list): List of fetched audit events.
        networking_events(list): List of fetched networking events.
    """
    if not num_audit_events_to_fetch or num_audit_events_to_fetch > MAX_AUDIT_API_REQS * MAX_GET_AUDIT_LIMIT:
        raise DemistoException(
            f"The maximum number of audit events per fetch should not exceed {MAX_AUDIT_API_REQS * MAX_GET_AUDIT_LIMIT}."
        )
    if not num_networking_events_to_fetch or num_networking_events_to_fetch > MAX_EVENT_API_REQS * MAX_GET_EVENTS_LIMIT:
        raise DemistoException(
            f"The maximum number of networking events per fetch should not exceed {MAX_EVENT_API_REQS * MAX_GET_EVENTS_LIMIT}."
        )

    audit_start_time = int(last_run.get("last_audit_ts", first_fetch_time))
    networking_start_time = int(last_run.get("last_networking_ts", first_fetch_time))
    end_time = int(time.time())
    demisto.debug(f"[Fetch] Fetching {num_audit_events_to_fetch} audit events from {audit_start_time} to {end_time}.")
    audit_events = client.fetch_audit_events(
        start_time=audit_start_time,
        end_time=end_time,
        amount_to_fetch=num_audit_events_to_fetch,
        last_run=last_run,
    )
    demisto.debug(f"[Fetch] Got {len(audit_events)} audit events.")

    networking_events = None
    if fetch_networking_events:
        demisto.debug(f"Fetching {num_networking_events_to_fetch} networking events from {networking_start_time} to {end_time}.")
        networking_events = client.fetch_networking_events(
            start_time=networking_start_time,
            end_time=end_time,
            amount_to_fetch=num_networking_events_to_fetch,
            last_run=last_run,
        )
        demisto.debug(f"Got {len(networking_events)} networking events.")

    next_run = create_next_run(
        audit_events=audit_events,
        networking_events=networking_events,
        end_time=end_time,
    )
    demisto.debug(f"Returning {next_run=}.")
    return next_run, audit_events, networking_events


""" MAIN FUNCTION """


def validate_authentication_params(
    auth_method: str,
    downloaded_token: str | None,
    user_name: str | None,
    user_password: str | None,
    customer_id: str | None,
) -> None:
    """
    Validates that the configuration provides a usable set of credentials for the selected authentication method.
    Raises a clear DemistoException instead of letting the integration attempt a doomed authentication.

    Note: The Authentication Method selector drives the UI triggers (which show/hide the relevant fields), but the
    UI triggers may not evaluate on initial page load on all server versions, so the actual validation is enforced
    here in Python based on the selected method.

    Args:
        auth_method (str): The selected authentication method ("Access Token" or "Basic Auth").
        downloaded_token (str | None): The Access Token JSON pasted from the Aruba Central UI.
        user_name (str | None): The configured username.
        user_password (str | None): The configured password.
        customer_id (str | None): The configured customer ID.
    """
    if auth_method == "Basic Auth":
        if not (user_name and user_password):
            raise DemistoException(
                "Authentication Method is 'Basic Auth', but a Username and/or Password is missing. "
                "Provide both, or switch the Authentication Method to 'Access Token'."
            )
        if not customer_id:
            raise DemistoException(
                "Authentication Method is 'Basic Auth', but the Customer ID is missing. "
                "Provide a Customer ID, or switch the Authentication Method to 'Access Token'."
            )
        return

    # "Access Token" method.
    if not downloaded_token:
        raise DemistoException(
            "Authentication Method is 'Access Token', but no Access Token was provided. "
            "In the Aruba Central UI, click the 'Download Token' button and paste the token JSON, or switch the "
            "Authentication Method to 'Basic Auth'."
        )
    # Validate the bundle format now so a bad paste fails fast with a clear message instead of mid-fetch.
    # Raises if the JSON has no 'refresh_token'.
    Client.parse_download_token(downloaded_token)


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    client_id = params.get("credentials", {}).get("identifier")
    client_secret = params.get("credentials", {}).get("password")
    # Default to "Basic Auth" so instances created before this field existed keep their original behavior on upgrade.
    auth_method = params.get("auth_method") or "Basic Auth"
    user_name = params.get("user", {}).get("identifier")
    user_password = params.get("user", {}).get("password")
    customer_id = params.get("customer_id", {}).get("password")
    downloaded_token = params.get("token", {}).get("password")
    # Clear a leftover Access Token so it can't override the Basic Auth flow.
    # (No reverse guard needed: the seeded token is always tried before user/password.)
    if auth_method == "Basic Auth":
        downloaded_token = ""
    base_url = params.get("url", "")
    fetch_networking_events = params.get("fetch_networking_events", False)
    max_audit_events_per_fetch = arg_to_number(params.get("max_audit_events_per_fetch")) or 0
    max_networking_events_per_fetch = arg_to_number(params.get("max_networking_events_per_fetch")) or 0
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    first_fetch_time = int(time.time())

    demisto.debug(f"Command being called is {command}")
    try:
        validate_authentication_params(auth_method, downloaded_token, user_name, user_password, customer_id)
        client = Client(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            user_name=user_name,
            user_password=user_password,
            customer_id=customer_id,
            downloaded_token=downloaded_token,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))

        if command == "aruba-auth-test":
            result = aruba_auth_test(
                client,
                first_fetch_time=first_fetch_time,
                fetch_networking_events=fetch_networking_events,
                max_audit_events_per_fetch=max_audit_events_per_fetch,
                max_networking_events_per_fetch=max_networking_events_per_fetch,
            )
            return_results(result)

        elif command == "aruba-central-get-events":
            should_push_events = argToBoolean(args.pop("should_push_events"))
            audit_events, networking_events, results = get_events(client, fetch_networking_events, args)
            return_results(results)

            if should_push_events:
                push_events(audit_events, networking_events)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, audit_events, networking_events = fetch_events(
                client=client,
                last_run=last_run,
                first_fetch_time=first_fetch_time,
                num_audit_events_to_fetch=max_audit_events_per_fetch,
                fetch_networking_events=fetch_networking_events,
                num_networking_events_to_fetch=max_networking_events_per_fetch,
            )

            push_events(audit_events, networking_events)
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

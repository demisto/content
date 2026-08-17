import base64
import bz2
import urllib.parse
from enum import Enum
from string import Template
from datetime import UTC
import demistomock as demisto
import urllib3
from CommonServerPython import *

from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

""" GLOBALS/PARAMS """
MAX_ATTEMPTS = 3
DEFAULT_MAX_FETCH = 50
DEFAULT_BASE_URL = "https://api.dlp.paloaltonetworks.com/v1/"
DEFAULT_AUTH_URL = "https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token"
REPORT_URL = "public/report/{}"
INCIDENTS_URL = "public/incident-notifications"
REFRESH_TOKEN_URL = "public/oauth/refreshToken"
UPDATE_INCIDENT_URL = "public/incident-feedback"
SLEEP_TIME_URL = "public/seconds-between-incident-notifications-pull"
V4_INCIDENTS_PATH = "/v4/api/incidents"
V4_PAGE_SIZE = 1000
V4_PENDING_ATTEMPTS = 3  # times to re-poll the query token while the backend reports PENDING
V4_PENDING_SLEEP = 2  # seconds between PENDING polls
FETCH_SLEEP = 5  # sleep between fetches (in seconds)
LAST_FETCH_TIME = "last_fetch_time"
DEFAULT_FIRST_FETCH = "60 minutes"
ACCESS_TOKEN = "access_token"
RESET_KEY = "reset"
CREDENTIAL = "credential"
IDENTIFIER = "identifier"
PASSWORD = "password"
END_TIME_BUFFER = 30  # seconds
MAX_API_CALLS_PER_FETCH = 100

# Last run
LAST_RUN_KEY = "last_run"
START_TIMESTAMP_KEY = "start_timestamp"
LAST_IDS_KEY = "last_ids"  # Legacy key (list[str]) — kept for migration only
LAST_IDS_TIMESTAMPS_KEY = "last_ids_timestamps"  # New key: dict[str, int] mapping incident_id → committedAt epoch
LOCAL_LAST_RUN: dict[str, Any] = {}  # In memory last run object during long running execution


class FeedbackStatus(Enum):
    PENDING_RESPONSE = "PENDING_RESPONSE"
    CONFIRMED_SENSITIVE = "CONFIRMED_SENSITIVE"
    CONFIRMED_FALSE_POSITIVE = "CONFIRMED_FALSE_POSITIVE"
    EXCEPTION_REQUESTED = "EXCEPTION_REQUESTED"
    OPERATIONAL_ERROR = "OPERATIONAL_ERROR"
    EXCEPTION_GRANTED = "EXCEPTION_GRANTED"
    EXCEPTION_NOT_REQUESTED = "EXCEPTION_NOT_REQUESTED"
    SEND_NOTIFICATION_FAILURE = "SEND_NOTIFICATION_FAILURE"
    EXCEPTION_DENIED = "EXCEPTION_DENIED"


class Client(BaseClient):
    def __init__(self, base_url: str, auth_url: str, credentials, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, headers=None, verify=verify, proxy=proxy)
        self.credentials = credentials
        self.auth_url = auth_url
        credential_name = credentials[CREDENTIAL]
        if not credential_name:
            self.access_token = credentials[IDENTIFIER]
            self.refresh_token = credentials[PASSWORD]
        else:
            self.access_token = ""
            self._refresh_token_with_client_credentials()

    def _refresh_token(self):
        """Refreshes Access Token"""
        headers = {"Authorization": "Bearer " + self.access_token, "Content-Type": "application/json"}
        params = {"refresh_token": self.refresh_token}
        print_debug_msg(f"Calling endpoint {self._base_url}{REFRESH_TOKEN_URL}")
        try:
            r = self._http_request(
                method="POST", headers=headers, url_suffix=REFRESH_TOKEN_URL, json_data=params, ok_codes=[200, 201, 204]
            )
            new_token = r.get("access_token")
            if new_token:
                self.access_token = new_token

        except Exception as e:
            print_debug_msg(str(e))
            raise

    def _refresh_token_with_client_credentials(self):
        client_id = self.credentials[IDENTIFIER]
        client_secret = self.credentials[PASSWORD]
        credentials = f"{client_id}:{client_secret}"
        auth_header = f"Basic {b64_encode(credentials)}"
        headers = {"Authorization": auth_header, "Content-Type": "application/x-www-form-urlencoded"}

        payload = "grant_type=client_credentials"
        try:
            r = self._http_request(full_url=self.auth_url, method="POST", headers=headers, data=payload, ok_codes=[200, 201, 204])
            new_token = r.get("access_token")
            if new_token:
                self.access_token = new_token

        except Exception as e:
            print_debug_msg(str(e))
            raise

    def _handle_4xx_errors(self, res):
        """
        Handles 4xx exception on get-dlp-report and tries to refresh token
        Args:
            res: Response of DLP API call
        """
        if res.status_code < 400 or res.status_code >= 500:
            return
        try:
            print_debug_msg(f"Got {res.status_code}, attempting to refresh access token")
            if self.credentials[CREDENTIAL]:
                print_debug_msg("Requesting access token with client id/client secret")
                self._refresh_token_with_client_credentials()
            else:
                print_debug_msg("Requesting new access token with old access token/refresh token")
                self._refresh_token()
        except Exception:
            pass

    def _get_dlp_api_call(self, url_suffix: str = "", full_url: str = "") -> tuple[dict[str, Any], int]:
        """
        Makes a HTTPS Get call on the DLP API
        Args:
            url_suffix: URL suffix for dlp api call
            full_url: Absolute URL (takes precedence over url_suffix)
        """
        count = 0
        log_url = full_url or f"{self._base_url}{url_suffix}"
        print_debug_msg(f"Calling GET method on {log_url}")
        while count < MAX_ATTEMPTS:
            http_kwargs: dict[str, Any] = {
                "method": "GET",
                "headers": {"Authorization": "Bearer " + self.access_token},
                "ok_codes": [200, 201, 204],
                "error_handler": self._handle_4xx_errors,
                "resp_type": "",
                "return_empty_response": True,
            }
            if full_url:
                http_kwargs["full_url"] = full_url
            else:
                http_kwargs["url_suffix"] = url_suffix
            res = self._http_request(**http_kwargs)
            if res.status_code < 400 or res.status_code >= 500:
                break
            count += 1

        result_json = {}
        if res.status_code != 204:
            try:
                result_json = res.json()
            # when installing simplejson the type of exception is requests.exceptions.JSONDecodeError
            except (json.decoder.JSONDecodeError, requests.exceptions.JSONDecodeError):
                result_json = {}

        return result_json, res.status_code

    def _post_dlp_api_call(self, url_suffix: str = "", payload: dict = None, full_url: str = ""):
        """
        Makes a POST HTTP(s) call to the DLP API
        Args:
            url_suffix: URL suffix for dlp api call
            payload: Optional JSON payload
            full_url: Absolute URL (takes precedence over url_suffix)
        """
        count = 0

        while count < MAX_ATTEMPTS:
            res = self._http_request(
                method="POST",
                headers={"Authorization": f"Bearer {self.access_token}"},
                url_suffix=url_suffix,
                full_url=full_url or None,
                json_data=payload,
                ok_codes=[200, 201, 204],
                error_handler=self._handle_4xx_errors,
                resp_type="response",
                return_empty_response=True,
            )
            if res.status_code < 400 or res.status_code >= 500:
                break
            count += 1

        result_json = {}
        if res.status_code != 204:
            try:
                result_json = res.json()
            # when installing simplejson the type of exception is requests.exceptions.JSONDecodeError
            except (json.decoder.JSONDecodeError, requests.exceptions.JSONDecodeError):
                result_json = {}

        return result_json, res.status_code

    def set_access_token(self, access_token):
        self.access_token = access_token

    def get_dlp_report(self, report_id: str, fetch_snippets=False):
        """
        Fetches DLP reports
        Args:
            report_id: Report ID to fetch from DLP service
            fetch_snippets: if True, fetches the snippets

        Returns: DLP Report json
        """
        url = REPORT_URL.format(report_id)
        if fetch_snippets:
            url = url + "?fetchSnippets=true"

        return self._get_dlp_api_call(url)

    def _v4_incidents_url(self) -> str:
        """Build the absolute v4 incidents URL from the configured base URL's host.

        The v4 API is not versioned under the v1 base path, so only the scheme and
        host are reused. Deriving the path by string replacement on ``base_url``
        silently no-ops when the URL is customized, so it is not used here.
        """
        parsed = urllib.parse.urlparse(self._base_url)
        return f"{parsed.scheme}://{parsed.netloc}{V4_INCIDENTS_PATH}"

    def get_incidents_first_page(
        self,
        start_time_ms: int,
        end_time_ms: int,
        regions: str = "",
        page_size: int = V4_PAGE_SIZE,
    ) -> tuple[dict[str, Any], int]:
        """Start a v4 incident inventory query and fetch its first page.

        Args:
            start_time_ms: Start time in epoch milliseconds (inclusive).
            end_time_ms: End time in epoch milliseconds (inclusive).
            regions: Comma-separated DLP regions. Empty = all regions.
            page_size: Rows per page.

        Returns:
            (response_json, status_code) — response contains ``rows``, ``status``,
            ``query_token`` and ``total_rows``.
        """
        payload: dict[str, Any] = {
            "time_range": "CUSTOM",
            "start_time": start_time_ms,
            "end_time": end_time_ms,
            "sort_by": "IncidentCreatedDate",
            "sort_order": "ASC",
            "page_size": page_size,
        }
        region_filter = build_region_filter(regions)
        if region_filter:
            payload["filter"] = region_filter

        return self._post_dlp_api_call(full_url=self._v4_incidents_url(), payload=payload)

    def get_incidents_next_page(self, token: str, offset: int, page_size: int = V4_PAGE_SIZE) -> tuple[dict[str, Any], int]:
        """Fetch a subsequent page of an already-started v4 inventory query.

        Args:
            token: Query token returned by ``get_incidents_first_page``.
            offset: Zero-indexed row offset into the query result set.
            page_size: Rows per page.

        Returns:
            (response_json, status_code)
        """
        query_string = urllib.parse.urlencode({"token": token, "offset": offset, "pageSize": page_size})
        return self._get_dlp_api_call(full_url=f"{self._v4_incidents_url()}?{query_string}")

    def update_dlp_incident(
        self,
        incident_id: str,
        feedback: FeedbackStatus,
        user_id: str,
        region: str,
        report_id: str,
        dlp_channel: str,
        error_details: str = None,
    ):
        """
        Update Incident with user provided feedback
        Args:
            incident_id: The id of the incident to update
            feedback: 'business_justified', 'true_positive' or 'false_positive'
            user_id: The user that initiated the request
            region: The DLP region
            report_id: The report ID for the incident
            dlp_channel: The DLP channel (service name)
            error_details: The error details if there is an error

        Returns: DLP Incident json
        """
        payload = {"user_id": user_id, "report_id": report_id, "service_name": dlp_channel}
        if error_details:
            payload["error_details"] = error_details

        url = f"{UPDATE_INCIDENT_URL}/{incident_id}?feedback_type={feedback.value}&region={region}"
        return self._post_dlp_api_call(url, payload)

    def query_for_sleep_time(self):
        resp, status = self._get_dlp_api_call(SLEEP_TIME_URL)
        return resp


def parse_data_pattern_rule(report_json, verdict_field, results_field):
    """
    Parses data pattern matches from a given rule in DLP report JSON
    Args:
        report_json: DLP report json
        verdict_field: Name of the verdict field
        results_field: Name of the result field

    Returns: data pattern matches for the given rule

    """
    if report_json.get(verdict_field) != "MATCHED":
        return []
    data_patterns = []
    for dp in report_json.get("scanContentRawReport", {}).get(results_field, []):
        if (dp.get("state") == "EVALUATED") and (dp.get("unique_detection_frequency", 0) >= 1):
            data_patterns.append(
                {
                    "DataPatternName": dp.get("name"),
                    "LowConfidenceFrequency": dp.get("low_confidence_frequency"),
                    "HighConfidenceFrequency": dp.get("high_confidence_frequency"),
                    "MediumConfidenceFrequency": dp.get("medium_confidence_frequency"),
                    "MatchedConfidenceLevel": dp.get("matched_confidence_level"),
                    "Detections": dp.get("detections"),
                }
            )
    return data_patterns


def parse_data_profiles(report_json: dict) -> list:
    """
    Parses the data_profiles array from the DLP report JSON.
    Args:
        report_json: DLP report JSON

    Returns: List of parsed data profile dicts with CamelCase keys
    """
    profiles = []
    data_profiles = report_json.get("data_profiles") or []
    for profile in data_profiles:
        parsed_patterns = []
        data_patterns = profile.get("data_patterns") or []
        for pattern in data_patterns:
            parsed_patterns.append(
                {
                    "Id": pattern.get("id"),
                    "IsMatched": pattern.get("is_matched"),
                    "ConfidenceLevel": pattern.get("confidence_level"),
                    "OccurrenceCount": pattern.get("occurrence_count"),
                    "OccurrenceOperatorType": pattern.get("occurrence_operator_type"),
                    "OccurrenceLow": pattern.get("occurrence_low"),
                    "OccurrenceHigh": pattern.get("occurrence_high"),
                }
            )
        profiles.append(
            {
                "Name": profile.get("name"),
                "Id": profile.get("id"),
                "Version": profile.get("version"),
                "IsTriggered": profile.get("is_triggered"),
                "DataPatterns": parsed_patterns,
            }
        )
    return profiles


def parse_data_patterns(report_json):
    """
    Parse data pattern matches from the raw report
    Args:
        report_json: DLP report JSON

    Returns: Data pattern matches
    """
    data_patterns = []
    data_patterns.extend(parse_data_pattern_rule(report_json, "data_pattern_rule_1_verdict", "data_pattern_rule_1_results"))
    data_patterns.extend(parse_data_pattern_rule(report_json, "data_pattern_rule_2_verdict", "data_pattern_rule_2_results"))
    data_profiles = parse_data_profiles(report_json)
    result: dict = {"DataProfile": report_json.get("data_profile_name"), "DataPatternMatches": data_patterns}
    if data_profiles:
        result["DataProfiles"] = data_profiles
    return result


def convert_to_human_readable(data_patterns):
    """
    Converts the results for human readable format
    Args:
        data_patterns: Data Pattern matches

    Returns: Human Readable Format result
    """
    matches: list = []
    if not data_patterns:
        return matches
    headers = ["DataPatternName", "ConfidenceFrequency", "MatchedConfidenceLevel"]
    for k in data_patterns.get("DataPatternMatches", []):
        match = {
            "DataPatternName": k.get("DataPatternName"),
            "ConfidenceFrequency": {
                "Low": k.get("LowConfidenceFrequency"),
                "Medium": k.get("MediumConfidenceFrequency"),
                "High": k.get("HighConfidenceFrequency"),
            },
            "MatchedConfidenceLevel": k.get("MatchedConfidenceLevel"),
        }
        index = 1
        detections = k.get("Detections", [])
        if detections:
            for detection in detections:
                col = f"Detection {index}"
                if col not in headers:
                    headers.append(col)
                match[col] = detection
                index += 1
        matches.append(match)
    title = "DLP Report for profile: {}".format(data_patterns.get("DataProfile"))
    return tableToMarkdown(title, matches, headers)


def parse_dlp_report(report_json) -> CommandResults:
    """
    Parses DLP Report for display
    Args:
        report_json: DLP report json

    Returns: DLP report results
    """
    data_patterns = parse_data_patterns(report_json)
    return CommandResults(
        outputs_prefix="DLP.Report",
        outputs_key_field="DataPatternName",
        outputs=data_patterns,
        readable_output=convert_to_human_readable(data_patterns),
        raw_response=report_json,
    )


def test(client: Client, params: dict):
    """Test Function to test validity of access and refresh tokens"""
    now_ms = int(datetime.now(tz=UTC).timestamp() * 1000)
    one_hour_ago_ms = now_ms - 3_600_000
    report_json, status_code = client.get_incidents_first_page(
        start_time_ms=one_hour_ago_ms, end_time_ms=now_ms, regions=params.get("dlp_regions", ""), page_size=1
    )
    if status_code in [200, 204]:
        return_results("ok")
    else:
        message = f"Integration test failed: Unexpected status ({status_code}) - "
        if "error" in report_json:
            message += f"Error message: \"{report_json.get('error')}\""
        else:
            message += "Could not determine the error reason. Make sure the DLP Regions parameter is configured correctly."
        raise DemistoException(message)


def print_debug_msg(msg: str):
    """
    Prints a message to debug with PAN-DLP-Msg prefix.
    Args:
        msg (str): Message to be logged.

    """
    demisto.debug(f"PAN-DLP-Msg - {msg}")


def update_incident_command(client: Client, args: dict) -> CommandResults:
    incident_id = args.get("incident_id", "")
    feedback = args.get("feedback", "")
    user_id = args.get("user_id", "")
    region = args.get("region", "")
    report_id = args.get("report_id", "")
    dlp_channel = args.get("dlp_channel", "")
    error_details = args.get("error_details")
    feedback_enum = FeedbackStatus[feedback.upper()]
    result_json, status = client.update_dlp_incident(
        incident_id, feedback_enum, user_id, region, report_id, dlp_channel, error_details
    )

    output = {"feedback": feedback_enum.value, "success": status == 200}
    if feedback_enum == FeedbackStatus.EXCEPTION_GRANTED:
        minutes = result_json["expiration_duration_in_minutes"]
        if minutes and minutes < 60:
            output["duration"] = f"{minutes} minutes"
        elif minutes:
            output["duration"] = f"{minutes / 60} hours"

        result = CommandResults(outputs_prefix="Exemption", outputs_key_field="duration", outputs=output)
    else:
        result = CommandResults(outputs_prefix="IncidentUpdate", outputs_key_field="feedback", outputs=output)
    return result


def parse_incident_details(compressed_details: str):
    details_byte_data = bz2.decompress(base64.b64decode(compressed_details))
    details_string = details_byte_data.decode("utf-8")
    details_obj = json.loads(details_string)
    demisto.debug(f"Parsed incident details: {details_obj}.")
    return details_obj


def build_region_filter(regions: str) -> str:
    """
    Build the v4 server-side filter expression for the configured regions.

    Region tokens are whitelisted to ``[A-Z0-9_]`` so an operator-supplied value
    cannot alter the filter expression.

    Args:
        regions: Comma-separated DLP regions (e.g. "us,eu").

    Returns:
        str: Filter expression, or an empty string when no valid region is configured.
    """
    tokens = [region.strip().upper() for region in regions.split(",")] if regions else []
    tokens = [region for region in tokens if re.fullmatch(r"[A-Z0-9_]+", region)]
    if not tokens:
        return ""
    return "Region in ({})".format(", ".join(f"'{region}'" for region in tokens))


def parse_created_date(value: Any) -> datetime | None:
    """
    Normalize a v4 ``created_date`` into a timezone-aware datetime.

    The field is typed as a number but the unit is not pinned by the contract —
    seconds, milliseconds and microseconds all appear — so the magnitude decides.
    Strings are handed to ``dateparser``.

    Args:
        value: Raw ``created_date`` value from a v4 inventory row.

    Returns:
        datetime | None: Parsed timestamp, or None when it cannot be parsed.
    """
    if value is None or value == "":
        return None

    if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().lstrip("-").isdigit()):
        seconds = float(value)
        if abs(seconds) >= 1e14:  # microseconds
            seconds /= 1_000_000
        elif abs(seconds) >= 1e11:  # milliseconds
            seconds /= 1_000
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None

    return dateparser.parse(str(value), settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True})


def create_incident(row: dict, created_at: datetime, incident_type: str = "Data Loss Prevention") -> dict[str, Any]:
    """
    Create an XSOAR incident from a v4 incident inventory row.

    Maps the flat v4 row onto the rawJSON keys the v1 fetch emitted — including the
    nested ``previousNotification`` and ``incidentDetails.headers`` shapes — so that
    downstream classifiers, layouts and playbooks keep resolving unchanged.

    Args:
        row: Single item from the v4 ``rows`` array.
        created_at: Parsed incident creation time.
        incident_type: Incident type label (default: "Data Loss Prevention").

    Returns:
        dict[str, Any]: XSOAR incident dict.
    """
    incident_id = row.get("incident_id", "")
    control_point = row.get("control_point") or ""
    # The server unwraps the data profiles JSON and derives data_profile_id from the
    # last element, so the matching name/version come from the same element.
    data_profiles = row.get("data_profiles") or []
    data_profile = data_profiles[-1] if data_profiles else {}

    raw_incident: dict[str, Any] = {
        "incidentId": incident_id,
        "userId": row.get("source"),
        "tenantId": None,
        "reportId": row.get("report_id"),
        "dataProfileId": row.get("data_profile_id"),
        "dataProfileName": data_profile.get("name"),
        "dataProfileVersion": data_profile.get("version"),
        "action": row.get("action"),
        "channel": control_point.lower().replace("_", "-"),
        "filename": row.get("asset_name"),
        "checksum": None,
        "fileType": None,
        "source": control_point,
        "appId": None,
        "appName": None,
        "createdAt": created_at.isoformat(),
        "region": row.get("source_region"),
        "previousNotification": {"feedback_status": row.get("feedback_status")},
        "incidentDetails": {"headers": [{"attribute_name": "severity", "attribute_value": row.get("severity")}]},
    }

    demisto.debug(f"Creating new incident with {incident_id=} in region={raw_incident['region']}.")
    event_dump = json.dumps(raw_incident)

    return {
        "name": f"Palo Alto Networks DLP Incident {incident_id}",
        "type": incident_type,
        "occurred": created_at.isoformat(),
        "rawJSON": event_dump,
        "details": event_dump,
    }


def compute_next_run(
    incident_ids_committed_timestamps: dict[str, int],
    last_run: dict[str, Any],
    has_new_incidents: bool,
    last_queried_end_time: int,
    look_back_minutes: int = 0,
) -> dict[str, Any]:
    """
    Compute the next run state based on fetched incidents using their committed timestamps.

    Retains incident IDs within the lookback retention window
    `[max_ts - (look_back_minutes * 60 + END_TIME_BUFFER), max_ts]` so that the next
    fetch can deduplicate incidents re-queried due to lookback.

    When no new incidents were fetched, advances `start_timestamp` to `last_queried_end_time`
    so the query window always slides forward and never grows unboundedly.

    Args:
        incident_ids_committed_timestamps (dict[str, int]): Mapping of incident ID → committedAt
            epoch timestamp (seconds). Must include carry-over IDs from the previous last run.
        last_run (dict[str, Any]): Previous last run state.
        has_new_incidents (bool): Whether any new (non-duplicate) incidents were fetched.
        last_queried_end_time (int): The end_time of the last queried interval. Used to advance
            start_timestamp when no new incidents are found.
        look_back_minutes (int): Minutes of lookback configured for the integration. Determines
            how wide the ID retention window is. Defaults to 0.

    Returns:
        dict[str, Any]: Next run state with `start_timestamp` and `last_ids_timestamps`.
    """
    if not has_new_incidents:
        demisto.debug(
            f"No new incidents were fetched. Advancing last run {START_TIMESTAMP_KEY} to {last_queried_end_time=} "
            "to slide the query window forward."
        )
        return {**last_run, START_TIMESTAMP_KEY: last_queried_end_time}

    new_last_committed_timestamp = max(incident_ids_committed_timestamps.values())

    # Retain IDs within (look_back_minutes * 60 + END_TIME_BUFFER) seconds of the latest timestamp
    # so they are available for deduplication on the next fetch that re-queries the lookback window.
    retention_cutoff = new_last_committed_timestamp - (look_back_minutes * 60 + END_TIME_BUFFER)
    demisto.debug(f"Computing next run: {new_last_committed_timestamp=}, {look_back_minutes=}, {retention_cutoff=}.")

    new_last_ids_timestamps: dict[str, int] = {
        _id: ts for _id, ts in incident_ids_committed_timestamps.items() if ts >= retention_cutoff
    }

    demisto.debug(f"Retaining {len(new_last_ids_timestamps)} incident IDs in last run for deduplication.")
    return {START_TIMESTAMP_KEY: new_last_committed_timestamp, LAST_IDS_TIMESTAMPS_KEY: new_last_ids_timestamps}


def get_start_end_time_intervals(start: int, end: int, seconds_delta: int) -> list[tuple[int, int]]:
    """
    Generate a list of time interval tuples from start to end timestamp.

    Args:
        start (int): Starting epoch timestamp in seconds
        end (int): Ending epoch timestamp in seconds
        seconds_delta (int): The delta in seconds for each interval

    Returns:
        A list of tuples where each tuple contains (interval_start, interval_end)

    Example:
        >>> get_start_end_time_intervals(0, 900, 300)
        [(0, 300), (300, 600), (600, 900)]
    """
    intervals: list[tuple[int, int]] = []
    current = start

    while current < end:
        next_timestamp = min(current + seconds_delta, end)
        intervals.append((current, next_timestamp))
        current = next_timestamp

    return intervals


def _migrate_last_run(last_run: dict[str, Any], start_timestamp: int) -> dict[str, int]:
    """
    Migrate the legacy `last_ids` list schema to the new `last_ids_timestamps` dict schema.

    Legacy IDs are seeded with `start_timestamp` as a conservative deduplication baseline.

    Args:
        last_run (dict[str, Any]): Raw last run object from `demisto.getLastRun()`.
        start_timestamp (int): Epoch timestamp (seconds) to assign to each migrated ID.

    Returns:
        dict[str, int]: Mapping of incident_id → committedAt epoch timestamp.
    """
    if LAST_IDS_TIMESTAMPS_KEY in last_run:
        return dict(last_run[LAST_IDS_TIMESTAMPS_KEY])

    # Legacy schema: plain list of IDs — migrate by seeding with start_timestamp
    legacy_ids: list[str] = last_run.get(LAST_IDS_KEY) or []
    if legacy_ids:
        demisto.debug(
            f"Migrating {len(legacy_ids)} legacy incident IDs from '{LAST_IDS_KEY}' "
            f"to '{LAST_IDS_TIMESTAMPS_KEY}' schema, seeding with {start_timestamp=}."
        )
    return {incident_id: start_timestamp for incident_id in legacy_ids}


def fetch_notifications(
    client: Client,
    regions: str,
    first_fetch_timestamp: int,
    incident_type: str = "Data Loss Prevention",
    max_fetch: int = DEFAULT_MAX_FETCH,
    look_back_minutes: int = 0,
) -> tuple[dict, list[dict]]:
    """
    Fetch DLP notifications using time-based queries with ID-based deduplication and optional lookback.

    Args:
        client (Client): DLP API client.
        regions (str): Comma-separated DLP regions to fetch from.
        first_fetch_timestamp (int): Timestamp to use for first fetch (unix epoch seconds).
        incident_type (str): Type of incident to create (default: "Data Loss Prevention").
        max_fetch (int): Maximum number of incidents to fetch (default: DEFAULT_MAX_FETCH).
        look_back_minutes (int): Minutes to look back from the last committed timestamp to catch
            late-indexed incidents. Defaults to 0 (no lookback).

    Returns:
        tuple[dict, list[dict]]: Next run state and list of new incidents.
    """
    integration_context = demisto.getIntegrationContext()
    access_token = integration_context.get(ACCESS_TOKEN)
    if access_token:
        client.set_access_token(access_token)

    last_run = demisto.getLastRun() or {}  # May return as "None" on the first fetch
    demisto.debug(f"Got {last_run=}.")
    start_timestamp = last_run.get(START_TIMESTAMP_KEY) or first_fetch_timestamp

    # Apply lookback: re-query from (start_timestamp - look_back_minutes) to catch late-indexed incidents
    effective_start_timestamp = start_timestamp - look_back_minutes * 60
    demisto.debug(f"Lookback applied: {look_back_minutes=}, {start_timestamp=}, {effective_start_timestamp=}.")

    # Provide buffer to account for minor indexing delays
    end_timestamp = int(datetime.now(tz=UTC).timestamp()) - END_TIME_BUFFER

    # Migrate legacy schema and seed the deduplication accumulator with previously seen IDs
    fetched_incident_ids_committed_timestamps: dict[str, int] = _migrate_last_run(last_run, start_timestamp)

    demisto.debug(f"Starting to fetch incidents using {max_fetch=} between {effective_start_timestamp=} and {end_timestamp=}.")
    demisto.debug(
        f"Deduplicating using {len(fetched_incident_ids_committed_timestamps)} IDs: "
        f"{list(fetched_incident_ids_committed_timestamps.keys())}."
    )

    new_incidents: list[dict] = []

    # Convert to milliseconds for the v4 API
    start_time_ms = effective_start_timestamp * 1000
    end_time_ms = end_timestamp * 1000

    # A single query covers every configured region, so the watermark below is derived
    # from all of them rather than from whichever region happened to be queried last.
    resp, _ = client.get_incidents_first_page(start_time_ms=start_time_ms, end_time_ms=end_time_ms, regions=regions)
    query_token = resp.get("query_token") or ""
    total_rows = resp.get("total_rows") or 0
    rows: list[dict] = resp.get("rows") or []
    demisto.debug(f"First page: {len(rows)} rows, {total_rows=}, status={resp.get('status')}.")

    # The backend can acknowledge the query before its results are ready.
    attempts = 0
    while resp.get("status") == "PENDING" and not rows and query_token and attempts < V4_PENDING_ATTEMPTS:
        attempts += 1
        demisto.debug(f"Query is PENDING, re-polling the query token (attempt {attempts}).")
        time.sleep(V4_PENDING_SLEEP)
        resp, _ = client.get_incidents_next_page(query_token, 0)
        rows = resp.get("rows") or []
        total_rows = resp.get("total_rows") or total_rows

    offset = 0
    while rows:
        offset += len(rows)
        for row in rows:
            if len(new_incidents) >= max_fetch:
                break

            incident_id = row.get("incident_id", "")
            if incident_id in fetched_incident_ids_committed_timestamps:
                demisto.debug(f"Skipping duplicate {incident_id=}.")
                continue

            created_at = parse_created_date(row.get("created_date"))
            if created_at is None:
                demisto.debug(f"Skipping {incident_id=}, unparsable created_date={row.get('created_date')!r}.")
                continue

            new_incidents.append(create_incident(row, created_at, incident_type))
            fetched_incident_ids_committed_timestamps[incident_id] = int(created_at.timestamp())

        if len(new_incidents) >= max_fetch or not query_token or (total_rows and offset >= total_rows):
            break

        resp, _ = client.get_incidents_next_page(query_token, offset)
        rows = resp.get("rows") or []
        demisto.debug(f"Fetched {len(rows)} rows at {offset=}.")

    demisto.debug(f"Finished fetching. Got {len(new_incidents)} new incidents.")
    demisto.debug(f"Fetched incidents: {[inc.get('name') for inc in new_incidents]}.")

    demisto.debug("Updating integration context with access token.")
    demisto.setIntegrationContext({ACCESS_TOKEN: client.access_token})

    next_run = compute_next_run(
        fetched_incident_ids_committed_timestamps,
        last_run=last_run,
        look_back_minutes=look_back_minutes,
        has_new_incidents=bool(new_incidents),
        last_queried_end_time=end_timestamp,
    )
    demisto.debug(f"Computed updated {next_run=}.")
    return next_run, new_incidents


def fetch_incidents(client: Client, params: dict) -> tuple[dict, list[dict]]:
    """
    Fetch incidents from Palo Alto Networks Enterprise DLP using time-based queries with deduplication.

    Args:
        client (Client): DLP API client instance.
        params (dict): Integration instance configuration parameters.

    Returns:
        tuple[dict, list[dict]]: Next run state and list of fetched incidents.
    """
    regions = params.get("dlp_regions", "")
    incident_type = params.get("incidentType", "Data Loss Prevention")

    first_fetch = params.get("first_fetch") or DEFAULT_FIRST_FETCH
    first_fetch_datetime = arg_to_datetime(first_fetch, settings={"TIMEZONE": "UTC"})
    first_fetch_timestamp = int(first_fetch_datetime.timestamp())  # type: ignore

    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
    look_back_minutes = arg_to_number(params.get("look_back")) or 0

    return fetch_notifications(
        client=client,
        regions=regions,
        first_fetch_timestamp=first_fetch_timestamp,
        incident_type=incident_type,
        max_fetch=max_fetch,
        look_back_minutes=look_back_minutes,
    )


def exemption_eligible_command(args: dict, params: dict) -> CommandResults:
    data_profile = args.get("data_profile")
    eligible_list = params.get("dlp_exemptible_list", "")
    if eligible_list == "*":
        eligible = True
    else:
        eligible = data_profile in eligible_list

    result = {"eligible": eligible}
    return CommandResults(outputs_prefix="DLP.exemption", outputs_key_field="eligible", outputs=result)


def slack_bot_message_command(args: dict, params: dict):
    message_template = params.get("dlp_slack_message", "")
    template = Template(message_template)
    message = template.substitute(
        user=args.get("user"),
        file_name=args.get("file_name"),
        data_profile_name=args.get("data_profile_name"),
        app_name=args.get("app_name"),
        snippets=args.get("snippets", ""),
    )
    result = {"message": message}
    return CommandResults(outputs_prefix="DLP.slack_message", outputs_key_field="slack_message", outputs=result)


def reset_last_run_command() -> CommandResults:
    """
    Deprecated command to reset flag inside integration context.
    Returns:
        CommandResults: Contains a human-readable message.
    """
    return CommandResults(
        readable_output="This command is deprecated."
        'Reset the "last run" timestamp via the integration instance configuration window.',
        entry_type=EntryType.WARNING,
    )


def main():
    """Main Function"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    try:
        print_debug_msg(f'Received parameters: {",".join(params.keys())}.')
        credentials = params.get("credentials", {})
        base_url = params.get("base_url") or DEFAULT_BASE_URL
        auth_url = params.get("auth_url") or DEFAULT_AUTH_URL
        verify = not params.get("insecure", True)
        proxy = params.get("proxy", False)

        demisto.info(f"Command being called is {command}.")
        client = Client(base_url, auth_url, credentials, verify, proxy)

        if command == "pan-dlp-get-report":
            report_id = args.get("report_id")
            fetch_snippets = argToBoolean(args.get("fetch_snippets"))
            report_json, _ = client.get_dlp_report(report_id, fetch_snippets)
            return_results(parse_dlp_report(report_json))
        elif command == "fetch-incidents":
            next_run, new_incidents = fetch_incidents(client, params)
            demisto.incidents(new_incidents)
            demisto.setLastRun(next_run)
        elif command == "pan-dlp-update-incident":
            return_results(update_incident_command(client, args))
        elif command == "pan-dlp-exemption-eligible":
            return_results(exemption_eligible_command(args, params))
        elif command == "pan-dlp-slack-message":
            return_results(slack_bot_message_command(args, params))
        elif command == "pan-dlp-reset-last-run":
            return_results(reset_last_run_command())
        elif command == "test-module":
            test(client, params)
        else:
            raise NotImplementedError(f"Unknown command {command}.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


if __name__ in ["__builtin__", "builtins", "__main__"]:
    main()

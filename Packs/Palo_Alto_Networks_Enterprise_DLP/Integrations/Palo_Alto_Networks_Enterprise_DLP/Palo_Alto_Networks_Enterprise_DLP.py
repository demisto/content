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
MAX_LAST_FETCHED_IDS = 200
DEFAULT_MAX_FETCH = 50
DEFAULT_BASE_URL = "https://api.dlp.paloaltonetworks.com/v1/"
DEFAULT_AUTH_URL = "https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token"
REPORT_URL = "public/report/{}"
INCIDENTS_URL = "public/incident-notifications"
REFRESH_TOKEN_URL = "public/oauth/refreshToken"
UPDATE_INCIDENT_URL = "public/incident-feedback"
SLEEP_TIME_URL = "public/seconds-between-incident-notifications-pull"
FETCH_SLEEP = 5  # sleep between fetches (in seconds)
LAST_FETCH_TIME = "last_fetch_time"
DEFAULT_FIRST_FETCH = "60 minutes"
ACCESS_TOKEN = "access_token"
RESET_KEY = "reset"
CREDENTIAL = "credential"
IDENTIFIER = "identifier"
PASSWORD = "password"
END_TIME_BUFFER = 30  # seconds

# Last run
LAST_RUN_KEY = "last_run"
START_TIMESTAMP_KEY = "start_timestamp"
LAST_IDS_KEY = "last_ids"
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

    def _get_dlp_api_call(self, url_suffix: str) -> tuple[dict[str, Any], int]:
        """
        Makes a HTTPS Get call on the DLP API
        Args:
            url_suffix: URL suffix for dlp api call
        """
        count = 0
        print_debug_msg(f"Calling GET method on {self._base_url}{url_suffix}")
        while count < MAX_ATTEMPTS:
            res = self._http_request(
                method="GET",
                headers={"Authorization": "Bearer " + self.access_token},
                url_suffix=url_suffix,
                ok_codes=[200, 201, 204],
                error_handler=self._handle_4xx_errors,
                resp_type="",
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

    def _post_dlp_api_call(self, url_suffix: str, payload: dict = None):
        """
        Makes a POST HTTP(s) call to the DLP API
        Args:
            url_suffix: URL suffix for dlp api call
            payload: Optional JSON payload
        """
        count = 0

        while count < MAX_ATTEMPTS:
            res = self._http_request(
                method="POST",
                headers={"Authorization": f"Bearer {self.access_token}"},
                url_suffix=url_suffix,
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

    def get_dlp_incidents(
        self,
        regions: str,
        start_time: int | None = None,
        end_time: int | None = None,
    ) -> tuple[dict[str, Any], int]:
        url = INCIDENTS_URL
        params = {}
        if regions:
            params["regions"] = regions
        if start_time:
            params["start_timestamp"] = str(start_time)
        if end_time:
            params["end_timestamp"] = str(end_time)
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"
        resp, status_code = self._get_dlp_api_call(url)
        return resp, status_code

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
    dlp_regions = params.get("dlp_regions", "")
    report_json, status_code = client.get_dlp_incidents(regions=dlp_regions)
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


def create_incident(notification: dict, region: str, incident_type: str = "Data Loss Prevention") -> dict[str, Any]:
    """
    Create an XSOAR incident from a DLP notification.

    Args:
        notification: DLP notification containing incident data and previous notifications
        region: DLP region where the incident occurred
        incident_type: Type of incident to create (default: "Data Loss Prevention")

    Returns:
        dict[str, Any]: XSOAR incident object with name, type, occurred time, and raw JSON data
    """
    raw_incident = notification["incident"]
    previous_notifications = notification["previous_notifications"]
    raw_incident["region"] = region
    raw_incident["previousNotification"] = previous_notifications[0] if len(previous_notifications) > 0 else None
    parsed_details = parse_incident_details(raw_incident["incidentDetails"])
    raw_incident["incidentDetails"] = parsed_details
    if not raw_incident.get("userId"):
        for header in parsed_details.get("headers", []):
            attribute_name = header.get("attribute_name")
            attribute_value = header.get("attribute_value")
            if attribute_name == "username" and attribute_value:
                raw_incident["userId"] = attribute_value

    incident_creation_time = cast(datetime, dateparser.parse(raw_incident["createdAt"]))
    incident_id = raw_incident["incidentId"]
    incident_timestamp = int(incident_creation_time.timestamp())
    demisto.debug(f"Creating new incident with {incident_id=} and {incident_timestamp=} in {region=}.")
    event_dump = json.dumps(raw_incident)

    return {
        "name": f"Palo Alto Networks DLP Incident {incident_id}",
        "type": incident_type,
        "occurred": incident_creation_time.isoformat(),
        "rawJSON": event_dump,
        "details": event_dump,
    }


def compute_next_run(incident_ids_committed_timestamps: dict[str, int], last_run: dict[str, Any]) -> dict[str, Any]:
    """
    Compute the next run state based on fetched incidents using their committed timestamps.

    Args:
        incident_ids_committed_timestamps (dict[str, int]): Dictionary mapping incident IDs to their committedAt timestamps.
        last_run (dict[str, Any]): Previous last run state to return if no incidents were fetched.

    Returns:
        dict[str, Any]: Dictionary with start_timestamp (latest committedAt) and last_ids
                        (all incident IDs with that timestamp) for next fetch.
    """
    if not incident_ids_committed_timestamps:
        return last_run

    new_last_committed_timestamp = max(incident_ids_committed_timestamps.values())
    # Filter incidents within buffer window, sort by timestamp (oldest to newest), keep newest MAX_LAST_FETCHED_IDS
    # 30 seconds buffer taken as a safety margin to account for resolution of filtering start_timestamp
    new_last_incident_ids = [
        _id
        for _id, _ in sorted(
            (
                (_id, ts)
                for _id, ts in incident_ids_committed_timestamps.items()
                if ts >= new_last_committed_timestamp - END_TIME_BUFFER
            ),
            key=lambda x: x[1],
        )[-MAX_LAST_FETCHED_IDS:]
    ]

    return {START_TIMESTAMP_KEY: new_last_committed_timestamp, LAST_IDS_KEY: new_last_incident_ids}


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


def fetch_notifications(
    client: Client,
    regions: str,
    first_fetch_timestamp: int,
    incident_type: str = "Data Loss Prevention",
    max_fetch: int = DEFAULT_MAX_FETCH,
) -> tuple[dict, list[dict]]:
    """
    Fetch DLP notifications using time-based queries with ID-based deduplication.

    Args:
        client: DLP API client.
        regions: Comma-separated DLP regions to fetch from.
        first_fetch_timestamp: Timestamp to use for first fetch (unix epoch seconds).
        incident_type: Type of incident to create (default: "Data Loss Prevention").
        max_fetch: Maximum number of incidents to fetch (default: DEFAULT_MAX_FETCH).

    Returns:
        tuple[dict, list[dict]]: Next run state and list of new incidents.
    """
    integration_context = demisto.getIntegrationContext()
    access_token = integration_context.get(ACCESS_TOKEN)
    if access_token:
        client.set_access_token(access_token)

    last_run = demisto.getLastRun() or {}  # May return as "None" on the first fetch
    demisto.debug(f"Got {last_run=}.")
    last_incident_ids = last_run.get(LAST_IDS_KEY) or []
    start_timestamp = last_run.get(START_TIMESTAMP_KEY) or first_fetch_timestamp
    # Provide buffer to account for minor indexing delays
    end_timestamp = int(datetime.now(tz=UTC).timestamp()) - END_TIME_BUFFER

    new_incidents: list[dict] = []
    fetched_incident_ids_committed_timestamps: dict[str, int] = {
        incident_id: start_timestamp for incident_id in last_incident_ids
    }

    demisto.debug(f"Starting to fetch incidents using {max_fetch=} between {start_timestamp=} and {end_timestamp=}.")
    demisto.debug(f"Deduplicating using {len(last_incident_ids)} IDs: {last_incident_ids}.")
    # Query the API in 3 minute start/end time window, this filters incidents according to their "committedAt" timestamps
    for start_time, end_time in get_start_end_time_intervals(start_timestamp, end_timestamp, seconds_delta=180):
        if len(new_incidents) >= max_fetch:
            demisto.debug(f"Reached or exceeded fetch limit. Fetched {len(new_incidents)} incidents. Breaking...")
            break

        demisto.debug(f"Getting incidents between {start_time=} and {end_time=} from {regions=}.")
        notification_map, _ = client.get_dlp_incidents(regions, start_time, end_time)

        notifications = [
            {**raw_notification, "region": region}
            for region, raw_notifications in notification_map.items()
            for raw_notification in raw_notifications
        ]
        demisto.debug(f"Received {len(notifications)} notifications between {start_time=} and {end_time=}.")
        notifications.sort(key=lambda x: x["incident"]["committedAt"])

        for notification in notifications:
            # Use "incidentId" and "committedAt" fields for deduplication and last run tracking
            # These are required fields that are guaranteed to exist for each DLP incident
            region = notification["region"]
            incident_id = notification["incident"]["incidentId"]
            incident_committed_timestamp = int(dateparser.parse(notification["incident"]["committedAt"]).timestamp())  # type: ignore
            if incident_id in fetched_incident_ids_committed_timestamps:
                demisto.debug(f"Skipping duplicate {incident_id=} with {incident_committed_timestamp=} in {region=}.")
                continue

            if len(new_incidents) >= max_fetch:
                demisto.debug(f"Reached or exceeded fetch limit. Fetched {len(new_incidents)} incidents. Breaking...")
                break

            incident = create_incident(notification, region, incident_type)
            new_incidents.append(incident)
            fetched_incident_ids_committed_timestamps[incident_id] = incident_committed_timestamp

    demisto.debug(f"Finished fetching incidents using {max_fetch=} between {start_timestamp=} and {end_timestamp=}.")
    demisto.debug(f"Fetched {len(new_incidents)} deduplicated incidents: {[inc.get('name') for inc in new_incidents]}.")

    demisto.debug("Updating integration context with access token.")
    demisto.setIntegrationContext({ACCESS_TOKEN: client.access_token})

    next_run = compute_next_run(fetched_incident_ids_committed_timestamps, last_run)
    demisto.debug(f"Computed updated {next_run=}.")
    return next_run, new_incidents


def fetch_incidents(client: Client, params: dict) -> tuple[dict, list[dict]]:
    """
    Fetch incidents from Palo Alto Networks Enterprise DLP using time-based queries with deduplication.

    Args:
        client: DLP API client instance.
        params: Integration instance configuration parameters.

    Returns:
        tuple[dict, list[dict]]: Next run state and list of fetched incidents.
    """
    regions = params.get("dlp_regions", "")
    incident_type = params.get("incidentType", "Data Loss Prevention")

    first_fetch = params.get("first_fetch") or DEFAULT_FIRST_FETCH
    first_fetch_datetime = arg_to_datetime(first_fetch, settings={"TIMEZONE": "UTC"})
    first_fetch_timestamp = int(first_fetch_datetime.timestamp())  # type: ignore

    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

    return fetch_notifications(
        client=client,
        regions=regions,
        first_fetch_timestamp=first_fetch_timestamp,
        incident_type=incident_type,
        max_fetch=max_fetch,
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

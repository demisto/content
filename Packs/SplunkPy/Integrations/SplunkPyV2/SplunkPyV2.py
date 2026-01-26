import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import hashlib
import io
import json
import re
import time
import urllib.parse
from datetime import datetime, timedelta

import dateparser
from collections import defaultdict

import pytz
import requests

from splunklib import client, results
from splunklib.binding import AuthenticationError, HTTPError, namespace
from splunklib.data import Record

INTEGRATION_LOG = "SplunkPyV2- "
OUTPUT_MODE_JSON = "json"  # type of response from splunk-sdk query (json/csv/xml)
params = demisto.params()
DEFAULT_ASSET_ENRICH_TABLES = "asset_lookup_by_str,asset_lookup_by_cidr"
DEFAULT_IDENTITY_ENRICH_TABLE = "identity_lookup_expanded"
VERIFY_CERTIFICATE = not bool(params.get("unsecure"))
FETCH_LIMIT = int(params.get("max_fetch")) if params.get("max_fetch") else 50
FETCH_LIMIT = max(min(200, FETCH_LIMIT), 1)
MIRROR_LIMIT = 1000
SPLUNK_INDEXING_TIME = 60
PROBLEMATIC_CHARACTERS = [".", "(", ")", "[", "]"]
REPLACE_WITH = "_"
REPLACE_FLAG = params.get("replaceKeys", False)
FIRST_FETCH_TIME = params.get("first_fetch", "10 minutes")
PROXIES = handle_proxy()
DEFAULT_DISPOSITIONS = {
    "Unassigned": "disposition:0",
    "True Positive - Suspicious Activity": "disposition:1",
    "Benign Positive - Suspicious But Expected": "disposition:2",
    "False Positive - Incorrect Analytic Logic": "disposition:3",
    "False Positive - Inaccurate Data": "disposition:4",
    "Other": "disposition:5",
    "Undetermined": "disposition:6",
}

DEFAULT_STATUSES = {
    "Unassigned": "0",
    "Assigned": "1",
    "In Progress": "2",
    "Pending": "3",
    "Resolved": "4",
    "Closed": "5",
}

# =========== Mirroring Mechanism Globals ===========
MIRROR_DIRECTION = {"None": None, "Incoming": "In", "Outgoing": "Out", "Incoming And Outgoing": "Both"}
OUTGOING_MIRRORED_FIELDS = ["note", "status", "owner", "urgency", "reviewer", "disposition"]

# === Note Tag Globals ===
NOTE_TAG_TO_SPLUNK = params.get("note_tag_to_splunk", "FROM XSOAR")
NOTE_TAG_FROM_SPLUNK = params.get("note_tag_from_splunk", "FROM SPLUNK")

# =========== Enrichment Mechanism Globals ===========
ENABLED_ENRICHMENTS = params.get("enabled_enrichments", [])

DRILLDOWN_ENRICHMENT = "Drilldown"
ASSET_ENRICHMENT = "Asset"
IDENTITY_ENRICHMENT = "Identity"
SUBMITTED_FINDINGS = "submitted_findings"
EVENT_ID = "event_id"
RULE_ID = "rule_id"
ISO_FORMAT_TZ_AWARE = "%Y-%m-%dT%H:%M:%S.%f%z"  # e.g '2025-12-03T11:53:45.138540+00:00
NOT_YET_SUBMITTED_FINDINGS = "not_yet_submitted_findings"
INFO_MIN_TIME = "info_min_time"
INFO_MAX_TIME = "info_max_time"
INCIDENTS = "incidents"
MIRRORED_ENRICHING_FINDINGS = "MIRRORED_ENRICHING_FINDINGS"
PROCESSED_MIRRORED_EVENTS = "processed_mirror_in_events_cache"
DUMMY = "dummy"
ENRICHMENTS = "enrichments"
MAX_HANDLE_FINDINGS = 20
MAX_SUBMIT_FINDINGS = 30
CACHE = "cache"
STATUS = "status"
DATA = "data"
TYPE = "type"
ID = "id"
CREATION_TIME = "creation_time"
QUERY_NAME = "query_name"
QUERY_SEARCH = "query_search"
INCIDENT_CREATED = "incident_created"

DRILLDOWN_REGEX = r'([^\s\$]+)\s*=\s*"?(\$[^\s\$\\]+\$)"?|"?(\$[^\s\$\\]+\$)"?'

ENRICHMENT_TYPE_TO_ENRICHMENT_STATUS = {
    DRILLDOWN_ENRICHMENT: "successful_drilldown_enrichment",
    ASSET_ENRICHMENT: "successful_asset_enrichment",
    IDENTITY_ENRICHMENT: "successful_identity_enrichment",
}
COMMENT_MIRRORED_FROM_XSOAR = "***Mirrored from Cortex XSOAR***"
USER_RELATED_FIELDS = ["user", "src_user"]

# =========== Not Missing Events Mechanism Globals ===========
CUSTOM_ID = "custom_id"
OCCURRED = "occurred"
INDEX_TIME = "index_time"
TIME_IS_MISSING = "time_is_missing"


# =========== Enrich User Mechanism ============
class UserMappingObject:
    def __init__(
        self,
        service: client.Service,
        should_map_user: bool,
        table_name: str = "splunk_xsoar_users",
        xsoar_user_column_name: str = "xsoar_user",
        splunk_user_column_name: str = "splunk_user",
    ):
        """
        Args:
            service (client.Service): Splunk service object.
            should_map_user (bool): Whether to map the user or not.
            table_name (str): The name of the table in Splunk.
            xsoar_user_column_name (str): The name of the column in the table that holds the XSOAR user.
            splunk_user_column_name (str): The name of the column in the table that holds the Splunk user.
        """
        self.service = service
        self.should_map = should_map_user
        self.table_name = table_name
        self.xsoar_user_column_name = xsoar_user_column_name
        self.splunk_user_column_name = splunk_user_column_name
        self._kvstore_data: list[dict[str, Any]] = []

    def _get_record(self, col: str, value_to_search: str) -> filter:
        """Gets the records with the value found in the relevant column."""
        if not self._kvstore_data:
            demisto.debug("UserMapping: kvstore data empty, initialize it")
            kvstore: client.KVStoreCollection = self.service.kvstore[self.table_name]
            self._kvstore_data = kvstore.data.query()
            demisto.debug(f"UserMapping: {self._kvstore_data=}")
        return filter(lambda row: row.get(col) == value_to_search, self._kvstore_data)

    def get_xsoar_user_by_splunk(self, splunk_user: str):
        record = list(self._get_record(self.splunk_user_column_name, splunk_user))

        if not record:
            demisto.error(
                f"UserMapping: Could not find xsoar user matching splunk's {splunk_user}. "
                f"Consider adding it to the {self.table_name} lookup."
            )
            return ""

        # assuming username is unique, so only one record is returned.
        xsoar_user = record[0].get(self.xsoar_user_column_name)

        if not xsoar_user:
            demisto.error(
                f"UserMapping: Xsoar user matching splunk's {splunk_user} is empty. Fix the record in {self.table_name} lookup."
            )
            return ""

        return xsoar_user

    def get_splunk_user_by_xsoar(self, xsoar_user: str, map_missing: bool = True):
        record = list(self._get_record(self.xsoar_user_column_name, xsoar_user))

        if not record:
            demisto.error(
                f"UserMapping: Could not find splunk user matching xsoar's {xsoar_user}. "
                f"Consider adding it to the {self.table_name} lookup."
            )
            return "unassigned" if map_missing else None

        # assuming username is unique, so only one record is returned.
        splunk_user = record[0].get(self.splunk_user_column_name)

        if not splunk_user:
            demisto.error(
                f"UserMapping: Splunk user matching Xsoar's {xsoar_user} is empty. Fix the record in {self.table_name} lookup."
            )
            return "unassigned" if map_missing else None

        return splunk_user

    def get_splunk_user_by_xsoar_command(self, args: dict[str, str]) -> CommandResults:
        xsoar_users = argToList(args.get("xsoar_username"))
        map_missing = argToBoolean(args.get("map_missing", True))

        outputs = []
        for user in xsoar_users:
            splunk_user = self.get_splunk_user_by_xsoar(user, map_missing=map_missing) if user else None
            outputs.append(
                {"XsoarUser": user, "SplunkUser": splunk_user or "Could not map splunk user, Check logs for more info."}
            )

        return CommandResults(
            outputs=outputs,
            outputs_prefix="Splunk.UserMapping",
            readable_output=tableToMarkdown("Xsoar-Splunk Username Mapping", outputs, headers=["XsoarUser", "SplunkUser"]),
        )

    def update_xsoar_user_in_findings(self, findings_data: list[dict]):
        """In case of `should_map_user` is True, update the 'owner' in the findings to be the mapped XSOAR user.

        Args:
            findings_data (list[dict]): The findings to be updated.
        """
        if self.should_map:
            demisto.debug("UserMapping: instance configured to map Splunk user to XSOAR users, trying to map.")
            for finding_data in findings_data:
                if splunk_user := finding_data.get("owner"):
                    xsoar_user = self.get_xsoar_user_by_splunk(splunk_user)
                    finding_data["owner"] = xsoar_user
                    demisto.debug(
                        f"UserMapping: 'owner' was mapped from {splunk_user} to {xsoar_user} "
                        f"for finding {finding_data.get(EVENT_ID)}."
                    )


class SplunkGetModifiedRemoteDataResponse(GetModifiedRemoteDataResponse):
    """get-modified-remote-data response parser

    :type modified_findings_data: ``list``
    :param modified_findings_data: The Findings that were modified since the last check.

    :type entries: ``list``
    :param entries: The entries you want to add to the war room.

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, modified_findings_data, entries):
        self.modified_findings_data = modified_findings_data
        self.entries = entries
        extensive_log(f"mirror-in: updated findings: {self.modified_findings_data}")
        extensive_log(f"mirror-in: updated entries: {self.entries}")

    def to_entry(self):
        """Convert data to entries.

        :return: List of findings data as entries + entries (from comments and close data),
                 or [{}] if there are only entries and no modified findings.
        :rtype: ``list``
        """
        findings_entries = [
            {
                "EntryContext": {"mirrorRemoteId": data[RULE_ID]},
                "Contents": data,
                "Type": EntryType.NOTE,
                "ContentsFormat": EntryFormat.JSON,
            }
            for data in self.modified_findings_data
        ]

        if not findings_entries and self.entries:
            return [{}] + self.entries

        return findings_entries + self.entries


# =========== Time & Date Utilities ===========


def get_current_splunk_time(splunk_service: client.Service) -> str:
    """Get the current time from the Splunk server in ISO format with timezone.

    This query uses the gentimes command to generate a single time event, then formats it
    using strftime to get the current server time in ISO_FORMAT_TZ_AWARE format.
    The timezone offset in the result is according to the timezone configured for the user
    who owns the token that was provided for authentication.

    Args:
        splunk_service: Splunk service object

    Returns:
        Current Splunk server time as a string in ISO_FORMAT_TZ_AWARE format
        (e.g., '2025-12-03T11:53:45.138540+02:00')

    Raises:
        ValueError: If the Splunk time cannot be fetched
    """
    get_time_query = f'| gentimes start=-1 | eval clock = strftime(time(), "{ISO_FORMAT_TZ_AWARE}") | sort 1 -_time | table clock'
    search_results = splunk_service.jobs.oneshot(get_time_query, count=1, output_mode=OUTPUT_MODE_JSON)

    reader = results.JSONResultsReader(search_results)
    for item in reader:
        if isinstance(item, dict):
            return item["clock"]
        if handle_message(item):
            continue

    raise ValueError("Error: Could not fetch Splunk time")


def extract_timezone_offset_from_splunk_time(splunk_time_str: str) -> str:
    """Extract timezone offset from Splunk time string.

    Args:
        splunk_time_str: Time string in ISO_FORMAT_TZ_AWARE format
                        (e.g., '2025-12-03T11:53:45.138540+02:00')

    Returns:
        Timezone offset string (e.g., '+02:00', '-05:00')
        Returns '+00:00' if extraction fails
    """
    try:
        # Parse the datetime string to extract timezone
        dt = datetime.strptime(splunk_time_str, ISO_FORMAT_TZ_AWARE)
        # Get the timezone offset
        tz_offset = dt.strftime("%z")
        # Format as +HH:MM
        return f"{tz_offset[:3]}:{tz_offset[3:]}"
    except Exception as e:
        demisto.error(f"Failed to extract timezone from '{splunk_time_str}' using +00:00 as timezone : {e}")
        return "+00:00"  # Default to UTC


def get_splunk_timezone_offset(service: client.Service) -> str:
    """Get Splunk server timezone offset with caching.

    Retrieves the timezone offset from integration context cache.
    If not cached, queries Splunk server and caches the result.

    Args:
        service: Splunk service object

    Returns:
        Timezone offset string (e.g., '+02:00')
    """
    TIMEZONE_CACHE_KEY = "splunk_timezone_offset"

    # Try to get from cache
    integration_context = get_integration_context()
    cached_timezone = integration_context.get(TIMEZONE_CACHE_KEY)

    if cached_timezone:
        demisto.debug(f"Using cached Splunk timezone: {cached_timezone}")
        return cached_timezone

    # Not cached - query Splunk
    demisto.debug("Timezone not cached, querying Splunk server")
    try:
        splunk_time = get_current_splunk_time(service)
        timezone_offset = extract_timezone_offset_from_splunk_time(splunk_time)

        # Cache the timezone
        integration_context[TIMEZONE_CACHE_KEY] = timezone_offset
        set_integration_context(integration_context)

        demisto.debug(f"Cached Splunk timezone: {timezone_offset}")
        return timezone_offset

    except Exception as e:
        demisto.error(f"Failed to get Splunk timezone: using +00:00 as default {e}")
        return "+00:00"  # Default to UTC on error


def enforce_lookback_time(fetch_window_start_time, fetch_window_end_time, look_behind_time):
    """Verifies that the start time of the fetch is at X minutes before
    the end time, X being the number of minutes specified in the look_behind parameter.
    The reason this is needed is to ensure that events that have a significant difference
    between their index time and occurrence time in Splunk are still fetched and are not missed.

    Args:
        fetch_window_start_time (str): The current start time of the fetch.
        fetch_window_end_time (str): The current end time of the fetch.
        look_behind_time (int): The minimal difference (in minutes) that should be enforced between
                                the start time and end time.

    Returns:
        fetch_window_start_time (str): The new start time for the fetch.
    """
    start_time_datetime = datetime.strptime(fetch_window_start_time, ISO_FORMAT_TZ_AWARE)
    end_time_datetime = datetime.strptime(fetch_window_end_time, ISO_FORMAT_TZ_AWARE)
    if end_time_datetime - start_time_datetime < timedelta(minutes=look_behind_time):
        start_time_datetime = end_time_datetime - timedelta(minutes=look_behind_time)
        return datetime.strftime(start_time_datetime, ISO_FORMAT_TZ_AWARE)
    return fetch_window_start_time


def get_fetch_time_window(params, service, last_run_fetch_window_start_time: str, last_run_fetch_window_end_time: str):
    """Calculate the time window (start and end times) for fetching incidents from Splunk.

    This function determines the boundaries of the fetch query time window, handling first-time fetches,
    enforcing look-behind periods for late-indexed events, and supporting both Splunk server time and local system time.

    Args:
        params: Integration parameters
        service: Splunk service object
        last_run_fetch_window_start_time: The earliest time from the last run (string in ISO_FORMAT_TZ_AWARE)
        last_run_fetch_window_end_time: The latest time from the last run (string in ISO_FORMAT_TZ_AWARE)

    Returns:
        tuple: (fetch_window_start_time, fetch_window_end_time) - both as strings in ISO_FORMAT_TZ_AWARE
    """
    fetch_window_start_time = last_run_fetch_window_start_time
    fetch_window_end_time = last_run_fetch_window_end_time

    # If this is the first fetch (no last run time), calculate it based on first_fetch parameter
    if not fetch_window_start_time:
        demisto.debug(f"[SplunkPy] First fetch - calculated earliest time: {fetch_window_start_time}")
        parse_setting = {"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True}
        if parsed_time := dateparser.parse(FIRST_FETCH_TIME, settings=parse_setting):  # type: ignore[arg-type]
            fetch_window_start_time = parsed_time.strftime(ISO_FORMAT_TZ_AWARE)
        else:
            raise DemistoException(f"Failed to parse first fetch time: {FIRST_FETCH_TIME}")

    # if fetch_window_end_time is not None it's mean we are in a batch fetch iteration with offset
    # if it's none - take the current time
    if not fetch_window_end_time:
        # Get current time string - either from Splunk server or local system
        # Use Splunk server time to avoid timezone issues
        current_time_from_splunk = get_current_splunk_time(service)
        if datatime_from_splunk_as_utc := dateparser.parse(current_time_from_splunk, settings={"TIMEZONE": "UTC"}):
            fetch_window_end_time = datatime_from_splunk_as_utc.strftime(ISO_FORMAT_TZ_AWARE)
        else:
            raise DemistoException(f"Failed to parse Splunk time: {current_time_from_splunk}")

    occurrence_time_look_behind_minutes = arg_to_number(params.get("occurrence_look_behind") or 15)
    extensive_log(f"[SplunkPy] occurrence look behind is: {occurrence_time_look_behind_minutes}")

    # Enforce look-back time to ensure we don't miss late-indexed events
    fetch_window_start_time = enforce_lookback_time(
        fetch_window_start_time, fetch_window_end_time, occurrence_time_look_behind_minutes
    )

    return fetch_window_start_time, fetch_window_end_time


# =========== Helper Utilities ===========


def quote_group(text: str) -> list[str]:
    """A function that splits groups of key value pairs.
    Taking into consideration key values pairs with nested quotes.
    """

    def clean(t):
        return t.strip().rstrip(",")

    # Return strings that aren't key-valued, as is.
    if len(text.strip()) < 3 or "=" not in text:
        return [text]

    # Remove prefix & suffix wrapping quotes if present around all the text
    # For example a text could be:
    # "a="123"", we want it to be: a="123"
    text = re.sub(r"^\"([\s\S]+\")\"$", r"\1", text)

    # Some of the texts don't end with a comma so we add it to make sure
    # everything acts the same.
    if not text.rstrip().endswith(","):
        text = text.rstrip()
        text += ","

    # Fix elements that aren't key=value (`111, a="123"` => `a="123"`)
    # (^) - start of text
    # ([^=]+), - everything without equal sign and a comma at the end
    #   ('111,' above)
    text = re.sub(r"(^)([^=]+),", ",", text).lstrip(",")

    # Wrap all key values without a quote (`a=123` => `a="123"`)
    # Key part: ([^\"\,]+?=)
    #   asdf=123, here it will match 'asdf'.
    #
    # Value part: ([^\"]+?)
    #   every string without a quote or doesn't start the text.
    #   For example: asdf=123, here it will match '123'.
    #
    # End value part: (,|\")
    #   we need to decide when to end the value, in our case
    #   with a comma. We also check for quotes for this case:
    #   a="b=nested_value_without_a_wrapping_quote", as we want to
    #   wrap 'nested_value_without_a_wrapping_quote' with quotes.
    text = re.sub(r"([^\"\,]+?=)([^\"]+?)(,|\")", r'\1"\2"\3', text)

    # The basic idea here is to check that every key value ends with a `",`
    # Assuming that there are even number of quotes before
    # (some values can have deep nested quotes).
    quote_counter = 0
    rindex = 0
    lindex = 0
    groups = []
    while rindex < len(text):
        # For every quote we increment the quote counter
        # (to preserve context on the opening/closed quotes)
        if text[rindex] == '"':
            quote_counter += 1

        # A quote group ends when `",` is encountered.
        is_end_keypair = rindex > 1 and text[rindex - 1] + text[rindex] == '",'

        # If the quote_counter isn't even we shouldn't close the group,
        # for example: a="b="1",c="3""                * *
        # I'll space for readability:   a = " b = " 1 " , c ...
        #                               0 1 2 3 4 5 6 7 8 9
        # quote_counter is even:            F     T   F   T
        # On index 7 & 8 we find a potential quote closing, but as you can
        # see it isn't a valid group (because of nesting) we need to check
        # the quote counter for an even number => a closing match.
        is_even_number_of_quotes = quote_counter % 2 == 0

        # We check both conditions to find a group
        if is_end_keypair and is_even_number_of_quotes:
            # Clean the match group and append to groups
            groups.append(clean(text[lindex:rindex]))

            # Incrementing the indexes to start searching for the next group.
            lindex = rindex + 1
            rindex += 1
            quote_counter = 0

        # Continue to walk the string until we find a quote again.
        rindex += 1

    # Sometimes there aren't any quotes in the string so we can just append it
    if not groups:
        groups.append(clean(text))

    return groups


def raw_to_dict(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        result = json.loads(raw)
    except ValueError:
        if '"message"' in raw:
            raw = raw.replace('"', "").strip("{").strip("}")
            key_val_arr = raw.split(",")
            for key_val in key_val_arr:
                single_key_val = key_val.split(":", 1)
                if len(single_key_val) <= 1:
                    single_key_val = key_val.split("=", 1)
                if len(single_key_val) > 1:
                    val = single_key_val[1]
                    key = single_key_val[0].strip()

                    result[key] = f"{result[key]},{val}" if key in tuple(result.keys()) else val
        else:
            # search for the pattern: `key="value", `
            # (the double quotes are optional)
            # we append `, ` to the end of the string to catch the last value
            groups = quote_group(raw)
            for g in groups:
                key_value = g.replace('"', "").strip()
                if key_value == "":
                    continue

                if "=" in key_value:
                    key_and_val = key_value.split("=", 1)
                    if key_and_val[0] not in result:
                        result[key_and_val[0]] = key_and_val[1]
                    else:
                        # If there are multiple values for a key, append them.
                        result[key_and_val[0]] = ", ".join([result[key_and_val[0]], key_and_val[1]])

    if REPLACE_FLAG:
        result = replace_keys(result)
    return result


def create_incident_custom_id(incident: dict[str, Any]):
    """This is used to create a custom incident ID, when fetching events that are **NOT** findings.

    Args:
        incident (dict[str, Any]): An incident created from a fetched event.

    Returns:
        str: The custom incident ID.
    """
    incident_raw_data = json.loads(incident["rawJSON"])
    fields_to_add = ["_cd", "index", "_time", "_indextime", "_raw"]
    fields_supplied_by_user = demisto.params().get("unique_id_fields") or ""
    fields_to_add.extend(fields_supplied_by_user.split(","))

    incident_custom_id = "___"
    for field_name in fields_to_add:
        if field_name in incident_raw_data:
            incident_custom_id += f"{field_name}___{incident_raw_data[field_name]}"
        elif field_name in incident:
            incident_custom_id += f"{field_name}___{incident[field_name]}"

    extensive_log(f"[SplunkPy] ID after all fields were added: {incident_custom_id}")

    unique_id = hashlib.md5(incident_custom_id.encode("utf-8")).hexdigest()  # nosec  # guardrails-disable-line
    extensive_log(f"[SplunkPy] Found incident ID is: {unique_id}")
    return unique_id


def extensive_log(message):
    if demisto.params().get("extensive_logs", False):
        demisto.debug(message)


def remove_irrelevant_incident_ids(
    last_run_fetched_ids: dict[str, dict[str, str]], window_start_time: str, window_end_time: str
) -> dict[str, Any]:
    """Remove all the IDs of the fetched incidents that are no longer in the fetch window, to prevent our
    last run object from becoming too large.

    Args:
        last_run_fetched_ids (dict[str, tuple]): The IDs incidents that were fetched in previous fetches.
        window_start_time (str): The window start time.
        window_end_time (str): The window end time.

    Returns:
        dict[str, Any]: The updated list of IDs, without irrelevant IDs.
    """
    new_last_run_fetched_ids: dict[str, dict[str, str]] = {}
    window_start_datetime = datetime.strptime(window_start_time, ISO_FORMAT_TZ_AWARE)
    demisto.debug(f"Beginning to filter irrelevant IDs with respect to window {window_start_time} - {window_end_time}")
    for incident_id, incident_occurred_time in last_run_fetched_ids.items():
        # We divided the handling of the last fetched IDs since we changed the handling of them
        # The first implementation caused IDs to be removed from the cache, even though they were still relevant
        # The second implementation now only removes the cached IDs that are not relevant to the fetch window
        extensive_log(f"[SplunkPy] Checking if {incident_id} is relevant to fetch window")
        # To handle last fetched IDs
        # Last fetched IDs hold the occurred time that they were seen, which is basically the end time of the fetch window
        # they were fetched in, and will be deleted from the last fetched IDs once they pass the fetch window
        incident_window_end_time_str = incident_occurred_time.get("occurred_time", "")
        incident_window_end_datetime = datetime.strptime(incident_window_end_time_str, ISO_FORMAT_TZ_AWARE)
        if incident_window_end_datetime >= window_start_datetime:
            # We keep the incident, since it is still in the fetch window
            extensive_log(f"[SplunkPy] Keeping {incident_id} as part of the last fetched IDs. {incident_window_end_time_str=}")
            new_last_run_fetched_ids[incident_id] = incident_occurred_time
        else:
            extensive_log(f"[SplunkPy] Removing {incident_id} from the last fetched IDs. {incident_window_end_time_str=}")

    return new_last_run_fetched_ids


def build_fetch_kwargs(
    fetch_window_start_time,
    fetch_window_end_time,
    search_offset,
    fetch_window_start_time_fieldname,
    fetch_window_end_time_fieldname,
):
    extensive_log(f"[SplunkPy] fetch_window_start_time_fieldname: {fetch_window_start_time_fieldname}")
    extensive_log(f"[SplunkPy] fetch_window_start_time: {fetch_window_start_time}")
    extensive_log(f"[SplunkPy] fetch_window_end_time_fieldname: {fetch_window_end_time_fieldname}")
    extensive_log(f"[SplunkPy] fetch_window_end_time: {fetch_window_end_time}")

    return {
        fetch_window_start_time_fieldname: fetch_window_start_time,
        fetch_window_end_time_fieldname: fetch_window_end_time,
        "count": FETCH_LIMIT,
        "offset": search_offset,
        "output_mode": OUTPUT_MODE_JSON,
    }


def build_fetch_query(params):
    fetch_query = params["fetchQuery"]

    if extract_fields := params.get("extractFields"):
        for field in extract_fields.split(","):
            field_trimmed = field.strip()
            fetch_query = f"{fetch_query} | eval {field_trimmed}={field_trimmed}"

    return fetch_query


def fetch_findings(
    service: client.Service,
    mapper: UserMappingObject,
    cache_object: "Cache" = None,
    enrich_findings=False,
):
    last_run_data = demisto.getLastRun()
    params = demisto.params()
    if not last_run_data:
        extensive_log("[SplunkPy] SplunkPy first run")

    earliest_time_from_last_run = last_run_data and last_run_data.get("next_run_earliest_time")
    latest_time_from_last_run = last_run_data and last_run_data.get("next_run_latest_time")
    search_offset = last_run_data.get("offset", 0)
    extensive_log(f"[SplunkPy] SplunkPy last run is:\n {last_run_data}")

    fetch_window_start_time, fetch_window_end_time = get_fetch_time_window(
        params, service, earliest_time_from_last_run, latest_time_from_last_run
    )

    finding_time_filter_type: str = params.get("finding_time_source") or "creation time"
    if finding_time_filter_type.startswith("index time"):
        # BETA: For index time based time calculations
        fetch_window_start_time_fieldname = "index_earliest"
        fetch_window_end_time_fieldname = "index_latest"
    else:
        # Finding filter time type defaults to "creation time"
        fetch_window_start_time_fieldname = "earliest_time"
        fetch_window_end_time_fieldname = "latest_time"
    kwargs_oneshot = build_fetch_kwargs(
        fetch_window_start_time,
        fetch_window_end_time,
        search_offset,
        fetch_window_start_time_fieldname,
        fetch_window_end_time_fieldname,
    )
    fetch_query = build_fetch_query(params)
    last_run_fetched_ids: dict[str, Any] = last_run_data.get("next_run_found_incidents_ids", {})
    if late_indexed_pagination := last_run_data.get("late_indexed_pagination"):
        # This is for handling the case when events get indexed late, and inserted in pages
        # that we have already went through
        window = f"{kwargs_oneshot.get(fetch_window_start_time_fieldname)}-{kwargs_oneshot.get(fetch_window_end_time_fieldname)}"
        demisto.debug(f"[SplunkPy] additional fetch for the window {window} to check for late indexed incidents")
        if last_run_fetched_ids:
            ids_to_exclude = [f'"{fetched_id}"' for fetched_id in last_run_fetched_ids]
            exclude_id_where = f'where not event_id in ({",".join(ids_to_exclude)})'
            fetch_query = f"{fetch_query} | {exclude_id_where}"
            kwargs_oneshot["offset"] = 0

    demisto.debug(f"[SplunkPy] fetch query = {fetch_query}")
    demisto.debug(f"[SplunkPy] oneshot query args = {kwargs_oneshot}")
    oneshotsearch_results = service.jobs.oneshot(fetch_query, **kwargs_oneshot)
    reader = results.JSONResultsReader(oneshotsearch_results)

    error_message = ""
    incidents = []
    findings = []
    incident_ids_to_add = []
    num_of_dropped = 0
    fetched_items = []
    for item in reader:
        if handle_message(item):
            if "Error" in str(item.message) or "error" in str(item.message):
                error_message = f"{error_message}\n{item.message}"
            continue
        fetched_items.append(item)
    if fetched_items:
        # enrich the fetched items with splunk notes
        finding_id_to_item = {item.get(EVENT_ID, ""): item for item in fetched_items if item.get(EVENT_ID)}
        enrich_findings_with_splunk_notes(service, finding_id_to_item, is_fetch=True)

    for item in fetched_items:
        extensive_log(f"[SplunkPy] Incident data before parsing to finding: {item}")
        finding_incident = Finding(data=item)
        inc = finding_incident.to_incident(mapper)
        extensive_log(f"[SplunkPy] Incident data after parsing to finding: {inc}")
        incident_id = finding_incident.id or create_incident_custom_id(inc)

        if incident_id not in last_run_fetched_ids:
            incident_ids_to_add.append(incident_id)
            incidents.append(inc)
            findings.append(finding_incident)
            extensive_log(f"[SplunkPy] - Fetched incident {incident_id} to be created.")
        else:
            num_of_dropped += 1
            extensive_log(f"[SplunkPy] - Dropped incident {incident_id} due to duplication.")

    if error_message and not incident_ids_to_add:
        raise DemistoException(f"Failed to fetch incidents, check the provided query in Splunk web search - {error_message}")
    extensive_log(f"[SplunkPy] Size of last_run_fetched_ids before adding new IDs: {len(last_run_fetched_ids)}")
    for incident_id in incident_ids_to_add:
        last_run_fetched_ids[incident_id] = {"occurred_time": fetch_window_end_time}
    extensive_log(f"[SplunkPy] Size of last_run_fetched_ids after adding new IDs: {len(last_run_fetched_ids)}")

    # New way to remove IDs
    last_run_fetched_ids = remove_irrelevant_incident_ids(last_run_fetched_ids, fetch_window_start_time, fetch_window_end_time)
    extensive_log(f"[SplunkPy] Size of last_run_fetched_ids after removing old IDs: {len(last_run_fetched_ids)}")
    extensive_log(f"[SplunkPy] SplunkPy - incidents fetched on last run = {last_run_fetched_ids}")

    demisto.debug(f"SplunkPy - total number of new incidents found is: {len(incidents)}")
    demisto.debug(f"SplunkPy - total number of dropped incidents is: {num_of_dropped}")

    if not enrich_findings or not cache_object:
        demisto.incidents(incidents)
    else:
        cache_object.not_yet_submitted_findings += findings
        if DUMMY not in last_run_data:
            # we add dummy data to the last run to differentiate between the fetch-incidents triggered to the
            # fetch-incidents running as part of "Pull from instance" in Classification & Mapping, as we don't
            # want to add data to the integration context (which will ruin the logic of the cache object)
            last_run_data.update({DUMMY: DUMMY})

    # We didn't get any new incidents or got less than limit,
    # so the next run's earliest time will be the fetch_window_end_time from this iteration
    if (len(incidents) + num_of_dropped) < FETCH_LIMIT:
        demisto.debug(
            f"[SplunkPy] Number of fetched incidents = {len(incidents)}, dropped = {num_of_dropped}. Sum is less"
            f" than {FETCH_LIMIT=}. Starting new fetch"
        )
        new_last_run = {
            "next_run_earliest_time": fetch_window_end_time,
            "next_run_latest_time": None,
            "offset": 0,
            "next_run_found_incidents_ids": last_run_fetched_ids,
        }
    # we get limit findings from splunk
    # we should fetch the entire queue with offset - so set the offset, next_run_earliest_time and next_run_latest_time
    # for the next run
    else:
        demisto.debug(
            f"[SplunkPy] Number of fetched incidents = {len(incidents)}, dropped = {num_of_dropped}. Sum is"
            f" equal/greater than {FETCH_LIMIT=}. Continue pagination"
        )
        new_last_run = {
            "next_run_earliest_time": fetch_window_start_time,
            "next_run_latest_time": fetch_window_end_time,
            "offset": search_offset + FETCH_LIMIT,
            "next_run_found_incidents_ids": last_run_fetched_ids,
        }
    new_last_run["late_indexed_pagination"] = False
    # Need to fetch again this "window" to be sure no "late" indexed events are missed
    if num_of_dropped >= FETCH_LIMIT and "`notable`" in fetch_query:
        demisto.debug('Need to fetch this "window" again to make sure no "late" indexed events are missed')
        new_last_run["late_indexed_pagination"] = True
    # If we are in the process of checking late indexed events, and len(fetch_incidents) == FETCH_LIMIT,
    # that means we need to continue the process of checking late indexed events
    if len(incidents) == FETCH_LIMIT and late_indexed_pagination:
        demisto.debug(
            f"Number of valid incidents equals {FETCH_LIMIT=}, and current fetch checked for late indexed events."
            " Continue checking for late events"
        )
        new_last_run["late_indexed_pagination"] = True

    demisto.debug(
        f'SplunkPy set last run - {new_last_run["next_run_earliest_time"]=}, {new_last_run["next_run_latest_time"]=}, '
        f'{new_last_run["offset"]=}, late_indexed_pagination={new_last_run.get("late_indexed_pagination")}'
    )
    last_run_data.update(new_last_run)
    demisto.setLastRun(last_run_data)
    extensive_log(f"[SplunkPy] last run was updated with: {last_run_data}")


def fetch_incidents(service: client.Service, mapper: UserMappingObject):
    if ENABLED_ENRICHMENTS:
        integration_context = get_integration_context()
        last_run = demisto.getLastRun()

        if not last_run and integration_context:
            # In "Pull from instance" in Classification & Mapping the last run object is empty, integration context
            # will not be empty because of the enrichment mechanism. In regular enriched fetch, we use dummy data
            # in the last run object to avoid entering this case
            demisto.debug(
                "fetch_incidents: last_run is empty but integration_context exists. "
                "This could be 'Pull from instance' or after 'reset last run'. "
                "If this message appears repeatedly, consider running the 'splunk-reset-enriching-fetch-mechanism' command "
                "to clear stale data and reset the enrichment mechanism."
            )
            demisto.debug("running fetch_incidents_for_mapping")

            fetch_incidents_for_mapping(integration_context)
            # Set DUMMY in last_run to prevent this path from being triggered again if incorrectly called
            demisto.setLastRun({DUMMY: DUMMY})
        else:
            demisto.debug("running run_enrichment_mechanism")
            run_enrichment_mechanism(service, integration_context, mapper)
    else:
        demisto.debug("enrichments not enabled running fetch_findings")

        fetch_findings(
            service=service,
            enrich_findings=False,
            mapper=mapper,
        )


# =========== Regular Fetch Mechanism ===========


# =========== Enriching Fetch Mechanism ===========


class Enrichment:
    """A class to represent an Enrichment. Each finding has 3 possible enrichment types: Drilldown, Asset & Identity

    Attributes:
        type (str): The enrichment type. Possible values are: Drilldown, Asset & Identity.
        id (str): The enrichment's job id in Splunk server.
        data (list): The enrichment's data list (events retrieved from the job's search).
        creation_time (str): The enrichment's creation time in ISO format.
        status (str): The enrichment's status.
        query_name (str): The enrichment's query name.
        query_search (str): The enrichment's query search.
    """

    FAILED = "Enrichment failed"
    EXCEEDED_TIMEOUT = "Enrichment exceed the given timeout"
    IN_PROGRESS = "Enrichment is in progress"
    SUCCESSFUL = "Enrichment successfully handled"
    HANDLED = (EXCEEDED_TIMEOUT, FAILED, SUCCESSFUL)

    def __init__(
        self, enrichment_type, status=None, enrichment_id=None, data=None, creation_time=None, query_name=None, query_search=None
    ):
        self.type = enrichment_type
        self.id = enrichment_id
        self.data = data or []
        self.creation_time = creation_time if creation_time else datetime.now(pytz.UTC).isoformat()
        self.status = status or Enrichment.IN_PROGRESS
        self.query_name = query_name
        self.query_search = query_search

    @classmethod
    def from_job(
        cls, enrichment_type: str, job: client.Job | None, query_name: str | None = None, query_search: str | None = None
    ) -> "Enrichment":
        """Creates an Enrichment object from Splunk Job object

        Args:
            enrichment_type (str): The enrichment type
            job (splunklib.client.Job): The corresponding Splunk Job
            query_name: The enrichment query name
            query_search: The enrichment query search

        Returns:
            The created enrichment (Enrichment)
        """
        if job:
            return cls(
                enrichment_type=enrichment_type, enrichment_id=job["sid"], query_name=query_name, query_search=query_search
            )
        else:
            return cls(enrichment_type=enrichment_type, status=Enrichment.FAILED)

    @classmethod
    def from_json(cls, enrichment_dict: dict[str, Any]) -> "Enrichment":
        """Deserialization method.

        Args:
            enrichment_dict (dict): The enrichment dict in JSON format.

        Returns:
            An instance of the Enrichment class constructed from JSON representation.

        """
        return cls(
            enrichment_type=enrichment_dict.get(TYPE),
            data=enrichment_dict.get(DATA),
            status=enrichment_dict.get(STATUS),
            enrichment_id=enrichment_dict.get(ID),
            creation_time=enrichment_dict.get(CREATION_TIME),
            query_name=enrichment_dict.get(QUERY_NAME),
            query_search=enrichment_dict.get(QUERY_SEARCH),
        )


class Finding:
    """A class to represent a finding (Splunk ES 8.2+).

    Attributes:
        data (dict): The finding data.
        id (str): The finding's id (event_id).
        enrichments (list): The list of all enrichments that needs to handle.
        incident_created (bool): Whether an incident created or not.
        occurred (str): The occurred time of the finding.
        custom_id (str): The custom ID of the finding (used in the fetch function).
        time_is_missing (bool): Whether the `_time` field has an empty value or not.
        index_time (str): The time the finding have been indexed.
    """

    def __init__(
        self,
        data: dict[str, Any],
        enrichments: list[Enrichment] | None = None,
        finding_id: str | None = None,
        occurred: str | None = None,
        custom_id: str | None = None,
        index_time: str | None = None,
        time_is_missing: bool | None = None,
        incident_created: bool | None = None,
    ) -> None:
        self.data = data
        self.id = finding_id or self.get_id()
        self.enrichments = enrichments or []
        self.incident_created = incident_created or False
        self.time_is_missing = time_is_missing or False
        self.index_time = index_time or self.data.get("_indextime")
        self.occurred = occurred or self.get_occurred()
        self.custom_id = custom_id or self.create_custom_id()

    def get_id(self) -> str:
        if EVENT_ID in self.data:
            return self.data[EVENT_ID]
        if ENABLED_ENRICHMENTS:
            raise Exception(
                "When using the enrichment mechanism, an event_id field is needed, and thus, "
                "one must use a fetch query of the following format: search `notable` .......\n"
                "Please re-edit the fetchQuery parameter in the integration configuration, reset "
                "the fetch mechanism using the splunk-reset-enriching-fetch-mechanism command and "
                "run the fetch again."
            )
        else:
            return ""

    @staticmethod
    def create_incident(finding_data: dict[str, Any], occurred: str, mapper: UserMappingObject) -> dict[str, Any]:
        rule_title, rule_name = "", ""
        params = demisto.params()
        if demisto.get(finding_data, "rule_title"):
            rule_title = finding_data["rule_title"]
        if demisto.get(finding_data, "rule_name"):
            rule_name = finding_data["rule_name"]
        incident: dict[str, Any] = {"name": f"{rule_title} : {rule_name}"}
        if demisto.get(finding_data, "urgency"):
            incident["severity"] = severity_to_level(finding_data["urgency"])
        if demisto.get(finding_data, "rule_description"):
            incident["details"] = finding_data["rule_description"]
        if finding_data.get("owner") and mapper.should_map and (owner := mapper.get_xsoar_user_by_splunk(finding_data["owner"])):
            finding_data["owner"] = owner
            incident["owner"] = owner

        incident["occurred"] = occurred
        finding_data = parse_finding(finding_data)
        finding_data.update(
            {
                "mirror_instance": demisto.integrationInstance(),
                "mirror_direction": MIRROR_DIRECTION.get(params.get("mirror_direction")),
                "mirror_tags": [NOTE_TAG_FROM_SPLUNK, NOTE_TAG_TO_SPLUNK],
            }
        )
        splunk_note_entries = []
        labels = []
        if params.get("parseFindingEventsRaw"):
            for key, value in raw_to_dict(finding_data["_raw"]).items():
                if not isinstance(value, str):
                    value = str(value)
                labels.append({"type": key, "value": value})
        if demisto.get(finding_data, "security_domain"):
            labels.append({"type": "security_domain", "value": finding_data["security_domain"]})
        splunk_note_entries = demisto.get(finding_data, "splunk_notes", [])
        incident["splunk_notes"] = splunk_note_entries
        labels.append({"type": "splunk_notes", "value": str(splunk_note_entries)})
        incident["labels"] = labels
        if finding_data.get(EVENT_ID):
            incident["dbotMirrorId"] = finding_data.get(EVENT_ID)
        # finding_data["splunk_notes"] = splunk_note_entries
        incident["rawJSON"] = json.dumps(finding_data)

        return incident

    def to_incident(self, mapper: UserMappingObject) -> dict[str, Any]:
        """Gathers all data from all finding's enrichments and return an incident"""
        self.incident_created = True

        for e in self.enrichments:
            if e.type == DRILLDOWN_ENRICHMENT:
                # A finding can have more than one drilldown search enrichment, in that case we keep the searches results in
                # a list of dictionaries - each dict contains the query detail and the search results of a drilldown search

                drilldown_enrichment_details = {
                    "query_name": e.query_name,
                    "query_search": e.query_search,
                    "query_results": e.data,
                    "enrichment_status": e.status,
                }

                if not self.data.get(e.type):  # first drilldown enrichment result to add - initiate the list
                    self.data[e.type] = [drilldown_enrichment_details]

                else:  # there are previous drilldown enrichments in the finding's data
                    self.data[e.type].append(drilldown_enrichment_details)

                if not self.data.get("successful_drilldown_enrichment"):
                    # Drilldown enrichment is successful if at least one drilldown search was successful
                    self.data["successful_drilldown_enrichment"] = e.status == Enrichment.SUCCESSFUL

            else:  # asset enrichment or identity enrichment
                self.data[e.type] = e.data
                self.data[ENRICHMENT_TYPE_TO_ENRICHMENT_STATUS[e.type]] = e.status == Enrichment.SUCCESSFUL

        return self.create_incident(
            self.data,
            self.occurred,
            mapper=mapper,
        )

    def submitted(self) -> bool:
        """Returns an indicator on whether any of the finding's enrichments was submitted or not"""
        finding_enrichment_types = {e.type for e in self.enrichments}
        return any(enrichment.status == Enrichment.IN_PROGRESS for enrichment in self.enrichments) and len(
            finding_enrichment_types
        ) == len(ENABLED_ENRICHMENTS)

        # Explanation of the conditions:
        # 1. First condition - if any of the finding's enrichments is 'in progress', it means that it was submitted to splunk.
        # 2. Second condition - The ENABLED_ENRICHMENTS list contains the enrichment types that the user wants to enrich.
        # According to the logic of the submit_finding() function, in a normal situation (where the code wasn't interrupted)
        # the finding.enrichments list should include an enrichment object for each enrichment type that exist in the
        # ENABLED_ENRICHMENTS list. That is because in the submit_finding() function we always add Enrichments objects to the
        # finding.enrichments list regardless their statuses (failed\success). So if the function had finished it's run without
        # any interruption we will have at least one enrichment object for each enrichment type (for drilldown enrichment we could
        # have more than one enrichment object - in a case of multiple drilldown searches enrichment).

    def failed_to_submit(self) -> bool:
        """Returns an indicator on whether all finding's enrichments were failed to submit or not"""
        finding_enrichment_types = {e.type for e in self.enrichments}
        return all(enrichment.status == Enrichment.FAILED for enrichment in self.enrichments) and len(
            finding_enrichment_types
        ) == len(ENABLED_ENRICHMENTS)

    def handled(self) -> bool:
        """Returns an indicator on whether all finding's enrichments were handled or not"""
        return all(enrichment.status in Enrichment.HANDLED for enrichment in self.enrichments) or any(
            enrichment.status == Enrichment.EXCEEDED_TIMEOUT for enrichment in self.enrichments
        )

    def get_submitted_enrichments(self) -> tuple[bool, bool, bool]:
        """Returns indicators on whether each enrichment was submitted/failed or not initiated"""
        submitted_drilldown, submitted_asset, submitted_identity = False, False, False

        for enrichment in self.enrichments:
            if enrichment.type == DRILLDOWN_ENRICHMENT:
                submitted_drilldown = True
            elif enrichment.type == ASSET_ENRICHMENT:
                submitted_asset = True
            elif enrichment.type == IDENTITY_ENRICHMENT:
                submitted_identity = True

        return submitted_drilldown, submitted_asset, submitted_identity

    def get_occurred(self) -> str:
        """Returns the occurred time, if not exists in data, returns the current fetch time"""
        if "_time" in self.data:
            finding_occurred = self.data["_time"]
        else:
            # Use-cases where fetching non-findings from Splunk

            finding_occurred = datetime.now(pytz.UTC).strftime(ISO_FORMAT_TZ_AWARE)
            self.time_is_missing = True
            demisto.debug(f"\n\n occurred time in else: {finding_occurred} \n\n")

        return finding_occurred

    def create_custom_id(self) -> str:
        """Generates a custom ID for a given finding"""
        if self.id:
            return self.id

        finding_raw_data = self.data.get("_raw", "")
        raw_hash = hashlib.md5(finding_raw_data.encode("utf-8")).hexdigest()  # nosec  # guardrails-disable-line

        if self.time_is_missing and self.index_time:
            finding_custom_id = f"{self.index_time}_{raw_hash}"  # index_time stays in epoch to differentiate
            demisto.debug("Creating finding custom id using the index time")
        else:
            finding_custom_id = f"{self.occurred}_{raw_hash}"

        return finding_custom_id

    def is_enrichment_process_exceeding_timeout(self, enrichment_timeout: int) -> bool:
        """Checks whether an enrichment process has exceeded timeout or not

        Args:
            enrichment_timeout (int): The timeout for the enrichment process

        Returns (bool): True if the enrichment process exceeded the given timeout, False otherwise
        """
        now = datetime.now(pytz.UTC)
        exceeding_timeout = False

        for enrichment in self.enrichments:
            if enrichment.status == Enrichment.IN_PROGRESS:
                creation_time_datetime = datetime.strptime(enrichment.creation_time, ISO_FORMAT_TZ_AWARE)
                if now - creation_time_datetime > timedelta(minutes=enrichment_timeout):
                    exceeding_timeout = True
                    enrichment.status = Enrichment.EXCEEDED_TIMEOUT

        return exceeding_timeout

    @classmethod
    def from_json(cls, finding_dict: dict[str, Any]) -> "Finding":
        """Deserialization method.

        Args:
            finding_dict: The finding dict in JSON format.

        Returns:
            An instance of the Finding class constructed from JSON representation.
        """
        return cls(
            data=finding_dict.get(DATA) or {},
            enrichments=list(map(Enrichment.from_json, finding_dict.get(ENRICHMENTS) or [])),
            finding_id=finding_dict.get(ID),
            custom_id=finding_dict.get(CUSTOM_ID),
            occurred=finding_dict.get(OCCURRED),
            time_is_missing=finding_dict.get(TIME_IS_MISSING),
            index_time=finding_dict.get(INDEX_TIME),
            incident_created=finding_dict.get(INCIDENT_CREATED),
        )


class Cache:
    """A class to represent the cache for the enriching fetch mechanism.

    Attributes:
        not_yet_submitted_findings (list): The list of all findings that were fetched but not yet submitted.
        submitted_findings (list): The list of all submitted findings that needs to be handled.
    """

    def __init__(
        self, not_yet_submitted_findings: list[Finding] | None = None, submitted_findings: list[Finding] | None = None
    ) -> None:
        self.not_yet_submitted_findings = not_yet_submitted_findings or []
        self.submitted_findings = submitted_findings or []

    def done_submitting(self) -> bool:
        return not self.not_yet_submitted_findings

    def done_handling(self) -> bool:
        return not self.submitted_findings

    def organize(self) -> list[Finding]:
        """This function is designated to handle unexpected behaviors in the enrichment mechanism.
         E.g. Connection error, instance disabling, etc...
         It re-organizes the cache object to the correct state of the mechanism when the exception was caught.
         If there are findings that were handled but the mechanism didn't create an incident for them, it returns them.
         This function is called in each "end" of execution of the enrichment mechanism.

        Returns:
            handled_not_created_incident (list): The list of all findings that have been handled but not created an
             incident.
        """
        not_yet_submitted, submitted, handled_not_created_incident = [], [], []

        for finding in self.not_yet_submitted_findings:
            if finding.submitted():
                if finding not in self.submitted_findings:
                    submitted.append(finding)
            elif finding.failed_to_submit():
                if not finding.incident_created:
                    handled_not_created_incident.append(finding)
            else:
                not_yet_submitted.append(finding)

        for finding in self.submitted_findings:
            if finding.handled():
                if not finding.incident_created:
                    handled_not_created_incident.append(finding)
            else:
                submitted.append(finding)

        self.not_yet_submitted_findings = not_yet_submitted
        self.submitted_findings = submitted

        return handled_not_created_incident

    @classmethod
    def from_json(cls, cache_dict: dict[str, Any]) -> "Cache":
        """Deserialization method.

        Args:
            cache_dict: The cache dict in JSON format.

        Returns:
            An instance of the Cache class constructed from JSON representation.
        """
        return cls(
            not_yet_submitted_findings=list(map(Finding.from_json, cache_dict.get(NOT_YET_SUBMITTED_FINDINGS, []))),
            submitted_findings=list(map(Finding.from_json, cache_dict.get(SUBMITTED_FINDINGS, []))),
        )

    @classmethod
    def load_from_integration_context(cls, integration_context: dict[str, Any]) -> "Cache":
        return Cache.from_json(json.loads(integration_context.get(CACHE, "{}")))

    def dump_to_integration_context(self) -> None:
        integration_context = get_integration_context()
        integration_context[CACHE] = json.dumps(self, default=lambda obj: obj.__dict__)
        set_integration_context(integration_context)


def get_fields_query_part(
    finding_data: dict[str, Any],
    prefix: str,
    fields: list[str],
    raw_dict: dict[str, Any] | None = None,
    add_backslash: bool = False,
) -> str:
    """Given the fields to search for in the findings and the prefix, creates the query part for splunk search.
    For example: if fields are ["user"], and the value of the "user" fields in the finding is ["u1", "u2"], and the
    prefix is "identity", the function returns: (identity="u1" OR identity="u2")

    Args:
        finding_data (dict): The finding.
        prefix (str): The prefix to attach to each value returned in the query.
        fields (list): The fields to search in the finding for.
        raw_dict (dict): The raw dict
        add_backslash (bool): For users that contains single backslash, we add one more

    Returns: The query part
    """
    if not raw_dict:
        raw_dict = raw_to_dict(finding_data.get("_raw", ""))
    raw_list: list = []
    for field in fields:
        raw_list += argToList(finding_data.get(field, "")) + argToList(raw_dict.get(field, ""))
    if add_backslash:
        raw_list = [item.replace("\\", "\\\\") for item in raw_list]
    raw_list = [f"""{prefix}="{item.strip('"')}\"""" for item in raw_list]

    if not raw_list:
        return ""
    elif len(raw_list) == 1:
        return raw_list[0]
    else:
        return f'({" OR ".join(raw_list)})'


def get_finding_field_and_value(
    raw_field: str, finding_data: dict[str, Any], raw: dict[str, Any] | None = None
) -> tuple[str, Any]:
    """Gets the value by the name of the raw_field. We don't search for equivalence because raw field
    can be "threat_match_field|s" while the field is "threat_match_field".

    Args:
        raw_field (str): The raw field
        finding_data (dict): The finding data
        raw (dict): The raw dict

    Returns: The value in the finding which is associated with raw_field

    """
    if not raw:
        raw = raw_to_dict(finding_data.get("_raw", ""))
    for field in finding_data:
        if field in raw_field:
            return field, finding_data[field]
    for field in raw:
        if field in raw_field:
            return field, raw[field]
    demisto.error(f"Field {raw_field} was not found in the finding.")
    return "", ""


def earliest_time_exists_in_query(query: str) -> bool:
    """
    Returns True if the query contains 'earliest=' or 'earliest ='
    (any amount of whitespace around the equals sign).
    """
    if query is None:
        return False

    pattern = r"earliest\s*=\s*"
    return re.search(pattern, query) is not None


def build_drilldown_search(
    finding_data: dict[str, Any], search: str, raw_dict: dict[str, Any], is_query_name: bool = False
) -> str:
    """Replaces all needed fields in a drilldown search query, or a search query name
    Args:
        finding_data (dict): The finding data
        search (str): The drilldown search query
        raw_dict (dict): The raw dict
        is_query_name (bool): Whether the given query is a query name (default is false)

    Returns (str): A searchable drilldown search query or a parsed query name
    """
    searchable_search: list = []
    start = 0

    for match in re.finditer(DRILLDOWN_REGEX, search):
        groups = match.groups()
        prefix = groups[0]
        raw_field = (groups[1] or groups[2]).strip("$")
        field, replacement = get_finding_field_and_value(raw_field, finding_data, raw_dict)
        if not field and not replacement:
            if not is_query_name:
                demisto.error(f"Failed building drilldown search query. Field {raw_field} was not found in the finding.")
            return ""

        if prefix:
            if field in USER_RELATED_FIELDS:
                replacement = get_fields_query_part(finding_data, prefix, [field], raw_dict, add_backslash=True)
            else:
                replacement = get_fields_query_part(finding_data, prefix, [field], raw_dict)

        end = match.start()
        searchable_search.extend((search[start:end], str(replacement)))
        start = match.end()
    searchable_search.append(search[start:])  # Handling the tail of the query

    parsed_query = "".join(searchable_search)

    demisto.debug(f"Parsed query is: {parsed_query}")

    return parsed_query


def get_drilldown_timeframe(finding_data, raw) -> tuple[str, str]:
    """Sets the drilldown search timeframe data.

    Args:
        finding_data (dict): The finding
        raw (dict): The raw dict

    Returns:
        earliest_offset: The earliest time to query from.
        latest_offset: The latest time to query to.
    """
    earliest_offset = finding_data.get("drilldown_earliest", "")
    latest_offset = finding_data.get("drilldown_latest", "")
    info_min_time = raw.get(INFO_MIN_TIME, "")
    info_max_time = raw.get(INFO_MAX_TIME, "")

    if not earliest_offset or earliest_offset == f"${INFO_MIN_TIME}$":
        if info_min_time:
            earliest_offset = info_min_time
        else:
            demisto.debug("Failed retrieving info min time")
    if not latest_offset or latest_offset == f"${INFO_MAX_TIME}$":
        if info_max_time:
            latest_offset = info_max_time
        else:
            demisto.debug("Failed retrieving info max time")

    return earliest_offset, latest_offset


def escape_invalid_chars_in_drilldown_json(drilldown_search: str) -> str:
    """Goes over the drilldown search, and replace the unescaped or invalid chars.

    Args:
        drilldown_search (str): The drilldown search.

    Returns:
        str: The escaped drilldown search.
    """
    # escape the " of string from the form of 'some_key="value"' which the " char are invalid in json value
    for unescaped_val in re.findall(r"(?<==)\s*\"[^\"]*\"", drilldown_search):
        escaped_val = unescaped_val.replace('"', '\\"')
        drilldown_search = drilldown_search.replace(unescaped_val, escaped_val)

    # replace the new line (\n) with in the IN (...) condition with ','
    # Splunk replace the value of some multiline fields to the value which contain \n
    # due to the 'expandtoken' macro
    for multiline_val in re.findall(r"(?<=in|IN)\s*\([^\)]*\n[^\)]*\)", drilldown_search):
        csv_val = multiline_val.replace("\n", ",")
        drilldown_search = drilldown_search.replace(multiline_val, csv_val)
    return drilldown_search


def parse_drilldown_searches(drilldown_searches: list[str]) -> list[dict[str, Any]]:
    """Goes over the drilldown searches list, parses each drilldown search and converts it to a python dictionary.

    Args:
        drilldown_searches (list): The list of the drilldown searches.

    Returns:
        list[dict]: A list of the drilldown searches dictionaries.
    """
    demisto.debug("There are multiple drilldown searches to enrich, parsing each drilldown search object")
    searches = []

    for drilldown_search in drilldown_searches:
        try:
            # drilldown_search may be a json list/dict represented as string
            drilldown_search = escape_invalid_chars_in_drilldown_json(drilldown_search)
            search = json.loads(drilldown_search)
            if isinstance(search, list):
                searches.extend(search)
            else:
                searches.append(search)
        except json.JSONDecodeError as e:
            demisto.error(
                f"Caught an exception while parsing a drilldown search object."
                f"Drilldown search is: {drilldown_search}, Original Error is: {e!s}"
            )

    return searches


def get_drilldown_searches(finding_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the drilldown_searches from the finding_data.
    It can be a list of objects, a single object or a simple string that contains the query.

    Args:
        finding_data (dict): The finding data

    Returns: A list that contains dict/s of the drilldown data like: name, search etc or the simple search query.
    """
    # Multiple drilldown searches is a feature added to Enterprise Security v7.2.0.
    # from this version, if a user set a drilldown search, we get a list of drilldown search objects (under
    # the 'drilldown_searches' key) and submit a splunk enrichment for each one of them.
    # To maintain backwards compatibility we keep using the 'drilldown_search' key as well.

    if drilldown_search := finding_data.get("drilldown_search"):
        # The drilldown_searches are in 'old' format a simple string query.
        return [drilldown_search]
    if drilldown_search := finding_data.get("drilldown_searches", []):
        if isinstance(drilldown_search, list):
            # The drilldown_searches are a list of searches data stored as json strings:
            return parse_drilldown_searches(drilldown_search)
        else:
            # The drilldown_searches are a dict/list of the search data in a JSON string representation.
            return parse_drilldown_searches([drilldown_search])
    return []


def drilldown_enrichment(
    service: client.Service, finding_data: dict[str, Any], num_enrichment_events: int
) -> list[tuple[str | None, str | None, client.Job | None]]:
    """Performs a drilldown enrichment.
    If the finding has multiple drilldown searches, enriches all the drilldown searches.

    Args:
        service (splunklib.client.Service): Splunk service object.
        finding_data (dict): The finding data
        num_enrichment_events (int): The maximal number of events to return per enrichment type.

    Returns: A list that contains tuples of a query name, query search and the splunk job that runs the query.
             [(query_name, query_search, splunk_job)]
    """
    jobs_and_queries: list[tuple[str | None, str | None, client.Job | None]] = []
    demisto.debug(f"finding data is: {finding_data}")
    if searches := get_drilldown_searches(finding_data):
        raw_dict = raw_to_dict(finding_data.get("_raw", ""))

        total_searches = len(searches)
        demisto.debug(f"Finding {finding_data[EVENT_ID]} has {total_searches} drilldown searches to enrich")

        for i in range(total_searches):
            # Iterates over the drilldown searches of the given finding to enrich each one of them
            search = searches[i]
            demisto.debug(f"Enriches drilldown search number {i+1} out of {total_searches} for finding {finding_data[EVENT_ID]}")

            if isinstance(search, dict):
                query_name = search.get("name", "")
                query_search = search.get("search", "")
                earliest_offset = search.get("earliest") or search.get("earliest_offset", "")  # The earliest time to query from.
                latest_offset = search.get("latest") or search.get("latest_offset", "")  # The latest time to query to.

            else:
                # Got a single drilldown search under the 'drilldown_search' key (BC)
                query_search = search
                query_name = finding_data.get("drilldown_name", "")
                earliest_offset, latest_offset = get_drilldown_timeframe(finding_data, raw_dict)

            try:
                parsed_query_name = build_drilldown_search(finding_data, query_name, raw_dict, True)
                if not parsed_query_name:  # if parsing failed - keep original unparsed name
                    demisto.debug(
                        f"Failed parsing drilldown search query name, using the original "
                        f"un-parsed query name instead: {query_name}."
                    )
                    parsed_query_name = query_name
            except Exception as e:
                demisto.error(f"Caught an exception while parsing the query name, using the original query name instead: {e!s}")
                parsed_query_name = query_name

            if searchable_query := build_drilldown_search(finding_data, query_search, raw_dict):
                demisto.debug(f"Search Query was build successfully for finding {finding_data[EVENT_ID]}")

                if (earliest_offset and latest_offset) or earliest_time_exists_in_query(searchable_query):
                    kwargs = {"max_count": num_enrichment_events, "exec_mode": "normal"}
                    if latest_offset:
                        kwargs["latest_time"] = latest_offset
                    if earliest_offset:
                        kwargs["earliest_time"] = earliest_offset
                    query = build_search_query({"query": searchable_query})
                    demisto.debug(f"Drilldown query for finding {finding_data[EVENT_ID]} is: {query}")
                    try:
                        job = service.jobs.create(query, **kwargs)
                        jobs_and_queries.append((parsed_query_name, query, job))

                    except Exception as e:
                        demisto.error(f"Caught an exception in drilldown_enrichment function: {e!s}")
                else:
                    demisto.debug(f"Failed getting the drilldown timeframe for finding {finding_data[EVENT_ID]}")
                    jobs_and_queries.append((None, None, None))
            else:
                demisto.debug(
                    f"Couldn't build search query for finding {finding_data[EVENT_ID]} "
                    f"with the following drilldown search {query_search}"
                )
                jobs_and_queries.append((None, None, None))
    else:
        demisto.debug(f"drill-down was not properly configured for finding {finding_data[EVENT_ID]}")
        jobs_and_queries.append((None, None, None))

    return jobs_and_queries


def identity_enrichment(service: client.Service, finding_data: dict[str, Any], num_enrichment_events: int) -> client.Job | None:
    """Performs an identity enrichment.

    Args:
        service (splunklib.client.Service): Splunk service object
        finding_data (dict): The finding data
        num_enrichment_events (int): The maximal number of events to return per enrichment type.

    Returns: The Splunk Job
    """
    job = None
    error_msg = f"Failed submitting identity enrichment request to Splunk for finding {finding_data[EVENT_ID]}"
    if users := get_fields_query_part(
        finding_data=finding_data,
        prefix="identity",
        fields=USER_RELATED_FIELDS,
        add_backslash=True,
    ):
        tables = argToList(demisto.params().get("identity_enrich_lookup_tables", DEFAULT_IDENTITY_ENRICH_TABLE))
        query = ""
        for table in tables:
            query += f"| inputlookup {table} where {users}"
        demisto.debug(f"Identity query for finding {finding_data[EVENT_ID]}: {query}")
        try:
            kwargs = {"max_count": num_enrichment_events, "exec_mode": "normal"}
            job = service.jobs.create(query, **kwargs)
        except Exception as e:
            demisto.error(f"Caught an exception in identity_enrichment function: {e!s}")
    else:
        demisto.debug(f"No users were found in finding. {error_msg}")

    return job


def asset_enrichment(service: client.Service, finding_data: dict[str, Any], num_enrichment_events: int) -> client.Job | None:
    """Performs an asset enrichment.

    Args:
        service (splunklib.client.Service): Splunk service object
        finding_data (dict): The finding data
        num_enrichment_events (int): The maximal number of events to return per enrichment type.

    Returns: The Splunk Job
    """
    job = None
    error_msg = f"Failed submitting asset enrichment request to Splunk for finding {finding_data[EVENT_ID]}"
    if assets := get_fields_query_part(
        finding_data=finding_data,
        prefix="asset",
        fields=["src", "dest", "src_ip", "dst_ip"],
    ):
        tables = argToList(demisto.params().get("asset_enrich_lookup_tables", DEFAULT_ASSET_ENRICH_TABLES))

        query = ""
        for table in tables:
            query += f"| inputlookup append=T {table} where {assets}"
        query += "| rename _key as asset_id | stats values(*) as * by asset_id"

        demisto.debug(f"Asset query for finding {finding_data[EVENT_ID]}: {query}")
        try:
            kwargs = {"max_count": num_enrichment_events, "exec_mode": "normal"}
            job = service.jobs.create(query, **kwargs)
        except Exception as e:
            demisto.error(f"Caught an exception in asset_enrichment function: {e!s}")
    else:
        demisto.debug(f"No assets were found in finding. {error_msg}")

    return job


def handle_submitted_findings(service: client.Service, cache_object: Cache) -> list[Finding]:
    """Handles submitted findings. For each submitted finding, tries to retrieve its results, if results aren't ready,
     it moves to the next submitted finding.

    Args:
        service (splunklib.client.Service): Splunk service object.
        cache_object (Cache): The enrichment mechanism cache object

    Returns:
        handled_findings (list[Finding]): The handled Findings
    """
    handled_findings = []
    if not (enrichment_timeout := arg_to_number(str(demisto.params().get("enrichment_timeout", "5")))):
        enrichment_timeout = 5
    findings = cache_object.submitted_findings
    total = len(findings)
    demisto.debug(f"Trying to handle {len(findings[:MAX_HANDLE_FINDINGS])}/{total} open enrichments")

    for finding in findings[:MAX_HANDLE_FINDINGS]:
        if handle_submitted_finding(service, finding, enrichment_timeout):
            handled_findings.append(finding)

    cache_object.submitted_findings = [n for n in findings if n not in handled_findings]

    if handled_findings:
        demisto.debug(f"Handled {len(handled_findings)}/{total} findings.")
    return handled_findings


def handle_submitted_finding(service: client.Service, finding: Finding, enrichment_timeout: int) -> bool:
    """Handles submitted finding. If enrichment process timeout has reached, creates an incident.

    Args:
        service (splunklib.client.Service): Splunk service object
        finding (Finding): The finding
        enrichment_timeout (int): The timeout for the enrichment process

    Returns:
        finding_status (str): The status of the finding
    """
    task_status = False

    if not finding.is_enrichment_process_exceeding_timeout(enrichment_timeout):
        demisto.debug(f"Trying to handle open enrichment for finding {finding.id}")
        for enrichment in finding.enrichments:
            if enrichment.status == Enrichment.IN_PROGRESS:
                try:
                    job = client.Job(service=service, sid=enrichment.id)
                    if job.is_done():
                        demisto.debug(f"Handling {enrichment.id=} of {enrichment.type=} for finding {finding.id}")
                        for item in results.JSONResultsReader(job.results(output_mode=OUTPUT_MODE_JSON)):
                            if handle_message(item):
                                continue
                            enrichment.data.append(item)
                        enrichment.status = Enrichment.SUCCESSFUL
                        demisto.debug(
                            f"{enrichment.id=} of {enrichment.type=} for finding {finding.id} status is successful "
                            f"{len(enrichment.data)=}"
                        )
                    else:
                        demisto.debug(f"{enrichment.id=} of {enrichment.type=} for finding {finding.id} is still not done")
                except Exception as e:
                    demisto.error(
                        f"Caught an exception while retrieving {enrichment.id=} of {enrichment.type=}\
                        results for finding {finding.id}: {e!s}"
                    )

                    enrichment.status = Enrichment.FAILED
                    demisto.error(f"{enrichment.id=} of {enrichment.type=} for finding {finding.id} was failed.")

        if finding.handled():
            task_status = True
            demisto.debug(f"Handled open enrichment for finding {finding.id}.")
        else:
            demisto.debug(f"Did not finish handling open enrichment for finding {finding.id}")

    else:
        task_status = True
        demisto.debug(
            f"Open enrichment for finding {finding.id} has exceeded the enrichment timeout of {enrichment_timeout}.\
            Submitting the finding without the enrichment."
        )

    return task_status


def submit_findings(service: client.Service, cache_object: Cache) -> tuple[list[Finding], list[Finding]]:
    """Submits fetched findings to Splunk for an enrichment.

    Args:
        service (splunklib.client.Service): Splunk service object
        cache_object (Cache): The enrichment mechanism cache object

    Returns:
        tuple[list[Finding], list[Finding]]: failed_findings, submitted_findings
    """
    failed_findings, submitted_findings = [], []
    num_enrichment_events = arg_to_number(str(demisto.params().get("num_enrichment_events", "20"))) or 20
    findings = cache_object.not_yet_submitted_findings
    total = len(findings)
    if findings:
        demisto.debug(f"Enriching {len(findings[:MAX_SUBMIT_FINDINGS])}/{total} fetched findings")

    for finding in findings[:MAX_SUBMIT_FINDINGS]:
        if submit_finding(service, finding, num_enrichment_events):
            cache_object.submitted_findings.append(finding)
            submitted_findings.append(finding)
            demisto.debug(f"Submitted enrichment request to Splunk for finding {finding.id}")
        else:
            failed_findings.append(finding)
            demisto.debug(f"Incident will be created from finding {finding.id} as each enrichment submission failed")

    cache_object.not_yet_submitted_findings = [n for n in findings if n not in submitted_findings + failed_findings]

    if submitted_findings:
        demisto.debug(f"Submitted {len(submitted_findings)}/{total} findings successfully.")

    if failed_findings:
        demisto.debug(
            f"The following {len(failed_findings)} findings failed the enrichment process: \
            {[finding.id for finding in failed_findings]}, \
            creating incidents without enrichment."
        )
    return failed_findings, submitted_findings


def submit_finding(service: client.Service, finding: Finding, num_enrichment_events: int) -> bool:
    """Submits fetched finding to Splunk for an Enrichment. Three enrichments possible: Drilldown, Asset & Identity.
     If all enrichment type executions were unsuccessful, creates a regular incident, Otherwise updates the
     integration context for the next fetch to handle the submitted finding.

    Args:
        service (splunklib.client.Service): Splunk service object
        finding (Finding): The finding.
        num_enrichment_events (int): The maximal number of events to return per enrichment type.

    Returns:
        task_status (bool): True if any of the enrichment's succeeded to be submitted to Splunk, False otherwise
    """
    submitted_drilldown, submitted_asset, submitted_identity = finding.get_submitted_enrichments()

    if DRILLDOWN_ENRICHMENT in ENABLED_ENRICHMENTS and not submitted_drilldown:
        jobs_and_queries = drilldown_enrichment(service, finding.data, num_enrichment_events)
        for job_and_query in jobs_and_queries:
            finding.enrichments.append(
                Enrichment.from_job(
                    DRILLDOWN_ENRICHMENT, job=job_and_query[2], query_name=job_and_query[0], query_search=job_and_query[1]
                )
            )
    if ASSET_ENRICHMENT in ENABLED_ENRICHMENTS and not submitted_asset:
        job = asset_enrichment(service, finding.data, num_enrichment_events)
        finding.enrichments.append(Enrichment.from_job(ASSET_ENRICHMENT, job))
    if IDENTITY_ENRICHMENT in ENABLED_ENRICHMENTS and not submitted_identity:
        job = identity_enrichment(service, finding.data, num_enrichment_events)
        finding.enrichments.append(Enrichment.from_job(IDENTITY_ENRICHMENT, job))

    return finding.submitted()


def create_incidents_from_findings(findings_to_be_created: list[Finding], mapper: UserMappingObject) -> list[dict[str, Any]]:
    """Create the actual incident from the handled Findings
        in addition, taking in account the data from the integration_context (from mirror-in process)
        about Findings which was updated by mirror-in during the Enrichment time.

    Args:
        findings_to_be_created (list[Finding]): The Findings to create incidents from (handled + failed enrichment Findings).
        mapper (UserMappingObject): a UserMappingObject object

    Returns:
        incidents (list[dict]): The created incidents.
    """
    integration_context = None
    mirrored_in_findings = {}
    incidents: list[dict] = []

    if is_mirror_in_enabled():
        integration_context = get_integration_context()
        mirrored_in_findings = integration_context.get(MIRRORED_ENRICHING_FINDINGS, {})
        demisto.debug(f"found {len(mirrored_in_findings)} enriched findings updated in mirror-in")
        demisto.debug(f"{mirrored_in_findings=}")

    for finding in findings_to_be_created:
        # in case the Finding was updated in Splunk between the time of fetch and create incident,
        # we need to take the updated delta.
        if finding.id in mirrored_in_findings:
            delta = mirrored_in_findings[finding.id]
            finding.data |= delta
            del mirrored_in_findings[finding.id]

        incidents.append(finding.to_incident(mapper))
    if integration_context:
        set_integration_context(integration_context)
    return incidents


def is_mirror_in_enabled() -> bool:
    params = demisto.params()
    return MIRROR_DIRECTION.get(params.get("mirror_direction", "")) in ["Both", "In"]


def run_enrichment_mechanism(service: client.Service, integration_context: dict[str, Any], mapper: UserMappingObject) -> None:
    """Execute the enriching fetch mechanism
    1. We first handle submitted findings that have not been handled in the last fetch run
    2. If we finished handling and submitting all fetched findings, we fetch new findings
    3. After we finish to fetch new findings or if we have left findings that have not been submitted, we submit
       them for an enrichment to Splunk
    4. Finally and in case of an Exception, we store the current cache object state in the integration context

    Args:
        service (splunklib.client.Service): Splunk service object.
        integration_context (dict): The integration context
    """
    incidents: list = []
    cache_object = Cache.load_from_integration_context(integration_context)

    try:
        handled_findings = handle_submitted_findings(service, cache_object)
        if cache_object.done_submitting() and cache_object.done_handling():
            fetch_findings(
                service=service,
                cache_object=cache_object,
                enrich_findings=True,
                mapper=mapper,
            )
            if is_mirror_in_enabled():
                # if mirror-in enabled, we need to store in cache the fetched findings ASAP,
                # as they need to be able to update by the mirror in process
                demisto.debug("dumping the cache object direct after fetch as mirror-in enabled")
                cache_object.dump_to_integration_context()

        failed_findings, _ = submit_findings(service, cache_object)
        incidents = create_incidents_from_findings(handled_findings + failed_findings, mapper)
    except Exception as e:
        err = f"Caught an exception while executing the enriching fetch mechanism. Additional Info: {e!s}"
        demisto.error(err)
        # we throw exception only if there is no incident to create
        if not incidents:
            raise e

    finally:
        store_incidents_for_mapping(incidents)
        handled_but_not_created_incidents = cache_object.organize()
        cache_object.dump_to_integration_context()
        incidents += [finding.to_incident(mapper) for finding in handled_but_not_created_incidents]
        demisto.incidents(incidents)


def store_incidents_for_mapping(incidents: list[dict[str, Any]]) -> None:
    """Stores ready incidents in integration context to allow the mapping to pull the incidents from the instance.
    We store at most 20 incidents.

    Args:
        incidents (list): The incidents
    """
    if incidents:
        integration_context = get_integration_context()
        integration_context[INCIDENTS] = incidents[:20]
        set_integration_context(integration_context)


def fetch_incidents_for_mapping(integration_context: dict[str, Any]) -> None:
    """Gets the stored incidents to the "Pull from instance" in Classification & Mapping (In case of enriched fetch)

    Args:
        integration_context (dict): The integration context
    """
    incidents = integration_context.get(INCIDENTS, [])
    demisto.debug(f'Retrieving {len(incidents)} incidents for "Pull from instance" in Classification & Mapping.')
    demisto.incidents(incidents)


def reset_enriching_fetch_mechanism() -> None:
    """Resets all the fields regarding the enriching fetch mechanism & the last run object"""

    # keys: INCIDENTS, CACHE, MIRRORED_ENRICHING_FINDINGS, PROCESSED_MIRRORED_EVENTS may exist in context
    set_integration_context({})
    demisto.setLastRun({})
    return_results("Enriching fetch mechanism was reset successfully.")


# =========== Mirroring Mechanism ===========


def format_splunk_note_for_xsoar(note: dict, timezone_offset: str = "+00:00") -> str:
    """Formats a Splunk note with author and timestamp in user's timezone.

    Args:
        note: The note dictionary from Splunk
        timezone_offset: Timezone offset string (e.g., '+02:00', '-05:00')

    Format:
    **author**  timestamp

    title

    note_content
    """
    # Extract author information - handle nested author object
    author = demisto.get(note, "author.username", "Unknown")

    # Extract and format timestamp with timezone
    timestamp = ""
    if time_value := note.get("update_time"):
        try:
            # Create timezone-aware datetime from epoch timestamp
            dt_utc = datetime.fromtimestamp(float(time_value), tz=pytz.UTC)

            # Parse timezone offset (e.g., '+02:00' -> hours=2, minutes=0)
            sign = 1 if timezone_offset[0] == "+" else -1
            hours = int(timezone_offset[1:3])
            minutes = int(timezone_offset[4:6])
            offset_minutes = sign * (hours * 60 + minutes)

            # Apply timezone offset
            dt_local = dt_utc + timedelta(minutes=offset_minutes)
            timestamp = dt_local.strftime("%b %d, %I:%M %p")

        except (ValueError, TypeError) as e:
            demisto.error(f"Failed to format timestamp {time_value}: {e}")
            timestamp = ""

    # Extract note content
    raw_title = note.get("title") or ""
    decoded_title = urllib.parse.unquote(raw_title)

    raw_content = note.get("content") or ""
    decoded_content = urllib.parse.unquote(raw_content)

    # Combine title and content
    note_text = decoded_title
    if decoded_content:
        note_text = f"{decoded_title}\n{decoded_content}" if decoded_title else decoded_content

    # Format with author and timestamp header
    header = f"**{author}**"
    if timestamp:
        header += f"  {timestamp}"

    # Return formatted note with header and content separated by blank line
    if note_text:
        return f"{header}\n\n{note_text}"
    else:
        return header


def get_war_room_note_entry(content: str, finding_id: str, format: str) -> dict[str, Any]:
    return {
        "EntryContext": {"mirrorRemoteId": finding_id},
        "Type": EntryType.NOTE,
        "Contents": content,
        "ContentsFormat": format,
        "Tags": [NOTE_TAG_FROM_SPLUNK],  # The list of tags to add to the entry
        "Note": True,
    }


def enrich_findings_with_splunk_notes(
    service: client.Service,
    id_to_finding_map: dict[str, dict[str, Any]],
    last_update_splunk_timestamp: float | None = None,
    is_fetch: bool = False,
) -> list[dict[str, Any]]:
    """Get finding notes from Splunk with timezone-aware timestamps.

    This implementation uses a search query to find note IDs associated with findings from the _audit index,
    then retrieves the actual notes from mc_notes KV store.

    Args:
        service (client.Service): Splunk service object
        id_to_finding_map (dict[str, dict]): Dictionary of findings by finding_id
        last_update_splunk_timestamp (str): Last update timestamp to filter notes (optional)
        is_fetch (bool): Whether the function is called from fetch

    Returns:
        list[dict]: The war room entries to create in XSOAR.
    """

    if not id_to_finding_map:
        return []

    # Get timezone offset (cached or from Splunk)
    timezone_offset = get_splunk_timezone_offset(service)
    demisto.debug(f"enrich_findings_with_splunk_notes: Using timezone offset: {timezone_offset} for note timestamps")

    # Build the OR clause for the search query with all finding IDs
    finding_ids = list(id_to_finding_map.keys())
    or_clauses = [f'"{finding_id}"' for finding_id in finding_ids]
    or_clause_str = " OR ".join(or_clauses)

    # We request all notes associated with findings, but limit the search to the last week
    # to avoid performance issues with large audit logs
    search_query = (
        f"search index=_audit source=mc_notes earliest=-7d ({or_clause_str}) "
        '| rex "(?<timestamp>[\\d.]+),(?<note_id>[\\w-]+),(?<user>[\\w_]+),(?<model>[\\w]+),(?<command>[\\w]+),(?<diff>.+)" '
        "| dedup note_id sortby -update_time"
        '| where command!="D"'  # filter out the deleted notes
        # '| table note_id, command, diff'
        "| table note_id"
    )

    demisto.debug(
        f"enrich_findings_with_splunk_notes: Running fetch query to find the changed note IDs in {len(finding_ids)} findings, "
        f"{search_query=}"
    )

    try:
        # Execute the search query to get note IDs
        start_time = time.time()
        oneshotsearch_results = service.jobs.oneshot(
            search_query,
            output_mode=OUTPUT_MODE_JSON,
            count=0,  # No limit
        )
        reader = results.JSONResultsReader(oneshotsearch_results)

        note_ids = []
        for item in reader:
            if handle_message(item):
                continue
            if isinstance(item, dict) and item.get("note_id"):
                note_ids.append(item["note_id"])

        query_time = time.time() - start_time
        demisto.debug(
            f"enrich_findings_with_splunk_notes: Search Note IDs from _audit completed in {query_time:.3f} sec, "
            f"found {len(note_ids)} note IDs"
        )

        if not note_ids:
            demisto.debug("enrich_findings_with_splunk_notes: No note IDs found")
            return []

        # Now query the mc_notes KV store with the note IDs
        start_time = time.time()
        query = json.dumps({"id": {"$in": note_ids}})
        mc_notes = service.kvstore["mc_notes"].data.query(query=query)
        query_time = time.time() - start_time
        demisto.debug(
            f"enrich_findings_with_splunk_notes: mc_notes KV store query completed in {query_time:.3f} sec, "
            f"retrieved {len(mc_notes)} notes"
        )

    except Exception as e:
        demisto.error(f"enrich_findings_with_splunk_notes: Failed to query notes: {e}")
        return []

    # Process the retrieved notes
    # Collect all notes grouped by finding_id for sorting
    finding_notes = defaultdict(list)
    war_room_notes = []
    for note in mc_notes:
        finding_id = note.get("notable_id")
        if not finding_id:
            demisto.debug(f"enrich_findings_with_splunk_notes: Skipping note without notable_id: {note}")
            continue

        # Collect note with update time for sorting
        if finding_id in id_to_finding_map:
            markdown_content = format_splunk_note_for_xsoar(note, timezone_offset)
            finding_notes[finding_id].append({"content": markdown_content, "update_time": float(note.get("update_time", 0))})

            # Creating a XSOAR war room note for a new note ONLY
            # in fetch - we don't create Entry notes for notes
            if (
                not is_fetch
                and last_update_splunk_timestamp
                and note.get("create_time", 0) > int(last_update_splunk_timestamp)
                and COMMENT_MIRRORED_FROM_XSOAR not in markdown_content
            ):
                war_room_notes.append(get_war_room_note_entry(markdown_content, finding_id, EntryFormat.MARKDOWN))

    # Sort notes by update time and update the notes in each finding
    extensive_log(f"enrich_findings_with_splunk_notes: finding_notes = {finding_notes}")
    for finding_id, splunk_notes in finding_notes.items():
        # Sort splunk notes by update_time (newest first)
        sorted_splunk_notes = sorted(splunk_notes, key=lambda x: x["update_time"], reverse=True)  # type: ignore[arg-type,return-value]
        splunk_notes_list = [{"Note": splunk_note["content"]} for splunk_note in sorted_splunk_notes]
        # splunk_notes key maped in the Splunk Finding - Incoming Mapper
        id_to_finding_map[finding_id]["splunk_notes"] = splunk_notes_list
    # handle a case of deliting all the notes

    return war_room_notes


def handle_enriching_findings(modified_findings: dict[str, dict[str, Any]]) -> None:
    """Store the mirror in "delta" of the findings which not yet created because of enrichment mechanism.

    Args:
        modified_findings (dict[str, str]): The Findings changes from get-modified-remote-data
    """
    try:
        integration_context = get_integration_context()
        cache_object = Cache.load_from_integration_context(integration_context)
        if enriching_findings := (cache_object.submitted_findings + cache_object.not_yet_submitted_findings):
            enriched_and_changed = [finding for finding in enriching_findings if finding.id in modified_findings]
            if enriched_and_changed:
                demisto.debug(f"mirror-in: found {len(enriched_and_changed)} submitted findings, updating delta in cache.")
                delta_map = integration_context.get(MIRRORED_ENRICHING_FINDINGS, {})
                for finding in enriched_and_changed:
                    updated_finding = modified_findings[finding.id]
                    delta = delta_map.get(finding.id, {})
                    delta |= {k: v for k, v in updated_finding.items() if finding.data.get(k) != v}
                    delta_map[finding.id] = delta
                    # delete it from the modified_findings as it still not exist in the server as incident
                    del modified_findings[finding.id]

                integration_context[MIRRORED_ENRICHING_FINDINGS] = delta_map
                extensive_log(f"delta map after mirror update: {delta_map}")
                set_integration_context(integration_context)
                demisto.debug(f"mirror-in: delta updated for the enriching findings - {[n.id for n in enriched_and_changed]}")
            else:
                demisto.debug("mirror-in: enriching findings was not updated in remote.")
        else:
            demisto.debug("mirror-in: no enriching findings found.")
    except Exception as e:
        demisto.error(f"mirror-in: failed to check for enriching findings, {e}")


def handle_closed_findings(
    modified_findings_map: dict[str, dict[str, Any]],
    close_extra_labels: list[str],
    close_end_statuses: bool,
    entries: list[dict[str, Any]],
) -> None:
    demisto.debug("Starting handling closing the finding")
    for finding_id, finding in modified_findings_map.items():
        status_label = finding.get("status_label", "")
        status_end = argToBoolean(finding.get("status_end", "false"))
        demisto.debug(
            f"handle_closed_findings: Evaluating closure for {finding_id}: status_label={status_label}, status_end={status_end}, "
            f"close_extra_labels={close_extra_labels}, close_end_statuses={close_end_statuses}"
        )

        should_close = (status_label == "Closed") or (status_label in close_extra_labels) or (close_end_statuses and status_end)

        if should_close:
            demisto.info(
                f"handle_closed_findings: closing incident for {finding_id} "
                f"(status_label={status_label}, status_end={status_end})"
            )
            reason = (
                f'Finding event was closed on Splunk with status "{status_label}".'
                if status_label
                else "Finding event was closed on Splunk based on end status."
            )
            entries.append(
                {
                    "EntryContext": {"mirrorRemoteId": finding_id},
                    "Type": EntryType.NOTE,
                    "Contents": {
                        "dbotIncidentClose": True,
                        "closeReason": reason,
                    },
                    "ContentsFormat": EntryFormat.JSON,
                }
            )


def get_modified_remote_data_command(
    service: client.Service,
    args: dict[str, Any],
    close_incident: bool,
    close_end_statuses: bool,
    close_extra_labels: list[str],
    mapper: UserMappingObject,
) -> None:
    """Gets the list of the findings data that have changed since a given time

    Args:
        service (splunklib.client.Service): Splunk service object
        args (dict): The command arguments
        close_incident (bool): Indicates whether to close the corresponding XSOAR incident if the finding
            has been closed on Splunk's end.
        close_end_statuses (bool): Specifies whether "End Status" statuses on Splunk should be closed when mirroring.
        close_extra_labels (list[str]): A list of additional Splunk status labels to close during mirroring.
        mapper (UserMappingObject): mapper to map the Splunk Username to the correct XSOAR username.

    Returns:
        SplunkGetModifiedRemoteDataResponse: The response containing the list of findings changed
    """
    remote_args = GetModifiedRemoteDataArgs(args)

    # Caching Mechanism for Handling Splunk Indexing Delays:
    # 1. A 60-second buffer is subtracted from the last run time to create an overlapping query window.
    #    This ensures we catch events that were indexed late by Splunk and missed in the previous run.
    # 2. To prevent processing duplicate events from this overlap, we cache the unique key (finding_id:timestamp)
    #    of every event processed in the current run.
    # 3. This cache is stored in the integration context and loaded at the start of the next run.
    # 4. Any fetched event whose key exists in the cache is skipped as a duplicate.
    integration_context = get_integration_context()
    processed_events_cache = set(integration_context.get(PROCESSED_MIRRORED_EVENTS, []))
    demisto.debug(f"Loaded {len(processed_events_cache)} processed events from cache.")

    # Build the query with the 60-second look-behind buffer.
    last_update_dt = dateparser.parse(remote_args.last_update, settings={"TIMEZONE": "UTC"})
    if not last_update_dt:
        raise DemistoException(f"Failed to parse last update time: {remote_args.last_update}")
    original_last_update_timestamp = last_update_dt.timestamp()
    demisto.debug(f"mirror-in: {remote_args.last_update=}, {original_last_update_timestamp=}")
    last_update_splunk_timestamp = original_last_update_timestamp - SPLUNK_INDEXING_TIME

    # Query the audit index to get modified findings
    # This query extracts last_modified_timestamp and rule_id and other findings keys from the audit logs,
    # sorts by timestamp (descending), deduplicates by rule_id
    mirror_in_search = (
        f"search index=_audit source=notable_update_rest_handler earliest={last_update_splunk_timestamp} "
        "| eval last_modified_timestamp = _time "
        "| sort last_modified_timestamp DESC "
        "| dedup rule_id "
        "| `get_current_status` "
        "| eval review_time = last_modified_timestamp"
        "| table review_time, rule_id, owner, "
        "status, status_label, status_end, disposition, disposition_label, urgency, sensitivity"
    )

    modified_findings_map = {}
    entries: list[dict] = []
    current_run_processed_events = set()

    demisto.debug(f"mirror-in: performing audit log search with query: {mirror_in_search}.")

    # Execute the search query to get modified findings
    for item in results.JSONResultsReader(
        service.jobs.oneshot(query=mirror_in_search, count=MIRROR_LIMIT, output_mode=OUTPUT_MODE_JSON)
    ):
        if handle_message(item):
            continue

        # Parse the finding data from the audit log
        updated_finding = parse_finding(item, to_dict=True)

        # Deduplication Mechanism:
        # Create a unique key for the event and check against the cache of previously processed events.
        finding_id = updated_finding.get("rule_id")
        last_modified = updated_finding.get("review_time")
        if not finding_id or not last_modified:
            continue
        event_key = f"{finding_id}:{last_modified}"
        if event_key in processed_events_cache:
            extensive_log(f"mirror-in: Skipping already processed event: {event_key}")
            continue

        # This is a new event. Add it to the map for processing and to the cache for the next run.
        modified_findings_map[finding_id] = updated_finding
        current_run_processed_events.add(event_key)

    # Persist the cache of events processed in this run for the next iteration.
    integration_context[PROCESSED_MIRRORED_EVENTS] = list(current_run_processed_events)
    set_integration_context(integration_context)

    if modified_findings_map:
        # Since ES version is 8.2+, notes are in the mc_notes KV Store
        # We use the query-based approach to fetch notes
        war_room_notes = enrich_findings_with_splunk_notes(service, modified_findings_map, original_last_update_timestamp)
        entries.extend(war_room_notes)

        mapper.update_xsoar_user_in_findings(modified_findings_map.values())  # type: ignore[arg-type]

        if ENABLED_ENRICHMENTS:
            handle_enriching_findings(modified_findings_map)

        if close_incident:
            handle_closed_findings(modified_findings_map, close_extra_labels, close_end_statuses, entries)

        demisto.debug(f"mirror-in: updated finding ids: {list(modified_findings_map.keys())}")

    else:
        demisto.debug(f"mirror-in: no findings was changed since {last_update_splunk_timestamp}")
    if len(modified_findings_map) >= MIRROR_LIMIT:
        demisto.info(f"mirror-in: the number of mirrored findings reach the limit of: {MIRROR_LIMIT}")

    res = SplunkGetModifiedRemoteDataResponse(modified_findings_data=list(modified_findings_map.values()), entries=entries)
    return_results(res)


def update_remote_system_command(
    args: dict[str, Any], params: dict[str, Any], service: client.Service, mapper: UserMappingObject
) -> str:
    """Pushes changes in XSOAR incident into the corresponding finding event in Splunk Server.

    Args:
        args (dict): Demisto args
        params (dict): Demisto params
        service (splunklib.client.Service): Splunk service object
        mapper: UserMappingObject for user mapping

    Returns:
        finding_id (str): The finding id
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    delta = parsed_args.delta
    finding_id = parsed_args.remote_incident_id
    entries = parsed_args.entries
    demisto.debug(f"mirroring args: entries:{parsed_args.entries} delta:{parsed_args.delta}")
    if parsed_args.incident_changed and delta:
        demisto.debug(
            f"Got the following delta keys {list(delta.keys())} to update incident corresponding to finding {finding_id}"
        )

        changed_data: dict[str, Any] = {field: None for field in OUTGOING_MIRRORED_FIELDS}
        for field in delta:
            if field == "owner" and params.get("userMapping", False):
                new_owner = mapper.get_splunk_user_by_xsoar(delta["owner"]) if mapper.should_map else None
                if new_owner:
                    changed_data["owner"] = new_owner
                else:
                    demisto.error("New owner was not found while userMapping is enabled.")
            elif field in OUTGOING_MIRRORED_FIELDS:
                changed_data[field] = delta[field]

        # Close finding if relevant
        if parsed_args.inc_status == IncidentStatus.DONE and params.get("close_finding"):
            demisto.debug(f"Closing finding {finding_id}")
            changed_data["status"] = "5"

        if any(changed_data.values()):
            demisto.debug(f"Sending update request to Splunk for finding {finding_id}, data: {changed_data}")
            try:
                # Use the new v2 investigations API for field updates
                demisto.debug(f"Using v2 API to update finding {finding_id}")
                response_info = update_investigation_or_finding(
                    service=service,
                    investigation_or_finding_id=finding_id,
                    owner=changed_data.get("owner"),
                    urgency=changed_data.get("urgency"),
                    status=changed_data.get("status"),
                    disposition=changed_data.get("disposition"),
                )
                demisto.debug(f"update-remote-system for finding {finding_id} via v2 API: {response_info}")

                # Handle notes separately using the new add_investigation_note function
                if changed_data.get("note"):
                    demisto.debug(f"Adding note to finding {finding_id} via add_investigation_note")
                    try:
                        note_content = f"{changed_data['note']}\n{COMMENT_MIRRORED_FROM_XSOAR}"
                        add_investigation_note(
                            service=service,
                            investigation_or_finding_id=finding_id,
                            content=note_content,
                        )
                        demisto.debug(f"Note added successfully to finding {finding_id}")
                    except Exception as e:
                        demisto.error(f"Failed adding note to finding {finding_id}: {e!s}")

            except Exception as e:
                demisto.error(
                    f"Error in Splunk outgoing mirror for incident corresponding to finding {finding_id}. Error message: {e!s}"
                )
        else:
            demisto.debug(f"Didn't find changed data to update incident corresponding to finding {finding_id}")

    else:
        demisto.debug(f"Incident corresponding to finding {finding_id} was not changed.")

    if entries:
        for entry in entries:
            entry_tags = entry.get("tags", [])
            demisto.debug(f"Got the entry tags: {entry_tags}")
            if NOTE_TAG_TO_SPLUNK in entry_tags:
                demisto.debug("Add new note")
                note_body = f'{entry.get("contents", "")}\n{COMMENT_MIRRORED_FROM_XSOAR}'
                try:
                    add_investigation_note(
                        service=service,
                        investigation_or_finding_id=finding_id,
                        content=note_body,
                    )
                    demisto.debug(f"Note added successfully to finding {finding_id}")
                except Exception as e:
                    demisto.error(
                        f"Error in Splunk outgoing mirror for incident corresponding to finding {finding_id}. "
                        f"Error message: {e!s}"
                    )
    return finding_id


# =========== Mapping Mechanism ===========


def create_mapping_dict(total_parsed_results: list[dict[str, Any]], type_field: str) -> dict[str, Any]:
    """
    Create a {'field_name': 'fields_properties'} dict to be used as mapping schemas.
    Args:
        total_parsed_results: list. the results from the splunk search query
        type_field: str. the field that represents the type of the event or alert.
    """
    types_map = {}
    for result in total_parsed_results:
        raw_json = json.loads(result.get("rawJSON", "{}"))
        if event_type_name := raw_json.get(type_field, ""):
            types_map[event_type_name] = raw_json

    return types_map


def get_mapping_fields_command(service: client.Service, mapper: UserMappingObject, params: dict[str, Any]) -> dict[str, Any]:
    # Create the query to get unique objects
    # The logic is identical to the 'fetch_incidents' command
    type_field = "source"
    total_parsed_results = []

    # Use get_fetch_time_window to calculate the time window
    fetch_window_start_time, fetch_window_end_time = get_fetch_time_window(params, service, "", "")

    kwargs_oneshot = {
        "earliest_time": fetch_window_start_time,
        "latest_time": fetch_window_end_time,
        "count": FETCH_LIMIT,
        "offset": 0,
        "output_mode": OUTPUT_MODE_JSON,
    }

    searchquery_oneshot = params["fetchQuery"]

    if extractFields := params.get("extractFields"):
        for field in extractFields.split(","):
            field_trimmed = field.strip()
            searchquery_oneshot = f"{searchquery_oneshot} | eval {field_trimmed}={field_trimmed}"

    searchquery_oneshot = f"{searchquery_oneshot} | dedup {type_field}"
    oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)
    reader = results.JSONResultsReader(oneshotsearch_results)
    for item in reader:
        if isinstance(item, dict):
            finding = Finding(data=item)
            total_parsed_results.append(finding.to_incident(mapper))
        elif handle_message(item):
            continue

    types_map = create_mapping_dict(total_parsed_results, type_field)
    return types_map


def get_cim_mapping_field_command() -> dict[str, dict[str, Any]]:
    finding = {
        "rule_name": "string",
        "rule_title": "string",
        "security_domain": "string",
        "index": "string",
        "rule_description": "string",
        "risk_score": "string",
        "host": "string",
        "host_risk_object_type": "string",
        "dest_risk_object_type": "string",
        "dest_risk_score": "string",
        "splunk_server": "string",
        "_sourcetype": "string",
        "_indextime": "string",
        "_time": "string",
        "src_risk_object_type": "string",
        "src_risk_score": "string",
        "_raw": "string",
        "urgency": "string",
        "owner": "string",
        "info_min_time": "string",
        "info_max_time": "string",
        "note": "string",
        "reviewer": "string",
        "rule_id": "string",
        "action": "string",
        "app": "string",
        "authentication_method": "string",
        "authentication_service": "string",
        "bugtraq": "string",
        "bytes": "string",
        "bytes_in": "string",
        "bytes_out": "string",
        "category": "string",
        "cert": "string",
        "change": "string",
        "change_type": "string",
        "command": "string",
        "comments": "string",
        "cookie": "string",
        "creation_time": "string",
        "cve": "string",
        "cvss": "string",
        "date": "string",
        "description": "string",
        "dest": "string",
        "dest_bunit": "string",
        "dest_category": "string",
        "dest_dns": "string",
        "dest_interface": "string",
        "dest_ip": "string",
        "dest_ip_range": "string",
        "dest_mac": "string",
        "dest_nt_domain": "string",
        "dest_nt_host": "string",
        "dest_port": "string",
        "dest_priority": "string",
        "dest_translated_ip": "string",
        "dest_translated_port": "string",
        "dest_type": "string",
        "dest_zone": "string",
        "direction": "string",
        "dlp_type": "string",
        "dns": "string",
        "duration": "string",
        "dvc": "string",
        "dvc_bunit": "string",
        "dvc_category": "string",
        "dvc_ip": "string",
        "dvc_mac": "string",
        "dvc_priority": "string",
        "dvc_zone": "string",
        "file_hash": "string",
        "file_name": "string",
        "file_path": "string",
        "file_size": "string",
        "http_content_type": "string",
        "http_method": "string",
        "http_referrer": "string",
        "http_referrer_domain": "string",
        "http_user_agent": "string",
        "icmp_code": "string",
        "icmp_type": "string",
        "id": "string",
        "ids_type": "string",
        "incident": "string",
        "ip": "string",
        "mac": "string",
        "message_id": "string",
        "message_info": "string",
        "message_priority": "string",
        "message_type": "string",
        "mitre_technique_id": "string",
        "msft": "string",
        "mskb": "string",
        "name": "string",
        "orig_dest": "string",
        "orig_recipient": "string",
        "orig_src": "string",
        "os": "string",
        "packets": "string",
        "packets_in": "string",
        "packets_out": "string",
        "parent_process": "string",
        "parent_process_id": "string",
        "parent_process_name": "string",
        "parent_process_path": "string",
        "password": "string",
        "payload": "string",
        "payload_type": "string",
        "priority": "string",
        "problem": "string",
        "process": "string",
        "process_hash": "string",
        "process_id": "string",
        "process_name": "string",
        "process_path": "string",
        "product_version": "string",
        "protocol": "string",
        "protocol_version": "string",
        "query": "string",
        "query_count": "string",
        "query_type": "string",
        "reason": "string",
        "recipient": "string",
        "recipient_count": "string",
        "recipient_domain": "string",
        "recipient_status": "string",
        "record_type": "string",
        "registry_hive": "string",
        "registry_key_name": "string",
        "registry_path": "string",
        "registry_value_data": "string",
        "registry_value_name": "string",
        "registry_value_text": "string",
        "registry_value_type": "string",
        "request_sent_time": "string",
        "request_payload": "string",
        "request_payload_type": "string",
        "response_code": "string",
        "response_payload_type": "string",
        "response_received_time": "string",
        "response_time": "string",
        "result": "string",
        "return_addr": "string",
        "rule": "string",
        "rule_action": "string",
        "sender": "string",
        "service": "string",
        "service_hash": "string",
        "service_id": "string",
        "service_name": "string",
        "service_path": "string",
        "session_id": "string",
        "sessions": "string",
        "severity": "string",
        "severity_id": "string",
        "sid": "string",
        "signature": "string",
        "signature_id": "string",
        "signature_version": "string",
        "site": "string",
        "size": "string",
        "source": "string",
        "sourcetype": "string",
        "src": "string",
        "src_bunit": "string",
        "src_category": "string",
        "src_dns": "string",
        "src_interface": "string",
        "src_ip": "string",
        "src_ip_range": "string",
        "src_mac": "string",
        "src_nt_domain": "string",
        "src_nt_host": "string",
        "src_port": "string",
        "src_priority": "string",
        "src_translated_ip": "string",
        "src_translated_port": "string",
        "src_type": "string",
        "src_user": "string",
        "src_user_bunit": "string",
        "src_user_category": "string",
        "src_user_domain": "string",
        "src_user_id": "string",
        "src_user_priority": "string",
        "src_user_role": "string",
        "src_user_type": "string",
        "src_zone": "string",
        "state": "string",
        "status": "string",
        "status_code": "string",
        "status_description": "string",
        "subject": "string",
        "tag": "string",
        "ticket_id": "string",
        "time": "string",
        "time_submitted": "string",
        "transport": "string",
        "transport_dest_port": "string",
        "type": "string",
        "uri": "string",
        "uri_path": "string",
        "uri_query": "string",
        "url": "string",
        "url_domain": "string",
        "url_length": "string",
        "user": "string",
        "user_agent": "string",
        "user_bunit": "string",
        "user_category": "string",
        "user_id": "string",
        "user_priority": "string",
        "user_role": "string",
        "user_type": "string",
        "vendor_account": "string",
        "vendor_product": "string",
        "vlan": "string",
        "xdelay": "string",
        "xref": "string",
    }

    drilldown = {
        "Drilldown": {
            "action": "string",
            "app": "string",
            "authentication_method": "string",
            "authentication_service": "string",
            "bugtraq": "string",
            "bytes": "string",
            "bytes_in": "string",
            "bytes_out": "string",
            "category": "string",
            "cert": "string",
            "change": "string",
            "change_type": "string",
            "command": "string",
            "comments": "string",
            "cookie": "string",
            "creation_time": "string",
            "cve": "string",
            "cvss": "string",
            "date": "string",
            "description": "string",
            "dest": "string",
            "dest_bunit": "string",
            "dest_category": "string",
            "dest_dns": "string",
            "dest_interface": "string",
            "dest_ip": "string",
            "dest_ip_range": "string",
            "dest_mac": "string",
            "dest_nt_domain": "string",
            "dest_nt_host": "string",
            "dest_port": "string",
            "dest_priority": "string",
            "dest_translated_ip": "string",
            "dest_translated_port": "string",
            "dest_type": "string",
            "dest_zone": "string",
            "direction": "string",
            "dlp_type": "string",
            "dns": "string",
            "duration": "string",
            "dvc": "string",
            "dvc_bunit": "string",
            "dvc_category": "string",
            "dvc_ip": "string",
            "dvc_mac": "string",
            "dvc_priority": "string",
            "dvc_zone": "string",
            "file_hash": "string",
            "file_name": "string",
            "file_path": "string",
            "file_size": "string",
            "http_content_type": "string",
            "http_method": "string",
            "http_referrer": "string",
            "http_referrer_domain": "string",
            "http_user_agent": "string",
            "icmp_code": "string",
            "icmp_type": "string",
            "id": "string",
            "ids_type": "string",
            "incident": "string",
            "ip": "string",
            "mac": "string",
            "message_id": "string",
            "message_info": "string",
            "message_priority": "string",
            "message_type": "string",
            "mitre_technique_id": "string",
            "msft": "string",
            "mskb": "string",
            "name": "string",
            "orig_dest": "string",
            "orig_recipient": "string",
            "orig_src": "string",
            "os": "string",
            "packets": "string",
            "packets_in": "string",
            "packets_out": "string",
            "parent_process": "string",
            "parent_process_id": "string",
            "parent_process_name": "string",
            "parent_process_path": "string",
            "password": "string",
            "payload": "string",
            "payload_type": "string",
            "priority": "string",
            "problem": "string",
            "process": "string",
            "process_hash": "string",
            "process_id": "string",
            "process_name": "string",
            "process_path": "string",
            "product_version": "string",
            "protocol": "string",
            "protocol_version": "string",
            "query": "string",
            "query_count": "string",
            "query_type": "string",
            "reason": "string",
            "recipient": "string",
            "recipient_count": "string",
            "recipient_domain": "string",
            "recipient_status": "string",
            "record_type": "string",
            "registry_hive": "string",
            "registry_key_name": "string",
            "registry_path": "string",
            "registry_value_data": "string",
            "registry_value_name": "string",
            "registry_value_text": "string",
            "registry_value_type": "string",
            "request_payload": "string",
            "request_payload_type": "string",
            "request_sent_time": "string",
            "response_code": "string",
            "response_payload_type": "string",
            "response_received_time": "string",
            "response_time": "string",
            "result": "string",
            "return_addr": "string",
            "rule": "string",
            "rule_action": "string",
            "sender": "string",
            "service": "string",
            "service_hash": "string",
            "service_id": "string",
            "service_name": "string",
            "service_path": "string",
            "session_id": "string",
            "sessions": "string",
            "severity": "string",
            "severity_id": "string",
            "sid": "string",
            "signature": "string",
            "signature_id": "string",
            "signature_version": "string",
            "site": "string",
            "size": "string",
            "source": "string",
            "sourcetype": "string",
            "src": "string",
            "src_bunit": "string",
            "src_category": "string",
            "src_dns": "string",
            "src_interface": "string",
            "src_ip": "string",
            "src_ip_range": "string",
            "src_mac": "string",
            "src_nt_domain": "string",
            "src_nt_host": "string",
            "src_port": "string",
            "src_priority": "string",
            "src_translated_ip": "string",
            "src_translated_port": "string",
            "src_type": "string",
            "src_user": "string",
            "src_user_bunit": "string",
            "src_user_category": "string",
            "src_user_domain": "string",
            "src_user_id": "string",
            "src_user_priority": "string",
            "src_user_role": "string",
            "src_user_type": "string",
            "src_zone": "string",
            "state": "string",
            "status": "string",
            "status_code": "string",
            "subject": "string",
            "tag": "string",
            "ticket_id": "string",
            "time": "string",
            "time_submitted": "string",
            "transport": "string",
            "transport_dest_port": "string",
            "type": "string",
            "uri": "string",
            "uri_path": "string",
            "uri_query": "string",
            "url": "string",
            "url_domain": "string",
            "url_length": "string",
            "user": "string",
            "user_agent": "string",
            "user_bunit": "string",
            "user_category": "string",
            "user_id": "string",
            "user_priority": "string",
            "user_role": "string",
            "user_type": "string",
            "vendor_account": "string",
            "vendor_product": "string",
            "vlan": "string",
            "xdelay": "string",
            "xref": "string",
        }
    }

    asset = {
        "Asset": {
            "asset": "string",
            "asset_id": "string",
            "asset_tag": "string",
            "bunit": "string",
            "category": "string",
            "city": "string",
            "country": "string",
            "dns": "string",
            "ip": "string",
            "is_expected": "string",
            "lat": "string",
            "long": "string",
            "mac": "string",
            "nt_host": "string",
            "owner": "string",
            "pci_domain": "string",
            "priority": "string",
            "requires_av": "string",
        }
    }

    identity = {
        "Identity": {
            "bunit": "string",
            "category": "string",
            "email": "string",
            "endDate": "string",
            "first": "string",
            "identity": "string",
            "identity_tag": "string",
            "last": "string",
            "managedBy": "string",
            "nick": "string",
            "phone": "string",
            "prefix": "string",
            "priority": "string",
            "startDate": "string",
            "suffix": "string",
            "watchlist": "string",
            "work_city": "string",
            "work_lat": "string",
            "work_long": "string",
        }
    }

    return {"Finding Data": finding, "Drilldown Data": drilldown, "Asset Data": asset, "Identity Data": identity}


# =========== Integration Functions & Classes ===========


class ResponseReaderWrapper(io.RawIOBase):
    """This class was supplied as a solution for a bug in Splunk causing the search to run slowly."""

    def __init__(self, response_reader):
        self.response_reader = response_reader

    def readable(self) -> bool:
        return True

    def close(self) -> None:
        self.response_reader.close()

    def read(self, n: int) -> bytes:  # type: ignore[override]
        return self.response_reader.read(n)

    def readinto(self, b: bytearray) -> int:  # type: ignore[override]
        sz = len(b)
        data = self.response_reader.read(sz)

        # Remove non utf-8 characters to avoid decode errors in JSONResultsReader
        # See resolution section from: https://splunk.my.site.com/customer/s/article/Search-Failed-Due-to
        cleaned_data = data.decode("utf-8", errors="ignore").encode("utf-8")
        if len(cleaned_data) != len(data):  # Check if any bytes were removed
            demisto.debug(
                "Removed non utf-8 characters in incoming Splunk data:\n"
                f"Original Splunk data: {data}\n"
                f"Modified data: {cleaned_data}\n"
            )

        for idx, ch in enumerate(cleaned_data):
            b[idx] = ch

        return len(cleaned_data)


def add_investigation_note(
    service: client.Service,
    investigation_or_finding_id: str,
    content: str,
    note_type: str | None = None,
):
    """Add a note to a Splunk investigation or finding via the v2 investigations API endpoint.

    Args:
        service: Splunk service connection
        investigation_or_finding_id: The ID of the investigation or finding
        content: The content of the note
        note_type: Optional type of the note (e.g., "Task")

    Returns:
        dict: The JSON response from the API
    """
    body = {"content": content}
    if note_type is not None:
        body["type"] = note_type

    endpoint = f"public/v2/investigations/{investigation_or_finding_id}/notes"

    demisto.debug(f"Adding note to investigation/finding {investigation_or_finding_id}")
    query_params = {"notable_time": "now"}
    response = service.post(endpoint, body=json.dumps(body), **query_params)
    response_data = response.body.read()
    result = json.loads(response_data)
    demisto.debug(f"Note added successfully: {result}")

    return result


def update_investigation_or_finding(
    service: client.Service,
    investigation_or_finding_id: str,
    owner: str | None = None,
    urgency: str | None = None,
    status: str | None = None,
    disposition: str | None = None,
):
    """
    Update a Splunk investigation or finding via the v2 investigations API endpoint.

    This function uses the service object to make a POST request to the
    /public/v2/investigations/:id endpoint with notable_time=now parameter.

    Args:
        service (client.Service): Splunk service object (already connected)
        investigation_or_finding_id (str): The ID of the investigation or finding to update
        owner (str | None): New owner for the investigation/finding
        urgency (str | None): New urgency level
        status (str | None): New status
        disposition (str | None): New disposition

    Returns:
        dict: The JSON response from the API

    Raises:
        Exception: If the API request fails
    """
    # Build the request body with only the fields that are provided
    body = {}
    if owner is not None:
        body["owner"] = owner
    if urgency is not None:
        body["urgency"] = urgency
    if status is not None:
        body["status"] = status
    if disposition is not None:
        body["disposition"] = disposition

    # If no fields to update, return early
    if not body:
        demisto.debug(f"No fields to update for investigation/finding {investigation_or_finding_id}")
        return {"success": False, "message": "No fields provided to update"}

    # Add notable_time query parameter
    query_params = {"notable_time": "now"}

    # Build the relative endpoint path
    endpoint = f"public/v2/investigations/{investigation_or_finding_id}"

    demisto.debug(
        f"Updating investigation/finding {investigation_or_finding_id} via v2 API. " f"Endpoint: {endpoint}, Body: {body}"
    )

    try:
        # Use service.post() to send POST request to the management port (8089)
        # Parameters are passed as POST form fields
        response = service.post(endpoint, body=json.dumps(body), **query_params)

        # Parse the response
        response_data = response.body.read()
        result = json.loads(response_data)

        demisto.debug(f"Successfully updated investigation/finding {investigation_or_finding_id}: {result}")
        return result

    except Exception as e:
        error_msg = f"Failed to update investigation/finding {investigation_or_finding_id} via v2 API: {e!s}"
        demisto.error(error_msg)
        raise Exception(error_msg)


def severity_to_level(severity: str | None) -> int | float:
    match severity:
        case "informational":
            return 0.5
        case "critical":
            return 4
        case "high":
            return 3
        case "medium":
            return 2
        case _:
            return 1


def parse_finding(finding: dict[str, Any], to_dict: bool = False) -> dict[str, Any]:
    """Parses the finding

    Args:
        finding (OrderedDict): The finding
        to_dict (bool): Whether to cast the finding to dict or not.

    Returns (OrderedDict or dict): The parsed finding
    """
    finding = replace_keys(finding) if REPLACE_FLAG else finding
    for key, val in list(finding.items()):
        # if finding event raw fields were sent in double quotes (e.g. "DNS Destination") and the field does not exist
        # in the event, then splunk returns the field with the key as value (e.g. ("DNS Destination", "DNS Destination")
        # so we go over the fields, and check if the key equals the value and set the value to be empty string
        if key == val:
            demisto.debug(
                f"Found finding event raw field [{key}] with key that equals the value - replacing the value with empty string"
            )
            finding[key] = ""
    return dict(finding) if to_dict else finding


def requests_handler(url: str, message: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    method = message["method"].lower()
    data = message.get("body", "") if method == "post" else None
    headers = dict(message.get("headers", []))
    try:
        response = requests.request(method, url, data=data, headers=headers, verify=VERIFY_CERTIFICATE, **kwargs)
    except requests.exceptions.HTTPError as e:
        # Propagate HTTP errors via the returned response message
        response = e.response
        demisto.debug(f"Got exception while using requests handler - {e!s}")
    return {
        "status": response.status_code,
        "reason": response.reason,
        "headers": list(response.headers.items()),
        "body": io.BytesIO(response.content),
    }


def build_search_kwargs(args: dict[str, Any], polling: bool = False) -> dict[str, Any]:
    t = datetime.now(pytz.UTC) - timedelta(days=7)
    time_str = t.strftime(ISO_FORMAT_TZ_AWARE)

    kwargs_normal_search: dict[str, Any] = {
        "earliest_time": time_str,
    }
    if demisto.get(args, "earliest_time"):
        kwargs_normal_search["earliest_time"] = args["earliest_time"]
    if demisto.get(args, "latest_time"):
        kwargs_normal_search["latest_time"] = args["latest_time"]
    if demisto.get(args, "app"):
        kwargs_normal_search["app"] = args["app"]
    if argToBoolean(demisto.get(args, "fast_mode")):
        kwargs_normal_search["adhoc_search_level"] = "fast"
    kwargs_normal_search["exec_mode"] = "normal" if polling else "blocking"
    return kwargs_normal_search


def build_search_query(args: dict[str, Any]) -> str:
    query = args["query"]
    if not query.startswith("search") and not query.startswith("Search") and not query.startswith("|"):
        query = f"search {query}"
    return query


def create_entry_context(
    args: dict[str, Any],
    parsed_search_results: list[dict[str, Any]],
    dbot_scores: list[dict[str, Any]],
    status_res: CommandResults | None,
    job_id: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    ec = {}
    dbot_ec = {}
    number_of_results = len(parsed_search_results)

    if args.get("update_context", "true") == "true":
        ec["Splunk.Result"] = parsed_search_results
        if len(dbot_scores) > 0:
            dbot_ec["DBotScore"] = dbot_scores
        if status_res:
            ec["Splunk.JobStatus(val.SID && val.SID === obj.SID)"] = {**status_res.outputs, "TotalResults": number_of_results}  # type: ignore[dict-item, assignment]
    if job_id and not status_res:
        status = "DONE" if (number_of_results > 0) else "NO RESULTS"
        ec["Splunk.JobStatus(val.SID && val.SID === obj.SID)"] = [
            {"SID": job_id, "TotalResults": number_of_results, "Status": status}
        ]
    return ec, dbot_ec


def schedule_polling_command(command: str, args: dict[str, Any], interval_in_secs: int) -> ScheduledCommand:
    """
    Returns a ScheduledCommand object which contain the needed arguments for schedule the polling command.
    """
    return ScheduledCommand(command=command, next_run_in_seconds=interval_in_secs, args=args, timeout_in_seconds=600)


def build_search_human_readable(args: dict[str, Any], parsed_search_results: list[dict[str, Any]], sid: str | None) -> str:
    headers: str | list[str] = ""
    if parsed_search_results and len(parsed_search_results) > 0:
        if not isinstance(parsed_search_results[0], dict):
            headers = "results"
        else:
            query = args.get("query", "")
            table_args = re.findall(" table (?P<table>[^|]*)", query)
            rename_args = re.findall(" rename (?P<rename>[^|]*)", query)

            chosen_fields: list = []
            for arg_string in table_args:
                chosen_fields.extend(field.strip('"') for field in re.findall(r'((?:".*?")|(?:[^\s,]+))', arg_string) if field)
            rename_dict = {}
            for arg_string in rename_args:
                for field in re.findall(r'((?:".*?")|(?:[^\s,]+))( AS )((?:".*?")|(?:[^\s,]+))', arg_string):
                    if field:
                        rename_dict[field[0].strip('"')] = field[-1].strip('"')

            # replace renamed fields
            chosen_fields = [rename_dict.get(field, field) for field in chosen_fields]

            headers = update_headers_from_field_names(parsed_search_results, chosen_fields)

    query = args["query"].replace("`", r"\`")
    hr_headline = "Splunk Search results for query:\n"
    if sid:
        hr_headline += f"sid: {sid!s}"
    return tableToMarkdown(hr_headline, parsed_search_results, headers)


def update_headers_from_field_names(search_result: list[dict[str, Any]], chosen_fields: list[str]) -> list[str]:
    headers: list = []
    search_result_keys: set = set().union(*(list(d.keys()) for d in search_result))
    for field in chosen_fields:
        if field[-1] == "*":
            temp_field = field.replace("*", ".*")
            headers.extend(key for key in search_result_keys if re.search(temp_field, key))
        elif field in search_result_keys:
            headers.append(field)

    return headers


def get_current_results_batch(search_job: client.Job, batch_size: int, results_offset: int) -> Any:
    current_batch_kwargs = {
        "count": batch_size,
        "offset": results_offset,
        "output_mode": OUTPUT_MODE_JSON,
    }

    return search_job.results(**current_batch_kwargs)


def parse_batch_of_results(
    current_batch_of_results: Any, max_results_to_add: float, app: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    parsed_batch_results = []
    batch_dbot_scores = []
    results_reader = results.JSONResultsReader(io.BufferedReader(ResponseReaderWrapper(current_batch_of_results)))
    for item in results_reader:
        if handle_message(item):
            continue

        elif isinstance(item, dict):
            if demisto.get(item, "host"):
                batch_dbot_scores.append(
                    {"Indicator": item["host"], "Type": "hostname", "Vendor": "Splunk", "Score": 0, "isTypedIndicator": True}
                )
            if app:
                item["app"] = app
            # Normal events are returned as dicts
            parsed_batch_results.append(item)

        if len(parsed_batch_results) >= max_results_to_add:
            break
    return parsed_batch_results, batch_dbot_scores


def raise_error_for_failed_job(job: client.Job | None) -> None:
    """
    Handle the case that the search job failed due to dome reason like parsing issues etc
    raise DemistoException in case there is a fatal error in the search job.
    see https://docs.splunk.com/Documentation/Splunk/9.3.0/RESTTUT/RESTsearches#:~:text=the%20results%20returned.-,dispatchState,-dispatchState%20is%20one

    Args:
        job (Job): the created search job

    Raises:
        Exception: DemistoException in case there is a fatal error
    """
    err_msg = None
    try:
        if job and job["dispatchState"] == "FAILED":
            messages = job["messages"]
            for err_type in ["fatal", "error"]:
                if messages.get(err_type):
                    err_msg = ",".join(messages[err_type])
                    break
    except Exception:
        pass
    if err_msg:
        raise DemistoException(f"Failed to run the search in Splunk: {err_msg}")


def splunk_search_command(service: client.Service, args: dict[str, Any]) -> CommandResults | list[CommandResults]:
    query = build_search_query(args)
    polling = argToBoolean(args.get("polling", False))
    search_kwargs = build_search_kwargs(args, polling)
    job_sid = args.get("sid")
    search_job = None
    interval_in_secs = int(args.get("interval_in_seconds", 30))
    if not job_sid or not polling:
        # create a new job to search the query.
        search_job = service.jobs.create(query, **search_kwargs)
        job_sid = search_job["sid"]
        args["sid"] = job_sid
        raise_error_for_failed_job(search_job)

    status_cmd_result: CommandResults | None = None
    if polling:
        status_cmd_results = splunk_job_status(service, args)
        assert status_cmd_results  # if polling is true, status_cmd_result should not be an empty list
        status_cmd_result = status_cmd_results[0]
        status = status_cmd_result.outputs["Status"]  # type: ignore[index]
        if status.lower() != "done":
            # Job is still running, schedule the next run of the command.
            scheduled_command = schedule_polling_command("splunk-search", args, interval_in_secs)
            status_cmd_result.scheduled_command = scheduled_command
            status_cmd_result.readable_output = "Job is still running, it may take a little while..."
            return status_cmd_result
        else:
            # Get the job by its SID.
            search_job = service.job(job_sid)
    num_of_results_from_query = search_job["resultCount"] if search_job else None

    results_limit = float(args.get("event_limit", 100))
    if results_limit == 0.0:
        # In Splunk, a result limit of 0 means no limit.
        results_limit = float("inf")
    batch_size = int(args.get("batch_limit", 25000))

    results_offset = 0
    total_parsed_results: list[dict[str, Any]] = []
    dbot_scores: list[dict[str, Any]] = []

    while (
        len(total_parsed_results) < int(num_of_results_from_query)  # type: ignore[arg-type]
        and len(total_parsed_results) < results_limit
    ):
        current_batch_of_results = get_current_results_batch(search_job, batch_size, results_offset)
        max_results_to_add = results_limit - len(total_parsed_results)
        parsed_batch_results, batch_dbot_scores = parse_batch_of_results(
            current_batch_of_results, max_results_to_add, search_kwargs.get("app", "")
        )
        total_parsed_results.extend(parsed_batch_results)
        dbot_scores.extend(batch_dbot_scores)

        results_offset += batch_size
    entry_context_splunk_search, entry_context_dbot_score = create_entry_context(
        args, total_parsed_results, dbot_scores, status_cmd_result, str(job_sid)
    )
    human_readable = build_search_human_readable(args, total_parsed_results, str(job_sid))
    results = [
        CommandResults(outputs=entry_context_splunk_search, raw_response=total_parsed_results, readable_output=human_readable)
    ]
    dbot_table_headers = ["Indicator", "Type", "Vendor", "Score", "isTypedIndicator"]
    if entry_context_dbot_score:
        results.append(
            CommandResults(
                outputs=entry_context_dbot_score,
                readable_output=tableToMarkdown("DBot Score", entry_context_dbot_score["DBotScore"], headers=dbot_table_headers),
            )
        )
    return results


def splunk_job_create_command(service: client.Service, args: dict[str, Any]) -> None:
    app = args.get("app", "")
    query = build_search_query(args)
    search_kwargs = {"exec_mode": "normal", "app": app}
    search_job = service.jobs.create(query, **search_kwargs)

    return_results(
        CommandResults(
            outputs_prefix="Splunk",
            readable_output=f"Splunk Job created with SID: {search_job.sid}",
            outputs={"Job": search_job.sid},
        )
    )


def splunk_results_command(service: client.Service, args: dict[str, Any]) -> str | None:
    res = []
    sid = args.get("sid", "")
    limit = int(args.get("limit", "100"))
    try:
        job = service.job(sid)
    except HTTPError as error:
        msg = error.message if hasattr(error, "message") else str(error)
        if error.status == 404:
            return f"Found no job for sid: {sid}"
        else:
            return_error(msg, error)
    else:
        for result in results.JSONResultsReader(job.results(count=limit, output_mode=OUTPUT_MODE_JSON)):
            if isinstance(result, results.Message):
                res.append({"Splunk message": json.dumps(result.message)})
            elif isinstance(result, dict):
                # Normal events are returned as dicts
                res.append(result)
        return_results(
            CommandResults(
                raw_response=json.dumps(res),
                content_format=EntryFormat.JSON,
            )
        )
    return None


def splunk_get_indexes_command(service: client.Service, app: str = "-"):
    search_query = f"""| rest "/servicesNS/nobody/{app}/data/indexes/?count=-1&offset=0"
    | eval name=title, count=totalEventCount
    | table name, count"""

    indexesNames = []

    # Try the first approach: REST API query
    try:
        demisto.debug("Attempting to get indexes using REST API query approach")
        for item in results.JSONResultsReader(service.jobs.oneshot(query=search_query, output_mode=OUTPUT_MODE_JSON)):
            if handle_message(item):
                continue
            indexesNames.append(item)
        demisto.debug(f"Successfully retrieved {len(indexesNames)} indexes using REST API query approach")
    except Exception as e:
        # Log the error and fall back to the second approach
        demisto.error(f"Failed to get indexes using REST API query approach: {e!s}")
        demisto.debug("Falling back to direct API approach using service.indexes")

        try:
            # Second approach: Direct API using service.indexes
            indexes = service.indexes
            for index in indexes:
                index_json = {"name": index.name, "count": index["totalEventCount"]}
                indexesNames.append(index_json)
            demisto.debug(f"Successfully retrieved {len(indexesNames)} indexes using direct API approach")
        except Exception as fallback_error:
            demisto.error(f"Failed to get indexes using direct API approach: {fallback_error!s}")
            raise DemistoException(
                f"Failed to retrieve indexes using both methods. " f"REST API error: {e!s}. Direct API error: {fallback_error!s}"
            )

    return_results(
        CommandResults(
            content_format=EntryFormat.JSON,
            raw_response=json.dumps(indexesNames),
            readable_output=tableToMarkdown("Splunk Indexes names", indexesNames, ""),
        )
    )


def splunk_submit_event_command(service: client.Service, args: dict[str, Any]) -> None:
    try:
        index = service.indexes[args["index"]]
    except KeyError:
        return_error(f'Found no Splunk index: {args["index"]}')

    else:
        data = args["data"]
        data_formatted = data.encode("utf8")
        r = index.submit(data_formatted, sourcetype=args["sourcetype"], host=args["host"])
        return_results(f"Event was created in Splunk index: {r.name}")


def get_events_from_file(entry_id: str) -> str:
    """
    Retrieves event data from a file in Demisto based on a specified entry ID as a string.

    Args:
        entry_id (int): The entry ID corresponding to the file containing event data.

    Returns:
        str: The content of the file as a string.
    """
    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res["path"]
    with open(file_path, encoding="utf-8") as file_data:
        return file_data.read()


def parse_fields(fields: str | None) -> dict[str, Any] | None:
    """
    Parses the `fields` input into a dictionary.

    - If `fields` is a valid JSON string, it is converted into the corresponding dictionary.
    - If `fields` is not valid JSON, it is wrapped as a dictionary with a single key-value pair,
    where the key is `"fields"` and the value is the original `fields` string.

    Examples:
    1. Input: '{"severity": "INFO", "category": "test2, test2"}'
       Output: {"severity": "INFO", "category": "test2, test2"}

    2. Input: 'severity: INFO, category: test2, test2'
       Output: {"fields": "severity: INFO, category: test2, test2"}
    """
    if fields:
        try:
            parsed_fields = json.loads(fields)
        except Exception:
            demisto.debug("Fields provided are not valid JSON; treating as a single field")
            parsed_fields = {"fields": fields}
        return parsed_fields
    return None


def splunk_submit_event_hec(
    hec_token: str | None,
    baseurl: str,
    event: str | None,
    fields: str | None,
    host: str | None,
    index: str | None,
    source_type: str | None,
    source: str | None,
    time_: str | None,
    request_channel: str | None,
    batch_event_data: str | None,
    entry_id: str | None,
    service: client.Service,
) -> requests.Response:
    if hec_token is None:
        raise Exception("The HEC Token was not provided")

    if batch_event_data:
        events = batch_event_data

    elif entry_id:
        demisto.debug(f"{INTEGRATION_LOG} - loading events data from file with {entry_id=}")
        events = get_events_from_file(entry_id)

    else:
        parsed_fields = parse_fields(fields)

        events = assign_params(
            event=event, host=host, fields=parsed_fields, index=index, sourcetype=source_type, source=source, time=time_
        )

    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json",
    }
    if request_channel:
        headers["X-Splunk-Request-Channel"] = request_channel

    data = ""
    if entry_id or batch_event_data:
        data = events
    else:
        data = json.dumps(events)

    return requests.post(
        f"{baseurl}/services/collector/event",
        data=data,
        headers=headers,
        verify=VERIFY_CERTIFICATE,
    )


def splunk_submit_event_hec_command(params: dict[str, Any], service: client.Service, args: dict[str, Any]) -> None:
    hec_token = params.get("cred_hec_token", {}).get("password")
    baseurl = params.get("hec_url")
    if baseurl is None:
        raise Exception("The HEC URL was not provided.")

    event = args.get("event")
    host = args.get("host")
    fields = args.get("fields")
    index = args.get("index")
    source_type = args.get("source_type")
    source = args.get("source")
    time_ = args.get("time")
    request_channel = args.get("request_channel")
    batch_event_data = args.get("batch_event_data")
    entry_id = args.get("entry_id")

    if not event and not batch_event_data and not entry_id:
        raise DemistoException(
            "Invalid input: Please specify one of the following arguments: `event`, `batch_event_data`, or `entry_id`."
        )

    response_info = splunk_submit_event_hec(
        hec_token,
        baseurl,
        event,
        fields,
        host,
        index,
        source_type,
        source,
        time_,
        request_channel,
        batch_event_data,
        entry_id,
        service,
    )

    if "Success" not in response_info.text:
        return_error(f"Could not send event to Splunk {response_info.text}")
    else:
        response_dict = json.loads(response_info.text)
        if response_dict and "ackId" in response_dict:
            return_results(f"The events were sent successfully to Splunk. AckID: {response_dict['ackId']}")
        else:
            return_results("The events were sent successfully to Splunk.")


def splunk_edit_finding_command(service: client.Service, args: dict) -> None:
    """Edit finding events in Splunk ES using the v2 investigations API.

    Args:
        service: Splunk service connection
        args: Command arguments containing event_ids and fields to update
    """
    event_ids = argToList(args.get("event_ids"))
    if not event_ids:
        return_error("event_ids parameter is required")
        return

    # Prepare the fields to update
    status = args.get("status")
    urgency = args.get("urgency")
    owner = args.get("owner")
    disposition = args.get("disposition", "")

    # Map the status label to the status id if needed
    if status and status in DEFAULT_STATUSES:
        status = DEFAULT_STATUSES[status]

    # Map the disposition label to the disposition id if needed
    if disposition and disposition in DEFAULT_DISPOSITIONS:
        disposition = DEFAULT_DISPOSITIONS[disposition]

    note = args.get("note")

    # Track results for each event ID
    results = []
    errors = []

    for event_id in event_ids:
        event_id = event_id.strip()
        try:
            # Update the finding using the v2 API
            update_investigation_or_finding(
                service=service,
                investigation_or_finding_id=event_id,
                owner=owner,
                urgency=urgency,
                status=status,
                disposition=disposition,
            )

            # Add note separately if provided
            if note:
                try:
                    add_investigation_note(
                        service=service,
                        investigation_or_finding_id=event_id,
                        content=note,
                    )
                    results.append(f"Successfully updated finding {event_id} (including note)")
                except Exception as e:
                    demisto.error(f"Failed to add note to finding {event_id}: {e!s}")
                    results.append(f"Successfully updated finding {event_id} (note failed: {e!s})")
            else:
                results.append(f"Successfully updated finding {event_id}")

        except Exception as e:
            error_msg = f"Failed to update finding {event_id}: {e!s}"
            demisto.error(error_msg)
            errors.append(error_msg)

    # Prepare the output message
    if results and not errors:
        return_results("Splunk Finding events updated successfully:\n" + "\n".join(results))
    elif results and errors:
        return_results(
            "Splunk Finding events partially updated:\n"
            "Successes:\n" + "\n".join(results) + "\n"
            "Errors:\n" + "\n".join(errors)
        )
    else:
        return_error("Failed to update all finding events:\n" + "\n".join(errors))


def splunk_job_status(service: client.Service, args: dict[str, Any]) -> list[CommandResults]:
    sids = argToList(args.get("sid"))
    job_results = []
    for sid in sids:
        try:
            job = service.job(sid)
        except HTTPError as error:
            if str(error) == "HTTP 404 Not Found -- Unknown sid.":
                job_results.append(CommandResults(readable_output=f"Not found job for SID: {sid}"))
            else:
                job_results.append(
                    CommandResults(readable_output=f"Querying splunk for SID: {sid} resulted in the following error {str(error)}")
                )
        else:
            status = job.state.content.get("dispatchState")
            entry_context = {"SID": sid, "Status": status}
            human_readable = tableToMarkdown("Splunk Job Status", entry_context)
            job_results.append(
                CommandResults(
                    outputs=entry_context,
                    readable_output=human_readable,
                    outputs_prefix="Splunk.JobStatus",
                    outputs_key_field="SID",
                )
            )
    return job_results


def splunk_job_share(service: client.Service, args: dict[str, Any]) -> list[CommandResults]:  # pragma: no cover
    sids = argToList(args.get("sid"))
    try:
        ttl = int(args.get("ttl", 1800))
    except ValueError:
        return_error(f"Input error: Invalid TTL provided, '{args.get('ttl')}'. Must be a valid integer.")

    job_results = []
    for sid in sids:
        try:
            job = service.job(sid)
        except HTTPError as error:
            if str(error) == "HTTP 404 Not Found -- Unknown sid.":
                job_results.append(CommandResults(readable_output=f"Not found job for SID: {sid}"))
            else:
                job_results.append(
                    CommandResults(readable_output=f"Querying splunk for SID: {sid} resulted in the following error {str(error)}")
                )
        else:
            try:
                ttl_results = True
                job.set_ttl(ttl)  # extend time-to-live for results
            except HTTPError as error:
                job_results.append(
                    CommandResults(
                        readable_output=f"Error increasing TTL for SID: {sid} resulted in the following error {str(error)}"
                    )
                )
                ttl_results = False
            try:
                share_results = True
                endpoint = f"search/jobs/{sid}/acl"
                service.post(endpoint, **{"sharing": "global", "perms.read": "*"})
            except HTTPError as error:
                job_results.append(
                    CommandResults(
                        readable_output=f"Error changing permissions for SID: {sid} resulted in the following error {str(error)}"
                    )
                )
                share_results = False

            entry_context = {"SID": sid, "TTL updated": str(ttl_results), "Sharing updated": str(share_results)}
            human_readable = tableToMarkdown("Splunk Job Updates", entry_context)
            job_results.append(
                CommandResults(
                    outputs=entry_context,
                    readable_output=human_readable,
                    outputs_prefix="Splunk.JobUpdates",
                    outputs_key_field="SID",
                )
            )
    return job_results


def splunk_parse_raw_command(args: dict[str, Any]) -> None:
    raw = args.get("raw", "")
    raw_dict = raw_to_dict(raw)
    return_results(
        CommandResults(
            outputs_prefix="Splunk.Raw.Parsed",
            raw_response=json.dumps(raw_dict),
            outputs=raw_dict,
            content_format=EntryFormat.JSON,
        )
    )


def test_module(service: client.Service, params: dict[str, Any]) -> None:
    try:
        # validate connection
        service.info()
    except AuthenticationError:
        return_error("Authentication error, please validate your credentials.")

    # validate fetch
    if params.get("isFetch"):
        t = datetime.now(pytz.UTC) - timedelta(days=3)
        time = t.strftime(ISO_FORMAT_TZ_AWARE)
        kwargs = {"count": 1, "earliest_time": time, "output_mode": OUTPUT_MODE_JSON}
        query = params["fetchQuery"]
        try:
            has_event_id = False
            for item in results.JSONResultsReader(service.jobs.oneshot(query, **kwargs)):
                if isinstance(item, results.Message):
                    continue

                if EVENT_ID not in item:
                    if MIRROR_DIRECTION.get(params.get("mirror_direction", "")):
                        return_error("Cannot mirror incidents if fetch query does not use the `notable` macro.")
                    if ENABLED_ENRICHMENTS:
                        return_error(
                            "When using the enrichment mechanism, an event_id field is needed, and thus, "
                            "one must use a fetch query of the following format: search `notable` .......\n"
                            "Please re-edit the fetchQuery parameter in the integration configuration, reset "
                            "the fetch mechanism using the splunk-reset-enriching-fetch-mechanism command and "
                            "run the fetch again."
                        )
                else:
                    has_event_id = True

        except HTTPError as error:
            return_error(str(error))

        # Validate custom ID generation for queries without `notable` macro
        if not has_event_id and "`notable`" not in query:
            try:
                demisto.debug("Running duplicate incident ID validation test")
                test_kwargs = {"count": 10, "earliest_time": time, "output_mode": OUTPUT_MODE_JSON}
                test_items = [
                    item
                    for item in results.JSONResultsReader(service.jobs.oneshot(query, **test_kwargs))
                    if not isinstance(item, results.Message)
                ]

                if len(test_items) >= 2:
                    custom_ids = [
                        create_incident_custom_id(
                            Finding(data=item).to_incident(
                                UserMappingObject(service, False, "splunk_xsoar_users", "xsoar_user", "splunk_user")
                            )
                        )
                        for item in test_items
                    ]

                    if len(set(custom_ids)) < len(custom_ids):
                        return_error(
                            f"Duplicate incident IDs detected in test ({len(custom_ids) - len(set(custom_ids))} duplicates).\n\n"
                            "IMPACT: Incidents with duplicate IDs will be incorrectly identified as already fetched during the "
                            "fetch process.\n"
                            "This means these incidents will be dropped and will NOT be created in XSOAR, resulting in missing "
                            "incidents.\n\n"
                            "CAUSE: The integration generates incident IDs from fields: _cd, index, _time, _indextime, _raw.\n"
                            "These fields may not provide unique values in your fetch query.\n\n"
                            "SOLUTION: Configure the 'Unique ID Fields' parameter in the integration settings.\n"
                            "Add a comma-separated list of additional fields "
                            "that will create unique combinations for each incident.\n"
                            "Example: source,host,unique_field\n\n"
                            "The parameter can be found in the integration configuration under:\n"
                            "Advanced Settings -> Unique ID Fields"
                        )
                    demisto.debug(
                        f"Duplicate ID validation passed: {len(set(custom_ids))} unique IDs from {len(custom_ids)} incidents"
                    )
            except Exception as e:
                demisto.debug(f"Could not complete duplicate ID validation: {e!s}")
    if params.get("hec_url"):
        headers = {"Content-Type": "application/json"}
        try:
            requests.get(params.get("hec_url", "") + "/services/collector/health", headers=headers, verify=VERIFY_CERTIFICATE)
        except Exception as e:
            return_error("Could not connect to HEC server. Make sure URL and token are correct.", e)


def replace_keys(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        return data
    for key in list(data.keys()):
        value = data.pop(key)
        for character in PROBLEMATIC_CHARACTERS:
            key = key.replace(character, REPLACE_WITH)

        data[key] = value
    return data


def kv_store_collection_create(service: client.Service, args: dict[str, Any]) -> CommandResults:
    try:
        service.kvstore.create(args["kv_store_name"])
    except HTTPError as error:
        if error.status == 409 and error.reason == "Conflict":
            raise DemistoException(
                f"KV store collection {service.namespace['app']} already exists.",
            ) from error
        raise

    return CommandResults(
        readable_output=f"KV store collection {service.namespace['app']} created successfully",
    )


def kv_store_collection_config(service: client.Service, args: dict[str, Any]) -> CommandResults:
    app = service.namespace["app"]
    kv_store_collection_name = args["kv_store_collection_name"]
    kv_store_fields = args["kv_store_fields"].split(",")
    for key_val in kv_store_fields:
        try:
            _key, val = key_val.split("=", 1)
        except ValueError:
            return_error(f"error when trying to parse {key_val} you possibly forgot to add the field type.")
        else:
            if _key.startswith("index."):
                service.kvstore[kv_store_collection_name].update_index(_key.replace("index.", ""), val)
            else:
                service.kvstore[kv_store_collection_name].update_field(_key.replace("field.", ""), val)
    return CommandResults(readable_output=f"KV store collection {app} configured successfully")


def kv_store_collection_create_transform(service: client.Service, args: dict[str, Any]) -> CommandResults:
    collection_name = args["kv_store_collection_name"]
    fields = args.get("supported_fields")
    if not fields:
        kv_store = service.kvstore[collection_name]
        default_keys = get_keys_and_types(kv_store).keys()
        if not default_keys:
            raise DemistoException("Please provide supported_fields or run first splunk-kv-store-collection-config")
        default_keys = (key.replace("field.", "").replace("index.", "") for key in default_keys)
        fields = f"_key,{','.join(default_keys)}"

    transforms = service.confs["transforms"]
    params = {"external_type": "kvstore", "collection": collection_name, "namespace": service.namespace, "fields_list": fields}
    transforms.create(name=collection_name, **params)
    return CommandResults(readable_output=f"KV store collection transforms {collection_name} created successfully")


def batch_kv_upload(kv_data_service_client: client.KVStoreCollectionData, json_data: str) -> dict[str, Any]:
    if json_data.startswith("[") and json_data.endswith("]"):
        record: Record = kv_data_service_client._post(
            "batch_save", headers=client.KVStoreCollectionData.JSON_HEADER, body=json_data.encode("utf-8")
        )
        return dict(record.items())
    elif json_data.startswith("{") and json_data.endswith("}"):
        return kv_data_service_client.insert(json_data.encode("utf-8"))
    else:
        raise DemistoException(
            'kv_store_data argument should be in json format. (e.g. {"key": "value"} or [{"key": "value"}, {"key": "value"}]'
        )


def kv_store_collection_add_entries(service: client.Service, args: dict[str, Any]) -> None:
    kv_store_data = args.get("kv_store_data", "")
    kv_store_collection_name = args["kv_store_collection_name"]
    indicator_path = args.get("indicator_path")
    batch_kv_upload(service.kvstore[kv_store_collection_name].data, kv_store_data)
    indicators_timeline = None
    if indicator_path:
        kv_store_data = json.loads(kv_store_data)
        indicators = extract_indicator(indicator_path, kv_store_data if isinstance(kv_store_data, list) else [kv_store_data])
        indicators_timeline = IndicatorsTimeline(
            indicators=indicators,
            category="Integration Update",
            message=f"Indicator added to {kv_store_collection_name} store in Splunk",
        )
    return_results(
        CommandResults(readable_output=f"Data added to {kv_store_collection_name}", indicators_timeline=indicators_timeline)
    )


def kv_store_collections_list(service: client.Service) -> None:
    app_name = service.namespace["app"]
    names = [x.name for x in service.kvstore.iter()]
    readable_output = "list of collection names {}\n| name |\n| --- |\n|{}|".format(app_name, "|\n|".join(names))
    return_results(
        CommandResults(outputs_prefix="Splunk.CollectionList", outputs=names, readable_output=readable_output, raw_response=names)
    )


def kv_store_collection_data_delete(service: client.Service, args: dict[str, Any]) -> None:
    kv_store_collection_name = args["kv_store_collection_name"].split(",")
    for store in kv_store_collection_name:
        service.kvstore[store].data.delete()
    return_results(f"The values of the {args['kv_store_collection_name']} were deleted successfully")


def kv_store_collection_delete(service: client.Service, args: dict[str, Any]) -> CommandResults:
    kv_store_names = args["kv_store_name"]
    for store in kv_store_names.split(","):
        service.kvstore[store].delete()
    return CommandResults(readable_output=f"The following KV store {kv_store_names} were deleted successfully.")


def build_kv_store_query(kv_store: client.KVStoreCollection, args: dict[str, Any]) -> str | dict[str, Any]:
    if "key" in args and "value" in args:
        _type = get_key_type(kv_store, args["key"])
        args["value"] = _type(args["value"]) if _type else args["value"]
        return json.dumps({args["key"]: args["value"]})
    elif "limit" in args:
        return {"limit": args["limit"]}
    else:
        return args.get("query", "{}")


def kv_store_collection_data(service: client.Service, args: dict[str, Any]) -> None:
    stores = args["kv_store_collection_name"].split(",")

    for i, store_res in enumerate(get_store_data(service)):
        store = service.kvstore[stores[i]]

        if store_res:
            readable_output = tableToMarkdown(name=f"list of collection values {store.name}", t=store_res)
            return_results(
                CommandResults(
                    outputs_prefix="Splunk.KVstoreData",
                    outputs={store.name: store_res},
                    readable_output=readable_output,
                    raw_response=store_res,
                )
            )
        else:
            return_results(get_kv_store_config(store))


def kv_store_collection_delete_entry(service: client.Service, args: dict[str, Any]) -> None:
    store_name = args["kv_store_collection_name"]
    indicator_path = args.get("indicator_path")
    store: client.KVStoreCollection = service.kvstore[store_name]
    query = build_kv_store_query(store, args)
    store_res = next(get_store_data(service))
    indicators = extract_indicator(indicator_path, store_res) if indicator_path else []
    store.data.delete(query=query)
    indicators_timeline = (
        IndicatorsTimeline(
            indicators=indicators, category="Integration Update", message=f"Indicator deleted from {store_name} store in Splunk"
        )
        if indicators
        else None
    )
    return_results(
        CommandResults(
            readable_output=f"The values of the {store_name} were deleted successfully", indicators_timeline=indicators_timeline
        )
    )


def check_error(service: client.Service, args: dict[str, Any]) -> None:
    app = args.get("app_name")
    store_name = args.get("kv_store_collection_name")
    if app not in service.apps:
        raise DemistoException("app not found")
    elif store_name and store_name not in service.kvstore:
        raise DemistoException("KV Store not found")


def get_key_type(kv_store: client.KVStoreCollection, _key: str) -> type | None:
    keys_and_types = get_keys_and_types(kv_store)
    types = {"number": float, "string": str, "cidr": str, "boolean": bool, "time": str}
    index = f"index.{_key}"
    field = f"field.{_key}"
    val_type = keys_and_types.get(field) or keys_and_types.get(index) or ""
    return types.get(val_type)


def get_keys_and_types(kv_store: client.KVStoreCollection) -> dict[str, str]:
    keys = kv_store.content()
    for key_name in list(keys.keys()):
        if not (key_name.startswith(("field.", "index."))):
            del keys[key_name]
    return keys


def get_kv_store_config(kv_store: client.KVStoreCollection) -> str:
    keys = get_keys_and_types(kv_store)
    readable = [f"#### configuration for {kv_store.name} store", "| field name | type |", "| --- | --- |"]
    readable.extend(f"| {_key} | {val} |" for _key, val in keys.items())
    return "\n".join(readable)


def extract_indicator(indicator_path: str, _dict_objects: list[dict[str, Any]]) -> list[str]:
    indicators = []
    indicator_paths = indicator_path.split(".")
    for indicator_obj in _dict_objects:
        indicator = ""
        for path in indicator_paths:
            indicator = indicator_obj.get(path, {})
        indicators.append(str(indicator))
    return indicators


def get_store_data(service: client.Service) -> Any:
    args = demisto.args()
    stores = args["kv_store_collection_name"].split(",")

    for store in stores:
        kvstore: client.KVStoreCollection = service.kvstore[store]
        query = build_kv_store_query(kvstore, args)
        if isinstance(query, str):
            query = {"query": query}
        yield kvstore.data.query(**query)


def get_connection_args(params: dict[str, Any]) -> dict[str, Any]:
    """
    This function gets the connection arguments: host, port, app, and verify.
    Parses the server_url parameter to extract host and port, with port 8089 as default.

    Returns: connection args
    """
    server_url = params.get("server_url", "")
    # If URL doesn't have a scheme, add one for proper parsing
    if not server_url.startswith(("http://", "https://")):
        server_url = f"https://{server_url}"
    parsed = urllib.parse.urlparse(server_url)

    # Extract host (hostname or netloc without port)
    host = parsed.hostname or parsed.netloc.split(":")[0]
    host = host.rstrip("/")

    # Extract port or use default 8089
    port = parsed.port if parsed.port else 8089

    app = params.get("app", "-")
    return {
        "host": host,
        "port": port,
        "app": app or "-",
        "verify": VERIFY_CERTIFICATE,
        "retries": 3,
        "retryDelay": 3,
    }


def handle_message(item: results.Message | dict) -> bool:
    """Checks if the response from JSONResultsReader is a message object.
        The message can be info etc.
        such as: "the test table is empty"

    Args:
        item (results.Message | dict): The item to be checked. It can be either a `results.Message`
            object or a dictionary.

    Returns:
        bool: Returns `True` if the item is an instance of `results.Message`, `False` otherwise.

    """
    if isinstance(item, results.Message):
        demisto.info(f"Splunk-SDK message: {item.message}")
        return True
    return False


def main() -> None:  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    if command == "splunk-parse-raw":
        splunk_parse_raw_command(args)
        sys.exit(0)
    service = None
    proxy = argToBoolean(params.get("proxy", False))

    connection_args = get_connection_args(params)
    password = params["authentication"]["password"]
    connection_args["splunkToken"] = password
    connection_args["autologin"] = True

    if proxy:
        handle_proxy()

    # Validate that the note tags are different
    if NOTE_TAG_TO_SPLUNK == NOTE_TAG_FROM_SPLUNK:
        raise DemistoException("Note Tag to Splunk and Note Tag from Splunk cannot have the same value.")

    connection_args["handler"] = requests_handler

    if (service := client.connect(**connection_args)) is None:
        return_error("Could not connect to Splunk")

    mapper = UserMappingObject(
        service,
        params.get("userMapping"),
        params.get("user_map_lookup_name"),
        params.get("xsoar_user_field"),
        params.get("splunk_user_field"),
    )

    # The command command holds the command sent from the user.
    if command == "test-module":
        test_module(service, params)
        return_results("ok")
    elif command == "splunk-reset-enriching-fetch-mechanism":
        reset_enriching_fetch_mechanism()
    elif command == "splunk-search":
        return_results(splunk_search_command(service, args))
    elif command == "splunk-job-create":
        splunk_job_create_command(service, args)
    elif command == "splunk-results":
        splunk_results_command(service, args)
    elif command == "splunk-get-indexes":
        splunk_get_indexes_command(service, app=connection_args.get("app", "-"))
    elif command == "fetch-incidents":
        demisto.info("########### FETCH #############")
        fetch_incidents(service, mapper)
        extensive_log("[SplunkPy] Fetch Incidents was successfully executed.")
    elif command == "splunk-submit-event":
        splunk_submit_event_command(service, args)
    elif command == "splunk-finding-event-edit" and service is not None:
        service.namespace = namespace(app="missioncontrol", owner="nobody")
        splunk_edit_finding_command(service, args)
    elif command == "splunk-submit-event-hec":
        splunk_submit_event_hec_command(params, service, args)
    elif command == "splunk-job-status":
        return_results(splunk_job_status(service, args))
    elif command == "splunk-job-share":
        return_results(splunk_job_share(service, args))
    elif command.startswith("splunk-kv-") and service is not None:
        app = args.get("app_name", "search")
        service.namespace = namespace(app=app, owner="nobody", sharing="app")
        check_error(service, args)

        if command == "splunk-kv-store-collection-create":
            return_results(kv_store_collection_create(service, args))
        elif command == "splunk-kv-store-collection-config":
            return_results(kv_store_collection_config(service, args))
        elif command == "splunk-kv-store-collection-create-transform":
            return_results(kv_store_collection_create_transform(service, args))
        elif command == "splunk-kv-store-collection-delete":
            return_results(kv_store_collection_delete(service, args))
        elif command == "splunk-kv-store-collections-list":
            kv_store_collections_list(service)
        elif command == "splunk-kv-store-collection-add-entries":
            kv_store_collection_add_entries(service, args)
        elif command in ["splunk-kv-store-collection-data-list", "splunk-kv-store-collection-search-entry"]:
            kv_store_collection_data(service, args)
        elif command == "splunk-kv-store-collection-data-delete":
            kv_store_collection_data_delete(service, args)
        elif command == "splunk-kv-store-collection-delete-entry":
            kv_store_collection_delete_entry(service, args)

    elif command == "get-mapping-fields":
        return_results(get_mapping_fields_command(service, mapper, params))
    elif command == "get-remote-data":
        raise NotImplementedError(f"the {command} command is not implemented, use get-modified-remote-data instead.")
    elif command == "get-modified-remote-data":
        demisto.info("########### MIRROR IN #############")
        try:
            get_modified_remote_data_command(
                service=service,
                args=args,
                close_incident=params.get("close_incident"),
                close_end_statuses=params.get("close_end_status_statuses"),
                close_extra_labels=argToList(params.get("close_extra_labels", "")),
                mapper=mapper,
            )
        except Exception as e:
            return_error(f"An error occurred during the Mirror In - in get_modified_remote_data_command: {e}")
    elif command == "update-remote-system" and service is not None:
        demisto.info("########### MIRROR OUT #############")
        service.namespace = namespace(app="missioncontrol", owner="nobody")
        return_results(update_remote_system_command(args, params, service, mapper))
    elif command == "splunk-get-username-by-xsoar-user":
        return_results(mapper.get_splunk_user_by_xsoar_command(args))
    else:
        raise NotImplementedError(f"Command not implemented: {command}")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()

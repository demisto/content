import concurrent.futures
import json
import time
import traceback
from copy import deepcopy
from threading import Lock
from typing import Callable, Dict, List, Optional
from urllib import parse

import requests
import urllib3
from requests.exceptions import HTTPError

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# disable insecure warnings
urllib3.disable_warnings()

""" ADVANCED GLOBAL PARAMETERS """
EVENTS_INTERVAL_SECS = 15           # interval between events polling
EVENTS_FAILURE_LIMIT = 3            # amount of consecutive failures events fetch will tolerate
FETCH_SLEEP = 60                    # sleep between fetches
BATCH_SIZE = 100                    # batch size used for offense ip enrichment
OFF_ENRCH_LIMIT = BATCH_SIZE * 10   # max amount of IPs to enrich per offense
LOCK_WAIT_TIME = 0.5                # time to wait for lock.acquire
MAX_WORKERS = 8                     # max concurrent workers used for events enriching
DOMAIN_ENRCH_FLG = "True"           # when set to true, will try to enrich offense and assets with domain names
RULES_ENRCH_FLG = "True"            # when set to true, will try to enrich offense with rule names

ADVANCED_PARAMETER_NAMES = [
    "EVENTS_INTERVAL_SECS",
    "EVENTS_FAILURE_LIMIT",
    "FETCH_SLEEP",
    "BATCH_SIZE",
    "OFF_ENRCH_LIMIT",
    "MAX_WORKERS",
    "DOMAIN_ENRCH_FLG",
    "RULES_ENRCH_FLG",
]

""" GLOBAL VARS """
SYNC_CONTEXT = True
RESET_KEY = "reset"
LAST_FETCH_KEY = "id"
API_USERNAME = "_api_token_key"
TERMINATING_SEARCH_STATUSES = {"CANCELED", "ERROR", "COMPLETED"}
EVENT_TIME_FIELDS = ["starttime"]
ASSET_TIME_FIELDS = ['created', 'last_reported', 'first_seen_scanner', 'last_seen_scanner']
EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)


""" Header names transformation maps """
# Format: {'OldName': 'NewName'}

OFFENSES_NAMES_MAP = {
    "follow_up": "Followup",
    "id": "ID",
    "description": "Description",
    "source_address_ids": "SourceAddress",
    "local_destination_address_ids": "DestinationAddress",
    "remote_destination_count": "RemoteDestinationCount",
    "start_time": "StartTime",
    "event_count": "EventCount",
    "magnitude": "Magnitude",
    "last_updated_time": "LastUpdatedTime",
    "offense_type": "OffenseType",
}

SINGLE_OFFENSE_NAMES_MAP = {
    "credibility": "Credibility",
    "relevance": "Relevance",
    "severity": "Severity",
    "assigned_to": "AssignedTo",
    "destination_networks": "DestinationHostname",
    "status": "Status",
    "closing_user": "ClosingUser",
    "closing_reason_id": "ClosingReason",
    "close_time": "CloseTime",
    "categories": "Categories",
    "follow_up": "Followup",
    "id": "ID",
    "description": "Description",
    "source_address_ids": "SourceAddress",
    "local_destination_address_ids": "DestinationAddress",
    "remote_destination_count": "RemoteDestinationCount",
    "start_time": "StartTime",
    "event_count": "EventCount",
    "flow_count": "FlowCount",
    "offense_source": "OffenseSource",
    "magnitude": "Magnitude",
    "last_updated_time": "LastUpdatedTime",
    "offense_type": "OffenseType",
    "protected": "Protected",
}

SEARCH_ID_NAMES_MAP = {"search_id": "ID", "status": "Status"}

ASSET_PROPERTIES_NAMES_MAP = {
    "Unified Name": "Name",
    "CVSS Collateral Damage Potential": "AggregatedCVSSScore",
    "Weight": "Weight",
}
ASSET_PROPERTIES_ENDPOINT_NAMES_MAP = {"Primary OS ID": "OS"}

FULL_ASSET_PROPERTIES_NAMES_MAP = {
    "Compliance Notes": "ComplianceNotes",
    "Compliance Plan": "CompliancePlan",
    "CVSS Collateral Damage Potential": "CollateralDamagePotential",
    "Location": "Location",
    "Switch ID": "SwitchID",
    "Switch Port ID": "SwitchPort",
    "Group Name": "GroupName",
    "Vulnerabilities": "Vulnerabilities",
}

REFERENCE_NAMES_MAP = {
    "number_of_elements": "NumberOfElements",
    "name": "Name",
    "creation_time": "CreationTime",
    "element_type": "ElementType",
    "time_to_live": "TimeToLive",
    "timeout_type": "TimeoutType",
    "data": "Data",
    "last_seen": "LastSeen",
    "source": "Source",
    "value": "Value",
    "first_seen": "FirstSeen",
}

DEVICE_MAP = {
    "asset_scanner_ids": "AssetScannerIDs",
    "custom_properties": "CustomProperties",
    "deleted": "Deleted",
    "description": "Description",
    "event_collector_ids": "EventCollectorIDs",
    "flow_collector_ids": "FlowCollectorIDs",
    "flow_source_ids": "FlowSourceIDs",
    "id": "ID",
    "log_source_ids": "LogSourceIDs",
    "log_source_group_ids": "LogSourceGroupIDs",
    "name": "Name",
    "qvm_scanner_ids": "QVMScannerIDs",
    "tenant_id": "TenantID",
}


class LongRunningIntegrationLogger(IntegrationLogger):
    """
    LOG class that ignores LOG calls if long_running
    """

    def __init__(self, long_running=False):
        super().__init__()
        self.long_running = long_running

    def __call__(self, message):
        # ignore messages if self.long_running
        if not self.long_running:
            super().__call__(message)


LOG = LongRunningIntegrationLogger(demisto.command() == "long-running-execution")


class FetchMode:
    """Enum class for fetch mode"""

    no_events = "Fetch Without Events"
    all_events = "Fetch With All Events"
    correlations_only = "Fetch Correlation Events Only"


class QRadarClient:
    """
    Client for sending QRadar requests
    """

    def __init__(
        self, server: str, proxies, credentials, offenses_per_fetch=50, insecure=False,
    ):
        self._server = server[:-1] if server.endswith("/") else server
        self._proxies = proxies
        self._auth_headers = {"Content-Type": "application/json"}
        self._use_ssl = not insecure
        self._username = credentials.get("identifier", "")
        self._password = credentials.get("password", "")
        if self._username == API_USERNAME:
            self._auth_headers["SEC"] = self._password
        self._offenses_per_fetch = min(
            int(offenses_per_fetch) if offenses_per_fetch else 50, 50
        )
        if not (self._username and self._password):
            raise Exception("Please provide a username/password or an API token.")
        self.lock = Lock()

    @property
    def server(self):
        return self._server

    @property
    def offenses_per_fetch(self):
        return self._offenses_per_fetch

    def send_request(self, method, url, headers=None, params=None, data=None):
        """
        Sends request to the server using the given method, url, headers and params
        """
        if not headers:
            headers = self._auth_headers
        res = None
        try:
            log_hdr = deepcopy(headers)
            sec_hdr = log_hdr.pop("SEC", None)
            formatted_params = json.dumps(params, indent=4)
            # default on sec_hdr, else, try username/password
            auth = (
                (self._username, self._password)
                if not sec_hdr and self._username and self._password
                else None
            )
            LOG(
                f"qradar is attempting {method} to {url} with headers:\n{headers}\nparams:\n{formatted_params}"
            )
            res = requests.request(
                method,
                url,
                proxies=self._proxies,
                headers=headers,
                params=params,
                verify=self._use_ssl,
                data=data,
                auth=auth,
            )
            res.raise_for_status()
        except HTTPError:
            if res is not None:
                try:
                    err_json = res.json()
                except ValueError:
                    raise Exception(f"Error code {str(res.status_code)}\nContent: {str(res.content)}")

                err_msg = ""
                if "message" in err_json:
                    err_msg += "Error: {0}.\n".format(err_json["message"])
                elif "http_response" in err_json:
                    err_msg += "Error: {0}.\n".format(err_json["http_response"])
                if "code" in err_json:
                    err_msg += "QRadar Error Code: {0}".format(err_json["code"])

                raise Exception(err_msg)
            else:
                raise

        try:
            json_body = res.json()
        except ValueError:
            LOG(
                "Got unexpected response from QRadar. Raw response: {}".format(res.text)
            )
            raise DemistoException("Got unexpected response from QRadar")
        return json_body

    def test_connection(self):
        """
        Test connection with databases (should always be up)
        """
        full_url = f"{self._server}/api/ariel/databases"
        self.send_request("GET", full_url, self._auth_headers)
        # If encountered error, send_request will return_error
        return "ok"

    def get_offenses(self, _range=None, _filter=None, _fields=None):
        """
        Returns the result of an offenses request
        """
        full_url = f"{self._server}/api/siem/offenses"
        params = {"filter": _filter} if _filter else {}
        headers = dict(self._auth_headers)
        if _fields:
            params["fields"] = _fields
        if _range:
            headers["Range"] = "items={0}".format(_range)
        return self.send_request("GET", full_url, headers, params)

    def get_offense_by_id(self, offense_id, _filter="", _fields=""):
        """
        Returns the result of a single offense request
        """
        full_url = f"{self._server}/api/siem/offenses/{offense_id}"
        params = {"filter": _filter} if _filter else {}
        headers = dict(self._auth_headers)
        if _fields:
            params["fields"] = _fields
        return self.send_request("GET", full_url, headers, params)

    def update_offense(self, offense_id, args):
        """
        Updates a single offense and returns the updated offense
        """
        url = f"{self._server}/api/siem/offenses/{offense_id}"
        return self.send_request("POST", url, params=args)

    def search(self, args):
        """
        Updates a single offense and returns the updated offense
        """
        url = f"{self._server}/api/ariel/searches"
        return self.send_request("POST", url, self._auth_headers, params=args)

    def get_search(self, search_id):
        """
        Returns a search object (doesn't contain result)
        """
        url = f"{self._server}/api/ariel/searches/{search_id}"
        return self.send_request("GET", url, self._auth_headers)

    def get_search_results(self, search_id, _range=None):
        """
        Returns a search result
        """
        url = f"{self._server}/api/ariel/searches/{search_id}/results"
        headers = dict(self._auth_headers)
        if _range:
            headers["Range"] = "items={0}".format(_range)
        return self.send_request("GET", url, headers)

    def get_assets(self, _range=None, _filter=None, _fields=None):
        """
        Returns the result of an assets request
        """
        url = f"{self._server}/api/asset_model/assets"
        params = {"filter": _filter} if _filter else {}
        headers = dict(self._auth_headers)
        if _fields:
            params["fields"] = _fields
        if _range:
            headers["Range"] = "items={0}".format(_range)
        return self.send_request("GET", url, headers, params)

    def get_closing_reasons(
        self,
        _range="",
        _filter="",
        _fields="",
        include_deleted=False,
        include_reserved=False,
    ):
        """
        Returns the result of a closing reasons request
        """
        url = f"{self._server}/api/siem/offense_closing_reasons"
        params = {}
        if _filter:
            params["filter"] = _filter
        if include_deleted:
            params["include_deleted"] = include_deleted
        if include_reserved:
            params["include_reserved"] = include_reserved
        headers = self._auth_headers
        if _range:
            headers["Range"] = "items={0}".format(_range)
        return self.send_request("GET", url, headers, params)

    def get_offense_types(self):
        """
        Returns the result of a offense types request
        """
        url = f"{self._server}/api/siem/offense_types"
        # Due to a bug in QRadar, this functions does not work if username/password was not provided
        if self._username and self._password:
            return self.send_request("GET", url)
        return {}

    def get_note(self, offense_id, note_id=None, fields=None):
        """
        Returns the result of a get note request
        """
        if note_id:
            url = f"{self._server}/api/siem/offenses/{offense_id}/notes/{note_id}"
        else:
            url = f"{self._server}/api/siem/offenses/{offense_id}/notes"
        params = {"fields": fields} if fields else {}
        return self.send_request("GET", url, self._auth_headers, params=params)

    def create_note(self, offense_id, note_text, fields=None):
        """
        Creates a note and returns the note as a result
        """
        url = f"{self._server}/api/siem/offenses/{offense_id}/notes"
        params = {"fields": fields} if fields else {}
        params["note_text"] = note_text
        return self.send_request("POST", url, self._auth_headers, params=params)

    def get_ref_set(self, ref_name, _range=None, _filter=None, _fields=None):
        """
        Returns the result of a reference request
        """
        url = f'{self._server}/api/reference_data/sets/{parse.quote(str(ref_name), safe="")}'
        params = {"filter": _filter} if _filter else {}
        headers = dict(self._auth_headers)
        if _fields:
            params["fields"] = _fields
        if _range:
            headers["Range"] = "items={0}".format(_range)
        return self.send_request("GET", url, headers, params=params)

    def create_reference_set(
        self, ref_name, element_type, timeout_type=None, time_to_live=None
    ):
        """
        Create or update a reference set
        """
        url = f"{self._server}/api/reference_data/sets"
        params = {"name": ref_name, "element_type": element_type}
        if timeout_type:
            params["timeout_type"] = timeout_type
        if time_to_live:
            params["time_to_live"] = time_to_live
        return self.send_request("POST", url, params=params)

    def delete_reference_set(self, ref_name):
        """
        Delete a refernce set
        """
        url = f'{self._server}/api/reference_data/sets/{parse.quote(str(ref_name), safe="")}'
        return self.send_request("DELETE", url)

    def update_reference_set_value(self, ref_name, value, source=None):
        """
        Update refernce set value
        """
        url = f'{self._server}/api/reference_data/sets/{parse.quote(str(ref_name), safe="")}'
        params = {"name": ref_name, "value": value}
        if source:
            params["source"] = source
        return self.send_request("POST", url, params=params)

    def delete_reference_set_value(self, ref_name, value):
        """
        Delete reference set value
        """
        url = f'{self._server}/api/reference_data/sets/{parse.quote(str(ref_name), safe="")}/{parse.quote(str(value), safe="")}'
        params = {"name": ref_name, "value": value}
        return self.send_request("DELETE", url, params=params)

    def get_rules(self, _range=None, _filter=None, _fields=None):
        """
        Get rules
        """
        url = f"{self._server}/api/analytics/rules"
        params = {"filter": _filter} if _filter else {}
        headers = dict(self._auth_headers)
        if _fields:
            params["fields"] = _fields
        if _range:
            headers["Range"] = "items={0}".format(_range)
        return self.send_request("GET", url, headers, params=params)

    def get_devices(self, _range=None, _filter=None, _fields=None):
        """
        Get devices
        """
        url = f"{self._server}/api/config/domain_management/domains"
        params = {"filter": _filter} if _filter else {}
        headers = dict(self._auth_headers)
        if _fields:
            params["fields"] = _fields
        if _range:
            headers["Range"] = "items={0}".format(_range)
        return self.send_request("GET", url, headers, params=params)

    def get_domains_by_id(self, domain_id, _fields=None):
        """
        Get domains by id
        """
        url = f"{self._server}/api/config/domain_management/domains/{domain_id}"
        headers = dict(self._auth_headers)
        params = {"fields": _fields} if _fields else {}
        return self.send_request("GET", url, headers, params=params)

    def convert_closing_reason_name_to_id(self, closing_name, closing_reasons=None):
        """
        Converts closing reason name to id
        """
        if not closing_reasons:
            closing_reasons = self.get_closing_reasons(
                include_deleted=True, include_reserved=True
            )
        for closing_reason in closing_reasons:
            if closing_reason["text"] == closing_name:
                return closing_reason["id"]
        return closing_name

    def convert_closing_reason_id_to_name(self, closing_id, closing_reasons=None):
        """
        Converts closing reason id to name
        """
        if not closing_reasons:
            closing_reasons = self.get_closing_reasons(
                include_deleted=True, include_reserved=True
            )
        for closing_reason in closing_reasons:
            if closing_reason["id"] == closing_id:
                return closing_reason["text"]
        return closing_id

    def convert_offense_type_id_to_name(self, offense_type_id, offense_types=None):
        """
        Converts offense type id to name
        """
        if not offense_types:
            offense_types = self.get_offense_types()
        if offense_types:
            for o_type in offense_types:
                if o_type["id"] == offense_type_id:
                    return o_type["name"]
        return offense_type_id

    def upload_indicators_list_request(self, reference_name, indicators_list):
        """
            Upload indicators list to the reference set

            Args:
                  reference_name (str): Reference set name
                  indicators_list (list): Indicators values list
            Returns:
                dict: Reference set object
        """
        url = f'{self._server}/api/reference_data/sets/bulk_load/{parse.quote(str(reference_name), safe="")}'
        params = {"name": reference_name}
        return self.send_request(
            "POST", url, params=params, data=json.dumps(indicators_list)
        )

    def get_custom_fields(
            self, limit: Optional[int] = None, field_name: Optional[List[str]] = None,
            likes: Optional[List[str]] = None, filter_: Optional[str] = None, fields: Optional[List[str]] = None
    ) -> List[dict]:
        """Get regex event properties from the API.

        Args:
            limit: Max properties to fetch.
            field_name: a list of exact names to pull.
            likes: a list of case insensitive and name (contains).
            filter_: a filter to send instead of likes/field names.
            fields: a list of fields to retrieve from the API.

        Returns:
            List of properties
        """
        url = urljoin(self._server, "api/config/event_sources/custom_properties/regex_properties")
        headers = self._auth_headers
        if limit is not None:
            headers['Range'] = f"items=0-{limit-1}"
        params = {}
        # Build filter if not given
        if not filter_:
            filter_ = ''
            if field_name:
                for field in field_name:
                    filter_ += f'name= "{field}" or '
            if likes:
                for like in likes:
                    filter_ += f'name ILIKE "%{like}%" or '
            # Remove trailing `or `
            filter_ = filter_.rstrip('or ')
        if filter_:
            params['filter'] = filter_
        if fields:
            params['fields'] = ' or '.join(fields)
        return self.send_request("GET", url, headers=headers, params=params)

    def enrich_source_addresses_dict(self, src_adrs):
        """
        helper function: Enriches the source addresses ids dictionary with the source addresses values corresponding to the ids
        """
        batch_size = BATCH_SIZE
        for b in batch(
            list(src_adrs.values())[:OFF_ENRCH_LIMIT], batch_size=int(batch_size)
        ):
            src_ids_str = ",".join(map(str, b))
            source_url = (
                f"{self._server}/api/siem/source_addresses?filter=id in ({src_ids_str})"
            )
            src_res = self.send_request("GET", source_url, self._auth_headers)
            for src_adr in src_res:
                src_adrs[src_adr["id"]] = src_adr["source_ip"]
        return src_adrs

    def enrich_destination_addresses_dict(self, dst_adrs):
        """
        helper function: Enriches the destination addresses ids dictionary with the source addresses values corresponding to
        the ids
        """
        batch_size = BATCH_SIZE
        for b in batch(
            list(dst_adrs.values())[:OFF_ENRCH_LIMIT], batch_size=int(batch_size)
        ):
            dst_ids_str = ",".join(map(str, b))
            destination_url = f"{self._server}/api/siem/local_destination_addresses?filter=id in ({dst_ids_str})"
            dst_res = self.send_request("GET", destination_url, self._auth_headers)
            for dst_adr in dst_res:
                dst_adrs[dst_adr["id"]] = dst_adr["local_destination_ip"]
        return dst_adrs


""" Utility functions """


def get_entry_for_object(
    title, obj, contents, headers=None, context_key=None, human_readable=None
):
    """
    Generic function that receives a result json, and turns it into an entryObject
    """
    if len(obj) == 0:
        return {
            "Type": entryTypes["note"],
            "Contents": contents,
            "ContentsFormat": formats["json"],
            "HumanReadable": "There is no output result",
        }
    obj = filter_dict_null(obj)
    if headers:
        if isinstance(headers, str):
            headers = headers.split(",")
        if isinstance(obj, dict):
            headers = list(set(headers).intersection(set(obj.keys())))
    ec = {context_key: obj} if context_key else obj
    return {
        "Type": entryTypes["note"],
        "Contents": contents,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": human_readable
        if human_readable
        else tableToMarkdown(title, obj, headers).replace("\t", " "),
        "EntryContext": ec,
    }


def epoch_to_iso(ms_passed_since_epoch):
    """
    Converts epoch (miliseconds) to ISO string
    """
    if isinstance(ms_passed_since_epoch, int) and ms_passed_since_epoch >= 0:
        return datetime.utcfromtimestamp(ms_passed_since_epoch / 1000.0).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    return ms_passed_since_epoch


def print_debug_msg(msg, lock: Lock = None):
    """
    Prints a debug message with QRadarMsg prefix, while handling lock.acquire (if available)
    """
    debug_msg = f"QRadarMsg - {msg}"
    if lock:
        if lock.acquire(timeout=LOCK_WAIT_TIME):
            demisto.debug(debug_msg)
            lock.release()
    else:
        demisto.debug(debug_msg)


def filter_dict_null(d):
    """
    Filters recursively null values from dictionary
    """
    if isinstance(d, dict):
        return dict(
            (k, filter_dict_null(v))
            for k, v in list(d.items())
            if filter_dict_null(v) is not None
        )
    elif isinstance(d, list):
        if len(d) > 0:
            return list(map(filter_dict_null, d))
        return None
    return d


def filter_dict_non_intersection_key_to_value(d1, d2):
    """
    Filters recursively from dictionary (d1) all keys that do not appear in d2
    """
    if isinstance(d1, list):
        return [filter_dict_non_intersection_key_to_value(x, d2) for x in d1]
    elif isinstance(d1, dict) and isinstance(d2, dict):
        d2values = list(d2.values())
        return dict((k, v) for k, v in list(d1.items()) if k in d2values)
    return d1


def replace_keys(src, trans_map):
    """
    Change the keys of a dictionary according to a conversion map
    trans_map - { 'OldKey': 'NewKey', ...}
    """

    def replace(key, trans_map_):
        if key in trans_map_:
            return trans_map_[key]
        return key

    if trans_map:
        if isinstance(src, list):
            return [replace_keys(x, trans_map) for x in src]
        else:
            src = {replace(k, trans_map): v for k, v in src.items()}
    return src


def dict_values_to_comma_separated_string(dic):
    """
    Transforms flat dictionary to comma separated values
    """
    return ",".join(str(v) for v in dic.values())


""" Command functions """


def test_module(client: QRadarClient):
    test_res = client.test_connection()

    params = demisto.params()
    is_long_running = params.get('longRunning')
    if is_long_running:
        # check fetch incidents can fetch and search events
        raw_offenses = client.get_offenses(_range="0-0")
        fetch_mode = params.get("fetch_mode")
        if raw_offenses and fetch_mode != FetchMode.no_events:
            events_columns = params.get("events_columns")
            events_limit = params.get("events_limit")
            offense = raw_offenses[0]
            offense_start_time = offense["start_time"]
            query_expression = (
                f'SELECT {events_columns} FROM events WHERE INOFFENSE({offense["id"]}) '
                f"limit {events_limit} START '{offense_start_time}'"
            )
            events_query = {"headers": "", "query_expression": query_expression}
            try_create_search_with_retry(client, events_query, offense)
    return test_res


def enrich_offense_with_events(
    client: QRadarClient, offense, fetch_mode, events_columns, events_limit
):
    additional_where = (
        "AND LOGSOURCETYPENAME(devicetype) = 'Custom Rule Engine'"
        if fetch_mode == FetchMode.correlations_only
        else ""
    )
    try:
        return perform_offense_events_enrichment(
            offense, additional_where, events_columns, events_limit, client,
        )
    except Exception as e:
        print_debug_msg(
            f"Failed events fetch for offense {offense['id']}: {str(e)}.", client.lock,
        )
        return offense


def perform_offense_events_enrichment(
    offense, additional_where, events_columns, events_limit, client: QRadarClient,
):
    """
    Performs an offense enrichment by:
        try to create events search via AQL
        if search created successfully:
            try to get search results
            if successfully:
                enrich offense with event
        return offense
    """
    if is_reset_triggered(client.lock):
        return offense

    offense_start_time = offense["start_time"]
    query_expression = (
        f'SELECT {events_columns} FROM events WHERE INOFFENSE({offense["id"]})'
        f"{additional_where} limit {events_limit} START '{offense_start_time}'"
    )
    events_query = {"headers": "", "query_expression": query_expression}
    print_debug_msg(f'Starting events fetch for offense {offense["id"]}.', client.lock)
    try:
        query_status, search_id = try_create_search_with_retry(
            client, events_query, offense
        )
        offense["events"] = try_poll_offense_events_with_retry(
            client, offense["id"], query_status, search_id
        )
    except Exception as e:
        print_debug_msg(
            f'Failed fetching event for offense {offense["id"]}: {str(e)}.',
            client.lock,
        )
    finally:
        return offense


def try_poll_offense_events_with_retry(
    client, offense_id, query_status, search_id, max_retries=None
):
    """
    Polls search until the search is done (completed/canceled/error), and then returns the search result
    will retry up to max_retries consecutive failures
    """
    if not max_retries:
        max_retries = EVENTS_FAILURE_LIMIT
    failures = 0
    start_time = time.time()
    while not (query_status in TERMINATING_SEARCH_STATUSES or failures >= max_retries):
        try:
            if is_reset_triggered(client.lock):
                return []

            raw_search = client.get_search(search_id)
            query_status = raw_search.get("status")
            # failures are relevant only when consecutive
            failures = 0
            if query_status in TERMINATING_SEARCH_STATUSES:
                raw_search_results = client.get_search_results(search_id)
                print_debug_msg(
                    f"Events fetched for offense {offense_id}.", client.lock
                )
                events = raw_search_results.get("events", [])
                for event in events:
                    try:
                        for time_field in EVENT_TIME_FIELDS:
                            if time_field in event:
                                event[time_field] = epoch_to_iso(event[time_field])
                    except TypeError:
                        continue
                return events
            else:
                # prepare next run
                elapsed = time.time() - start_time
                if elapsed >= FETCH_SLEEP:  # print status debug every fetch sleep (or after)
                    print_debug_msg(
                        f"Still fetching offense {offense_id} events, search_id: {search_id}.",
                        client.lock,
                    )
                    start_time = time.time()
                time.sleep(EVENTS_INTERVAL_SECS)
        except Exception as e:
            print_debug_msg(f"Error while fetching offense {offense_id} events, search_id: {search_id}. "
                            f"Error details: {str(e)}")
            failures += 1
    return []


def try_create_search_with_retry(client, events_query, offense, max_retries=None):
    if max_retries is None:
        max_retries = EVENTS_FAILURE_LIMIT
    failures = 0
    search_created_successfully = False
    query_status = ""
    search_id = ""
    err = ""
    while not search_created_successfully and failures <= max_retries:
        try:
            raw_search = client.search(events_query)
            search_res_events = deepcopy(raw_search)
            search_res_events = filter_dict_non_intersection_key_to_value(
                replace_keys(search_res_events, SEARCH_ID_NAMES_MAP),
                SEARCH_ID_NAMES_MAP,
            )
            search_id = search_res_events.get("ID")
            query_status = search_res_events.get("Status")
            search_created_successfully = True
        except Exception as e:
            err = str(e)
            failures += 1
    if failures >= max_retries:
        raise DemistoException(f"Unable to create search for offense: {offense['id']}. Error: {err}")
    return query_status, search_id


def fetch_raw_offenses(client: QRadarClient, offense_id, user_query):
    """
    Use filter frames based on id ranges: "id>offense_id AND id<(offense_id+incidents_per_fetch)"

    If couldn’t fetch offense:
        Fetch last fetchable offense, and set it as the upper limit
        is limit greater than last fetched offense id?
             yes - fetch with increments until manage to fetch (or until limit is reached - dead condition)
             no  - finish fetch-incidents
    """
    # try to adjust start_offense_id to user_query start offense id
    try:
        if isinstance(user_query, str) and "id>" in user_query:
            user_offense_id = int(user_query.split("id>")[1].split(" ")[0])
            if user_offense_id > offense_id:
                offense_id = user_offense_id
    except ValueError:
        pass

    # fetch offenses
    raw_offenses, fetch_query = seek_fetchable_offenses(client, offense_id, user_query)
    if raw_offenses:
        print_debug_msg(f"Fetched {fetch_query}successfully.", client.lock)

    return raw_offenses


def seek_fetchable_offenses(client: QRadarClient, start_offense_id, user_query):
    """
    Look for offenses in QRadar using an increasing search window until a fetchable offense is found
    """
    raw_offenses = []
    fetch_query = ""
    lim_id = None
    latest_offense_fnd = False
    while not latest_offense_fnd:
        end_offense_id = int(start_offense_id) + client.offenses_per_fetch + 1
        fetch_query = "id>{0} AND id<{1} {2}".format(
            start_offense_id,
            end_offense_id,
            "AND ({})".format(user_query) if user_query else "",
        )
        print_debug_msg(f"Fetching {fetch_query}.")
        raw_offenses = client.get_offenses(
            _range="0-{0}".format(client.offenses_per_fetch - 1), _filter=fetch_query
        )
        if raw_offenses:
            latest_offense_fnd = True
        else:
            if not lim_id:
                # set fetch upper limit
                lim_offense = client.get_offenses(_range="0-0")
                if not lim_offense:
                    raise Exception(
                        "No offenses could be fetched, please make sure there are offenses available for this user."
                    )
                lim_id = lim_offense[0]["id"]  # if there's no id, raise exception
            if lim_id >= end_offense_id:  # increment the search until we reach limit
                start_offense_id += client.offenses_per_fetch
            else:
                latest_offense_fnd = True
    return raw_offenses, fetch_query


def fetch_incidents_long_running_samples():
    last_run = get_integration_context(SYNC_CONTEXT)
    return last_run.get("samples", [])  # type: ignore [attr-defined]


def is_reset_triggered(lock, handle_reset=False):
    """
    Returns if reset signal is set. If handle_reset=True, will also reset the integration context
    """
    if lock.acquire(timeout=LOCK_WAIT_TIME):
        ctx = get_integration_context(SYNC_CONTEXT)
        if ctx and RESET_KEY in ctx:
            if handle_reset:
                print_debug_msg("Reset fetch-incidents.")
                set_integration_context(
                    {"samples": ctx.get("samples", [])}, sync=SYNC_CONTEXT
                )
            lock.release()
            return True
        lock.release()
    return False


def fetch_incidents_long_running_events(
    client: QRadarClient,
    incident_type,
    user_query,
    ip_enrich,
    asset_enrich,
    fetch_mode,
    events_columns,
    events_limit,
):
    last_run = get_integration_context(SYNC_CONTEXT)
    offense_id = last_run["id"] if last_run and "id" in last_run else 0

    raw_offenses = fetch_raw_offenses(client, offense_id, user_query)

    if len(raw_offenses) == 0:
        return
    if isinstance(raw_offenses, list):
        raw_offenses.reverse()
    for offense in raw_offenses:
        offense_id = max(offense_id, offense["id"])
    enriched_offenses = []

    futures = []
    for offense in raw_offenses:
        futures.append(
            EXECUTOR.submit(
                enrich_offense_with_events,
                client=client,
                offense=offense,
                fetch_mode=fetch_mode,
                events_columns=events_columns,
                events_limit=events_limit,
            )
        )
    for future in concurrent.futures.as_completed(futures):
        enriched_offenses.append(future.result())

    if is_reset_triggered(client.lock, handle_reset=True):
        return

    enriched_offenses.sort(key=lambda offense: offense.get("id", 0))
    if ip_enrich or asset_enrich:
        print_debug_msg("Enriching offenses")
        enrich_offense_result(client, enriched_offenses, ip_enrich, asset_enrich)
        print_debug_msg("Enriched offenses successfully.")
    new_incidents_samples = create_incidents(enriched_offenses, incident_type)
    incidents_batch_for_sample = (
        new_incidents_samples if new_incidents_samples else last_run.get("samples", [])
    )

    context = {LAST_FETCH_KEY: offense_id, "samples": incidents_batch_for_sample}
    set_integration_context(context, sync=SYNC_CONTEXT)


def create_incidents(enriched_offenses, incident_type):
    if not enriched_offenses:
        return []

    incidents = []
    for offense in enriched_offenses:
        incidents.append(create_incident_from_offense(offense, incident_type))
    print_debug_msg(f"Creating {len(incidents)} incidents")
    demisto.createIncidents(incidents)
    return incidents


def fetch_incidents_long_running_no_events(
    client: QRadarClient, incident_type, user_query, ip_enrich, asset_enrich
):
    last_run = get_integration_context(SYNC_CONTEXT)
    offense_id = last_run["id"] if last_run and "id" in last_run else 0

    raw_offenses = fetch_raw_offenses(client, offense_id, user_query)
    if len(raw_offenses) == 0:
        return
    if isinstance(raw_offenses, list):
        raw_offenses.reverse()

    for offense in raw_offenses:
        offense_id = max(offense_id, offense["id"])

    if ip_enrich or asset_enrich:
        print_debug_msg("Enriching offenses")
        enrich_offense_result(client, raw_offenses, ip_enrich, asset_enrich)
        print_debug_msg("Enriched offenses successfully.")

    # handle reset signal
    if is_reset_triggered(client.lock, handle_reset=True):
        return

    incidents_batch = create_incidents(raw_offenses, incident_type)
    incidents_batch_for_sample = (
        incidents_batch if incidents_batch else last_run.get("samples", [])
    )

    context = {LAST_FETCH_KEY: offense_id, "samples": incidents_batch_for_sample}
    set_integration_context(context, sync=SYNC_CONTEXT)


def create_incident_from_offense(offense, incident_type):
    """
    Creates incidents from offense
    """
    occured = epoch_to_iso(offense["start_time"])
    keys = list(offense.keys())
    labels = []
    for i in range(len(keys)):
        labels.append({"type": keys[i], "value": str(offense[keys[i]])})
    return {
        "name": "{id} {description}".format(
            id=offense["id"], description=offense["description"]
        ),
        "labels": labels,
        "rawJSON": json.dumps(offense),
        "occurred": occured,
        "type": incident_type
    }


def get_offenses_command(
    client: QRadarClient, range=None, filter=None, fields=None, headers=None
):
    raw_offenses = client.get_offenses(range, filter, fields)
    offenses = deepcopy(raw_offenses)
    enrich_offense_result(client, offenses)
    offenses = filter_dict_non_intersection_key_to_value(
        replace_keys(offenses, OFFENSES_NAMES_MAP), OFFENSES_NAMES_MAP
    )

    # prepare for printing:
    if not headers:
        offenses_names_map_cpy = dict(OFFENSES_NAMES_MAP)
        offenses_names_map_cpy.pop("id", None)
        offenses_names_map_cpy.pop("description", None)
        headers = "ID,Description," + dict_values_to_comma_separated_string(
            offenses_names_map_cpy
        )

    return get_entry_for_object(
        "QRadar offenses",
        offenses,
        raw_offenses,
        headers,
        "QRadar.Offense(val.ID === obj.ID)",
    )


def enrich_offense_result(
    client: QRadarClient, response, ip_enrich=False, asset_enrich=False
):
    """
    Enriches the values of a given offense result
    * epoch timestamps -> ISO time string
    * closing reason id -> name
    * Domain id -> name
        - collect all ids from offenses (if available)
        - collect all ids from assets (if available)
        - get id->name map
        - update all values in offenses and assets
    * Rule id -> name
    * IP id -> value
    * IP value -> Asset
    * Add offense link
    """
    domain_ids = set()
    rule_ids = set()
    if isinstance(response, list):
        type_dict = client.get_offense_types()
        closing_reason_dict = client.get_closing_reasons(
            include_deleted=True, include_reserved=True
        )
        for offense in response:
            offense["LinkToOffense"] = f"{client.server}/console/do/sem/offensesummary?" \
                                       f"appName=Sem&pageId=OffenseSummary&summaryId={offense.get('id')}"
            enrich_offense_timestamps_and_closing_reason(
                client, offense, type_dict, closing_reason_dict
            )
            if 'domain_id' in offense:
                domain_ids.add(offense['domain_id'])
            if 'rules' in offense and isinstance(offense['rules'], list):
                for rule in offense['rules']:
                    if 'id' in rule:
                        rule_ids.add(rule['id'])

        if ip_enrich or asset_enrich:
            enrich_offenses_with_assets_and_source_destination_addresses(
                client, response, ip_enrich, asset_enrich
            )
            if asset_enrich:
                # get assets from offenses that have assets
                assets_list = list(map(lambda o: o['assets'], filter(lambda o: 'assets' in o, response)))
                for assets in assets_list:
                    domain_ids.update({asset['domain_id'] for asset in assets})
        if domain_ids and DOMAIN_ENRCH_FLG == "True":
            enrich_offense_res_with_domain_names(client, domain_ids, response)
        if rule_ids and RULES_ENRCH_FLG == "True":
            enrich_offense_res_with_rule_names(client, rule_ids, response)
    else:
        enrich_offense_timestamps_and_closing_reason(client, response)

    return response


def enrich_offense_res_with_domain_names(client, domain_ids, response):
    """
    Add domain_name to the offense and assets results
    """
    domain_filter = 'id=' + 'or id='.join(str(domain_ids).replace(' ', '').split(','))[1:-1]
    domains = client.get_devices(_filter=domain_filter)
    domain_names = {d['id']: d['name'] for d in domains}
    for offense in response:
        if 'domain_id' in offense:
            offense['domain_name'] = domain_names.get(offense['domain_id'], '')
        if 'assets' in offense:
            for asset in offense['assets']:
                if 'domain_id' in asset:
                    asset['domain_name'] = domain_names.get(asset['domain_id'], '')


def enrich_offense_res_with_rule_names(client, rule_ids, response):
    """
    Add name to the offense rules
    """
    rule_filter = 'id=' + 'or id='.join(str(rule_ids).replace(' ', '').split(','))[1:-1]
    rules = client.get_rules(_filter=rule_filter)
    rule_names = {r['id']: r['name'] for r in rules}
    for offense in response:
        if 'rules' in offense and isinstance(offense['rules'], list):
            for rule in offense['rules']:
                if 'id' in rule:
                    rule['name'] = rule_names.get(rule['id'], '')


def enrich_offense_timestamps_and_closing_reason(
    client: QRadarClient, offense, type_dict=None, closing_reason_dict=None,
):
    """
    Convert epoch to iso and closing_reason_id to closing reason name
    """
    enrich_offense_times(offense)
    if "offense_type" in offense:
        offense["offense_type"] = client.convert_offense_type_id_to_name(
            offense["offense_type"], type_dict
        )
    if "closing_reason_id" in offense:
        offense["closing_reason_id"] = client.convert_closing_reason_id_to_name(
            offense["closing_reason_id"], closing_reason_dict
        )


def enrich_offenses_with_assets_and_source_destination_addresses(
    client: QRadarClient, offenses, ip_enrich=False, asset_enrich=False
):
    """
    Enriches offense result dictionary with source and destination addresses and assets depending on the ips
    """
    src_adrs, dst_adrs = extract_source_and_destination_addresses_ids(offenses)
    # This command might encounter HTML error page in certain cases instead of JSON result. Fallback: cancel operation
    try:
        if src_adrs:
            client.enrich_source_addresses_dict(src_adrs)
        if dst_adrs:
            client.enrich_destination_addresses_dict(dst_adrs)
        if isinstance(offenses, list) and (ip_enrich or asset_enrich):
            for offense in offenses:
                # calling this function changes given offenses IP ids to IP values
                assets_ips = get_asset_ips_and_enrich_offense_addresses(
                    offense, src_adrs, dst_adrs, not ip_enrich
                )
                if asset_enrich:
                    assets = get_assets_for_offense(client, assets_ips)
                    if assets:
                        offense["assets"] = assets
    finally:
        return offenses


def get_assets_for_offense(client: QRadarClient, assets_ips):
    """
    Get the assets that correlate to the given asset_ip_ids in the expected offense result format
    """
    assets = []
    for ips_batch in batch(list(assets_ips), batch_size=BATCH_SIZE):
        query = ""
        for ip in ips_batch:
            query = (f"{query} or " if query else "") + f'interfaces contains ip_addresses contains value="{ip}"'
        if query:
            assets = client.get_assets(_filter=query)
            if assets:
                transform_asset_time_fields_recursive(assets)
                for asset in assets:
                    # flatten properties
                    if isinstance(asset.get('properties'), list):
                        properties = {p['name']: p['value'] for p in asset['properties'] if
                                      ('name' in p and 'value' in p)}
                        asset.update(properties)
                        # remove previous format of properties
                        asset.pop('properties')
                    # simplify interfaces
                    if isinstance(asset.get('interfaces'), list):
                        asset['interfaces'] = get_simplified_asset_interfaces(asset['interfaces'])
    return assets


def get_simplified_asset_interfaces(interfaces):
    """
    Get a simplified version of asset interfaces with just the following fields:
     * id
     * mac_address
     * ip_addresses.type
     * ip_addresses.value
    """
    new_interfaces = []
    for interface in interfaces:
        new_ip_adrss = []
        for ip_adrs in interface.get('ip_addresses', []):
            new_ip_adrss.append(assign_params(
                type=ip_adrs.get('type'),
                value=ip_adrs.get('value')
            ))
        new_interfaces.append(assign_params(
            mac_address=interface.get('mac_address'),
            id=interface.get('id'),
            ip_addresses=new_ip_adrss
        ))
    return new_interfaces


def transform_asset_time_fields_recursive(asset):
    """
    Transforms the asset time fields recursively
    """
    if isinstance(asset, list):
        for sub_asset_object in asset:
            transform_asset_time_fields_recursive(sub_asset_object)
    if isinstance(asset, dict):
        for k, v in asset.items():
            if isinstance(v, (list, dict)):
                transform_asset_time_fields_recursive(v)
            elif k in ASSET_TIME_FIELDS and v:
                asset[k] = epoch_to_iso(v)


def extract_source_and_destination_addresses_ids(response):
    """
    helper function: Extracts all source and destination addresses ids from an offense result
    """
    src_ids = {}  # type: dict
    dst_ids = {}  # type: dict
    if isinstance(response, list):
        for offense in response:
            populate_src_and_dst_dicts_with_single_offense(offense, src_ids, dst_ids)
    else:
        populate_src_and_dst_dicts_with_single_offense(response, src_ids, dst_ids)

    return src_ids, dst_ids


def populate_src_and_dst_dicts_with_single_offense(offense, src_ids, dst_ids):
    """
    helper function: Populates source and destination id dictionaries with the id key/values
    :return:
    """
    if "source_address_ids" in offense and isinstance(
        offense["source_address_ids"], list
    ):
        for source_id in offense["source_address_ids"]:
            src_ids[source_id] = source_id
    if "local_destination_address_ids" in offense and isinstance(
        offense["local_destination_address_ids"], list
    ):
        for destination_id in offense["local_destination_address_ids"]:
            dst_ids[destination_id] = destination_id
    return None


def get_asset_ips_and_enrich_offense_addresses(
    offense, src_adrs, dst_adrs, skip_enrichment=False
):
    """
    Get offense asset IPs,
    and given skip_enrichment=False,
        replace the source and destination ids of the offense with the real addresses
    """
    asset_ips = set()
    if isinstance(offense.get("source_address_ids"), list):
        for i in range(len(offense["source_address_ids"])):
            source_address = src_adrs[offense["source_address_ids"][i]]
            if not skip_enrichment:
                offense["source_address_ids"][i] = source_address
            asset_ips.add(source_address)
    if isinstance(offense.get("local_destination_address_ids"), list):
        for i in range(len(offense["local_destination_address_ids"])):
            destination_address = dst_adrs[offense["local_destination_address_ids"][i]]
            if not skip_enrichment:
                offense["local_destination_address_ids"][i] = destination_address
            asset_ips.add(destination_address)

    return asset_ips


def enrich_offense_times(offense):
    """
    Replaces the epoch times with ISO string
    """
    if "start_time" in offense:
        offense["start_time"] = epoch_to_iso(offense["start_time"])
    if "last_updated_time" in offense:
        offense["last_updated_time"] = epoch_to_iso(offense["last_updated_time"])
    if offense.get("close_time"):
        offense["close_time"] = epoch_to_iso(offense["close_time"])

    return None


def get_offense_by_id_command(
    client: QRadarClient, offense_id=None, filter=None, fields=None, headers=None
):
    raw_offense = client.get_offense_by_id(offense_id, filter, fields)
    offense = deepcopy(raw_offense)
    enrich_offense_result(client, offense, ip_enrich=True)
    offense = filter_dict_non_intersection_key_to_value(
        replace_keys(offense, SINGLE_OFFENSE_NAMES_MAP), SINGLE_OFFENSE_NAMES_MAP
    )
    return get_entry_for_object(
        "QRadar Offenses",
        offense,
        raw_offense,
        headers,
        "QRadar.Offense(val.ID === obj.ID)",
    )


def update_offense_command(
    client: QRadarClient,
    offense_id=None,
    closing_reason_name=None,
    closing_reason_id=None,
    protected=None,
    assigned_to=None,
    follow_up=None,
    status=None,
    fields=None,
    headers=None,
):
    args = assign_params(
        closing_reason_name=closing_reason_name,
        closing_reason_id=closing_reason_id,
        protected=protected,
        assigned_to=assigned_to,
        follow_up=follow_up,
        status=status,
        fields=fields,
    )
    if "closing_reason_name" in args:
        args["closing_reason_id"] = client.convert_closing_reason_name_to_id(
            closing_reason_name
        )
    elif "CLOSED" == args.get("status") and not args.get("closing_reason_id"):
        raise ValueError(
            'Invalid input - must provide closing reason name or id (may use "qradar-get-closing-reasons" command to '
            "get them) to close offense"
        )
    raw_offense = client.update_offense(offense_id, args)
    offense = deepcopy(raw_offense)
    enrich_offense_result(client, offense, ip_enrich=True)
    offense = filter_dict_non_intersection_key_to_value(
        replace_keys(offense, SINGLE_OFFENSE_NAMES_MAP), SINGLE_OFFENSE_NAMES_MAP
    )
    return get_entry_for_object(
        "QRadar Offense",
        offense,
        raw_offense,
        headers,
        "QRadar.Offense(val.ID === obj.ID)",
    )


def search_command(client: QRadarClient, query_expression=None, headers=None):
    search_args = assign_params(query_expression=query_expression, headers=headers)
    raw_search = client.search(search_args)
    search_res = deepcopy(raw_search)
    search_res = filter_dict_non_intersection_key_to_value(
        replace_keys(search_res, SEARCH_ID_NAMES_MAP), SEARCH_ID_NAMES_MAP
    )
    return get_entry_for_object(
        "QRadar Search",
        search_res,
        raw_search,
        headers,
        "QRadar.Search(val.ID === obj.ID)",
    )


def get_search_command(client: QRadarClient, search_id=None, headers=None):
    raw_search = client.get_search(search_id)
    search = deepcopy(raw_search)
    search = filter_dict_non_intersection_key_to_value(
        replace_keys(search, SEARCH_ID_NAMES_MAP), SEARCH_ID_NAMES_MAP
    )
    return get_entry_for_object(
        "QRadar Search Info",
        search,
        raw_search,
        headers,
        'QRadar.Search(val.ID === "{0}")'.format(search_id),
    )


def get_search_results_command(
    client: QRadarClient, search_id=None, range=None, headers=None, output_path=None
):
    raw_search_results = client.get_search_results(search_id, range)
    result_key = list(raw_search_results.keys())[0]
    title = "QRadar Search Results from {}".format(str(result_key))
    context_key = (
        output_path
        if output_path
        else 'QRadar.Search(val.ID === "{0}").Result.{1}'.format(search_id, result_key)
    )
    context_obj = raw_search_results[result_key]
    return get_entry_for_object(
        title, context_obj, raw_search_results, headers, context_key,
    )


def get_assets_command(
    client: QRadarClient, range=None, filter=None, fields=None, headers=None
):
    raw_assets = client.get_assets(range, filter, fields)
    assets_result, human_readable_res = create_assets_result(client, deepcopy(raw_assets))
    return get_entry_for_assets(
        "QRadar Assets", assets_result, raw_assets, human_readable_res, headers,
    )


def get_asset_by_id_command(client: QRadarClient, asset_id=None, headers=None):
    _filter = f"id={asset_id}"
    raw_asset = client.get_assets(_filter=_filter)
    asset_result, human_readable_res = create_assets_result(
        client, deepcopy(raw_asset), full_values=True
    )
    return get_entry_for_assets(
        "QRadar Asset", asset_result, raw_asset, human_readable_res, headers,
    )


def get_entry_for_assets(title, obj, contents, human_readable_obj, headers=None):
    """
    Specific implementation for assets commands, that turns asset result to entryObject
    """
    if len(obj) == 0:
        return "There is no output result"
    obj = filter_dict_null(obj)
    human_readable_obj = filter_dict_null(human_readable_obj)
    if headers:
        if isinstance(headers, str):
            headers = headers.split(",")
        headers = list(
            [x for x in list_entry if x in headers] for list_entry in human_readable_obj
        )
    human_readable_md = ""
    for k, h_obj in human_readable_obj.items():
        human_readable_md = human_readable_md + tableToMarkdown(k, h_obj, headers)
    return {
        "Type": entryTypes["note"],
        "Contents": contents,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": "### {0}\n{1}".format(title, human_readable_md),
        "EntryContext": obj,
    }


def create_assets_result(client, assets, full_values=False):
    trans_assets = {}
    human_readable_trans_assets = {}
    endpoint_dict = create_empty_endpoint_dict(full_values)
    for asset in assets:
        asset_key = "QRadar.Asset"
        human_readable_key = "Asset"
        if "id" in asset:
            asset_key += '(val.ID === "{0}")'.format(asset["id"])
            human_readable_key += "(ID:{0})".format(asset["id"])
        populated_asset = create_single_asset_result_and_enrich_endpoint_dict(
            client, asset, endpoint_dict, full_values
        )
        trans_assets[asset_key] = populated_asset
        human_readable_trans_assets[human_readable_key] = transform_single_asset_to_hr(
            populated_asset
        )
    # Adding endpoints context items
    trans_assets["Endpoint"] = endpoint_dict
    human_readable_trans_assets["Endpoint"] = endpoint_dict
    return trans_assets, human_readable_trans_assets


def transform_single_asset_to_hr(asset):
    """
    Prepares asset for human readable
    """
    hr_asset = []
    for k, v in asset.items():
        if isinstance(v, dict):
            hr_item = v
            hr_item["Property Name"] = k
            hr_asset.append(hr_item)
    return hr_asset


def create_single_asset_result_and_enrich_endpoint_dict(
    client, asset, endpoint_dict, full_values
):
    asset_dict = {"ID": asset.get("id")}
    for interface in asset.get("interfaces", []):
        if full_values:
            endpoint_dict.get("MACAddress").append(interface.get("mac_address"))
        for ip_address in interface.get("ip_addresses"):
            endpoint_dict.get("IPAddress").append(ip_address.get("value"))
    if full_values:
        if "domain_id" in asset:
            domain = client.get_domains_by_id(asset.get("domain_id"))
            domain_name = domain.get('name') if isinstance(domain, dict) else None
            if domain_name:
                endpoint_dict.get("Domain").append(domain_name)
    # Adding values found in properties of the asset
    enrich_dict_using_asset_properties(asset, asset_dict, endpoint_dict, full_values)
    return asset_dict


def enrich_dict_using_asset_properties(asset, asset_dict, endpoint_dict, full_values):
    for prop in asset.get("properties", []):
        if prop.get("name") in ASSET_PROPERTIES_NAMES_MAP:
            asset_dict[ASSET_PROPERTIES_NAMES_MAP[prop.get("name")]] = {
                "Value": prop.get("value"),
                "LastUser": prop.get("last_reported_by"),
            }
        elif prop.get("name") in ASSET_PROPERTIES_ENDPOINT_NAMES_MAP:
            endpoint_dict[
                ASSET_PROPERTIES_ENDPOINT_NAMES_MAP[prop.get("name")]
            ] = prop.get("value")
        elif full_values:
            if prop.get("name") in FULL_ASSET_PROPERTIES_NAMES_MAP:
                asset_dict[FULL_ASSET_PROPERTIES_NAMES_MAP[prop.get("name")]] = {
                    "Value": prop.get("value"),
                    "LastUser": prop.get("last_reported_by"),
                }
    return None


def create_empty_endpoint_dict(full_values):
    """
    Creates an empty endpoint dictionary (for use in other functions)
    """
    endpoint_dict = {"IPAddress": [], "OS": []}  # type: dict
    if full_values:
        endpoint_dict["MACAddress"] = []
        endpoint_dict["Domain"] = []
    return endpoint_dict


def get_closing_reasons_command(
    client: QRadarClient,
    range=None,
    filter=None,
    fields=None,
    include_deleted=None,
    include_reserved=None,
):
    closing_reasons_map = {
        "id": "ID",
        "text": "Name",
        "is_reserved": "IsReserved",
        "is_deleted": "IsDeleted",
    }
    raw_closing_reasons = client.get_closing_reasons(
        range, filter, fields, include_deleted, include_reserved
    )
    closing_reasons = replace_keys(raw_closing_reasons, closing_reasons_map)

    # prepare for printing:
    closing_reasons_map.pop("id", None)
    closing_reasons_map.pop("text", None)
    headers = "ID,Name," + dict_values_to_comma_separated_string(closing_reasons_map)

    return get_entry_for_object(
        "Offense Closing Reasons",
        closing_reasons,
        raw_closing_reasons,
        context_key="QRadar.Offense.ClosingReasons",
        headers=headers,
    )


def get_note_command(
    client: QRadarClient, offense_id=None, note_id=None, fields=None, headers=None
):
    raw_note = client.get_note(offense_id, note_id, fields)
    note_names_map = {
        "id": "ID",
        "note_text": "Text",
        "create_time": "CreateTime",
        "username": "CreatedBy",
    }
    notes = replace_keys(raw_note, note_names_map)
    if not isinstance(notes, list):
        notes = [notes]
    for note in notes:
        if "CreateTime" in note:
            note["CreateTime"] = epoch_to_iso(note["CreateTime"])
    return get_entry_for_object(
        "QRadar note for offense: {0}".format(str(offense_id)),
        notes,
        raw_note,
        headers,
        'QRadar.Note(val.ID === "{0}")'.format(note_id),
    )


def create_note_command(
    client: QRadarClient, offense_id=None, note_text=None, fields=None, headers=None
):
    raw_note = client.create_note(offense_id, note_text, fields)
    note_names_map = {
        "id": "ID",
        "note_text": "Text",
        "create_time": "CreateTime",
        "username": "CreatedBy",
    }
    note = replace_keys(raw_note, note_names_map)
    note["CreateTime"] = epoch_to_iso(note["CreateTime"])
    return get_entry_for_object("QRadar Note", note, raw_note, headers, "QRadar.Note")


def get_reference_by_name_command(client: QRadarClient, ref_name=None, date_value=None):
    raw_ref = client.get_ref_set(ref_name)
    ref = replace_keys(raw_ref, REFERENCE_NAMES_MAP)
    convert_date_elements = (
        True if date_value == "True" and ref["ElementType"] == "DATE" else False
    )
    enrich_reference_set_result(ref, convert_date_elements)
    return get_entry_for_reference_set(ref)


def enrich_reference_set_result(ref, convert_date_elements=False):
    if "Data" in ref:
        ref["Data"] = replace_keys(ref["Data"], REFERENCE_NAMES_MAP)
        for item in ref["Data"]:
            item["FirstSeen"] = epoch_to_iso(item["FirstSeen"])
            item["LastSeen"] = epoch_to_iso(item["LastSeen"])
            if convert_date_elements:
                try:
                    item["Value"] = epoch_to_iso(int(item["Value"]))
                except ValueError:
                    pass
    if "CreationTime" in ref:
        ref["CreationTime"] = epoch_to_iso(ref["CreationTime"])
    return ref


def get_entry_for_reference_set(ref, title="QRadar References"):
    ref_cpy = deepcopy(ref)
    data = ref_cpy.pop("Data", None)
    ec_key = "QRadar.Reference(val.Name === obj.Name)"
    entry = get_entry_for_object(
        title, ref_cpy, ref, demisto.args().get("headers"), ec_key
    )
    # Add another table for the data values
    if data:
        entry["HumanReadable"] = entry["HumanReadable"] + tableToMarkdown(
            "Reference Items", data
        )
        entry["EntryContext"][ec_key]["Data"] = data
    return entry


def create_reference_set_command(
    client: QRadarClient,
    ref_name=None,
    element_type=None,
    timeout_type=None,
    time_to_live=None,
):
    raw_ref = client.create_reference_set(
        ref_name, element_type, timeout_type, time_to_live
    )
    ref = replace_keys(raw_ref, REFERENCE_NAMES_MAP)
    enrich_reference_set_result(ref)
    return get_entry_for_reference_set(ref)


def delete_reference_set_command(client: QRadarClient, ref_name=None):
    raw_ref = client.delete_reference_set(ref_name)
    return {
        "Type": entryTypes["note"],
        "Contents": raw_ref,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": "Reference Data Deletion Task for '{0}' was initiated. Reference set '{0}' should be deleted "
        "shortly.".format(ref_name),
    }


def update_reference_set_value_command(
    client: QRadarClient, ref_name, value, date_value=None, source=None
):
    """
    Creates or updates values in QRadar reference set
    """
    values = argToList(value)
    if date_value == "True":
        values = [
            date_to_timestamp(v, date_format="%Y-%m-%dT%H:%M:%S.%f000Z") for v in values
        ]
    if len(values) > 1 and not source:
        raw_ref = client.upload_indicators_list_request(ref_name, values)
    elif len(values) >= 1:
        for value in values:
            raw_ref = client.update_reference_set_value(ref_name, value, source)
    else:
        raise DemistoException(
            "Expected at least a single value, cant create or update an empty value"
        )
    ref = replace_keys(raw_ref, REFERENCE_NAMES_MAP)
    enrich_reference_set_result(ref)
    return get_entry_for_reference_set(
        ref, title="Element value was updated successfully in reference set:"
    )


def delete_reference_set_value_command(
    client: QRadarClient, ref_name, value, date_value=None,
):
    if date_value == "True":
        value = date_to_timestamp(value, date_format="%Y-%m-%dT%H:%M:%S.%f000Z")
    raw_ref = client.delete_reference_set_value(ref_name, value)
    ref = replace_keys(raw_ref, REFERENCE_NAMES_MAP)
    enrich_reference_set_result(ref)
    return get_entry_for_reference_set(
        ref, title="Element value was deleted successfully in reference set:"
    )


def get_domains_command(client: QRadarClient, range=None, filter=None, fields=None):
    raw_domains = client.get_devices(range, filter, fields)
    domains = []

    for raw_domain in raw_domains:
        domain = replace_keys(raw_domain, DEVICE_MAP)
        domains.append(domain)
    if len(domains) == 0:
        return "No Domains Found"
    else:
        ec = {"QRadar.Domains": createContext(domains, removeNull=True)}
        return {
            "Type": entryTypes["note"],
            "Contents": domains,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown("Domains Found", domains),
            "EntryContext": ec,
        }


def get_domains_by_id_command(client: QRadarClient, id=None, fields=None):
    raw_domains = client.get_domains_by_id(id, fields)
    formatted_domain = replace_keys(raw_domains, DEVICE_MAP)

    if len(formatted_domain) == 0:
        return "No Domain Found"
    else:
        ec = {"QRadar.Domains": createContext(formatted_domain, removeNull=True)}
        return {
            "Type": entryTypes["note"],
            "Contents": raw_domains,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown(
                "Domains Found", formatted_domain, removeNull=True
            ),
            "EntryContext": ec,
        }


def upload_indicators_command(
    client: QRadarClient,
    ref_name=None,
    element_type=None,
    timeout_type=None,
    query=None,
    time_to_live=None,
    limit=1000,
    page=0,
):
    """
    Finds indicators according to user query and updates QRadar reference set

    Returns:
        (string, dict). Human readable and the raw response
    """
    try:
        limit = int(limit)
        page = int(page)
        if not check_ref_set_exist(client, ref_name):
            if element_type:
                client.create_reference_set(
                    ref_name, element_type, timeout_type, time_to_live
                )
            else:
                return_error(
                    "There isn't a reference set with the name {0}. To create one,"
                    " please enter an element type".format(ref_name)
                )
        else:
            if element_type or time_to_live or timeout_type:
                return_error(
                    "The reference set {0} is already exist. Element type, time to live or timeout type "
                    "cannot be modified".format(ref_name)
                )
        indicators_values_list, indicators_data_list = get_indicators_list(
            query, limit, page
        )
        if len(indicators_values_list) == 0:
            return (
                "No indicators found, Reference set {0} didn't change".format(ref_name),
                {},
                {},
            )
        else:
            raw_response = client.upload_indicators_list_request(
                ref_name, indicators_values_list
            )
            ref_set_data = client.get_ref_set(ref_name)
            ref = replace_keys(ref_set_data, REFERENCE_NAMES_MAP)
            enrich_reference_set_result(ref)
            indicator_headers = ["Value", "Type"]
            ref_set_headers = [
                "Name",
                "ElementType",
                "TimeoutType",
                "CreationTime",
                "NumberOfElements",
            ]
            hr = tableToMarkdown(
                "reference set {0} was updated".format(ref_name),
                ref,
                headers=ref_set_headers,
            ) + tableToMarkdown(
                "Indicators list", indicators_data_list, headers=indicator_headers
            )
            return {
                "Type": entryTypes["note"],
                "HumanReadable": hr,
                "ContentsFormat": formats["json"],
                "Contents": raw_response,
            }

    # Gets an error if the user tried to add indicators that dont match to the reference set type
    except Exception as e:
        if "1005" in str(e):
            return "You tried to add indicators that dont match to reference set type"
        raise e


def check_ref_set_exist(client: QRadarClient, ref_set_name):
    """
        The function checks if reference set is exist

    Args:
        client (QRadarClient): QRadar client
        ref_set_name (str): Reference set name

    Returns:
        dict: If found - Reference set object, else - Error
    """

    try:
        return client.get_ref_set(ref_set_name)
    # If reference set does not exist, return None
    except Exception as e:
        if "1002" in str(e):
            return None
        raise e


def get_indicators_list(indicator_query, limit, page):
    """
        Get Demisto indicators list using demisto.searchIndicators

        Args:
              indicator_query (str): The query demisto.searchIndicators use to find indicators
              limit (int): The amount of indicators the user want to add to reference set
              page (int): Page's number the user would like to start from
        Returns:
             list, list: List of indicators values and a list with all indicators data
    """
    indicators_values_list = []
    indicators_data_list = []
    fetched_iocs = demisto.searchIndicators(
        query=indicator_query, page=page, size=limit
    ).get("iocs")
    for indicator in fetched_iocs:
        indicators_values_list.append(indicator["value"])
        indicators_data_list.append(
            {"Value": indicator["value"], "Type": indicator["indicator_type"]}
        )
    return indicators_values_list, indicators_data_list


def fetch_loop_with_events(
    client: QRadarClient,
    incident_type,
    user_query,
    ip_enrich,
    asset_enrich,
    fetch_mode,
    events_columns,
    events_limit,
):
    while True:
        is_reset_triggered(client.lock, handle_reset=True)

        print_debug_msg("Starting fetch loop with events.")
        fetch_incidents_long_running_events(
            client,
            incident_type,
            user_query,
            ip_enrich,
            asset_enrich,
            fetch_mode,
            events_columns,
            events_limit,
        )
        time.sleep(FETCH_SLEEP)


def fetch_loop_no_events(client: QRadarClient, incident_type, user_query, ip_enrich, asset_enrich):
    while True:
        is_reset_triggered(client.lock, handle_reset=True)

        print_debug_msg("Starting fetch loop with no events.")
        fetch_incidents_long_running_no_events(
            client, incident_type, user_query, ip_enrich, asset_enrich
        )
        time.sleep(FETCH_SLEEP)


def long_running_main(
    client: QRadarClient,
    incident_type,
    user_query,
    ip_enrich,
    asset_enrich,
    fetch_mode,
    events_columns,
    events_limit,
):
    print_debug_msg(f'Starting fetch with "{fetch_mode}".')
    if fetch_mode in (FetchMode.all_events, FetchMode.correlations_only):
        fetch_loop_with_events(
            client,
            incident_type,
            user_query,
            ip_enrich,
            asset_enrich,
            fetch_mode,
            events_columns,
            events_limit,
        )
    elif fetch_mode == FetchMode.no_events:
        fetch_loop_no_events(client, incident_type, user_query, ip_enrich, asset_enrich)


def reset_fetch_incidents():
    ctx = get_integration_context(SYNC_CONTEXT)
    ctx[RESET_KEY] = True
    set_integration_context(ctx, sync=SYNC_CONTEXT)
    return "fetch-incidents was reset successfully."


def get_mapping_fields(client: QRadarClient) -> dict:
    offense = {
        "username_count": "int",
        "description": "str",
        "rules": {
            "id": "int",
            "type": "str",
            "name": "str"
        },
        "event_count": "int",
        "flow_count": "int",
        "assigned_to": "NoneType",
        "security_category_count": "int",
        "follow_up": "bool",
        "source_address_ids": "str",
        "source_count": "int",
        "inactive": "bool",
        "protected": "bool",
        "closing_user": "str",
        "destination_networks": "str",
        "source_network": "str",
        "category_count": "int",
        "close_time": "str",
        "remote_destination_count": "int",
        "start_time": "str",
        "magnitude": "int",
        "last_updated_time": "str",
        "credibility": "int",
        "id": "int",
        "categories": "str",
        "severity": "int",
        "policy_category_count": "int",
        "closing_reason_id": "str",
        "device_count": "int",
        "offense_type": "str",
        "relevance": "int",
        "domain_id": "int",
        "offense_source": "str",
        "local_destination_address_ids": "int",
        "local_destination_count": "int",
        "status": "str",
        "domain_name": "str"
    }
    events = {
        "events": {
            "qidname_qid": "str",
            "logsourcename_logsourceid": "str",
            "categoryname_highlevelcategory": "str",
            "categoryname_category": "str",
            "protocolname_protocolid": "str",
            "sourceip": "str",
            "sourceport": "int",
            "destinationip": "str",
            "destinationport": "int",
            "qiddescription_qid": "str",
            "username": "NoneType",
            "rulename_creeventlist": "str",
            "sourcegeographiclocation": "str",
            "sourceMAC": "str",
            "sourcev6": "str",
            "destinationgeographiclocation": "str",
            "destinationv6": "str",
            "logsourcetypename_devicetype": "str",
            "credibility": "int",
            "severity": "int",
            "magnitude": "int",
            "eventcount": "int",
            "eventDirection": "str",
            "postNatDestinationIP": "str",
            "postNatDestinationPort": "int",
            "postNatSourceIP": "str",
            "postNatSourcePort": "int",
            "preNatDestinationPort": "int",
            "preNatSourceIP": "str",
            "preNatSourcePort": "int",
            "utf8_payload": "str",
            "starttime": "str",
            "devicetime": "int"
        }
    }
    assets = {
        "assets": {
            "interfaces": {
                "mac_address": "str",
                "ip_addresses": {
                    "type": "str",
                    "value": "str"
                },
                "id": "int",
                'Unified Name': "str",
                'Technical User': "str",
                'Switch ID': "str",
                'Business Contact': "str",
                'CVSS Availability Requirement': "str",
                'Compliance Notes': "str",
                'Primary OS ID': "str",
                'Compliance Plan': "str",
                'Switch Port ID': "str",
                'Weight': "str",
                'Location': "str",
                'CVSS Confidentiality Requirement': "str",
                'Technical Contact': "str",
                'Technical Owner': "str",
                'CVSS Collateral Damage Potential': "str",
                'Description': "str",
                'Business Owner': "str",
                'CVSS Integrity Requirement': "str"
            },
            "id": "int",
            "domain_id": "int",
            "domain_name": "str"
        }
    }
    custom_fields = {
        'events': {field['name']: field['property_type'] for field in client.get_custom_fields()}
    }
    fields = {
        'Offense': offense,
        'Events: Builtin Fields': events,
        'Events: Custom Fields': custom_fields,
        'Assets': assets,
    }
    return fields


def get_custom_properties_command(
        client: QRadarClient, limit: Optional[str] = None, field_name: Optional[str] = None,
        like_name: Optional[str] = None, filter: Optional[str] = None, fields: Optional[str] = None) -> dict:
    """Gives the user the regex event properties

    Args:
        client: QRadar Client
        limit: Maximum of properties to fetch
        field_name: exact name in `field`
        like_name: contains and case insensitive name in `field`
        filter: a custom filter query
        fields: Fields to retrieve. if None, will retrieve them all

    Returns:
        CortexXSOAR entry.
    """
    limit = int(limit) if limit else None
    field_names = argToList(field_name)
    likes = argToList(like_name)
    fields = argToList(fields)
    if filter and (likes or field_names):
        raise DemistoException('Can\'t send the `filter` argument with `field_name` or `like_name`')
    response = client.get_custom_fields(limit, field_names, likes, filter, fields)
    # Convert epoch times
    if not fields:
        for i in range(len(response)):
            for key in ['creation_date', 'modification_date']:
                try:
                    response[i][key] = epochToTimestamp(response[i][key])
                except KeyError:
                    pass
    return {
        "Type": entryTypes["note"],
        "Contents": response,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": tableToMarkdown(
            "Custom Properties",
            response,
            removeNull=True
        ),
        "EntryContext": {'QRadar.Properties': response},
    }


def main():
    params = demisto.params()

    # handle allowed advanced parameters
    adv_params = params.get("adv_params")
    if adv_params:
        globals_ = globals()
        for adv_p in adv_params.split(","):
            adv_p_kv = adv_p.split("=")
            if len(adv_p_kv) != 2:
                return_error(
                    f"Could not read advanced parameter: {adv_p} - please make sure you entered it correctly."
                )
            if adv_p_kv[0] not in ADVANCED_PARAMETER_NAMES:
                return_error(
                    f"The parameter: {adv_p_kv[0]} is not a valid advanced parameter. Please remove it"
                )
            else:
                try:
                    globals_[adv_p_kv[0]] = int(adv_p_kv[1])
                except (TypeError, ValueError):
                    globals_[adv_p_kv[0]] = adv_p_kv[1]

    server = params.get("server")
    credentials = params.get("credentials")
    insecure = params.get("insecure", False)
    offenses_per_fetch = params.get("offenses_per_fetch")
    proxies = handle_proxy()
    client = QRadarClient(
        server=server,
        proxies=proxies,
        credentials=credentials,
        offenses_per_fetch=offenses_per_fetch,
        insecure=insecure,
    )

    incident_type = params.get("incidentType")
    fetch_mode = params.get("fetch_mode")
    user_query = params.get("query")
    ip_enrich = params.get("ip_enrich")
    asset_enrich = params.get("asset_enrich")
    events_columns = params.get("events_columns")
    events_limit = int(params.get("events_limit") or 20)

    # Command selector
    command = demisto.command()
    try:
        demisto.debug(f"Command being called is {command}")
        normal_commands: Dict[str, Callable] = {
            "test-module": test_module,
            "qradar-offenses": get_offenses_command,
            "qradar-offense-by-id": get_offense_by_id_command,
            "qradar-update-offense": update_offense_command,
            "qradar-searches": search_command,
            "qradar-get-search": get_search_command,
            "qradar-get-search-results": get_search_results_command,
            "qradar-get-assets": get_assets_command,
            "qradar-get-asset-by-id": get_asset_by_id_command,
            "qradar-get-closing-reasons": get_closing_reasons_command,
            "qradar-get-note": get_note_command,
            "qradar-create-note": create_note_command,
            "qradar-get-reference-by-name": get_reference_by_name_command,
            "qradar-create-reference-set": create_reference_set_command,
            "qradar-delete-reference-set": delete_reference_set_command,
            "qradar-create-reference-set-value": update_reference_set_value_command,
            "qradar-update-reference-set-value": update_reference_set_value_command,
            "qradar-delete-reference-set-value": delete_reference_set_value_command,
            "qradar-get-domains": get_domains_command,
            "qradar-get-domain-by-id": get_domains_by_id_command,
            "qradar-upload-indicators": upload_indicators_command,
            "qradar-get-custom-properties": get_custom_properties_command
        }
        if command in normal_commands:
            args = demisto.args()
            demisto.results(normal_commands[command](client, **args))
        elif command == "fetch-incidents":
            demisto.incidents(fetch_incidents_long_running_samples())
        elif command == "long-running-execution":
            long_running_main(
                client,
                incident_type,
                user_query,
                ip_enrich,
                asset_enrich,
                fetch_mode,
                events_columns,
                events_limit,
            )
        elif command == "qradar-reset-last-run":
            demisto.results(reset_fetch_incidents())
        elif command == "get-mapping-fields":
            demisto.results(get_mapping_fields(client))
    except Exception as e:
        error = f"Error has occurred in the QRadar Integration: {str(e)}"
        LOG(traceback.format_exc())
        if demisto.command() == "fetch-incidents":
            LOG(error)
            LOG.print_log()
            raise Exception(error)
        else:
            return_error(error)


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()

import demistomock as demisto
from CommonServerPython import *

""" IMPORTS """
import json
import os
import requests
import urllib3
import py42.sdk
import py42.settings
from datetime import datetime
from uuid import UUID
from py42.services.detectionlists.departing_employee import DepartingEmployeeFilters
from py42.services.detectionlists.high_risk_employee import HighRiskEmployeeFilters
from py42.sdk.queries.fileevents.file_event_query import FileEventQuery as FileEventQueryV1
from py42.sdk.queries.fileevents.v2.file_event_query import FileEventQuery as FileEventQueryV2
from py42.sdk.queries.fileevents.filters import (
    MD5,
    SHA256,
    OSHostname,
    DeviceUsername,
    ExposureType,
    FileCategory,
)
from py42.sdk.queries.fileevents.v2 import filters as v2_filters
from py42.sdk.queries.fileevents.util import FileEventFilterStringField
from py42.sdk.queries.alerts.alert_query import AlertQuery
from py42.sdk.queries.alerts.filters import DateObserved, Severity, AlertState
from py42.exceptions import Py42NotFoundError, Py42HTTPError


class EventId(FileEventFilterStringField):
    _term = "eventId"


class EventIdV2(FileEventFilterStringField):
    _term = "event.id"


# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
CODE42_EVENT_CONTEXT_FIELD_MAPPER = {
    "eventTimestamp": "EventTimestamp",
    "createTimestamp": "FileCreated",
    "deviceUid": "EndpointID",
    "deviceUserName": "DeviceUsername",
    "emailFrom": "EmailFrom",
    "emailRecipients": "EmailTo",
    "emailSubject": "EmailSubject",
    "eventId": "EventID",
    "eventType": "EventType",
    "fileCategory": "FileCategory",
    "fileOwner": "FileOwner",
    "fileName": "FileName",
    "filePath": "FilePath",
    "fileSize": "FileSize",
    "modifyTimestamp": "FileModified",
    "md5Checksum": "FileMD5",
    "osHostName": "FileHostname",
    "privateIpAddresses": "DevicePrivateIPAddress",
    "publicIpAddresses": "DevicePublicIPAddress",
    "removableMediaBusType": "RemovableMediaType",
    "removableMediaCapacity": "RemovableMediaCapacity",
    "removableMediaMediaName": "RemovableMediaMediaName",
    "removableMediaName": "RemovableMediaName",
    "removableMediaSerialNumber": "RemovableMediaSerialNumber",
    "removableMediaVendor": "RemovableMediaVendor",
    "sha256Checksum": "FileSHA256",
    "shared": "FileShared",
    "sharedWith": "FileSharedWith",
    "source": "Source",
    "tabUrl": "ApplicationTabURL",
    "url": "FileURL",
    "processName": "ProcessName",
    "processOwner": "ProcessOwner",
    "windowTitle": "WindowTitle",
    "exposure": "Exposure",
    "sharingTypeAdded": "SharingTypeAdded",
}

CODE42_ALERT_CONTEXT_FIELD_MAPPER = {
    "actor": "Username",
    "createdAt": "Occurred",
    "description": "Description",
    "id": "ID",
    "name": "Name",
    "state": "State",
    "type": "Type",
    "riskSeverity": "Severity",
}

FILE_CONTEXT_FIELD_MAPPER = {
    "fileName": "Name",
    "filePath": "Path",
    "fileSize": "Size",
    "md5Checksum": "MD5",
    "sha256Checksum": "SHA256",
    "osHostName": "Hostname",
}

SECURITY_EVENT_HEADERS = [
    "EventType",
    "FileName",
    "FileSize",
    "FileHostname",
    "FileOwner",
    "FileCategory",
    "DeviceUsername",
]

SECURITY_ALERT_HEADERS = ["Type", "Occurred", "Username", "Name", "Description", "State", "ID"]


def _format_list(_list):
    return "\n".join(f"• {item}" for item in _list)


def _flatten_file_event(_dict: dict) -> dict:
    flat = {}
    for key, value in _dict.items():
        if isinstance(value, dict):
            for next_k, next_v in _flatten_file_event(value).items():
                flat[f"{key}.{next_k}"] = next_v
        elif isinstance(value, list) and len(value):
            list_str = _format_list(value)
            if len(_dict) > 1:
                list_str = "\n" + list_str
            flat[key] = list_str
        elif value:
            flat[key] = value
    return flat


def _columnize_file_event(obj):
    """
    If obj is a dictionary, converts it into a vertical column of key: value pairs
    for aligning vertically in the markdown table.
    """
    if isinstance(obj, dict):
        flat = _flatten_file_event(obj)
        column_rows = [f"**{k}:** {v}" for k, v in flat.items()]
        return "\n".join(column_rows)
    elif isinstance(obj, list) and len(obj):
        return _format_list(obj)
    else:
        return obj


def format_file_events(events: List[dict]):
    """
    Formats Code42 file events into a markdown table.
    """
    formatted_events = []
    for event in events:
        formatted = {}
        for k, v in event.items():
            column = _columnize_file_event(v)
            if column:
                formatted[k] = column
        formatted_events.append(formatted)
    return tableToMarkdown("", formatted_events, removeNull=True, sort_headers=False)


def deduplicate_v2_file_events(events: List[dict]):
    """Takes a list of v2 file events and returns a new list removing any duplicate events."""
    unique = []
    id_set = set()
    for event in events:
        _id = event["event"]["id"]
        if _id not in id_set:
            id_set.add(_id)
            unique.append(event)
    return unique


def deduplicate_v1_file_events(events: List[dict]):
    """Takes a list of v1 file events and returns a new list removing any duplicate events."""
    unique = []
    id_set = set()
    for event in events:
        _id = event["eventid"]
        if _id not in id_set:
            id_set.add(_id)
            unique.append(event)
    return unique


def _get_severity_filter_value(severity_arg):
    """Converts single str to upper case. If given list of strs, converts all to upper case."""
    if severity_arg:
        return (
            [severity_arg.upper()]
            if isinstance(severity_arg, str)
            else list(map(lambda x: x.upper(), severity_arg))
        )


def _create_alert_query(event_severity_filter, start_time):
    """Creates an alert query for the given severity (or severities) and start time."""
    alert_filters = AlertQueryFilters()
    severity = event_severity_filter
    alert_filters.append_result(_get_severity_filter_value(severity), Severity.is_in)
    alert_filters.append(AlertState.eq(AlertState.OPEN))
    alert_filters.append_result(start_time, DateObserved.on_or_after)
    alert_query = alert_filters.to_all_query()
    return alert_query


def _get_all_high_risk_employees_from_page(page, risk_tags):
    res = []
    employees = page.get("items") or []
    for employee in employees:
        if not risk_tags:
            res.append(employee)
            continue

        employee_tags = employee.get("riskFactors")
        # If the employee risk tags contain all the given risk tags
        if employee_tags and set(risk_tags) <= set(employee_tags):
            res.append(employee)
    return res


class Code42Client(BaseClient):
    """
    Client will implement the service API, should not contain Cortex XSOAR logic.
    Should do requests and return data
    """

    def __init__(self, sdk, base_url, auth, verify=True, proxy=False):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self._base_url = base_url
        self._auth = auth
        self._sdk = sdk

        if not proxy:
            for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                if os.environ.get(var):
                    del os.environ[var]

        py42.settings.set_user_agent_suffix("Cortex XSOAR")
        py42.settings.verify_ssl_certs = verify

    @property
    def sdk(self):
        if self._sdk is None:
            def api_client_provider():
                r = requests.post(
                    f"https://{self._base_url}/api/v3/oauth/token",
                    params={"grant_type": "client_credentials"},
                    auth=self._auth
                )
                r.raise_for_status()
                return r.json()["access_token"]

            self._sdk = py42.sdk.SDKClient.from_jwt_provider(self._base_url, api_client_provider)
        return self._sdk

    # Departing Employee methods (deprecated, replaced by Watchlist methods)

    def get_departing_employee(self, username):
        user_id = self._get_user_id(username)
        response = self.sdk.detectionlists.departing_employee.get(user_id)
        return response.data

    def add_user_to_departing_employee(self, username, departure_date=None, note=None):
        user_id = self._get_user_id(username)
        self.sdk.detectionlists.departing_employee.add(
            user_id, departure_date=departure_date
        )
        if note:
            self.sdk.detectionlists.update_user_notes(user_id, note)
        return user_id

    def remove_user_from_departing_employee(self, username):
        user_id = self._get_user_id(username)
        self.sdk.detectionlists.departing_employee.remove(user_id)
        return user_id

    def get_all_departing_employees(self, results, filter_type):
        res = []
        results = int(results) if results else 50
        filter_type = filter_type if filter_type else DepartingEmployeeFilters.OPEN
        pages = self.sdk.detectionlists.departing_employee.get_all(filter_type=filter_type)
        for page in pages:
            employees = page.data.get("items") or []
            for employee in employees:
                res.append(employee)
                if results and len(res) == results:
                    return res
        return res

    # High Risk Employee methods (deprecated, replaced by Watchlist methods)

    def get_high_risk_employee(self, username):
        user_id = self._get_user_id(username)
        response = self.sdk.detectionlists.high_risk_employee.get(user_id)
        return response.data

    def add_user_to_high_risk_employee(self, username, note=None):
        user_id = self._get_user_id(username)
        self.sdk.detectionlists.high_risk_employee.add(user_id)
        if note:
            self.sdk.detectionlists.update_user_notes(user_id, note)
        return user_id

    def remove_user_from_high_risk_employee(self, username):
        user_id = self._get_user_id(username)
        self.sdk.detectionlists.high_risk_employee.remove(user_id)
        return user_id

    def add_user_risk_tags(self, username, risk_tags):
        risk_tags = argToList(risk_tags)
        user_id = self._get_user_id(username)
        self.sdk.detectionlists.add_user_risk_tags(user_id, risk_tags)
        return user_id

    def remove_user_risk_tags(self, username, risk_tags):
        risk_tags = argToList(risk_tags)
        user_id = self._get_user_id(username)
        self.sdk.detectionlists.remove_user_risk_tags(user_id, risk_tags)
        return user_id

    def get_all_high_risk_employees(self, risk_tags, results, filter_type):
        risk_tags = argToList(risk_tags)
        results = int(results) if results else 50
        filter_type = filter_type if filter_type else HighRiskEmployeeFilters.OPEN
        res = []
        pages = self.sdk.detectionlists.high_risk_employee.get_all(filter_type=filter_type)
        for page in pages:
            employees = _get_all_high_risk_employees_from_page(page.data, risk_tags)
            for employee in employees:
                res.append(employee)
                if results and len(res) == results:
                    return res
        return res

    # Alert methods

    def fetch_alerts(self, start_time, event_severity_filter):
        query = _create_alert_query(event_severity_filter, start_time)
        res = self.sdk.alerts.search(query)
        return res.data.get("alerts")

    def get_alert_details(self, alert_id):
        try:
            py42_res = self.sdk.alerts.get_details(alert_id)
            res = py42_res.data.get("alerts")
            return res[0]
        except Py42NotFoundError:
            raise Code42AlertNotFoundError(alert_id)

    def resolve_alert(self, id):
        self.sdk.alerts.resolve(id)
        return id

    def get_user(self, username):
        py42_res = self.sdk.users.get_by_username(username)
        res = py42_res.data.get("users")
        if not res:
            raise Code42UserNotFoundError(username)
        return res[0]

    def create_user(self, org_name, username, email):
        org_uid = self._get_org_id(org_name)
        response = self.sdk.users.create_user(org_uid, username, email)
        return response.data

    def block_user(self, username):
        user_id = self._get_legacy_user_id(username)
        self.sdk.users.block(user_id)
        return user_id

    def unblock_user(self, username):
        user_id = self._get_legacy_user_id(username)
        self.sdk.users.unblock(user_id)
        return user_id

    def deactivate_user(self, username):
        user_id = self._get_legacy_user_id(username)
        self.sdk.users.deactivate(user_id)
        return user_id

    def reactivate_user(self, username):
        user_id = self._get_legacy_user_id(username)
        self.sdk.users.reactivate(user_id)
        return user_id

    def get_legal_hold_matter(self, matter_name):
        matter_pages = self.sdk.legalhold.get_all_matters(name=matter_name)
        for matter_page in matter_pages:
            matters = matter_page["legalHolds"]
            for matter in matters:
                return matter
        raise Code42LegalHoldMatterNotFoundError(matter_name)

    def add_user_to_legal_hold_matter(self, username, matter_name):
        user_uid = self._get_user_id(username)
        matter_id = self._get_legal_hold_matter_id(matter_name)
        response = self.sdk.legalhold.add_to_matter(user_uid, matter_id)
        return response.data

    def remove_user_from_legal_hold_matter(self, username, matter_name):
        user_uid = self._get_user_id(username)
        matter_id = self._get_legal_hold_matter_id(matter_name)
        membership_id = self._get_legal_hold_matter_membership_id(user_uid, matter_id)
        if membership_id:
            self.sdk.legalhold.remove_from_matter(membership_id)
            return user_uid, matter_id

        raise Code42InvalidLegalHoldMembershipError(username, matter_name)

    def get_org(self, org_name):
        org_pages = self.sdk.orgs.get_all()
        for org_page in org_pages:
            orgs = org_page.data.get("orgs")
            for org in orgs:
                if org.get("orgName", "") == org_name:
                    return org
        raise Code42OrgNotFoundError(org_name)

    def search_file_events(self, payload):
        py42_res = self.sdk.securitydata.search_file_events(payload)
        return py42_res.data.get("fileEvents")

    def download_file(self, hash_arg):
        security_module = self.sdk.securitydata
        if _hash_is_md5(hash_arg):
            return security_module.stream_file_by_md5(hash_arg)
        elif _hash_is_sha256(hash_arg):
            return security_module.stream_file_by_sha256(hash_arg)
        else:
            raise Code42UnsupportedHashError()

    def _get_user_id(self, username):
        user_id = self.get_user(username).get("userUid")
        if user_id:
            return user_id
        raise Code42UserNotFoundError(username)

    def _get_legacy_user_id(self, username):
        user_id = self.get_user(username).get("userId")
        if user_id:
            return user_id
        raise Code42UserNotFoundError(username)

    def _get_org_id(self, org_name):
        org_uid = self.get_org(org_name).get("orgUid")
        if org_uid:
            return org_uid
        raise Code42OrgNotFoundError(org_name)

    def _get_legal_hold_matter_id(self, matter_name):
        matter_id = self.get_legal_hold_matter(matter_name).get("legalHoldUid")
        return matter_id

    def _get_legal_hold_matter_membership_id(self, user_id, matter_id):
        member_pages = self.sdk.legalhold.get_all_matter_custodians(legal_hold_uid=matter_id, user_uid=user_id)
        for member_page in member_pages:
            members = member_page["legalHoldMemberships"]
            for member in members:
                return member["legalHoldMembershipUid"]


class Code42AlertNotFoundError(Exception):
    def __init__(self, alert_id):
        super(Code42AlertNotFoundError, self).__init__(
            "No alert found with ID {0}.".format(alert_id)
        )


class Code42UserNotFoundError(Exception):
    def __init__(self, username):
        super(Code42UserNotFoundError, self).__init__(
            "No user found with username {0}.".format(username)
        )


class Code42OrgNotFoundError(Exception):
    def __init__(self, org_name):
        super(Code42OrgNotFoundError, self).__init__(
            "No organization found with name {0}.".format(org_name)
        )


class Code42InvalidWatchlistTypeError(Exception):
    def __init__(self, watchlist):
        msg = "Invalid Watchlist type: {0}, run !code42-watchlists-list to get a list of available Watchlists.".format(
            watchlist
        )
        super().__init__(msg)


class Code42UnsupportedHashError(Exception):
    def __init__(self):
        super(Code42UnsupportedHashError, self).__init__(
            "Unsupported hash. Must be SHA256 or MD5."
        )


class Code42UnsupportedV2ParameterError(Exception):
    def __init__(self, param: str):
        super(Code42UnsupportedV2ParameterError, self).__init__(
            f"Unsupported parameter: {param} when 'v2_events' is enabled on Code42 integration."
        )


class Code42MissingSearchArgumentsError(Exception):
    def __init__(self):
        super(Code42MissingSearchArgumentsError, self).__init__(
            "No query args provided for searching Code42 security events."
        )


class Code42LegalHoldMatterNotFoundError(Exception):
    def __init__(self, matter_name):
        super(Code42LegalHoldMatterNotFoundError, self).__init__(
            "No legal hold matter found with name {0}.".format(matter_name)
        )


class Code42InvalidLegalHoldMembershipError(Exception):
    def __init__(self, username, matter_name):
        super(Code42InvalidLegalHoldMembershipError, self).__init__(
            "User '{0}' is not an active member of legal hold matter '{1}'".format(
                username, matter_name
            )
        )


class Code42SearchFilters(object):
    def __init__(self):
        self._filters = []

    @property
    def filters(self):
        return self._filters

    def to_all_query(self):
        """Override"""

    def append(self, _filter):
        if _filter:
            self._filters.append(_filter)

    def extend(self, _filters):
        if _filters:
            self._filters.extend(_filters)

    def append_result(self, value, create_filter):
        """Safely creates and appends the filter to the working list."""
        if not value:
            return
        _filter = create_filter(value)
        self.append(_filter)


class FileEventQueryFilters(Code42SearchFilters):
    """Class for simplifying building up a file event search query"""

    def __init__(self, pg_size=None):
        self._pg_size = pg_size
        super(FileEventQueryFilters, self).__init__()

    def to_all_query(self):
        """Convert list of search criteria to *args"""
        query = FileEventQueryV1.all(*self._filters)
        if self._pg_size:
            query.page_size = self._pg_size
        return query


class AlertQueryFilters(Code42SearchFilters):
    """Class for simplifying building up an alert search query"""

    def to_all_query(self):
        query = AlertQuery.all(*self._filters)
        query.page_size = 500
        query.sort_direction = "asc"
        return query


@logger
def build_query_payload(args):
    """Build a query payload combining passed args"""

    pg_size = args.get("results")
    _hash = args.get("hash")
    hostname = args.get("hostname")
    username = args.get("username")
    exposure = args.get("exposure")

    if not _hash and not hostname and not username and not exposure:
        raise Code42MissingSearchArgumentsError()

    search_args = FileEventQueryFilters(pg_size)
    search_args.append_result(_hash, _create_hash_filter)
    search_args.append_result(hostname, OSHostname.eq)
    search_args.append_result(username, DeviceUsername.eq)
    search_args.append_result(exposure, _create_exposure_filter)

    query = search_args.to_all_query()
    LOG("File Event Query: {}".format(str(query)))
    return query


@logger
def build_v2_query_payload(args):
    """Build a query payload combining passed args"""
    _hash = args.get("hash")
    hostname = args.get("hostname")
    username = args.get("username")
    min_risk_score = arg_to_number(args.get("min_risk_score"), arg_name="min_risk_score") or 1

    if not _hash and not hostname and not username:
        raise Code42MissingSearchArgumentsError()

    filters = []
    if _hash:
        if _hash_is_md5(_hash):
            filters.append(v2_filters.file.MD5.eq(_hash))
        elif _hash_is_sha256(_hash):
            filters.append(v2_filters.file.SHA256.eq(_hash))
    if hostname:
        filters.append(v2_filters.source.Name.eq(hostname))
    if username:
        filters.append(v2_filters.user.Email.eq(username))
    if min_risk_score > 0:
        filters.append(v2_filters.risk.Score.greater_than(min_risk_score - 1))

    query = FileEventQueryV2(*filters)
    return query


def _hash_is_sha256(hash_arg):
    return hash_arg and len(hash_arg) == 64


def _hash_is_md5(hash_arg):
    return hash_arg and len(hash_arg) == 32


def _create_hash_filter(hash_arg):
    if _hash_is_md5(hash_arg):
        return MD5.eq(hash_arg)
    elif _hash_is_sha256(hash_arg):
        return SHA256.eq(hash_arg)


def _create_exposure_filter(exposure_arg):
    # Because the CLI can't accept lists, convert the args to a list if the type is string.
    exposure_arg = argToList(exposure_arg)
    if "All" in exposure_arg:
        return ExposureType.exists()
    return ExposureType.is_in(exposure_arg)


def get_file_category_value(key):
    # Meant to handle all possible cases
    key = key.lower().replace("-", "").replace("_", "")
    category_map = {
        "sourcecode": FileCategory.SOURCE_CODE,
        "audio": FileCategory.AUDIO,
        "executable": FileCategory.EXECUTABLE,
        "document": FileCategory.DOCUMENT,
        "image": FileCategory.IMAGE,
        "pdf": FileCategory.PDF,
        "presentation": FileCategory.PRESENTATION,
        "script": FileCategory.SCRIPT,
        "spreadsheet": FileCategory.SPREADSHEET,
        "video": FileCategory.VIDEO,
        "virtualdiskimage": FileCategory.VIRTUAL_DISK_IMAGE,
        "archive": FileCategory.ZIP,
    }
    return category_map.get(key, "UNCATEGORIZED")


@logger
def map_to_code42_event_context(obj):
    code42_context = _map_obj_to_context(obj, CODE42_EVENT_CONTEXT_FIELD_MAPPER)
    # FileSharedWith is a special case and needs to be converted to a list
    shared_with_list = code42_context.get("FileSharedWith")
    if shared_with_list:
        shared_list = [u.get("cloudUsername") for u in shared_with_list if u.get("cloudUsername")]
        code42_context["FileSharedWith"] = str(shared_list)
    return code42_context


@logger
def map_to_code42_alert_context(obj):
    return _map_obj_to_context(obj, CODE42_ALERT_CONTEXT_FIELD_MAPPER)


@logger
def map_to_file_context(obj):
    return _map_obj_to_context(obj, FILE_CONTEXT_FIELD_MAPPER)


@logger
def _map_obj_to_context(obj, context_mapper):
    return {v: obj.get(k) for k, v in context_mapper.items() if obj.get(k)}


"""Commands"""


@logger
def alert_get_command(client, args):
    code42_securityalert_context = []
    try:
        alert = client.get_alert_details(args.get("id"))
    except Code42AlertNotFoundError:
        return CommandResults(
            readable_output="No results found",
            outputs={"Results": []},
            outputs_key_field="ID",
            outputs_prefix="Code42.SecurityAlert",
            raw_response={},
        )

    code42_context = map_to_code42_alert_context(alert)
    code42_securityalert_context.append(code42_context)
    readable_outputs = tableToMarkdown(
        "Code42 Security Alert Results",
        code42_securityalert_context,
        headers=SECURITY_ALERT_HEADERS,
    )
    return CommandResults(
        outputs_prefix="Code42.SecurityAlert",
        outputs_key_field="ID",
        outputs=code42_securityalert_context,
        readable_output=readable_outputs,
        raw_response=alert,
    )


@logger
def alert_resolve_command(client, args):
    code42_securityalert_context = []
    alert_id = client.resolve_alert(args.get("id"))
    if not alert_id:
        return CommandResults(
            readable_output="No results found",
            outputs={"Results": []},
            outputs_key_field="ID",
            outputs_prefix="Code42.SecurityAlert",
            raw_response={},
        )

    # Retrieve new alert details
    alert_details = client.get_alert_details(alert_id)
    code42_context = map_to_code42_alert_context(alert_details)
    code42_securityalert_context.append(code42_context)
    readable_outputs = tableToMarkdown(
        "Code42 Security Alert Resolved",
        code42_securityalert_context,
        headers=SECURITY_ALERT_HEADERS,
    )
    return CommandResults(
        outputs_prefix="Code42.SecurityAlert",
        outputs_key_field="ID",
        outputs=code42_securityalert_context,
        readable_output=readable_outputs,
        raw_response=alert_details,
    )


@logger
def departingemployee_add_command(client, args):
    departing_date = args.get("departuredate")
    username = args.get("username")
    note = args.get("note")
    user_id = client.add_user_to_departing_employee(username, departing_date, note)
    # CaseID included but is deprecated.
    de_context = {
        "CaseID": user_id,
        "UserID": user_id,
        "Username": username,
        "DepartureDate": departing_date,
        "Note": note,
    }
    readable_outputs = tableToMarkdown("Code42 Departing Employee List User Added", de_context)
    return CommandResults(
        outputs_prefix="Code42.DepartingEmployee",
        outputs_key_field="UserID",
        outputs=de_context,
        readable_output=readable_outputs,
        raw_response=user_id,
    )


@logger
def departingemployee_remove_command(client, args):
    username = args.get("username")
    user_id = client.remove_user_from_departing_employee(username)
    # CaseID included but is deprecated.
    de_context = {"CaseID": user_id, "UserID": user_id, "Username": username}
    readable_outputs = tableToMarkdown("Code42 Departing Employee List User Removed", de_context)
    return CommandResults(
        outputs_prefix="Code42.DepartingEmployee",
        outputs_key_field="UserID",
        outputs=de_context,
        readable_output=readable_outputs,
        raw_response=user_id,
    )


@logger
def departingemployee_get_all_command(client, args):
    results = args.get("results", 50)
    filter_type = args.get("filtertype", DepartingEmployeeFilters.OPEN)
    employees = client.get_all_departing_employees(results, filter_type)
    if not employees:
        return CommandResults(
            readable_output="No results found",
            outputs_prefix="Code42.DepartingEmployee",
            outputs_key_field="UserID",
            outputs={"Results": []},
            raw_response={},
        )

    employees_context = [
        {
            "UserID": e.get("userId"),
            "Username": e.get("userName"),
            "DepartureDate": e.get("departureDate"),
            "Note": e.get("notes"),
        }
        for e in employees
    ]
    readable_outputs = tableToMarkdown("All Departing Employees", employees_context)
    return CommandResults(
        outputs_prefix="Code42.DepartingEmployee",
        outputs_key_field="UserID",
        outputs=employees_context,
        readable_output=readable_outputs,
        raw_response=employees,
    )


@logger
def departingemployee_get_command(client, args):
    username = args.get("username")
    departing_employee = client.get_departing_employee(username)
    de_context = {
        "UserID": departing_employee.get("userId"),
        "Username": departing_employee.get("userName"),
        "DepartureDate": departing_employee.get("departureDate"),
        "Note": departing_employee.get("notes"),
    }
    readable_outputs = tableToMarkdown("Retrieve departing employee", de_context)
    return CommandResults(
        outputs_prefix="Code42.DepartingEmployee",
        outputs_key_field="UserID",
        outputs=de_context,
        readable_output=readable_outputs,
        raw_response=username,
    )


@logger
def highriskemployee_get_command(client, args):
    username = args.get("username")
    high_risk_employee = client.get_high_risk_employee(username)
    hre_context = {
        "UserID": high_risk_employee.get("userId"),
        "Username": high_risk_employee.get("userName"),
        "Note": high_risk_employee.get("notes")
    }
    readable_outputs = tableToMarkdown("Retrieve high risk employee", hre_context)
    return CommandResults(
        outputs_prefix="Code42.HighRiskEmployee",
        outputs_key_field="UserID",
        outputs=hre_context,
        readable_output=readable_outputs,
        raw_response=username,
    )


@logger
def highriskemployee_add_command(client, args):
    username = args.get("username")
    note = args.get("note")
    user_id = client.add_user_to_high_risk_employee(username, note)
    hr_context = {"UserID": user_id, "Username": username}
    readable_outputs = tableToMarkdown("Code42 High Risk Employee List User Added", hr_context)
    return CommandResults(
        outputs_prefix="Code42.HighRiskEmployee",
        outputs_key_field="UserID",
        outputs=hr_context,
        readable_output=readable_outputs,
        raw_response=user_id,
    )


@logger
def highriskemployee_remove_command(client, args):
    username = args.get("username")
    user_id = client.remove_user_from_high_risk_employee(username)
    hr_context = {"UserID": user_id, "Username": username}
    readable_outputs = tableToMarkdown("Code42 High Risk Employee List User Removed", hr_context)
    return CommandResults(
        outputs_prefix="Code42.HighRiskEmployee",
        outputs_key_field="UserID",
        outputs=hr_context,
        readable_output=readable_outputs,
        raw_response=user_id,
    )


@logger
def highriskemployee_get_all_command(client, args):
    tags = args.get("risktags")
    results = args.get("results", 50)
    filter_type = args.get("filtertype", HighRiskEmployeeFilters.OPEN)
    employees = client.get_all_high_risk_employees(tags, results, filter_type)
    if not employees:
        return CommandResults(
            readable_output="No results found",
            outputs_prefix="Code42.HighRiskEmployee",
            outputs_key_field="UserID",
            outputs={"Results": []},
            raw_response={},
        )
    employees_context = [
        {"UserID": e.get("userId"), "Username": e.get("userName"), "Note": e.get("notes")}
        for e in employees
    ]
    readable_outputs = tableToMarkdown("Retrieved All High Risk Employees", employees_context)
    return CommandResults(
        outputs_prefix="Code42.HighRiskEmployee",
        outputs_key_field="UserID",
        outputs=employees_context,
        readable_output=readable_outputs,
        raw_response=employees,
    )


@logger
def highriskemployee_add_risk_tags_command(client, args):
    username = args.get("username")
    tags = args.get("risktags")
    user_id = client.add_user_risk_tags(username, tags)
    rt_context = {"UserID": user_id, "Username": username, "RiskTags": tags}
    readable_outputs = tableToMarkdown("Code42 Risk Tags Added", rt_context)
    return CommandResults(
        outputs_prefix="Code42.HighRiskEmployee",
        outputs_key_field="UserID",
        outputs=rt_context,
        readable_output=readable_outputs,
        raw_response=user_id,
    )


@logger
def highriskemployee_remove_risk_tags_command(client, args):
    username = args.get("username")
    tags = args.get("risktags")
    user_id = client.remove_user_risk_tags(username, tags)
    rt_context = {"UserID": user_id, "Username": username, "RiskTags": tags}
    readable_outputs = tableToMarkdown("Code42 Risk Tags Removed", rt_context)
    return CommandResults(
        outputs_prefix="Code42.HighRiskEmployee",
        outputs_key_field="UserID",
        outputs=rt_context,
        readable_output=readable_outputs,
        raw_response=user_id,
    )


@logger
def securitydata_search_command(client, args):
    code42_security_data_context = []
    _json = args.get("json")
    file_context = []

    # If JSON payload is passed as an argument, ignore all other args and search by JSON payload
    if _json is not None:
        file_events = client.search_file_events(_json)
    else:
        # Build payload
        payload = build_query_payload(args)
        file_events = client.search_file_events(payload)
    if file_events:
        for file_event in file_events:
            code42_context_event = map_to_code42_event_context(file_event)
            code42_security_data_context.append(code42_context_event)
            file_context_event = map_to_file_context(file_event)
            file_context.append(file_context_event)
        readable_outputs = tableToMarkdown(
            "Code42 Security Data Results",
            code42_security_data_context,
            headers=SECURITY_EVENT_HEADERS,
        )
        code42_results = CommandResults(
            outputs_prefix="Code42.SecurityData",
            outputs_key_field="EventID",
            outputs=code42_security_data_context,
            readable_output=readable_outputs,
            raw_response=file_events,
        )
        file_results = CommandResults(
            outputs_prefix="File", outputs_key_field=None, outputs=file_context
        )
        return code42_results, file_results

    else:
        return CommandResults(
            readable_output="No results found",
            outputs={"Results": []},
            outputs_key_field="EventID",
            outputs_prefix="Code42.SecurityData",
            raw_response={},
        )


@logger
def file_events_search_command(client, args):
    json_query = args.get("json")
    add_to_context = argToBoolean(args.get("add-to-context"))
    page_size = arg_to_number(args.get("results"), arg_name="results")
    # If JSON payload is passed as an argument, ignore all other args and search by JSON payload
    if json_query is not None:
        try:
            query = FileEventQueryV2.from_dict(json.loads(json_query))
        except KeyError as err:
            return_error(f"Error parsing json query: {err}")
    else:
        query = build_v2_query_payload(args)
    try:
        query.page_size = page_size
        file_events = client.search_file_events(query)
        markdown_table = format_file_events(file_events)
        if add_to_context:
            context = demisto.context()
            if "Code42" in context and "FileEvents" in context["Code42"]:
                context_events = context["Code42"]["FileEvents"]
                file_events = deduplicate_v2_file_events(file_events + context_events)
            return CommandResults(
                outputs_prefix="Code42.FileEvents",
                outputs=file_events,
                readable_output=markdown_table
            )
        else:
            return CommandResults(readable_output=markdown_table)
    except Py42HTTPError as err:
        return_error(f"Error executing json query. Make sure your query is a V2 file event query. Error={err}")


@logger
def user_create_command(client, args):
    org_name = args.get("orgname")
    username = args.get("username")
    email = args.get("email")
    res = client.create_user(org_name, username, email)
    outputs = {
        "Username": res.get("username"),
        "UserID": res.get("userUid"),
        "Email": res.get("email"),
    }
    readable_outputs = tableToMarkdown("Code42 User Created", outputs)
    return CommandResults(
        outputs_prefix="Code42.User",
        outputs_key_field="UserID",
        outputs=outputs,
        readable_output=readable_outputs,
        raw_response=res,
    )


@logger
def user_block_command(client, args):
    username = args.get("username")
    user_id = client.block_user(username)
    outputs = {"UserID": user_id}
    readable_outputs = tableToMarkdown("Code42 User Blocked", outputs)
    return CommandResults(
        outputs_prefix="Code42.User",
        outputs_key_field="UserID",
        outputs=outputs,
        readable_output=readable_outputs,
        raw_response=user_id,
    )


@logger
def user_unblock_command(client, args):
    username = args.get("username")
    user_id = client.unblock_user(username)
    outputs = {"UserID": user_id}
    readable_outputs = tableToMarkdown("Code42 User Unblocked", outputs)
    return CommandResults(
        outputs_prefix="Code42.User",
        outputs_key_field="UserID",
        outputs=outputs,
        readable_output=readable_outputs,
        raw_response=user_id,
    )


@logger
def user_deactivate_command(client, args):
    username = args.get("username")
    user_id = client.deactivate_user(username)
    outputs = {"UserID": user_id}
    readable_outputs = tableToMarkdown("Code42 User Deactivated", outputs)
    return CommandResults(
        outputs_prefix="Code42.User",
        outputs_key_field="UserID",
        outputs=outputs,
        readable_output=readable_outputs,
        raw_response=user_id,
    )


@logger
def user_reactivate_command(client, args):
    username = args.get("username")
    user_id = client.reactivate_user(username)
    outputs = {"UserID": user_id}
    readable_outputs = tableToMarkdown("Code42 User Reactivated", outputs)
    return CommandResults(
        outputs_prefix="Code42.User",
        outputs_key_field="UserID",
        outputs=outputs,
        readable_output=readable_outputs,
        raw_response=user_id,
    )


@logger
def legal_hold_add_user_command(client, args):
    username = args.get("username")
    matter_name = args.get("mattername")
    response = client.add_user_to_legal_hold_matter(username, matter_name)
    legal_hold_info = response.get("legalHold")
    user_info = response.get("user")
    outputs = {
        "MatterID": legal_hold_info.get("legalHoldUid") if legal_hold_info else None,
        "MatterName": legal_hold_info.get("name") if legal_hold_info else None,
        "UserID": user_info.get("userUid") if legal_hold_info else None,
        "Username": user_info.get("username") if user_info else None,
    }
    readable_outputs = tableToMarkdown("Code42 User Added to Legal Hold Matter", outputs)
    return CommandResults(
        outputs_prefix="Code42.LegalHold",
        outputs_key_field="MatterID",
        outputs=outputs,
        readable_output=readable_outputs,
        raw_response=response
    )


@logger
def legal_hold_remove_user_command(client, args):
    username = args.get("username")
    matter_name = args.get("mattername")
    user_uid, matter_id = client.remove_user_from_legal_hold_matter(username, matter_name)
    outputs = {
        "MatterID": matter_id,
        "MatterName": matter_name,
        "UserID": user_uid,
        "Username": username
    }
    readable_outputs = tableToMarkdown("Code42 User Removed from Legal Hold Matter", outputs)
    return CommandResults(
        outputs_prefix="Code42.LegalHold",
        outputs_key_field="MatterID",
        outputs=outputs,
        readable_output=readable_outputs,
        raw_response=user_uid
    )


@logger
def download_file_command(client, args):
    file_hash = args.get("hash")
    filename = args.get("filename") or file_hash
    response = client.download_file(file_hash)
    file_chunks = [c for c in response.iter_content(chunk_size=128) if c]
    return fileResult(filename, data=b"".join(file_chunks))


@logger
def list_watchlists_command(client, args):
    watchlists_context = []
    for page in client.sdk.watchlists.get_all():
        for watchlist in page["watchlists"]:
            watchlists_context.append(
                {
                    "WatchlistID": watchlist["watchlistId"],
                    "WatchlistType": watchlist["listType"],
                    "IncludedUsersCount": watchlist["stats"].get("includedUsersCount", 0)
                }
            )

    if not watchlists_context:
        CommandResults(
            readable_output="No results found",
            outputs_prefix="Code42.Watchlists",
            outputs_key_field="WatchlistID",
            outputs={"Results": []},
            raw_response={},
        )

    readable_outputs = tableToMarkdown("Watchlists", watchlists_context)
    return CommandResults(
        outputs_prefix="Code42.Watchlists",
        outputs_key_field="WatchlistID",
        outputs=watchlists_context,
        readable_output=readable_outputs,
        raw_response=watchlists_context,
    )


@logger
def list_watchlists_included_users(client, args):
    watchlist = args.get("watchlist")
    try:
        UUID(hex=watchlist)
        watchlist_id = watchlist
    except ValueError:
        watchlist_id = client.sdk.watchlists._watchlists_service.watchlist_type_id_map.get(watchlist)
        if watchlist_id is None:
            raise Code42InvalidWatchlistTypeError(watchlist)
    included_users_context = []
    for page in client.sdk.watchlists.get_all_included_users(watchlist_id):
        for user in page["includedUsers"]:
            included_users_context.append(
                {"Username": user["username"], "AddedTime": user["addedTime"], "WatchlistID": watchlist_id}
            )
    readable_outputs = tableToMarkdown("Watchlists", included_users_context)
    return CommandResults(
        outputs_prefix="Code42.WatchlistUsers",
        outputs=included_users_context,
        readable_output=readable_outputs,
    )


@logger
def add_user_to_watchlist_command(client, args):
    username = args.get("username")
    watchlist = args.get("watchlist")
    user = client.get_user(username)
    user_id = user["userUid"]
    try:
        UUID(hex=watchlist)
        resp = client.sdk.watchlists.add_included_users_by_watchlist_id(user_id, watchlist)
    except ValueError:
        resp = client.sdk.watchlists.add_included_users_by_watchlist_type(user_id, watchlist)
    return CommandResults(
        outputs_prefix="Code42.UsersAddedToWatchlists",
        outputs_key_field="Watchlist",
        outputs={"Watchlist": watchlist, "Username": username, "Success": resp.status_code == 200},
    )


@logger
def update_user_risk_profile(client, args):
    username = args.get("username")
    start_date = args.get("start_date")
    end_date = args.get("end_date")
    notes = args.get("notes")

    user = client.get_user(username)
    user_id = user["userUid"]

    resp = client.sdk.userriskprofile.update(
        user_id,
        start_date=start_date,
        end_date=end_date,
        notes=notes
    )
    outputs = {
        "Username": username,
        "Success": resp.status_code == 200,
        "EndDate": resp.data.get("endDate"),
        "StartDate": resp.data.get("startDate"),
        "Notes": resp.data.get("notes"),
    }
    readable_outputs = tableToMarkdown("Code42 User Risk Profile Updated", outputs)
    return CommandResults(
        outputs_prefix="Code42.UpdatedUserRiskProfiles",
        outputs_key_field="Profile",
        outputs=outputs,
        readable_output=readable_outputs,
    )


@logger
def get_user_risk_profile(client, args):
    username = args.get("username")
    resp = client.sdk.userriskprofile.get_by_username(username)
    outputs = {
        "Username": username,
        "EndDate": resp.data.get("endDate"),
        "StartDate": resp.data.get("startDate"),
        "Notes": resp.data.get("notes"),
    }
    return CommandResults(
        outputs_prefix="Code42.UserRiskProfiles",
        outputs_key_field="Profile",
        outputs=outputs,
    )


@logger
def remove_user_from_watchlist_command(client, args):
    username = args.get("username")
    watchlist = args.get("watchlist")
    user = client.get_user(username)
    user_id = user["userUid"]
    try:
        UUID(hex=watchlist)
        resp = client.sdk.watchlists.remove_included_users_by_watchlist_id(user_id, watchlist)
    except ValueError:
        resp = client.sdk.watchlists.remove_included_users_by_watchlist_type(user_id, watchlist)
    return CommandResults(
        outputs_prefix="Code42.UsersRemovedFromWatchlists",
        outputs_key_field="Watchlist",
        outputs={"Watchlist": watchlist, "Username": username, "Success": resp.status_code == 200},
    )


@logger
def file_events_to_table_command(client, args):
    incident = demisto.incident()
    file_event_version = incident["CustomFields"].get("code42fileeventsversion", "1")
    path = args.get("include")
    events = []
    if path in ("incident", "all"):
        events.extend(incident["CustomFields"]["code42fileevents"])
    if path in ("searches", "all"):
        context = demisto.context()
        if "Code42" in context and "FileEvents" in context["Code42"]:
            events.extend(context["Code42"]["FileEvents"])
    if file_event_version == "2":
        events = deduplicate_v2_file_events(events)
    else:
        events = deduplicate_v1_file_events(events)
    table = format_file_events(events)
    return CommandResults(readable_output=table)


"""Fetching"""


def _process_event_from_observation(event):
    # We need to convert certain fields to a stringified list else React.JS will throw an error
    shared_with = event.get("sharedWith")
    private_ip_addresses = event.get("privateIpAddresses")
    if shared_with:
        shared_list = [u.get("cloudUsername") for u in shared_with if u.get("cloudUsername")]
        event["sharedWith"] = str(shared_list)
    if private_ip_addresses:
        event["privateIpAddresses"] = str(private_ip_addresses)
    return event


class Code42SecurityIncidentFetcher(object):
    def __init__(
        self,
        client,
        last_run,
        first_fetch_time,
        event_severity_filter,
        fetch_limit,
        include_files,
        v2_events,
        integration_context=None,
    ):
        self._client = client
        self._last_run = last_run
        self._first_fetch_time = first_fetch_time
        self._event_severity_filter = event_severity_filter
        self._fetch_limit = fetch_limit
        self._include_files = include_files
        self._v2_events = v2_events
        self._integration_context = integration_context

    @logger
    def fetch(self):
        remaining_incidents_from_last_run = self._fetch_remaining_incidents_from_last_run()
        if remaining_incidents_from_last_run:
            return remaining_incidents_from_last_run
        start_query_time = self._get_start_query_time()
        alerts = self._fetch_alerts(start_query_time)
        incidents = [self._create_incident_from_alert(a) for a in alerts]
        save_time = datetime.utcnow().timestamp()
        next_run = {"last_fetch": save_time}
        return next_run, incidents[: self._fetch_limit], incidents[self._fetch_limit:]

    def _fetch_remaining_incidents_from_last_run(self):
        if self._integration_context:
            remaining_incidents = self._integration_context.get("remaining_incidents")
            # return incidents if exists in context.
            if remaining_incidents:
                return (
                    self._last_run,
                    remaining_incidents[:self._fetch_limit],
                    remaining_incidents[self._fetch_limit:],
                )

    def _get_start_query_time(self):
        start_query_time = self._try_get_last_fetch_time()

        # Handle first time fetch, fetch incidents retroactively
        if not start_query_time:
            start_query_time, _ = parse_date_range(
                self._first_fetch_time, to_timestamp=True, utc=True
            )
            start_query_time /= 1000

        return start_query_time

    def _try_get_last_fetch_time(self):
        return self._last_run.get("last_fetch")

    def _fetch_alerts(self, start_query_time):
        return self._client.fetch_alerts(start_query_time, self._event_severity_filter)

    def _create_incident_from_alert(self, alert):
        response = self._client.sdk.alerts.get_aggregate_data(alert.get("id"))
        details = response.data.get("alert")
        details["alertId"] = alert.get("id")
        self._format_summary(details)
        incident = {"name": "Code42 - {}".format(details.get("name")), "occurred": details.get("createdAt")}
        if self._include_files:
            details = self._relate_files_to_alert(details)
        incident["rawJSON"] = json.dumps(details)
        return incident

    def _relate_files_to_alert(self, alert_details):
        observations = alert_details.get("observations")
        if not observations:
            alert_details["fileevents"] = []
            return alert_details
        event_ids = []
        for o in observations:
            data = json.loads(o["data"])
            files = data.get("files")
            if files:
                for file in files:
                    event_ids.append(file["eventId"])
        if not event_ids:
            alert_details["fileevents"] = []
            return alert_details
        if self._v2_events:
            alert_details["fileevents_version"] = 2
            query = FileEventQueryV2(EventIdV2.is_in(event_ids))
        else:
            alert_details["fileevents_version"] = 1
            query = FileEventQueryV1(EventId.is_in(event_ids))
        events = self._client.search_file_events(query)
        alert_details["fileevents"] = list(events)
        return alert_details

    def _format_summary(self, alert_details):
        summary = alert_details["riskSeveritySummary"]
        string_list = []
        for s in summary:
            string_list.append(f"{s['numEvents']} {s['severity']} events:")
            for indicator in s["summarizedRiskIndicators"]:
                string_list.append(f"\t- {indicator['numEvents']} {indicator['name']}")
        alert_details["risksummary"] = "\n".join(string_list)


def fetch_incidents(
    client,
    last_run,
    first_fetch_time,
    event_severity_filter,
    fetch_limit,
    include_files,
    v2_events,
    integration_context=None,
):
    fetcher = Code42SecurityIncidentFetcher(
        client,
        last_run,
        first_fetch_time,
        event_severity_filter,
        fetch_limit,
        include_files,
        v2_events,
        integration_context,
    )
    return fetcher.fetch()


"""Main and test"""


def test_module(client):
    try:
        # Will fail if unauthorized
        client.sdk.usercontext.get_current_tenant_id()
        return "ok"
    except Exception:
        return (
            "Invalid credentials or host address. Check that the username and password are correct, that the host "
            "is available and reachable, and that you have supplied the full scheme, domain, and port "
            "(e.g. https://myhost.code42.com:4285)."
        )


def handle_fetch_command(client):
    integration_context = demisto.getIntegrationContext()
    # Set and define the fetch incidents command to run after activated via integration settings.
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run=demisto.getLastRun(),
        first_fetch_time=demisto.params().get("fetch_time"),
        event_severity_filter=demisto.params().get("alert_severity"),
        fetch_limit=int(demisto.params().get("fetch_limit")),
        include_files=demisto.params().get("include_files"),
        v2_events=demisto.params().get("v2_events"),
        integration_context=integration_context,
    )
    demisto.setLastRun(next_run)
    demisto.incidents(incidents)
    # Store remaining incidents in integration context
    integration_context["remaining_incidents"] = remaining_incidents
    demisto.setIntegrationContext(integration_context)


def run_command(command):
    try:
        results = command()
        if not isinstance(results, (tuple, list)):
            results = [results]
        for result in results:
            return_results(result)
    except Exception as e:
        msg = "Failed to execute command {0} command. Error: {1}".format(demisto.command(), e)
        return_error(msg)


def create_client():
    api_client_id = demisto.params().get("credentials").get("identifier")
    if not api_client_id.startswith("key-") or "@" in api_client_id:
        raise Exception(f"Got invalid API Client ID: {api_client_id}")
    password = demisto.params().get("credentials").get("password")
    base_url = demisto.params().get("console_url")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)
    return Code42Client(
        base_url=base_url,
        sdk=None,
        auth=(api_client_id, password),
        verify=verify_certificate,
        proxy=proxy,
    )


def main():
    client = create_client()
    command_key = demisto.command()
    # switch case
    commands = {
        "code42-alert-get": alert_get_command,
        "code42-alert-resolve": alert_resolve_command,
        "code42-securitydata-search": securitydata_search_command,
        "code42-file-events-search": file_events_search_command,
        "code42-file-events-table": file_events_to_table_command,
        "code42-departingemployee-add": departingemployee_add_command,
        "code42-departingemployee-remove": departingemployee_remove_command,
        "code42-departingemployee-get-all": departingemployee_get_all_command,
        "code42-departingemployee-get": departingemployee_get_command,
        "code42-highriskemployee-add": highriskemployee_add_command,
        "code42-highriskemployee-remove": highriskemployee_remove_command,
        "code42-highriskemployee-get-all": highriskemployee_get_all_command,
        "code42-highriskemployee-add-risk-tags": highriskemployee_add_risk_tags_command,
        "code42-highriskemployee-remove-risk-tags": highriskemployee_remove_risk_tags_command,
        "code42-highriskemployee-get": highriskemployee_get_command,
        "code42-user-create": user_create_command,
        "code42-user-block": user_block_command,
        "code42-user-unblock": user_unblock_command,
        "code42-user-deactivate": user_deactivate_command,
        "code42-user-reactivate": user_reactivate_command,
        "code42-user-get-risk-profile": get_user_risk_profile,
        "code42-user-update-risk-profile": update_user_risk_profile,
        "code42-legalhold-add-user": legal_hold_add_user_command,
        "code42-legalhold-remove-user": legal_hold_remove_user_command,
        "code42-download-file": download_file_command,
        "code42-watchlists-list": list_watchlists_command,
        "code42-watchlists-list-included-users": list_watchlists_included_users,
        "code42-watchlists-add-user": add_user_to_watchlist_command,
        "code42-watchlists-remove-user": remove_user_from_watchlist_command,
    }
    LOG("Command being called is {0}.".format(command_key))
    if command_key == "test-module":
        result = test_module(client)
        demisto.results(result)
    elif command_key == "fetch-incidents":
        handle_fetch_command(client)
    elif command_key in commands:
        run_command(lambda: commands[command_key](client, demisto.args()))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

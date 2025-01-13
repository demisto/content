import demistomock as demisto
from CommonServerPython import *

""" IMPORTS """
import json
import os
import requests
import urllib3
import incydr
import py42.sdk
import py42.settings
from datetime import datetime, UTC
from uuid import UUID
from py42.sdk.queries.fileevents.v2.file_event_query import FileEventQuery as FileEventQueryV2

from py42.sdk.queries.fileevents.v2 import filters as v2_filters
from py42.sdk.queries.fileevents.util import FileEventFilterStringField
from py42.sdk.queries.alerts.alert_query import AlertQuery
from py42.exceptions import Py42HTTPError
from requests.exceptions import HTTPError


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
    "beginTimeIso": "Occurred",
    "rule_names": "Description",
    "sessionId": "ID",
    "exfiltrationSummary": "Name",
    "state": "State",
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

SECURITY_ALERT_HEADERS = ["Occurred", "Username", "Name", "Description", "State", "ID"]

SESSION_SEVERITY_LIST = [
    "NO RISK",
    "LOW",
    "MODERATE",
    "HIGH",
    "CRITICAL"
]


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


def _get_severity_filter_value(severity_arg):
    """Converts string to the appropriate severity enum number, or list of strings to a list of the appropriate numbers."""
    if severity_arg:
        return (
            SESSION_SEVERITY_LIST.index(severity_arg.upper())
            if isinstance(severity_arg, str)
            else [SESSION_SEVERITY_LIST.index(x.upper()) for x in severity_arg]
        )
    return None


class Code42Client(BaseClient):
    """
    Client will implement the service API, should not contain Cortex XSOAR logic.
    Should do requests and return data
    """

    def __init__(self, sdk, base_url, auth, api_url, verify=True, proxy=False, incydr_sdk=None):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self._base_url = base_url
        self._auth = auth
        self._sdk = sdk
        self._incydr_sdk = incydr_sdk
        self._api_url = api_url

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

    @property
    def incydr_sdk(self):
        if self._incydr_sdk is None:
            self._incydr_sdk = incydr.Client(
                url=f"https://{self._api_url}",
                api_client_id=self._auth[0],
                api_client_secret=self._auth[1]
            )
            self._incydr_sdk.settings.user_agent_prefix = "Cortex XSOAR"
        return self._incydr_sdk

    # Alert methods

    def fetch_alerts(self, start_time, event_severity_filter):
        all_sessions = self.incydr_sdk.sessions.v1.iter_all(
            start_time=start_time,
            severities=_get_severity_filter_value(event_severity_filter)
        )
        res = []
        for page in all_sessions:
            res.append(self._process_alert(page))
        return res

    def get_alert_details(self, alert_id):
        try:
            res = self.incydr_sdk.sessions.v1.get_session_details(alert_id)
            return self._process_alert(res)
        except HTTPError as e:
            if e.response.status_code == 404:
                raise Code42AlertNotFoundError(alert_id)

    def get_alert_file_events(self, alert_id):
        return self.incydr_sdk.sessions.v1.get_session_events(alert_id)

    def update_session_state(self, id, state):
        self.incydr_sdk.sessions.v1.update_state_by_id(id, state)
        return id

    def get_user(self, username):
        py42_res = self.sdk.users.get_by_username(username)
        res = py42_res.data.get("users")
        if not res:
            raise Code42UserNotFoundError(username)
        return res[0]

    def get_actor(self, username):
        return self.incydr_sdk.actors.v1.get_actor_by_name(username, prefer_parent=True)

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
            raise Code42UnsupportedHashError

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
        return None

    def _process_alert(self, alert):
        # some important alert information is not returned directly by the API and must be inferred or queried.
        # This helper method does this for incoming sessions.
        alert.riskSeverity = SESSION_SEVERITY_LIST[max(alert.scores, key=lambda x: x.severity).severity]
        alert.state = max(alert.states, key=lambda x: x.source_timestamp).state
        alert.actor = self.incydr_sdk.actors.v1.get_actor_by_id(alert.actor_id).name
        rule_name_list = []
        # It is possible for a session to trigger an alert rule that no longer exists.
        # We need to handle the 404 case.
        for rule in alert.triggered_alerts:
            try:
                rule_name_list.append(self.incydr_sdk.alert_rules.v2.get_rule(rule.rule_id).name)
            except HTTPError:
                pass
        alert.rule_names = ", ".join(rule_name_list)
        alert.beginTimeIso = datetime.fromtimestamp(alert.begin_time / 1000).replace(tzinfo=UTC).isoformat()
        alert.alertUrl = f"{self._base_url}/app/#/alerts/review-alerts/{alert.session_id}"
        return alert


class Code42AlertNotFoundError(Exception):
    def __init__(self, alert_id):
        super().__init__(
            f"No alert found with ID {alert_id}."
        )


class Code42UserNotFoundError(Exception):
    def __init__(self, username):
        super().__init__(
            f"No user found with username {username}."
        )


class Code42OrgNotFoundError(Exception):
    def __init__(self, org_name):
        super().__init__(
            f"No organization found with name {org_name}."
        )


class Code42InvalidWatchlistTypeError(Exception):
    def __init__(self, watchlist):
        msg = "Invalid Watchlist type: {}, run !code42-watchlists-list to get a list of available Watchlists.".format(
            watchlist
        )
        super().__init__(msg)


class Code42UnsupportedHashError(Exception):
    def __init__(self):
        super().__init__(
            "Unsupported hash. Must be SHA256 or MD5."
        )


class Code42MissingSearchArgumentsError(Exception):
    def __init__(self):
        super().__init__(
            "No query args provided for searching Code42 security events."
        )


class Code42LegalHoldMatterNotFoundError(Exception):
    def __init__(self, matter_name):
        super().__init__(
            f"No legal hold matter found with name {matter_name}."
        )


class Code42InvalidLegalHoldMembershipError(Exception):
    def __init__(self, username, matter_name):
        super().__init__(
            "User '{}' is not an active member of legal hold matter '{}'".format(
                username, matter_name
            )
        )


class Code42SearchFilters:
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


class AlertQueryFilters(Code42SearchFilters):
    """Class for simplifying building up an alert search query"""

    def to_all_query(self):
        query = AlertQuery.all(*self._filters)
        query.page_size = 500
        query.sort_direction = "asc"
        return query


@logger
def build_v2_query_payload(args):
    """Build a query payload combining passed args"""
    _hash = args.get("hash")
    hostname = args.get("hostname")
    username = args.get("username")
    min_risk_score = arg_to_number(args.get("min_risk_score"), arg_name="min_risk_score") or 1

    if not _hash and not hostname and not username:
        raise Code42MissingSearchArgumentsError

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

    code42_context = map_to_code42_alert_context(alert.dict())
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
        raw_response=alert.dict(),
    )


@logger
def alert_update_state_command(client, args):
    code42_securityalert_context = []
    alert_id = client.update_session_state(args.get("id"), args.get("state"))
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
    code42_context = map_to_code42_alert_context(alert_details.dict())
    code42_securityalert_context.append(code42_context)
    readable_outputs = tableToMarkdown(
        "Code42 Security Alert Updated",
        code42_securityalert_context,
        headers=SECURITY_ALERT_HEADERS,
    )
    return CommandResults(
        outputs_prefix="Code42.SecurityAlert",
        outputs_key_field="ID",
        outputs=code42_securityalert_context,
        readable_output=readable_outputs,
        raw_response=alert_details.dict(),
    )


@logger
def alert_resolve_command(client, args):
    args.update({"state": "CLOSED_TP"})
    results = alert_update_state_command(client, args)
    return results


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

    actor = client.get_actor(username)
    actor_id = actor.actor_id

    resp = client.incydr_sdk.actors.v1.update_actor(
        actor_id,
        start_date=start_date,
        end_date=end_date,
        notes=notes
    )
    if (
        (resp.start_date == start_date if start_date else True)
        and (resp.end_date == end_date if end_date else True)
        and (resp.notes == notes if notes else True)
    ):
        success = True
    else:
        success = False
    outputs = {
        "Username": resp.name,
        "Success": success,
        "EndDate": resp.end_date,
        "StartDate": resp.start_date,
        "Notes": resp.notes,
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
    actor = client.get_actor(username)
    outputs = {
        "Username": actor.name,
        "EndDate": actor.end_date,
        "StartDate": actor.start_date,
        "Notes": actor.notes,
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
    incident["CustomFields"].get("code42fileeventsversion", "1")
    path = args.get("include")
    events = []
    if path in ("incident", "all"):
        events.extend(incident["CustomFields"]["code42fileevents"])
    if path in ("searches", "all"):
        context = demisto.context()
        if "Code42" in context and "FileEvents" in context["Code42"]:
            events.extend(context["Code42"]["FileEvents"])

    events = deduplicate_v2_file_events(events)

    table = format_file_events(events)
    return CommandResults(readable_output=table)


"""Fetching"""


class Code42SecurityIncidentFetcher:
    def __init__(
        self,
        client,
        last_run,
        first_fetch_time,
        event_severity_filter,
        fetch_limit,
        include_files,
        integration_context=None,
    ):
        self._client = client
        self._last_run = last_run
        self._first_fetch_time = first_fetch_time
        self._event_severity_filter = event_severity_filter
        self._fetch_limit = fetch_limit
        self._include_files = include_files
        self._integration_context = integration_context

    @logger
    def fetch(self):
        remaining_incidents_from_last_run = self._fetch_remaining_incidents_from_last_run()
        if remaining_incidents_from_last_run:
            return remaining_incidents_from_last_run
        start_query_time = self._get_start_query_time()
        alerts = self._fetch_alerts(start_query_time)
        incidents = [self._create_incident_from_alert(a) for a in alerts]
        save_time = datetime.now(UTC).timestamp()
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
            return None
        return None

    def _get_start_query_time(self):
        start_query_time = self._try_get_last_fetch_time()

        # Handle first time fetch, fetch incidents retroactively
        if not start_query_time:
            start_query_time, _ = parse_date_range(
                self._first_fetch_time, to_timestamp=True, utc=True
            )
            start_query_time /= 1000

        return start_query_time * 1000

    def _try_get_last_fetch_time(self):
        return self._last_run.get("last_fetch")

    def _fetch_alerts(self, start_query_time):
        return self._client.fetch_alerts(start_query_time, self._event_severity_filter)

    def _create_incident_from_alert(self, alert):
        details = alert.dict()
        if self._include_files:
            details = self._relate_files_to_alert(details)
        incident = {
            "name": "Code42 - {}".format(details.get("exfiltrationSummary")),
            "occurred": alert.beginTimeIso
        }
        incident["rawJSON"] = json.dumps(details)
        return incident

    def _relate_files_to_alert(self, alert_details):
        observations = self._client.get_alert_file_events(alert_details["sessionId"])
        alert_details["exfiltrationSummary"] = "{} {}".format(
            observations.total_count,
            alert_details["exfiltrationSummary"]
        )
        # it is necessary to dump to/load from json here because otherwise we will get "datetime" string representations
        # instead of isoformat timestamps.
        alert_details["fileevents"] = [json.loads(e.json()) for e in observations.file_events]
        return alert_details


def fetch_incidents(
    client,
    last_run,
    first_fetch_time,
    event_severity_filter,
    fetch_limit,
    include_files,
    integration_context=None,
):
    fetcher = Code42SecurityIncidentFetcher(
        client,
        last_run,
        first_fetch_time,
        event_severity_filter,
        fetch_limit,
        include_files,
        integration_context,
    )
    return fetcher.fetch()


"""Main and test"""


def test_module(client):
    try:
        # Will fail if unauthorized
        client.sdk.usercontext.get_current_tenant_id()
        client.incydr_sdk.actors.v1.get_page(page_size=1)
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
        if not (isinstance(results, list | tuple)):
            results = [results]
        for result in results:
            return_results(result)
    except Exception as e:
        msg = f"Failed to execute command {demisto.command()} command. Error: {e}"
        return_error(msg)


def create_client():
    api_client_id = demisto.params().get("credentials").get("identifier")
    if not api_client_id.startswith("key-") or "@" in api_client_id:
        raise Exception(f"Got invalid API Client ID: {api_client_id}")
    password = demisto.params().get("credentials").get("password")
    base_url = demisto.params().get("console_url")
    api_url = demisto.params().get("api_url")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)
    return Code42Client(
        base_url=base_url,
        sdk=None,
        api_url=api_url,
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
        "code42-alert-update": alert_update_state_command,
        "code42-file-events-search": file_events_search_command,
        "code42-file-events-table": file_events_to_table_command,
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
    LOG(f"Command being called is {command_key}.")
    if command_key == "test-module":
        result = test_module(client)
        demisto.results(result)
    elif command_key == "fetch-incidents":
        handle_fetch_command(client)
    elif command_key in commands:
        run_command(lambda: commands[command_key](client, demisto.args()))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

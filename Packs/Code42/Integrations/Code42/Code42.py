import demistomock as demisto
from CommonServerPython import *

""" IMPORTS """
import json
import os
import urllib3
import incydr
from incydr import EventQuery
from _incydr_sdk.file_events.models.event import FileEventV2
from _incydr_sdk.exceptions import WatchlistNotFoundError
from datetime import datetime
from uuid import UUID
from requests.exceptions import HTTPError


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

SESSION_SEVERITY_LIST = ["NO RISK", "LOW", "MODERATE", "HIGH", "CRITICAL"]


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


def format_file_events(events: list):
    """
    Formats Code42 file events into a markdown table.
    """
    formatted_events = []
    for event in events:
        formatted = {}
        if hasattr(event, "json") and callable(event.json):
            event = json.loads(event.json())
        for k, v in event.items():
            column = _columnize_file_event(v)
            if column:
                formatted[k] = column
        formatted_events.append(formatted)
    return tableToMarkdown("", formatted_events, removeNull=True, sort_headers=False)


def deduplicate_v2_file_events(events: List):
    """Takes a list of v2 file events and returns a new list removing any duplicate events."""
    unique = []
    id_set = set()
    for event in events:
        if isinstance(event, FileEventV2):
            _id = event.event.id
        else:
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

    def __init__(self, auth, api_url, verify=True, proxy=False, incydr_sdk=None):
        super().__init__(api_url, verify=verify, proxy=proxy)
        self._auth = auth
        self._incydr_sdk = incydr_sdk
        self._api_url = api_url

        if not proxy:
            for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                if os.environ.get(var):
                    del os.environ[var]

    @property
    def incydr_sdk(self):
        if self._incydr_sdk is None:
            version = get_pack_version()
            self._incydr_sdk = incydr.Client(
                url=f"https://{self._api_url}",
                api_client_id=self._auth[0],
                api_client_secret=self._auth[1],
                user_agent_prefix=f"Code42 - Cortex XSOAR/{version} (Code42; code42.com)",
            )
        return self._incydr_sdk

    # Alert methods

    def fetch_alerts(self, start_query_time, last_fetch_timestamp, event_severity_filter, fetched_incidents):
        all_sessions = self.incydr_sdk.sessions.v1.iter_all(
            start_time=start_query_time,
            severities=_get_severity_filter_value(event_severity_filter),
            states=["OPEN", "OPEN_NEW_DATA"],
        )
        res = []
        # handle last fetch timestamp being something other than int
        try:
            last_fetch_timestamp = int(last_fetch_timestamp)
        except (ValueError, TypeError):
            last_fetch_timestamp = 0
        next_last_fetch_timestamp = last_fetch_timestamp
        for session in all_sessions:
            if session.first_observed >= last_fetch_timestamp and session.session_id not in fetched_incidents:
                res.append(self._process_alert(session))
        for session in res:
            if session.first_observed > next_last_fetch_timestamp:
                next_last_fetch_timestamp = session.first_observed
                fetched_incidents = []
            if session.first_observed == next_last_fetch_timestamp:
                fetched_incidents.append(session.session_id)

        return res, next_last_fetch_timestamp, fetched_incidents

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
        try:
            return self.incydr_sdk.users.v1.get_user(username)
        except ValueError:
            raise Code42UserNotFoundError(username)

    def get_actor(self, username):
        return self.incydr_sdk.actors.v1.get_actor_by_name(username, prefer_parent=True)

    def deactivate_user(self, username):
        user_id = self._get_user_id(username)
        self.incydr_sdk.users.v1.deactivate(user_id)
        return user_id

    def reactivate_user(self, username):
        user_id = self._get_user_id(username)
        self.incydr_sdk.users.v1.activate(user_id)
        return user_id

    def get_legal_hold_matter(self, matter_name):
        matterspage = self.incydr_sdk.legal_hold.v1.get_matters_page(name=matter_name)
        if matterspage.matters:
            return matterspage.matters[0]
        raise Code42LegalHoldMatterNotFoundError(matter_name)

    def add_user_to_legal_hold_matter(self, username, matter_name):
        user_uid = self._get_user_id(username)
        matter_id = self._get_legal_hold_matter_id(matter_name)
        response = self.incydr_sdk.legal_hold.v1.add_custodian(user_id=user_uid, matter_id=matter_id)
        return response

    def remove_user_from_legal_hold_matter(self, username, matter_name):
        user_uid = self._get_user_id(username)
        matter_id = self._get_legal_hold_matter_id(matter_name)
        try:
            self.incydr_sdk.legal_hold.v1.remove_custodian(user_id=user_uid, matter_id=matter_id)
            return user_uid, matter_id
        except HTTPError:
            raise Code42InvalidLegalHoldMembershipError(username, matter_name)

    def get_org(self, org_name):
        orgs_list = self.incydr_sdk.orgs.v1.list()
        for org in orgs_list:
            if org.org_name == org_name:
                return org
        raise Code42OrgNotFoundError(org_name)

    def search_file_events(self, query):
        result = self.incydr_sdk.file_events.v2.search(query)
        file_events = result.file_events
        while result.next_pg_token:
            result = self.incydr_sdk.file_events.v2.search(query)
            file_events.extend(result.file_events)
        return file_events

    def download_file(self, hash_arg):
        if not (_hash_is_md5(hash_arg) or _hash_is_sha256(hash_arg)):
            raise Code42UnsupportedHashError
        elif _hash_is_md5(hash_arg):
            query = EventQuery().equals(term="file.hash.md5", values=hash_arg)
            hash_arg = self.incydr_sdk.file_events.v2.search(query).file_events[0].file.hash.sha256
        return self.incydr_sdk.files.v1.stream_file_by_sha256(hash_arg)

    def download_file_by_xfc_id(self, xfc_id):
        try:
            return self.incydr_sdk.files.v1.stream_file_by_xfc_content_id(xfc_id)
        except Exception as e:
            raise Code42FileDownloadError(e)

    def _get_user_id(self, username):
        user_id = self.get_user(username).user_id
        if user_id:
            return user_id
        raise Code42UserNotFoundError(username)

    def _get_org_id(self, org_name):
        org_uid = self.get_org(org_name).get("orgUid")
        if org_uid:
            return org_uid
        raise Code42OrgNotFoundError(org_name)

    def _get_legal_hold_matter_id(self, matter_name):
        matter_id = self.get_legal_hold_matter(matter_name).matter_id
        return matter_id

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
        alert.beginTimeIso = datetime.fromtimestamp(alert.begin_time / 1000).replace(tzinfo=timezone.utc).isoformat()
        console_url = self._base_url.replace("api", "console", 1)
        alert.alertUrl = f"{console_url}/app/#/alerts/review-alerts/{alert.session_id}"
        return alert


class Code42AlertNotFoundError(Exception):
    def __init__(self, alert_id):
        super().__init__(f"No alert found with ID {alert_id}.")


class Code42UserNotFoundError(Exception):
    def __init__(self, username):
        super().__init__(f"No user found with username {username}.")


class Code42OrgNotFoundError(Exception):
    def __init__(self, org_name):
        super().__init__(f"No organization found with name {org_name}.")


class Code42InvalidWatchlistTypeError(Exception):
    def __init__(self, watchlist):
        msg = f"Invalid Watchlist type: {watchlist}, run !code42-watchlists-list to get a list of available Watchlists."
        super().__init__(msg)


class Code42UnsupportedHashError(Exception):
    def __init__(self):
        super().__init__("Unsupported hash. Must be SHA256 or MD5.")


class Code42MissingSearchArgumentsError(Exception):
    def __init__(self):
        super().__init__("No query args provided for searching Code42 security events.")


class Code42LegalHoldMatterNotFoundError(Exception):
    def __init__(self, matter_name):
        super().__init__(f"No legal hold matter found with name {matter_name}.")


class Code42InvalidLegalHoldMembershipError(Exception):
    def __init__(self, username, matter_name):
        super().__init__(f"User '{username}' is not an active member of legal hold matter '{matter_name}'")


class Code42FileDownloadError(Exception):
    def __init__(self, exception):
        super().__init__(f"Error downloading file: {exception}")


@logger
def build_v2_query_payload(args):
    """Build a query payload combining passed args"""
    _hash = args.get("hash")
    hostname = args.get("hostname")
    username = args.get("username")
    min_risk_score = arg_to_number(args.get("min_risk_score"), arg_name="min_risk_score") or 1
    modified_risk_score = min_risk_score - 1

    if not _hash and not hostname and not username:
        raise Code42MissingSearchArgumentsError

    query = EventQuery().greater_than(term="risk.score", value=modified_risk_score)
    if _hash:
        if _hash_is_md5(_hash):
            query = query.equals(term="file.hash.md5", values=_hash)
        elif _hash_is_sha256(_hash):
            query = query.equals(term="file.hash.sha256", values=_hash)
    if hostname:
        query = query.equals(term="source.name", values=hostname)
    if username:
        query = query.equals(term="user.email", values=username)

    return query


def _hash_is_sha256(hash_arg):
    return hash_arg and len(hash_arg) == 64


def _hash_is_md5(hash_arg):
    return hash_arg and len(hash_arg) == 32


@logger
def map_to_code42_alert_context(obj):
    return _map_obj_to_context(obj, CODE42_ALERT_CONTEXT_FIELD_MAPPER)


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
        query = EventQuery.parse_obj(json.loads(json_query))
    else:
        query = build_v2_query_payload(args)
    try:
        query.page_size = page_size if page_size else 100
        try:
            file_events = client.search_file_events(query)
        except Exception as err:
            return_error(f"Error searching for file events: {err}")
        markdown_table = format_file_events(file_events)
        if add_to_context:
            file_events = [json.loads(x.json()) for x in file_events]
            context = demisto.context()
            if "Code42" in context and "FileEvents" in context["Code42"]:
                context_events = context["Code42"]["FileEvents"]
                file_events = deduplicate_v2_file_events(file_events + context_events)
            return CommandResults(outputs_prefix="Code42.FileEvents", outputs=file_events, readable_output=markdown_table)
        else:
            return CommandResults(readable_output=markdown_table)
    except HTTPError as err:
        return_error(f"Error executing json query. Make sure your query is a V2 file event query. Error={err}")


@logger
def user_create_command(client, args):
    outputs: dict = {}
    readable_outputs = tableToMarkdown("Deprecated command - use the Incydr console to create users.", outputs)
    return CommandResults(
        outputs_prefix="Code42.User",
        outputs_key_field="UserID",
        outputs=outputs,
        readable_output=readable_outputs,
    )


@logger
def user_block_command(client, args):
    outputs: dict = {}
    readable_outputs = tableToMarkdown("Deprecated command - use the Incydr console to block users.", outputs)
    return CommandResults(
        outputs_prefix="Code42.User",
        outputs_key_field="UserID",
        outputs=outputs,
        readable_output=readable_outputs,
    )


@logger
def user_unblock_command(client, args):
    outputs: dict = {}
    readable_outputs = tableToMarkdown("Deprecated command - use the Incydr console to unblock users.", outputs)
    return CommandResults(
        outputs_prefix="Code42.User",
        outputs_key_field="UserID",
        outputs=outputs,
        readable_output=readable_outputs,
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
    outputs = {
        "MatterID": response.matter.matter_id if response.matter.matter_id else None,
        "MatterName": response.matter.name if response.matter.name else None,
        "UserID": response.custodian.user_id if response.custodian.user_id else None,
        "Username": response.custodian.username if response.custodian.username else None,
    }
    readable_outputs = tableToMarkdown("Code42 User Added to Legal Hold Matter", outputs)
    return CommandResults(
        outputs_prefix="Code42.LegalHold",
        outputs_key_field="MatterID",
        outputs=outputs,
        readable_output=readable_outputs,
        raw_response=json.loads(response.json()),
    )


@logger
def legal_hold_remove_user_command(client, args):
    username = args.get("username")
    matter_name = args.get("mattername")
    user_uid, matter_id = client.remove_user_from_legal_hold_matter(username, matter_name)
    outputs = {"MatterID": matter_id, "MatterName": matter_name, "UserID": user_uid, "Username": username}
    readable_outputs = tableToMarkdown("Code42 User Removed from Legal Hold Matter", outputs)
    return CommandResults(
        outputs_prefix="Code42.LegalHold",
        outputs_key_field="MatterID",
        outputs=outputs,
        readable_output=readable_outputs,
        raw_response=user_uid,
    )


@logger
def download_file_command(client, args):
    file_hash = args.get("hash")
    filename = args.get("filename") or file_hash
    response = client.download_file(file_hash)
    file_chunks = [c for c in response.iter_content(chunk_size=128) if c]
    return fileResult(filename, data=b"".join(file_chunks))


@logger
def download_file_by_xfc_id_command(client, args):
    file_xfc_event_id = args.get("xfc_id")
    filename = args.get("filename") or file_xfc_event_id
    response = client.download_file_by_xfc_id(file_xfc_event_id)
    file_chunks = [c for c in response.iter_content(chunk_size=128) if c]
    return fileResult(filename, data=b"".join(file_chunks))


@logger
def list_watchlists_command(client, args):
    watchlists_context = []
    for watchlist in client.incydr_sdk.watchlists.v2.iter_all():
        watchlists_context.append(
            {
                "WatchlistID": watchlist.watchlist_id,
                "WatchlistType": watchlist.list_type,
                "IncludedUsersCount": watchlist.stats.included_users_count if watchlist.stats.included_users_count else 0,
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
        try:
            watchlist_id = client.incydr_sdk.watchlists.v2.get_id_by_name(watchlist)
        except WatchlistNotFoundError:
            raise Code42InvalidWatchlistTypeError(watchlist)
    included_users_context = []
    for user in client.incydr_sdk.watchlists.v2.iter_all_members(watchlist_id):
        included_users_context.append(
            {"Username": user.actor_name, "AddedTime": user.added_time.isoformat(), "WatchlistID": watchlist_id}
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
    actor = client.get_actor(username)
    actor_id = actor.actor_id
    try:
        UUID(hex=watchlist)
        watchlist_id = watchlist
    except ValueError:
        try:
            watchlist_id = client.incydr_sdk.watchlists.v2.get_id_by_name(watchlist)
        except WatchlistNotFoundError:
            raise Code42InvalidWatchlistTypeError(watchlist)
    client.incydr_sdk.watchlists.v2.add_included_actors(watchlist_id=watchlist_id, actor_ids=actor_id)
    return CommandResults(
        outputs_prefix="Code42.UsersAddedToWatchlists",
        outputs_key_field="Watchlist",
        outputs={"Watchlist": watchlist, "Username": username, "Success": True},
    )


@logger
def update_user_risk_profile(client, args):
    username = args.get("username")
    start_date = args.get("start_date")
    end_date = args.get("end_date")
    notes = args.get("notes")

    actor = client.get_actor(username)
    actor_id = actor.actor_id

    resp = client.incydr_sdk.actors.v1.update_actor(actor_id, start_date=start_date, end_date=end_date, notes=notes)
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
    actor = client.get_actor(username)
    actor_id = actor.actor_id
    try:
        UUID(hex=watchlist)
        watchlist_id = watchlist
    except ValueError:
        try:
            watchlist_id = client.incydr_sdk.watchlists.v2.get_id_by_name(watchlist)
        except WatchlistNotFoundError:
            raise Code42InvalidWatchlistTypeError(watchlist)
    client.incydr_sdk.watchlists.v2.remove_included_actors(watchlist_id=watchlist_id, actor_ids=actor_id)
    return CommandResults(
        outputs_prefix="Code42.UsersRemovedFromWatchlists",
        outputs_key_field="Watchlist",
        outputs={"Watchlist": watchlist, "Username": username, "Success": True},
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
        fetched_incidents = (
            self._last_run.get("incidents_at_last_fetch_timestamp")
            if "incidents_at_last_fetch_timestamp" in self._last_run
            else []
        )
        alerts, save_time, fetched_incidents = self._client.fetch_alerts(
            start_query_time, self._try_get_last_fetch_time(), self._event_severity_filter, fetched_incidents
        )
        incidents = [self._create_incident_from_alert(a) for a in alerts]
        next_run = {"last_fetch": save_time, "incidents_at_last_fetch_timestamp": fetched_incidents}
        return next_run, incidents[: self._fetch_limit], incidents[self._fetch_limit :]

    def _fetch_remaining_incidents_from_last_run(self):
        if self._integration_context:
            remaining_incidents = self._integration_context.get("remaining_incidents")
            # return incidents if exists in context.
            if remaining_incidents:
                return (
                    self._last_run,
                    remaining_incidents[: self._fetch_limit],
                    remaining_incidents[self._fetch_limit :],
                )
            return None
        return None

    def _get_start_query_time(self):
        last_fetch_time = self._try_get_last_fetch_time()
        start_query_time, _ = parse_date_range(self._first_fetch_time, to_timestamp=True, utc=True)
        last_fetch_time = last_fetch_time * 1000 if last_fetch_time else start_query_time
        # if the last fetch was before the time we'd otherwise use, use last fetch to avoid missing anything
        if last_fetch_time < start_query_time:
            return last_fetch_time
        return start_query_time

    def _try_get_last_fetch_time(self):
        return self._last_run.get("last_fetch")

    def _filter_fetched_incident_dict(self, incidents, filter_datetime):
        return {key: value for key, value in incidents.items() if datetime.fromisoformat(value) > filter_datetime}

    def _create_incident_from_alert(self, alert):
        details = alert.dict()
        if self._include_files:
            details = self._relate_files_to_alert(details)
        incident = {"name": "Code42 - {}".format(details.get("exfiltrationSummary")), "occurred": alert.beginTimeIso}
        incident["rawJSON"] = json.dumps(details)
        return incident

    def _relate_files_to_alert(self, alert_details):
        observations = self._client.get_alert_file_events(alert_details["sessionId"])
        alert_details["exfiltrationSummary"] = "{} {}".format(observations.total_count, alert_details["exfiltrationSummary"])
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
    api_url = demisto.params().get("api_url")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)
    return Code42Client(
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
        "code42-download-file-by-xfc-id": download_file_by_xfc_id_command,
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

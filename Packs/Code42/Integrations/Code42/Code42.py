from typing import Optional, Dict, Any
import demistomock as demisto
from CommonServerPython import *

""" IMPORTS """
import json
import requests
import py42.sdk
import py42.settings
from datetime import datetime
from py42.sdk.queries.fileevents.file_event_query import FileEventQuery
from py42.sdk.queries.fileevents.filters import (
    MD5,
    SHA256,
    Actor,
    EventTimestamp,
    OSHostname,
    DeviceUsername,
    ExposureType,
    EventType,
)
from py42.sdk.queries.alerts.alert_query import AlertQuery
from py42.sdk.queries.alerts.filters import DateObserved, Severity, AlertState
import time

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

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
    "severity": "Severity",
}

FILE_CONTEXT_FIELD_MAPPER = {
    "fileName": "Name",
    "filePath": "Path",
    "fileSize": "Size",
    "md5Checksum": "MD5",
    "sha256Checksum": "SHA256",
    "osHostName": "Hostname",
}

CODE42_FILE_TYPE_MAPPER = {
    "SourceCode": "SOURCE_CODE",
    "Audio": "AUDIO",
    "Executable": "EXECUTABLE",
    "Document": "DOCUMENT",
    "Image": "IMAGE",
    "PDF": "PDF",
    "Presentation": "PRESENTATION",
    "Script": "SCRIPT",
    "Spreadsheet": "SPREADSHEET",
    "Video": "VIDEO",
    "VirtualDiskImage": "VIRTUAL_DISK_IMAGE",
    "Archive": "ARCHIVE",
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


class Code42Client(BaseClient):
    """
    Client will implement the service API, should not contain Cortex XSOAR logic.
    Should do requests and return data
    """

    def __init__(self, sdk, base_url, auth, verify=True, proxy=False):
        super().__init__(base_url, verify=verify, proxy=proxy)
        # Create the Code42 SDK instance
        self._sdk = sdk or py42.sdk.from_local_account(base_url, auth[0], auth[1])
        py42.settings.set_user_agent_suffix("Cortex XSOAR")

    def add_user_to_departing_employee(self, username, departure_epoch=None, note=None):
        try:
            user_id = self.get_user_id(username)
            self._sdk.detectionlists.departing_employee.add(
                user_id, departure_epoch=departure_epoch
            )
            not note or self._sdk.detectionlists.update_user_notes(note)
        except Exception:
            return None
        return user_id

    def fetch_alerts(self, start_time, event_severity_filter=None):
        alert_filter = []
        # Create alert filter
        if event_severity_filter:
            f = event_severity_filter
            severity_filter = (f.upper() if isinstance(f, str) else list(map(lambda x: x.upper(), f)))
            alert_filter.append(Severity.is_in(severity_filter))
        alert_filter.append(AlertState.eq(AlertState.OPEN))
        alert_filter.append(DateObserved.on_or_after(start_time))
        tenant_id = self._sdk.usercontext.get_current_tenant_id()
        alert_query = AlertQuery(tenant_id, *alert_filter)
        alert_query.sort_direction = "asc"
        try:
            res = self._sdk.alerts.search_alerts(alert_query)
        except Exception:
            return None
        return res["alerts"]

    def get_alert_details(self, alert_id):
        try:
            res = self._sdk.alerts.get_details(alert_id)
        except Exception:
            return None
        details = res["alerts"][0] if res["alerts"] else None
        return details

    def get_current_user(self):
        try:
            res = self._sdk.users.get_current_user()
        except Exception:
            return None
        return res

    def remove_user_from_departing_employee(self, username):
        try:
            user_id = self.get_user_id(username)
            self._sdk.detectionlists.departing_employee.resolve(user_id)
        except Exception:
            return None
        return user_id

    def resolve_alert(self, alert_id):
        try:
            self._sdk.alerts.resolve(alert_id)
        except Exception:
            return None
        return alert_id

    def get_user_id(self, username):
        try:
            res = self._sdk.users.get_by_username(username)
        except Exception:
            return None
        return res["users"][0]["userUid"] if res["users"] else None

    def search_json(self, payload):
        try:
            res = self._sdk.securitydata.search_file_events(payload)
        except Exception:
            return None
        return res["fileEvents"]


@logger
def build_query_payload(args):
    """
    Build a query payload combining passed args
    """
    search_args = []
    if args.get("hash"):
        if len(args["hash"]) == 32:
            search_args.append(MD5.eq(args["hash"]))
        elif len(args["hash"]) == 64:
            search_args.append(SHA256.eq(args["hash"]))
    if args.get("hostname"):
        search_args.append(OSHostname.eq(args["hostname"]))
    if args.get("username"):
        search_args.append(DeviceUsername.eq(args["username"]))
    if args.get("exposure"):
        # Because the CLI can't accept lists, convert the args to a list if the type is string.
        if isinstance(args["exposure"], str):
            args["exposure"] = args["exposure"].split(",")
        search_args.append(ExposureType.is_in(args["exposure"]))
    # Convert list of search criteria to *args
    query = FileEventQuery.all(*search_args)
    query.page_size = args.get("results")
    LOG("File Event Query: {}".format(query))
    return str(query)


@logger
def map_observation_to_security_query(observation, actor):
    file_categories: Dict[str, Any]
    observation_data = observation["data"]
    search_args = []
    exp_types = []
    exposure_types = observation_data["exposureTypes"]
    begin_time = observation_data["firstActivityAt"]
    end_time = observation_data["lastActivityAt"]
    if observation["type"] == "FedEndpointExfiltration":
        search_args.append(DeviceUsername.eq(actor))
    else:
        search_args.append(Actor.eq(actor))
    search_args.append(
        EventTimestamp.on_or_after(
            int(
                time.mktime(
                    time.strptime(begin_time.replace("0000000", "000"), "%Y-%m-%dT%H:%M:%S.000Z")
                )
            )
        )
    )
    search_args.append(
        EventTimestamp.on_or_before(
            int(
                time.mktime(
                    time.strptime(end_time.replace("0000000", "000"), "%Y-%m-%dT%H:%M:%S.000Z")
                )
            )
        )
    )
    # Determine exposure types based on alert type
    if observation["type"] == "FedCloudSharePermissions":
        if "PublicSearchableShare" in exposure_types:
            exp_types.append(ExposureType.IS_PUBLIC)
        if "PublicLinkShare" in exposure_types:
            exp_types.append(ExposureType.SHARED_VIA_LINK)
    elif observation["type"] == "FedEndpointExfiltration":
        exp_types = exposure_types
        search_args.append(EventType.is_in(["CREATED", "MODIFIED", "READ_BY_APP"]))
    search_args.append(ExposureType.is_in(exp_types))
    # Determine if file categorization is significant
    file_categories = {"filterClause": "OR"}
    filters = []
    for filetype in observation_data["fileCategories"]:
        if filetype["isSignificant"]:
            file_category = {
                "operator": "IS",
                "term": "fileCategory",
                "value": CODE42_FILE_TYPE_MAPPER.get(filetype["category"], "UNCATEGORIZED"),
            }
            filters.append(file_category)
    if len(filters):
        file_categories["filters"] = filters
        search_args.append(json.dumps(file_categories))
    # Convert list of search criteria to *args
    query = FileEventQuery.all(*search_args)
    LOG("Alert Observation Query: {}".format(query))
    return str(query)


@logger
def map_to_code42_event_context(obj):
    code42_context = _map_obj_to_context(obj, CODE42_EVENT_CONTEXT_FIELD_MAPPER)
    # FileSharedWith is a special case and needs to be converted to a list
    if code42_context.get("FileSharedWith"):
        shared_list = [u["cloudUsername"] for u in code42_context["FileSharedWith"]]
        code42_context["FileSharedWith"] = str(shared_list)
    return code42_context


@logger
def map_to_code42_alert_context(obj):
    return _map_obj_to_context(obj, CODE42_ALERT_CONTEXT_FIELD_MAPPER)


@logger
def map_to_file_context(obj):
    return _map_obj_to_context(obj, FILE_CONTEXT_FIELD_MAPPER)


def _map_obj_to_context(obj, context_mapper):
    return {v: obj.get(k) for k, v in context_mapper.items() if obj.get(k)}


@logger
def alert_get_command(client, args):
    code42_securityalert_context = []
    alert = client.get_alert_details(args["id"])
    if alert:
        code42_context = map_to_code42_alert_context(alert)
        code42_securityalert_context.append(code42_context)
        readable_outputs = tableToMarkdown(
            f"Code42 Security Alert Results",
            code42_securityalert_context,
            headers=SECURITY_ALERT_HEADERS,
        )
        return readable_outputs, {"Code42.SecurityAlert": code42_securityalert_context}, alert
    else:
        return "No results found", {}, {}


@logger
def alert_resolve_command(client, args):
    code42_security_alert_context = []
    alert_id = client.resolve_alert(args["id"])

    if not alert_id:
        return "No results found", {}, {}

    # Retrieve new alert details
    alert_details = client.get_alert_details(alert_id)
    if not alert_details:
        return "Error retrieving updated alert", {}, {}

    code42_context = map_to_code42_alert_context(alert_details)
    code42_security_alert_context.append(code42_context)
    readable_outputs = tableToMarkdown(
        f"Code42 Security Alert Resolved",
        code42_security_alert_context,
        headers=SECURITY_ALERT_HEADERS,
    )
    return (
        readable_outputs,
        {"Code42.SecurityAlert": code42_security_alert_context},
        alert_details,
    )


@logger
def departingemployee_add_command(client, args):
    departure_epoch: Optional[int]
    # Convert date to epoch
    departure_epoch = None
    if args.get("departuredate"):
        try:
            departure_epoch = int(time.mktime(time.strptime(args["departuredate"], "%Y-%m-%d")))
        except Exception:
            return_error(
                message="Could not add user to Departing Employee Lens: "
                "unable to parse departure date. Is it in yyyy-MM-dd format?"
            )
    user_id = client.add_user_to_departing_employee(
        args["username"], departure_epoch, args.get("note")
    )
    if not user_id:
        return_error(message="Could not add user to Departing Employee List")

    de_context = {
        "UserID": user_id,
        "Username": args["username"],
        "DepartureDate": args.get("departuredate"),
        "Note": args.get("note"),
    }
    readable_outputs = tableToMarkdown(f"Code42 Departing Employee Lens User Added", de_context)
    return readable_outputs, {"Code42.DepartingEmployee": de_context}, user_id


@logger
def departingemployee_remove_command(client, args):
    case = client.remove_user_from_departing_employee(args["username"])
    if case:
        de_context = {"CaseID": case, "Username": args["username"]}
        readable_outputs = tableToMarkdown(
            f"Code42 Departing Employee Lens User Removed", de_context
        )
        return readable_outputs, {"Code42.DepartingEmployee": de_context}, case
    else:
        return_error(message="Could not remove user from Departing Employee Lens")


def _create_incident_from_alert_details(details):
    return {"name": "Code42 - {}".format(details["name"]), "occurred": details["createdAt"]}


def _stringify_lists_if_needed(event):
    # We need to convert certain fields to a stringified list or React.JS will throw an error
    if event.get("sharedWith"):
        shared_list = [u["cloudUsername"] for u in event["sharedWith"]]
        event["sharedWith"] = str(shared_list)
    if event.get("privateIpAddresses"):
        event["privateIpAddresses"] = str(event["privateIpAddresses"])


def _process_event_from_observation(event):
    _stringify_lists_if_needed(event)
    return event


class Code42SecurityIncidentFetcher(object):
    def __init__(self,
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
        self._include_files = include_files,
        self._integration_context = integration_context
    
    def fetch(self):
        incidents = []
        
        remaining_incidents_from_last_run = self._fetch_remaining_incidents_from_last_run()
        if remaining_incidents_from_last_run:
            return remaining_incidents_from_last_run
        
        start_query_time = self._get_start_query_time()
        alerts = self._fetch_alerts(start_query_time)
        
        for alert in alerts:
            details = self._client.get_alert_details(alert["id"])
            incident = _create_incident_from_alert_details(details)
            self._relate_files_to_alert(details)
            incident["rawJSON"] = json.dumps(details)
            incidents.append(incident)
        save_time = datetime.utcnow().timestamp()
        next_run = {"last_fetch": save_time}
        return next_run, incidents[:self._fetch_limit], incidents[self._fetch_limit:]
    
    def _fetch_remaining_incidents_from_last_run(self):
        if self._integration_context:
            remaining_incidents = self._integration_context.get("remaining_incidents")
            # return incidents if exists in context.
            if remaining_incidents:
                return self._last_run, remaining_incidents[:self._fetch_limit], remaining_incidents[self._fetch_limit:]
    
    def _get_start_query_time(self):
        start_query_time = self._try_get_last_fetch_time()

        # Handle first time fetch, fetch incidents retroactively
        if not start_query_time:
            start_query_time, _ = parse_date_range(self._first_fetch_time, to_timestamp=True, utc=True)
            start_query_time /= 1000
        
        return start_query_time
    
    def _try_get_last_fetch_time(self):
        return self._last_run.get("last_fetch")
    
    def _fetch_alerts(self, start_query_time):
        return self._client.fetch_alerts(start_query_time, self._event_severity_filter)
    
    def _relate_files_to_alert(self, alert_details):
        for obs in alert_details["observations"]:
            file_events = self._get_file_events_from_alert_details(obs, alert_details)
            alert_details["fileevents"] = [_process_event_from_observation(e) for e in file_events]
    
    def _get_file_events_from_alert_details(self, observation, alert_details):
        security_data_query = map_observation_to_security_query(observation, alert_details["actor"])
        return self._client.search_json(security_data_query)


@logger
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
        client, last_run, first_fetch_time, event_severity_filter, fetch_limit, include_files, integration_context
    )
    return fetcher.fetch()


@logger
def securitydata_search_command(client, args):
    code42_securitydata_context = []
    file_context = []
    # If JSON payload is passed as an argument, ignore all other args and search by JSON payload
    if args.get("json") is not None:
        file_events = client.search_json(args.get("json"))
    else:
        # Build payload
        payload = build_query_payload(args)
        file_events = client.search_json(payload)
    if file_events:
        for file_event in file_events:
            code42_context_event = map_to_code42_event_context(file_event)
            code42_securitydata_context.append(code42_context_event)
            file_context_event = map_to_file_context(file_event)
            file_context.append(file_context_event)
        readable_outputs = tableToMarkdown(
            f"Code42 Security Data Results",
            code42_securitydata_context,
            headers=SECURITY_EVENT_HEADERS,
        )
        return (
            readable_outputs,
            {
                "Code42.SecurityData(val.EventID && val.EventID == obj.EventID)": code42_securitydata_context,
                "File": file_context,
            },
            file_events,
        )
    else:
        return "No results found", {}, {}


def test_module(client):
    if client.get_current_user():
        return "ok"
    return "Invalid credentials or host address. Check that the username and password are correct, \
           that the host is available and reachable, and that you have supplied the full scheme, \
           domain, and port (e.g. https://myhost.code42.com:4285)"


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get("credentials").get("identifier")
    password = demisto.params().get("credentials").get("password")
    base_url = demisto.params().get("console_url")
    # Remove trailing slash to prevent wrong URL path to service
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)
    LOG(f"Command being called is {demisto.command()}")
    try:
        client = Code42Client(
            base_url=base_url, auth=(username, password), verify=verify_certificate, proxy=proxy
        )
        commands = {
            "code42-alert-get": alert_get_command,
            "code42-alert-resolve": alert_resolve_command,
            "code42-securitydata-search": securitydata_search_command,
            "code42-departingemployee-add": departingemployee_add_command,
            "code42-departingemployee-remove": departingemployee_remove_command,
        }
        command = demisto.command()
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif command == "fetch-incidents":
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
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

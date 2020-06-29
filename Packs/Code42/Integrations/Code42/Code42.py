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
    FileCategory,
)
from py42.sdk.queries.alerts.alert_query import AlertQuery
from py42.sdk.queries.alerts.filters import DateObserved, Severity, AlertState

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
    for employee in page["items"]:
        if not risk_tags:
            res.append(employee)
            continue

        employee_tags = employee.get("riskFactors")
        # If the employee risk tags contain all the given risk tags
        if employee_tags and set(risk_tags) <= set(employee_tags):
            res.append(employee)
    return res


def _try_convert_str_list_to_list(str_list):
    if isinstance(str_list, str):
        return str_list.split()
    return str_list


class Code42Client(BaseClient):
    """
    Client will implement the service API, should not contain Cortex XSOAR logic.
    Should do requests and return data
    """

    def __init__(self, sdk, base_url, auth, verify=True, proxy=False):
        super().__init__(base_url, verify=verify, proxy=proxy)
        # Allow sdk parameter for unit testing.
        # Otherwise, lazily load the SDK so that the TEST Command can effectively check auth.
        self._sdk = sdk
        self._sdk_factory = lambda: py42.sdk.from_local_account(base_url, auth[0], auth[1]) if not self._sdk else None
        py42.settings.set_user_agent_suffix("Cortex XSOAR")

    def _get_sdk(self):
        if self._sdk is None:
            self._sdk = self._sdk_factory()
        return self._sdk

    def add_user_to_departing_employee(self, username, departure_date=None, note=None):
        user_id = self.get_user(username)["userUid"]
        self._get_sdk().detectionlists.departing_employee.add(
            user_id, departure_date=departure_date
        )
        if note:
            self._get_sdk().detectionlists.update_user_notes(user_id, note)
        return user_id

    def remove_user_from_departing_employee(self, username):
        user_id = self.get_user(username)["userUid"]
        self._get_sdk().detectionlists.departing_employee.remove(user_id)
        return user_id

    def get_all_departing_employees(self, results):
        res = []
        results = int(results) if results else None
        pages = self._get_sdk().detectionlists.departing_employee.get_all()
        for page in pages:
            employees = page["items"]
            for employee in employees:
                res.append(employee)
                if results and len(res) == results:
                    return res
        return res

    def add_user_to_high_risk_employee(self, username, note=None):
        user_id = self.get_user(username)["userUid"]
        self._get_sdk().detectionlists.high_risk_employee.add(user_id)
        if note:
            self._get_sdk().detectionlists.update_user_notes(user_id, note)
        return user_id

    def remove_user_from_high_risk_employee(self, username):
        user_id = self.get_user(username)["userUid"]
        self._get_sdk().detectionlists.high_risk_employee.remove(user_id)
        return user_id

    def add_user_risk_tags(self, username, risk_tags):
        risk_tags = _try_convert_str_list_to_list(risk_tags)
        user_id = self.get_user(username)["userUid"]
        self._get_sdk().detectionlists.add_user_risk_tags(user_id, risk_tags)
        return user_id

    def remove_user_risk_tags(self, username, risk_tags):
        risk_tags = _try_convert_str_list_to_list(risk_tags)
        user_id = self.get_user(username)["userUid"]
        self._get_sdk().detectionlists.remove_user_risk_tags(user_id, risk_tags)
        return user_id

    def get_all_high_risk_employees(self, risk_tags, results):
        risk_tags = _try_convert_str_list_to_list(risk_tags)
        results = int(results) if results else None
        res = []
        pages = self._get_sdk().detectionlists.high_risk_employee.get_all()
        for page in pages:
            employees = _get_all_high_risk_employees_from_page(page, risk_tags)
            for employee in employees:
                res.append(employee)
                if results and len(res) == results:
                    return res
        return res

    def fetch_alerts(self, start_time, event_severity_filter):
        query = _create_alert_query(event_severity_filter, start_time)
        res = self._get_sdk().alerts.search(query)
        return res["alerts"]

    def get_alert_details(self, alert_id):
        res = self._get_sdk().alerts.get_details(alert_id)["alerts"]
        if not res:
            raise Exception("No alert found with ID {0}.".format(alert_id))
        return res[0]

    def resolve_alert(self, id):
        self._get_sdk().alerts.resolve(id)
        return id

    def get_current_user(self):
        res = self._get_sdk().users.get_current()
        return res

    def get_user(self, username):
        res = self._get_sdk().users.get_by_username(username)["users"]
        if not res:
            raise Exception("No user found with username {0}.".format(username))
        return res[0]

    def create_user(self, org_name, username, email):
        org_uid = self.get_org(org_name)["orgUid"]
        return self._get_sdk().users.create_user(org_uid, username, email)

    def block_user(self, username):
        user_id = self.get_user(username)["userId"]
        return self._get_sdk().users.block(user_id)

    def deactivate_user(self, username):
        user_id = self.get_user(username)["userId"]
        return self._get_sdk().users.deactivate(user_id)

    def get_org(self, org_name):
        org_pages = self._get_sdk().orgs.get_all()
        for org_page in org_pages:
            for org in org_page["orgs"]:
                if org["orgName"] == org_name:
                    return org
        raise Exception("No org found with name {0}.".format(org_name))

    def search_file_events(self, payload):
        res = self._get_sdk().securitydata.search_file_events(payload)
        return res["fileEvents"]


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
        query = FileEventQuery.all(*self._filters)
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

    search_args = FileEventQueryFilters(pg_size)
    search_args.append_result(_hash, _create_hash_filter)
    search_args.append_result(hostname, OSHostname.eq)
    search_args.append_result(username, DeviceUsername.eq)
    search_args.append_result(exposure, _create_exposure_filter)

    query = search_args.to_all_query()
    LOG("File Event Query: {}".format(str(query)))
    return query


def _create_hash_filter(hash_arg):
    if not hash_arg:
        return None
    elif len(hash_arg) == 32:
        return MD5.eq(hash_arg)
    elif len(hash_arg) == 64:
        return SHA256.eq(hash_arg)


def _create_exposure_filter(exposure_arg):
    # Because the CLI can't accept lists, convert the args to a list if the type is string.
    if isinstance(exposure_arg, str):
        exposure_arg = exposure_arg.split(",")
    return ExposureType.is_in(exposure_arg)


def _create_category_filter(file_type):
    category_value = CODE42_FILE_TYPE_MAPPER.get(file_type["category"], "UNCATEGORIZED")
    return FileCategory.eq(category_value)


class ObservationToSecurityQueryMapper(object):
    """Class to simplify the process of mapping observation data to query objects."""

    # Exfiltration consts
    _ENDPOINT_TYPE = "FedEndpointExfiltration"
    _CLOUD_TYPE = "FedCloudSharePermissions"

    # Query consts
    _PUBLIC_SEARCHABLE = "PublicSearchableShare"
    _PUBLIC_LINK = "PublicLinkShare"
    _OUTSIDE_TRUSTED_DOMAINS = "SharedOutsideTrustedDomain"

    exposure_type_map = {
        "PublicSearchableShare": ExposureType.IS_PUBLIC,
        "PublicLinkShare": ExposureType.SHARED_VIA_LINK,
        "SharedOutsideTrustedDomain": "OutsideTrustedDomains",
    }

    def __init__(self, observation, actor):
        self._obs = observation
        self._actor = actor

    @property
    def _observation_data(self):
        return self._obs["data"]

    @property
    def _exfiltration_type(self):
        return self._obs["type"]

    @property
    def _is_endpoint_exfiltration(self):
        return self._exfiltration_type == self._ENDPOINT_TYPE

    @property
    def _is_cloud_exfiltration(self):
        return self._exfiltration_type == self._CLOUD_TYPE

    def _create_user_filter(self):
        return (
            DeviceUsername.eq(self._actor)
            if self._is_endpoint_exfiltration
            else Actor.eq(self._actor)
        )

    def map(self):
        search_args = self._create_search_args()
        query = search_args.to_all_query()
        LOG("Alert Observation Query: {}".format(query))
        return query

    def _create_search_args(self):
        filters = FileEventQueryFilters()
        exposure_types = self._observation_data["exposureTypes"]
        begin_time = _convert_date_arg_to_epoch(self._observation_data["firstActivityAt"])
        end_time = _convert_date_arg_to_epoch(self._observation_data["lastActivityAt"])

        filters.append(self._create_user_filter())
        filters.append(EventTimestamp.on_or_after(begin_time))
        filters.append(EventTimestamp.on_or_before(end_time))
        filters.extend(self._create_exposure_filters(exposure_types))
        filters.append(self._create_file_category_filters())

        return filters

    @logger
    def _create_exposure_filters(self, exposure_types):
        """Determine exposure types based on alert type"""
        exp_types = []
        if self._is_cloud_exfiltration:
            for t in exposure_types:
                exp_type = self.exposure_type_map.get(t)
                if exp_type:
                    exp_types.append(exp_type)
                else:
                    LOG("Received unsupported exposure type {0}.".format(t))
            if exp_types:
                return [ExposureType.is_in(exp_types)]
            else:
                # If not given a support exposure type, search for all unsupported exposure types
                supported_exp_types = list(self.exposure_type_map.values())
                return [ExposureType.not_in(supported_exp_types)]
        elif self._is_endpoint_exfiltration:
            return [
                EventType.is_in([EventType.CREATED, EventType.MODIFIED, EventType.READ_BY_APP]),
                ExposureType.is_in(exposure_types),
            ]
        return []

    def _create_file_category_filters(self):
        """Determine if file categorization is significant"""
        observed_file_categories = self._observation_data["fileCategories"]
        categories = [c["category"].upper() for c in observed_file_categories if c["isSignificant"]]
        if categories:
            return FileCategory.is_in(categories)


def map_observation_to_security_query(observation, actor):
    mapper = ObservationToSecurityQueryMapper(observation, actor)
    return mapper.map()


def _convert_date_arg_to_epoch(date_arg):
    date_arg = date_arg[:25]
    return (
        datetime.strptime(date_arg, "%Y-%m-%dT%H:%M:%S.%f") - datetime.utcfromtimestamp(0)
    ).total_seconds()


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


@logger
def _map_obj_to_context(obj, context_mapper):
    return {v: obj.get(k) for k, v in context_mapper.items() if obj.get(k)}


def create_command_error_message(cmd, ex):
    return "Failed to execute command {0} command. Error: {1}".format(cmd, str(ex))


"""Commands"""


@logger
def alert_get_command(client, args):
    code42_securityalert_context = []
    try:
        alert = client.get_alert_details(args["id"])
        if not alert:
            return "No results found", {}, {}

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
    except Exception as e:
        return_error(create_command_error_message(demisto.command(), e))


@logger
def alert_resolve_command(client, args):
    code42_securityalert_context = []

    try:
        alert_id = client.resolve_alert(args["id"])

        if not alert_id:
            return "No results found", {}, {}

        # Retrieve new alert details
        alert_details = client.get_alert_details(alert_id)
        if not alert_details:
            return "Error retrieving updated alert", {}, {}

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
    except Exception as e:
        return_error(create_command_error_message(demisto.command(), e))


@logger
def departingemployee_add_command(client, args):
    departing_date = args.get("departuredate")
    username = args["username"]
    note = args.get("note")
    try:
        user_id = client.add_user_to_departing_employee(username, departing_date, note)
        de_context = {
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
    except Exception as e:
        return_error(create_command_error_message(demisto.command(), e))


@logger
def departingemployee_remove_command(client, args):
    username = args["username"]
    try:
        user_id = client.remove_user_from_departing_employee(username)
        de_context = {"UserID": user_id, "Username": username}
        readable_outputs = tableToMarkdown(
            "Code42 Departing Employee List User Removed", de_context
        )
        return CommandResults(
            outputs_prefix="Code42.DepartingEmployee",
            outputs_key_field="UserID",
            outputs=de_context,
            readable_output=readable_outputs,
            raw_response=user_id,
        )
    except Exception as e:
        return_error(create_command_error_message(demisto.command(), e))


@logger
def departingemployee_get_all_command(client, args):
    results = args.get("results") or 50
    try:
        employees = client.get_all_departing_employees(results)
        employees_context = [
            {
                "UserID": e["userId"],
                "Username": e["userName"],
                "DepartureDate": e.get("departureDate"),
                "Note": e["notes"],
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
    except Exception as e:
        return_error(create_command_error_message(demisto.command(), e))


@logger
def highriskemployee_add_command(client, args):
    username = args["username"]
    note = args.get("note")
    try:
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
    except Exception as e:
        return_error(create_command_error_message(demisto.command(), e))


@logger
def highriskemployee_remove_command(client, args):
    username = args["username"]
    try:
        user_id = client.remove_user_from_high_risk_employee(username)
        hr_context = {"UserID": user_id, "Username": username}
        readable_outputs = tableToMarkdown(
            "Code42 High Risk Employee List User Removed", hr_context
        )
        return CommandResults(
            outputs_prefix="Code42.HighRiskEmployee",
            outputs_key_field="UserID",
            outputs=hr_context,
            readable_output=readable_outputs,
            raw_response=user_id,
        )
    except Exception as e:
        return_error(create_command_error_message(demisto.command(), e))


@logger
def highriskemployee_get_all_command(client, args):
    tags = args.get("risktags")
    results = args.get("results") or 50
    try:
        employees = client.get_all_high_risk_employees(tags, results)
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

    except Exception as e:
        return_error(create_command_error_message(demisto.command(), e))


@logger
def highriskemployee_add_risk_tags_command(client, args):
    username = args.get("username")
    tags = args.get("risktags")
    try:
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
    except Exception as e:
        return_error(create_command_error_message(demisto.command(), e))


@logger
def highriskemployee_remove_risk_tags_command(client, args):
    username = args.get("username")
    tags = args.get("risktags")
    try:
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
    except Exception as e:
        return_error(create_command_error_message(demisto.command(), e))


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
            raw_response=file_events
        )
        file_results = CommandResults(
            outputs_prefix="File",
            outputs_key_field=None,
            outputs=file_context,
        )
        return code42_results, file_results

    else:
        return "No results found", {}, {}


def user_create_command(client, args):



def user_block_command(client, args):
    pass


def user_deactivate_command(client, args):
    pass


"""Fetching"""


def _create_incident_from_alert_details(details):
    return {"name": "Code42 - {}".format(details["name"]), "occurred": details["createdAt"]}


def _stringify_lists_if_needed(event):
    # We need to convert certain fields to a stringified list or React.JS will throw an error
    shared_with = event.get("sharedWith")
    private_ip_addresses = event.get("privateIpAddresses")
    if shared_with:
        shared_list = [u.get("cloudUsername") for u in shared_with if u.get("cloudUsername")]
        event["sharedWith"] = str(shared_list)
    if private_ip_addresses:
        event["privateIpAddresses"] = str(private_ip_addresses)
    return event


def _process_event_from_observation(event):
    return _stringify_lists_if_needed(event)


class Code42SecurityIncidentFetcher(object):
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
        self._include_files = (include_files,)
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
        details = self._client.get_alert_details(alert["id"])
        incident = _create_incident_from_alert_details(details)
        details = self._relate_files_to_alert(details)
        incident["rawJSON"] = json.dumps(details)
        return incident

    def _relate_files_to_alert(self, alert_details):
        observations = alert_details.get("observations")
        if not observations:
            alert_details["fileevents"] = []
            return
        for obs in observations:
            file_events = self._get_file_events_from_alert_details(obs, alert_details)
            alert_details["fileevents"] = [_process_event_from_observation(e) for e in file_events]
        return alert_details

    def _get_file_events_from_alert_details(self, observation, alert_details):
        security_data_query = map_observation_to_security_query(observation, alert_details["actor"])
        return self._client.search_file_events(security_data_query)


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
        client.get_current_user()
        return "ok"
    except Exception:
        return (
            "Invalid credentials or host address. Check that the username and password are correct, that the host "
            "is available and reachable, and that you have supplied the full scheme, domain, and port "
            "(e.g. https://myhost.code42.com:4285)."
        )


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
    LOG("Command being called is {0}.".format(demisto.command()))
    try:
        client = Code42Client(
            base_url=base_url,
            sdk=None,
            auth=(username, password),
            verify=verify_certificate,
            proxy=proxy,
        )
        commands = {
            "code42-alert-get": alert_get_command,
            "code42-alert-resolve": alert_resolve_command,
            "code42-securitydata-search": securitydata_search_command,
            "code42-departingemployee-add": departingemployee_add_command,
            "code42-departingemployee-remove": departingemployee_remove_command,
            "code42-departingemployee-get-all": departingemployee_get_all_command,
            "code42-highriskemployee-add": highriskemployee_add_command,
            "code42-highriskemployee-remove": highriskemployee_remove_command,
            "code42-highriskemployee-get-all": highriskemployee_get_all_command,
            "code42-highriskemployee-add-risk-tags": highriskemployee_add_risk_tags_command,
            "code42-highriskemployee-remove-risk-tags": highriskemployee_remove_risk_tags_command,
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
            results = commands[command](client, demisto.args())
            if not isinstance(results, tuple) and not isinstance(results, list):
                results = [results]
            for result in results:
                return_results(result)

    # Log exceptions
    except Exception as e:
        return_error("Failed to execute {0} command. Error: {1}".format(demisto.command(), str(e)))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

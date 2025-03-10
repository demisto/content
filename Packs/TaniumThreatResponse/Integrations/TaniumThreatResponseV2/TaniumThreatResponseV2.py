import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import ast
import copy
import json
import os
import traceback
import urllib.parse
from typing import Any
from datetime import datetime

import urllib3
from dateutil.parser import parse
from lxml import etree

""" IMPORTS """

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

""" GLOBALS/PARAMS """
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

PROCESS_TEXT = "Process information for process with PTID"
PARENT_PROCESS_TEXT = "Parent process for process with PTID"
PROCESS_CHILDREN_TEXT = "Children for process with PTID"

# The commands below won't work unless the connection passed in `connection_name` argument is active.
COMMANDS_DEPEND_ON_CONNECTIVITY = [
    "tanium-tr-create-snapshot",
    "tanium-tr-list-events-by-connection",
    "tanium-tr-get-process-info",
    "tanium-tr-get-events-by-process",
    "tanium-tr-get-process-children",
    "tanium-tr-get-parent-process",
    "tanium-tr-get-process-tree",
    "tanium-tr-create-evidence",
    "tanium-tr-request-file-download",
    "tanium-tr-list-files-in-directory",
    "tanium-tr-get-file-info",
    "tanium-tr-delete-file-from-endpoint",
]
DEPENDENT_COMMANDS_ERROR_MSG = "\nPlease verify that the connection you have specified is active."


class Client(BaseClient):
    def __init__(self, base_url, username, password, api_version, api_token=None, **kwargs):  # pragma: no cover
        self.username = username
        self.password = password
        self.session = ""
        self.api_token = api_token
        self.api_version = api_version
        super().__init__(base_url, **kwargs)

    def do_request(
        self,
        method: str,
        url_suffix: str,
        data: dict = None,
        params: dict = None,
        resp_type: str = "json",
        headers: dict = None,
        body: Any = None,
    ):  # pragma: no cover
        if headers is None:
            headers = {}
        if not self.session:
            self.update_session()
        headers["session"] = self.session
        res = self._http_request(
            method,
            url_suffix,
            headers=headers,
            json_data=data,
            data=body,
            params=params,
            resp_type="response",
            ok_codes=(200, 201, 202, 204, 400, 401, 403, 404),
        )

        if res.status_code == 401:
            if self.api_token:
                err_msg = (
                    "Unauthorized Error: please verify that the given API token is valid and that the IP of the "
                    "client is listed in the api_token_trusted_ip_address_list global setting.\n"
                )
            else:
                err_msg = ""
            try:
                err_msg += str(res.json())
            except ValueError:
                err_msg += str(res)
            return_error(err_msg)

        # if session expired
        if res.status_code == 403:
            self.update_session()
            res = self._http_request(
                method, url_suffix, headers=headers, json_data=data, data=body, params=params, ok_codes=(200, 400, 404)
            )
            return res

        if res.status_code == 404 or res.status_code == 400:
            if res.content:
                raise requests.HTTPError(str(res.content))
            if res.reason:
                raise requests.HTTPError(str(res.reason))
            raise requests.HTTPError(res.json().get("text"))

        if resp_type == "json":
            try:
                return res.json()
            except json.JSONDecodeError:
                return res.content
        if resp_type == "text":
            return res.text, res.headers.get("Content-Disposition")
        if resp_type == "content":
            return res.content, res.headers.get("Content-Disposition")

        return res

    def update_session(self):  # pragma: no cover
        if self.api_token:
            res = self._http_request("GET", "api/v2/session/current", headers={"session": self.api_token}, ok_codes=(200,))
            if res.get("data"):
                self.session = self.api_token
        elif self.username and self.password:
            body = {"username": self.username, "password": self.password}

            res = self._http_request("POST", "/api/v2/session/login", json_data=body, ok_codes=(200,))

            self.session = res.get("data").get("session")
        else:  # no API token and no credentials were provided, raise an error:
            return_error("Please provide either an API Token or Username & Password.")
        return self.session

    def login(self):
        return self.update_session()

    def get_threat_response_endpoint(self):
        return "threat-response" if self.api_version == "4.x" else "detect3"


""" GENERAL HELPER FUNCTIONS """


def format_context_data(context_to_format: Union[list, dict]) -> Union[list, dict]:
    """Format a context dictionary to the standard demisto format.
    :type context_to_format: ``dict``
    :param context_to_format:
        The object to convert.

    :return: the formatted dictionary
    :rtype: ``dict``
    """

    def format_context_dict(context_dict: dict) -> dict:
        # The API result keys are in camelCase and the context is expecting PascalCase
        formatted_context = camelize(snakify(context_dict), "_")
        cur_id = formatted_context.get("Id")
        if cur_id:
            formatted_context["ID"] = cur_id
            del formatted_context["Id"]
        return formatted_context

    if isinstance(context_to_format, list):
        return [format_context_dict(item) for item in context_to_format]
    else:
        return format_context_dict(context_to_format)


def convert_to_int(int_to_parse: Any) -> Optional[int]:
    """Tries to convert an object to int.

    :type int_to_parse: ``Any``
    :param int_to_parse:
        The object to convert.

    :return: the converted number or None if the number cannot be converted
    :rtype: ``int`` or ``None``

    """
    try:
        res: Optional[int] = int(int_to_parse)
    except (TypeError, ValueError):
        res = None
    return res


def are_filters_match_response_content(all_filter_arguments: list[tuple[list, str]], api_response: dict) -> bool:
    """
    Verify whether any filter arguments of a command match the api response content.

    Args:
        all_filter_arguments (list[tuple]): pairs of filter arguments inputs & a response key.
        api_response (dict): api response.

    Returns:
        bool: True if in any of the filter arguments there was a match, False otherwise.
    """
    for arguments in all_filter_arguments:
        command_args, resp_key = arguments
        for arg in command_args:
            if arg == api_response.get(resp_key):
                return True
    return False


def filter_to_tanium_api_syntax(filter_str):  # pragma: no cover
    filter_dict = {}
    try:
        if filter_str:
            filter_expressions = ast.literal_eval(filter_str)
            for i, expression in enumerate(filter_expressions):
                filter_dict["f" + str(i)] = expression[0]
                filter_dict["o" + str(i)] = expression[1]
                filter_dict["v" + str(i)] = expression[2]
        return filter_dict
    except IndexError:
        raise ValueError("Invalid filter argument.")


def get_file_data(entry_id: str) -> tuple[str, str, str]:
    """Gets a file name and content from the file's entry ID.

    :type entry_id: ``str``
    :param entry_id:
        the file's entry ID.

    :return: file name, path and content
    :rtype: ``tuple``

    """
    file = demisto.getFilePath(entry_id)
    file_path = file.get("path")
    file_name = file.get("name")
    with open(file_path) as f:
        file_content = f.read()
    return file_name, file_path, file_content


def get_future_date(date_string: str) -> str:
    """Gets a date string and returns an ISO 8061 formatted datetime string

    :type date_string: ``str``
    :param date_string:
        The date string in "<number> <unit>" format (i.e. "7 days")

    :return: ISO8061 formatted datetime string
    :rtype: ``str``

    """
    try:
        if "in" not in date_string:
            date_string = f"in {date_string}"
        parsed_date = dateparser.parse(date_string)
        if parsed_date:
            return parsed_date.isoformat()
        else:
            raise ValueError
    except Exception:
        raise DemistoException('Invalid date string format. Must be "<amount> <unit>"')


""" EVIDENCE HELPER FUNCTIONS """


def get_event_header(event_type):  # pragma: no cover
    if event_type == "combined":
        headers = ["id", "type", "processPath", "detail", "timestamp", "operation"]

    elif event_type == "file":
        headers = ["id", "file", "timestamp", "processTableId", "processPath", "userName"]

    elif event_type == "network":
        headers = [
            "id",
            "timestamp",
            "groupName",
            "processTableId",
            "pid",
            "processPath",
            "userName",
            "operation",
            "localAddress",
            "localAddressPort",
            "remoteAddress",
            "remoteAddressPort",
        ]

    elif event_type == "registry":
        headers = ["id", "timestamp", "groupName", "processTableId", "pid", "processPath", "userName", "keyPath", "valueName"]

    elif event_type == "process":
        headers = [
            "groupName",
            "processTableId",
            "processCommandLine",
            "pid",
            "processPath",
            "exitCode",
            "userName",
            "createTime",
            "endTime",
        ]

    elif event_type == "driver":
        headers = [
            "id",
            "timestamp",
            "processTableID",
            "hashes",
            "imageLoaded",
            "signature",
            "signed",
            "eventId",
            "eventOpcode",
            "eventRecordId",
            "eventTaskId",
        ]

    elif event_type == "dns":
        headers = [
            "id",
            "timestamp",
            "groupName",
            "processTableId",
            "pid",
            "processPath",
            "userName",
            "operation",
            "query",
            "response",
        ]

    else:  # if event_type == 'image'
        headers = ["id", "timestamp", "imagePath", "processTableID", "processID", "processName", "username", "hash", "signature"]
    return headers


""" GENERAL HELPER FUNCTIONS"""


def normalize_api_response(raw_response):
    """parse the api response. from 4.x version of the api, the response is returned with a data dict
    :param raw_response:
        The raw response returned from api call

    :return: the parsed api response.
    :rtype: ``dict or list``

    """
    return raw_response.get("data", raw_response) if type(raw_response) is dict else raw_response


""" INTEL DOCS HELPER FUNCTIONS """


def get_intel_doc_item(intel_doc: dict) -> dict:
    """Gets the relevant fields from a given intel doc.

    :type intel_doc: ``dict``
    :param intel_doc:
        The intel doc obtained from api call

    :return: a dictionary containing only the relevant fields.
    :rtype: ``dict``

    """
    intel_doc_data = normalize_api_response(intel_doc)  # 4.x version parses info in a data dict into the intel_doc dict
    return {
        "ID": intel_doc_data.get("id"),
        "Name": intel_doc_data.get("name"),
        "Type": intel_doc_data.get("type"),
        "Description": intel_doc_data.get("description"),
        "AlertCount": intel_doc_data.get("alertCount"),
        "UnresolvedAlertCount": intel_doc_data.get("unresolvedAlertCount"),
        "CreatedAt": intel_doc_data.get("createdAt"),
        "UpdatedAt": intel_doc_data.get("updatedAt"),
        "LabelIds": intel_doc_data.get("labelIds"),
    }


def get_intel_doc_label_item(intel_doc_label: dict) -> dict:
    """Gets the relevant fields from a given intel doc label.

    :type intel_doc_label: ``dict``
    :param intel_doc_label:
        The intel doc label obtained from api call

    :return: a dictionary containing only the relevant fields.
    :rtype: ``dict``

    """
    return {
        "ID": intel_doc_label.get("id"),
        "Name": intel_doc_label.get("name"),
        "Description": intel_doc_label.get("description"),
        "IndicatorCount": intel_doc_label.get("indicatorCount"),
        "SignalCount": intel_doc_label.get("signalCount"),
        "CreatedAt": intel_doc_label.get("createdAt"),
        "UpdatedAt": intel_doc_label.get("updatedAt"),
    }


def get_intel_doc_status(status_data):
    return {
        "CreatedAt": status_data.get("createdAt"),
        "ModifiedAt": status_data.get("modifiedAt"),
        "CurrentRevision": status_data.get("currentRevision"),
        "CurrentSize": status_data.get("currentSize"),
    }


def update_content_from_xml(file_path: str, intrinsic_id: str) -> str:
    """Parse an xml file, and update the content to match the same intrinsic_id as the current content.
    the api will update docs only if the intel doc content (before update) has the same intrinsic_id as the new content,
    otherwise it will create a new intel doc.
    this function will force update so if they are not equal it changes the new ID to be equal to the previous ID.

    :type file_path: ``str``
    :param file_path:
        The xml file path

    :type intrinsic_id: ``str``
    :param intrinsic_id:
        The current intel doc id (before update)

    :return: an updated xml content where the id matches the previous intrinsic_id
    :rtype: ``str``

    """
    for _, xml_root in etree.iterparse(file_path, events=("start",), resolve_entities=False):
        content_id = xml_root.attrib.get("id")
        if content_id is not None and intrinsic_id != content_id:
            xml_root.attrib["id"] = intrinsic_id
            return etree.tostring(xml_root, encoding="unicode", pretty_print=True)
    return ""


def get_quick_scan_item(quick_scan):
    return {
        "IntelDocId": quick_scan.get("intelDocId"),
        "ComputerGroupId": quick_scan.get("computerGroupId"),
        "ID": quick_scan.get("id"),
        "AlertCount": quick_scan.get("alertCount"),
        "CreatedAt": quick_scan.get("createdAt"),
        "UserId": quick_scan.get("userId"),
        "QuestionId": quick_scan.get("questionId"),
    }


""" ALERTS DOCS HELPER FUNCTIONS """


def get_alert_item(alert):
    return {
        "ID": alert.get("id"),
        "AlertedAt": alert.get("alertedAt"),
        "ComputerIpAddress": alert.get("computerIpAddress"),
        "ComputerName": alert.get("computerName"),
        "CreatedAt": alert.get("createdAt"),
        "GUID": alert.get("guid"),
        "IntelDocId": alert.get("intelDocId"),
        "Priority": alert.get("priority"),
        "Severity": alert.get("severity"),
        "State": alert.get("state").title(),
        "Type": alert.get("type"),
        "UpdatedAt": alert.get("updatedAt"),
    }


""" FETCH INCIDENTS HELPER FUNCTIONS """


def alarm_to_incident(client, alarm):  # pragma: no cover
    host = alarm.get("computerName", "")

    if details := alarm.get("details"):
        alarm_details = json.loads(details)
        alarm["details"] = alarm_details

    intel_doc = ""
    if intel_doc_id := alarm.get("intelDocId", ""):
        raw_response = client.do_request(
            "GET", "/plugin/products/" f"{client.get_threat_response_endpoint()}" f"/api/v1/intels/{intel_doc_id}"
        )
        raw_response_data = normalize_api_response(raw_response)
        intel_doc = raw_response_data.get("name")
        alarm["intelDocDetails"] = raw_response_data
        intel_doc_labels = []
        intel_doc_labels_resp = client.do_request(
            "GET", "/plugin/products/" f"{client.get_threat_response_endpoint()}" f"/api/v1/intels/{intel_doc_id}/labels"
        )

        labels_list = normalize_api_response(intel_doc_labels_resp)

        for label in labels_list:
            intel_doc_labels.append(label["name"])
        alarm["labels"] = intel_doc_labels

    return {
        "name": f"{host} found {intel_doc}",
        "occurred": alarm.get("alertedAt"),
        "starttime": alarm.get("createdAt"),
        "alertid": alarm.get("id"),
        "rawJSON": json.dumps(alarm),
    }


def state_params_suffix(alerts_states_to_retrieve):
    valid_alert_states = ["unresolved", "inprogress", "resolved", "suppressed"]

    for state in alerts_states_to_retrieve:
        if state.lower() not in valid_alert_states:
            raise ValueError(
                f"Invalid state '{state}' in filter_alerts_by_state parameter."
                f"Possible values are 'unresolved', 'inprogress', 'resolved' or 'suppressed'."
            )

    return "&".join(["state=" + state.lower() for state in alerts_states_to_retrieve])


""" COMMANDS + REQUESTS FUNCTIONS """
""" GENERAL COMMANDS FUNCTIONS """


def test_module(client, data_args):
    try:
        if client.login():
            return demisto.results("ok")
    except Exception as e:
        raise ValueError(f"Please check your credentials and try again. Error is:\n{str(e)}")


def fetch_incidents(
    client: Client, alerts_states_to_retrieve: str, label_name_to_retrieve: str, last_run: dict, fetch_time: str, max_fetch: int
):  # pragma: no cover
    """
    Fetch events from this integration and return them as Demisto incidents

    returns:
        Demisto incidents
    """
    # Get the last fetch time and data if it exists
    last_fetch = last_run.get("time")
    last_id = int(last_run.get("id", "0"))
    alerts_states = argToList(alerts_states_to_retrieve)
    offset = 0
    label_name_suffix = ""

    # Handle first time fetch, fetch incidents retroactively
    if not last_fetch:
        last_fetch, _ = parse_date_range(fetch_time, date_format=DATE_FORMAT)

    demisto.debug(f"Get last run: last_id {last_id}, last_time: {last_fetch}.\n")

    last_fetch = parse(last_fetch)

    alerts_states_suffix = state_params_suffix(alerts_states)
    if label_name_to_retrieve:
        label_name_suffix = f"&labelName={urllib.parse.quote(label_name_to_retrieve)}"
    incidents = []

    while True:
        demisto.debug(f"Sending new alerts api request with offset: {offset}.")
        url_suffix = (
            "/plugin/products/"
            f"{client.get_threat_response_endpoint()}/api/v1/alerts?"
            + alerts_states_suffix
            + f"&sort=-createdAt&limit=500&offset={offset}"
            + label_name_suffix
        )

        raw_response = client.do_request("GET", url_suffix)
        raw_response_data = normalize_api_response(raw_response)
        if not raw_response_data:
            demisto.debug("Stop fetch loop, no incidents in raw response.")
            break

        # convert the data/events to demisto incidents
        for alarm in raw_response_data:
            incident = alarm_to_incident(client, alarm)
            temp_date = parse(incident.get("starttime"))
            new_id = incident.get("alertid")
            demisto.debug(f"Fetched new alert, id: {new_id}, created_at: {temp_date}.\n")

            if temp_date >= last_fetch and new_id > last_id:
                demisto.debug(f"Adding new incident with id: {new_id}")
                incidents.append(incident)
            else:
                demisto.debug(f"Stop fetch loop, temp date < last fetch: {temp_date} < {last_fetch}.")
                break

        if temp_date >= last_fetch:
            offset += 500
        else:
            demisto.debug(f"Stop fetch loop, temp date < last fetch: {temp_date} < {last_fetch}.")
            break

    if len(incidents) > max_fetch:
        demisto.debug("Re-sizing incidents list.")
        incidents = incidents[len(incidents) - max_fetch :]

    if incidents:
        last_incident = incidents[0]
        last_fetch = parse(last_incident.get("starttime"))
        last_id = last_incident.get("alertid")

    next_run = {"time": datetime.strftime(last_fetch, DATE_FORMAT), "id": str(last_id)}

    demisto.debug(f"Set last run: last_id {last_id}, last_time: {last_fetch}.\n")
    demisto.debug(f"Fetched {len(incidents)} incidents.")

    return incidents, next_run


""" INTEL DOCS COMMANDS FUNCTIONS """


def get_intel_doc(client: Client, data_args: dict) -> tuple[str, dict, Union[list, dict]]:
    """Gets a single intel doc from a given id.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    id_ = data_args.get("intel_doc_id")
    try:
        raw_response = client.do_request(
            "GET", "/plugin/products/" f"{client.get_threat_response_endpoint()}" f"/api/v1/intels/{id_}"
        )
    # If the user provided a intel doc ID which does not exist, the do_request will throw HTTPError exception
    # with a "Not Found" message.
    except requests.HTTPError as e:
        if "not found" in str(e):
            raise DemistoException(f"Check the intel doc ID and try again.\n({str(e)})")
        raise
    intel_doc = get_intel_doc_item(raw_response)
    # A more readable format for the human readable section.
    if intel_doc:
        intel_doc["LabelIds"] = str(intel_doc.get("LabelIds", [])).strip("[]")
    context_data = format_context_data(normalize_api_response(raw_response))
    context = createContext(context_data, removeNull=True)
    outputs = {"Tanium.IntelDoc(val.ID && val.ID === obj.ID)": context}

    headers = ["ID", "Name", "Type", "Description", "AlertCount", "UnresolvedAlertCount", "CreatedAt", "UpdatedAt", "LabelIds"]
    human_readable = tableToMarkdown(
        "Intel Doc information", intel_doc, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


def get_intel_docs(client: Client, data_args: dict) -> tuple[str, dict, Union[list, dict]]:
    """Gets a single intel doc from a given id.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    # data_args contains some fields which can filter the intel docs result.
    params = (
        assign_params(
            name=data_args.get("name"),
            description=data_args.get("description"),
            type=data_args.get("type"),
            limit=convert_to_int(data_args.get("limit")),
            offset=convert_to_int(data_args.get("offset")),
            labelId=data_args.get("label_id"),
            mitreTechniqueId=data_args.get("mitre_technique_id"),
        )
        if data_args
        else {}
    )
    raw_response = client.do_request(
        "GET", "/plugin/products/" f"{client.get_threat_response_endpoint()}" f"/api/v1/intels/", params=params
    )

    intel_docs = []
    intel_doc = {}

    raw_response = normalize_api_response(raw_response)
    # append raw response to a list in case raw_response is a dictionary
    tmp_list = [raw_response] if type(raw_response) is dict else raw_response
    for item in tmp_list:
        intel_doc = get_intel_doc_item(item)
        if intel_doc:
            intel_doc["LabelIds"] = str(intel_doc.get("LabelIds", [])).strip("[]")
        intel_docs.append(intel_doc)
    context_data = format_context_data(raw_response)
    context = createContext(context_data, removeNull=True)
    outputs = {"Tanium.IntelDoc(val.ID && val.ID === obj.ID)": context}

    headers = ["ID", "Name", "Type", "Description", "AlertCount", "UnresolvedAlertCount", "CreatedAt", "UpdatedAt", "LabelIds"]
    human_readable = tableToMarkdown("Intel docs", intel_docs, headers=headers, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_intel_docs_labels_list(client: Client, data_args: dict) -> tuple[str, dict, Union[list, dict]]:
    """Gets the labels list of a given intel doc.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    id_ = data_args.get("intel_doc_id")
    try:
        raw_response = client.do_request(
            "GET", "/plugin/products/" f"{client.get_threat_response_endpoint()}" f"/api/v1/intels/{id_}/labels"
        )
    except requests.HTTPError as e:
        raise DemistoException(f"Check the intel doc ID and try again.\n({str(e)})")

    intel_docs_labels = []
    intel_doc_label = {}
    raw_response_data = normalize_api_response(raw_response)
    # append raw response to a list in case raw_response is a dictionary
    tmp_list = [raw_response_data] if type(raw_response_data) is dict else raw_response_data
    for item in tmp_list:
        intel_doc_label = get_intel_doc_label_item(item)
        intel_docs_labels.append(intel_doc_label)
    context_data = format_context_data(raw_response_data)
    context = createContext({"IntelDocID": id_, "LabelsList": context_data}, removeNull=True)
    outputs = {"Tanium.IntelDocLabel(val.IntelDocID && val.IntelDocID === obj.IntelDocID)": context}
    headers = ["ID", "Name", "Description", "IndicatorCount", "SignalCount", "CreatedAt", "UpdatedAt"]
    human_readable = tableToMarkdown(
        f"Intel doc ({id_}) labels", intel_docs_labels, headerTransform=pascalToSpace, headers=headers, removeNull=True
    )
    return human_readable, outputs, raw_response


def add_intel_docs_label(client: Client, data_args: dict) -> tuple[str, dict, Union[list, dict]]:
    """Creates a new label (given label ID) association for an identified intel document (given intel-doc ID).

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    intel_doc_id = data_args.get("intel_doc_id")
    label_id = data_args.get("label_id")
    params = assign_params(id=label_id)

    try:
        raw_response = client.do_request(
            "PUT",
            "/plugin/products/" f"{client.get_threat_response_endpoint()}" f"/api/v1/intels/{intel_doc_id}/labels",
            data=params,
        )
    # If the user provided a intel doc ID which does not exist, the do_request will throw HTTPError exception
    # with a "Not Found" message.
    except requests.HTTPError as e:
        if "not found" in str(e):
            raise DemistoException(f"Check the intel doc ID and try again.\n({str(e)})")
        raise
    # If the user provided a label ID which does not exist, the do_request will throw a DemistoException
    # with "internal server error" message.
    except DemistoException as e:
        if "internal server error" in str(e):
            raise DemistoException(f"Check the given label ID.\n({str(e)})")
        raise

    intel_docs_labels = []
    intel_doc_label = {}
    raw_response_data = normalize_api_response(raw_response)
    tmp_list = [raw_response_data] if type(raw_response_data) is dict else raw_response_data
    for item in tmp_list:
        intel_doc_label = get_intel_doc_label_item(item)
        intel_docs_labels.append(intel_doc_label)
    context_data = format_context_data(raw_response_data)
    context = createContext({"IntelDocID": intel_doc_id, "LabelsList": context_data}, removeNull=True)
    outputs = {"Tanium.IntelDocLabel(val.IntelDocID && val.IntelDocID === obj.IntelDocID)": context}
    headers = ["ID", "Name", "Description", "IndicatorCount", "SignalCount", "CreatedAt", "UpdatedAt"]
    human_readable = tableToMarkdown(
        f"Successfully created a new label ({label_id}) association for the identified intel document ({intel_doc_id}).",
        intel_docs_labels,
        headers=headers,
        headerTransform=pascalToSpace,
        removeNull=True,
    )
    return human_readable, outputs, raw_response


def remove_intel_docs_label(client: Client, data_args: dict) -> tuple[str, dict, Union[list, dict]]:
    """Removes a label (given label ID) association for an identified intel document (given intel-doc ID).

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """

    intel_doc_id = data_args.get("intel_doc_id")
    label_id_to_delete = data_args.get("label_id")
    try:
        raw_response = client.do_request(
            "DELETE",
            "/plugin/products/"
            f"{client.get_threat_response_endpoint()}"
            f"/api/v1/intels/{intel_doc_id}/labels/{label_id_to_delete}",
        )
    # If the user provided a intel doc ID which does not exist, the do_request will throw HTTPError exception
    # with a "Not Found" message.
    except requests.HTTPError as e:
        if "not found" in str(e):
            raise DemistoException(f"Check the intel doc ID and try again.\n({str(e)})")
        raise
    # If the user provided a label ID which does not exist, the do_request will throw a DemistoException
    # with "internal server error" message.
    except DemistoException as e:
        if "internal server error" in str(e):
            raise DemistoException(f"Check the given label ID.\n({str(e)})")
        raise

    intel_docs_labels = []
    intel_doc_label = {}
    raw_response_data = normalize_api_response(raw_response)
    tmp_list = [raw_response_data] if type(raw_response_data) is dict else raw_response_data
    for item in tmp_list:
        intel_doc_label = get_intel_doc_label_item(item)
        intel_docs_labels.append(intel_doc_label)

    # This API call returns the latest labels associated to the given intel-doc ID.
    # This gives us the ability to update the context on deletion.
    context_data = format_context_data(raw_response_data)
    context = createContext({"IntelDocID": intel_doc_id, "LabelsList": context_data}, removeNull=True)
    outputs = {"Tanium.IntelDocLabel(val.IntelDocID && val.IntelDocID === obj.IntelDocID)": context}
    headers = ["ID", "Name", "Description", "IndicatorCount", "SignalCount", "CreatedAt", "UpdatedAt"]
    human_readable = tableToMarkdown(
        f"Successfully removed the label ({label_id_to_delete}) association for the identified intel document ({intel_doc_id}).",
        intel_docs_labels,
        headers=headers,
        headerTransform=pascalToSpace,
        removeNull=True,
    )
    return human_readable, outputs, raw_response


def create_intel_doc(client: Client, data_args: dict) -> tuple[str, dict, Union[list, dict]]:
    """Adds a new intel-doc to the system by providing its document contents with an appropriate content-type header.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    entry_id = data_args.get("entry_id")
    file_extension = data_args.get("file_extension")
    raw_response = {}
    try:
        file_name, _, file_content = get_file_data(str(entry_id))
    except Exception as e:
        raise DemistoException(f"Check your file entry ID.\n{str(e)}")

    raw_response = client.do_request(
        "POST",
        "/plugin/products/" f"{client.get_threat_response_endpoint()}/api/v1/intels",
        headers={"Content-Disposition": f"attachment; filename=file.{file_extension}", "Content-Type": "application/xml"},
        body=file_content,
    )

    intel_doc = get_intel_doc_item(raw_response)
    # A more readable format for the human readable section.
    if intel_doc:
        intel_doc["LabelIds"] = str(intel_doc.get("LabelIds", [])).strip("[]")

    context_data = format_context_data(normalize_api_response(raw_response))
    context = createContext(context_data, removeNull=True)
    outputs = {"Tanium.IntelDoc(val.ID && val.ID === obj.ID)": context}

    headers = ["ID", "Name", "Type", "AlertCount", "UnresolvedAlertCount", "CreatedAt", "UpdatedAt", "LabelIds"]
    human_readable = tableToMarkdown(
        "Intel Doc information", intel_doc, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


def update_intel_doc(client: Client, data_args: dict) -> tuple[str, dict, Union[list, dict]]:
    """Updates the contents of an existing intel document by providing the document contents with an appropriate
    content-type header.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """

    id_ = data_args.get("intel_doc_id")
    intrinsic_id = ""
    try:
        # get intel doc intrinsicId
        raw_response = client.do_request(
            "GET", "/plugin/products/" f"{client.get_threat_response_endpoint()}" f"/api/v1/intels/{id_}"
        )
        raw_response_data = normalize_api_response(raw_response)
        intrinsic_id = raw_response_data.get("intrinsicId")
    # If the user provided a intel doc ID which does not exist, the do_request will throw HTTPError exception
    # with a "Not Found" message.
    except requests.HTTPError as e:
        if "not found" in str(e):
            raise DemistoException(f"Check the intel doc ID and try again.\n({str(e)})")
        raise

    entry_id = data_args.get("entry_id")
    file_extension = data_args.get("file_extension")
    content_disposition = f"filename=file.{file_extension}"
    raw_response = {}
    try:
        file_name, file_path, file_content = get_file_data(str(entry_id))
    except Exception as e:
        raise DemistoException(f"Check your file entry ID.\n{str(e)}")

    updated_content = file_content
    if file_extension in ["ioc", "stix"]:
        updated_content = update_content_from_xml(file_path, intrinsic_id)

    elif file_extension == "yara":
        # in yara files the update will take place when the previous intrinsic_id is entered in the Content Disposition
        content_disposition = f"filename={intrinsic_id}"

    content_disposition = f"attachment; {content_disposition}"
    raw_response = client.do_request(
        "PUT",
        "/plugin/products/" f"{client.get_threat_response_endpoint()}" f"/api/v1/intels/{id_}",
        headers={"Content-Disposition": content_disposition, "Content-Type": "application/xml"},
        body=updated_content,
    )

    intel_doc = get_intel_doc_item(raw_response)
    # A more readable format for the human readble section.
    if intel_doc:
        intel_doc["LabelIds"] = str(intel_doc.get("LabelIds", [])).strip("[]")

    context_data = format_context_data(normalize_api_response(raw_response))
    context = createContext(context_data, removeNull=True)
    outputs = {"Tanium.IntelDoc(val.ID && val.ID === obj.ID)": context}

    headers = ["ID", "Name", "Type", "Description", "AlertCount", "UnresolvedAlertCount", "CreatedAt", "UpdatedAt", "LabelIds"]
    human_readable = tableToMarkdown(
        "Intel Doc information", intel_doc, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


def delete_intel_doc(client, data_args):
    params = {"id": data_args.get("intel_doc_id")}
    try:
        raw_response = client.do_request(
            "DELETE", "/plugin/products/" f"{client.get_threat_response_endpoint()}" f"/api/v1/intels/", params=params
        )

    # If the user provided a intel doc ID which does not exist, the do_request will throw HTTPError exception
    # with a "Not Found" message.
    except requests.HTTPError as e:
        if "not found" in str(e):
            raise DemistoException(f"Could not find the intel doc ID.\n({str(e)})")
        raise

    return "Intel doc deleted", {}, str(raw_response)


def start_quick_scan(client, data_args):
    # get computer group ID from computer group name
    computer_group_name = data_args.get("computer_group_name")
    raw_response = client.do_request("GET", f"/api/v2/groups/by-name/{computer_group_name}")
    raw_response_data = normalize_api_response(raw_response)
    if not raw_response_data:
        msg = (
            f"No group exists with name {computer_group_name} or"
            f" your account does not have sufficient permissions to access the groups"
        )
        raise DemistoException(msg)

    data = {"intelDocId": int(data_args.get("intel_doc_id")), "computerGroupId": int(raw_response_data.get("id"))}
    if client.api_version == "4.x":
        url_suffix = "/plugin/products/threat-response/api/v1/on-demand-scans/"
    else:
        url_suffix = "/plugin/products/detect3/api/v1/quick-scans/"
    raw_response = client.do_request("POST", url_suffix, data=data)
    quick_scan = get_quick_scan_item(raw_response.get("data", raw_response))

    context = createContext(quick_scan, removeNull=True)
    outputs = {"Tanium.QuickScan(val.ID && val.ID === obj.ID)": context}

    human_readable = tableToMarkdown("Quick Scan started", quick_scan, headerTransform=pascalToSpace, removeNull=True)

    return human_readable, outputs, raw_response


def deploy_intel(client: Client, data_args: dict) -> tuple[str, dict, Union[list, dict]]:
    """Deploys intel using the service account context.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    raw_response = client.do_request("POST", "/plugin/products/threat-response/api/v1/intel/deploy")
    human_readable = ""

    # The response is of the form:
    # {
    #     "data": {
    #         "taskId": 779
    #     }
    # }
    if raw_response and raw_response.get("data"):
        human_readable = "Successfully deployed intel."
    else:
        raise DemistoException("Something went wrong while deploying intel docs.")
    return human_readable, {}, raw_response


def get_deploy_status(client: Client, data_args: dict) -> tuple[str, dict, Union[list, dict]]:
    """Displays status of last intel deployment.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    raw_response = client.do_request("GET", "/plugin/products/threat-response/api/v1/intel/status")

    status_data = raw_response.get("data", {})
    status = get_intel_doc_status(status_data)
    context_data = format_context_data(status_data)
    context = createContext(context_data, removeNull=True)

    outputs = {"Tanium.IntelDeployStatus": context}

    headers = ["CreatedAt", "ModifiedAt", "CurrentRevision", "CurrentSize"]
    human_readable = tableToMarkdown(
        "Intel deploy status", status, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


""" ALERTS COMMANDS FUNCTIONS """


def get_alerts(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Get alerts from tanium.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    limit = arg_to_number(data_args.get("limit"))
    offset = arg_to_number(data_args.get("offset"))
    ip_address = data_args.get("computer_ip_address")
    computer_name = data_args.get("computer_name")
    scan_config_id = data_args.get("scan_config_id")
    intel_doc_id = data_args.get("intel_doc_id")
    severity = data_args.get("severity")
    priority = data_args.get("priority")
    type_ = data_args.get("type")
    state = data_args.get("state")

    params = assign_params(
        type=type_,
        priority=priority,
        severity=severity,
        intelDocId=intel_doc_id,
        scanConfigId=scan_config_id,
        computerName=computer_name,
        computerIpAddress=ip_address,
        limit=limit,
        offset=offset,
        state=state.lower() if state else None,
    )

    raw_response = client.do_request(
        "GET", "/plugin/products/" f"{client.get_threat_response_endpoint()}" f"/api/v1/alerts/", params=params
    )

    alerts = []
    raw_response_data = normalize_api_response(raw_response)
    for item in raw_response_data:
        alert = get_alert_item(item)
        alerts.append(alert)

    context = createContext(alerts, removeNull=True)
    headers = [
        "ID",
        "Type",
        "Severity",
        "Priority",
        "AlertedAt",
        "CreatedAt",
        "UpdatedAt",
        "ComputerIpAddress",
        "ComputerName",
        "GUID",
        "State",
        "IntelDocId",
    ]
    outputs = {"Tanium.Alert(val.ID && val.ID === obj.ID)": context}
    human_readable = tableToMarkdown("Alerts", alerts, headers=headers, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_alert(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Get alert by id.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    alert_id = data_args.get("alert_id")
    raw_response = client.do_request(
        "GET", "/plugin/products/" f"{client.get_threat_response_endpoint()}" f"/api/v1/alerts/{alert_id}"
    )
    raw_response_data = raw_response.get("data", raw_response)
    alert = get_alert_item(raw_response_data)

    context = createContext(alert, removeNull=True)
    outputs = {"Tanium.Alert(val.ID && val.ID === obj.ID)": context}
    headers = [
        "ID",
        "Name",
        "Type",
        "Severity",
        "Priority",
        "AlertedAt",
        "CreatedAt",
        "UpdatedAt",
        "ComputerIpAddress",
        "ComputerName",
        "GUID",
        "State",
        "IntelDocId",
    ]
    human_readable = tableToMarkdown("Alert information", alert, headers=headers, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def alert_update_state(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Update alert status by alert ids.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    alert_ids = argToList(data_args.get("alert_ids"))
    state = data_args.get("state")

    body = {"state": state.lower()}
    if client.api_version == "4.x":
        if len(alert_ids) == 1:
            client.do_request("PUT", f"/plugin/products/threat-response/api/v1/alerts/{alert_ids[0]}", data=body)
        else:
            client.do_request("PUT", "/plugin/products/threat-response/api/v1/alerts/", data=body, params={"id": alert_ids})

    else:
        client.do_request("PUT", "/plugin/products/detect3/api/v1/alerts/", data=body.update({"id": alert_ids}))

    return f"Alert state updated to {state}.", {}, {}


""" SANPSHOTS COMMANDS FUNCTIONS """


def list_snapshots(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """List all snapshots at the system.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    limit = arg_to_number(data_args.get("limit"))
    offset = arg_to_number(data_args.get("offset"))

    params = assign_params(limit=limit, offset=offset)
    raw_response = client.do_request(method="GET", url_suffix="/plugin/products/threat-response/api/v1/snapshot", params=params)
    snapshots = raw_response.get("snapshots", [])

    for snapshot in snapshots:
        if created := snapshot.get("created"):
            try:
                snapshot["created"] = timestamp_to_datestring(created)
            except ValueError:
                pass

    context = createContext(snapshots, removeNull=True)
    headers = ["uuid", "name", "evidenceType", "hostname", "created"]
    outputs = {"Tanium.Snapshot(val.uuid === obj.uuid)": context}
    human_readable = tableToMarkdown("Snapshots:", snapshots, headers=headers, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def create_snapshot(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Create new snapshot of the connection.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    connection_id = data_args.get("connection_id")
    raw_response = client.do_request("POST", f"/plugin/products/threat-response/api/v1/conns/{connection_id}/snapshot")
    hr = f"Initiated snapshot creation request for {connection_id}."

    context = {"connection": connection_id}
    if task_id := raw_response.get("taskInfo", {}).get("id"):
        hr += f" Task id: {task_id}."

        context = copy.deepcopy(raw_response.get("taskInfo"))
        context.update(context.get("metadata", {}))
        context["taskId"] = task_id

        del context["id"]
        del context["metadata"]

    outputs = {"Tanium.SnapshotTask(val.taskId === obj.taskId && val.connection === obj.connection)": context} if context else {}
    return hr, outputs, raw_response


def delete_snapshot(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Delete exsisting snapshot from the system.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    snapshot_ids = argToList(data_args.get("snapshot_ids"))
    body = {"ids": snapshot_ids}
    client.do_request("DELETE", "/plugin/products/threat-response/api/v1/snapshot", data=body)
    return f'Snapshot {",".join(snapshot_ids)} deleted successfully.', {}, {}


def delete_local_snapshot(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Delete local snapshot from the system.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    connection_id = data_args.get("connection_id")
    client.do_request("DELETE", f"/plugin/products/threat-response/api/v1/conns/{connection_id}", resp_type="content")
    return f"Local snapshot of connection {connection_id} was deleted successfully.", {}, {}


""" CONNECTIONS COMMANDS FUNCTIONS """


def get_connections(client, command_args) -> tuple[str, dict, Union[list, dict]]:
    """
    Implement the 'tanium-tr-list-connections' command - Get list of user connections.

    Note:
        Given either ip/status/hostname/platform as command arguments, the output of the connections will be filtered.

    Args:
        client (Client): client that connects to the Tanium-Threat-Response API.
        command_args (dict): command arguments entered by the user. (limit, offset, ip, status, hostname, platform).

    Returns:
        tuple (str, dict, list[dict]): table output, context output and raw response by the Tanium-Threat-Response API.
    """
    limit = arg_to_number(command_args.get("limit"))
    offset = arg_to_number(command_args.get("offset", 0))
    ips = argToList(arg=command_args.get("ip"))
    statuses = argToList(arg=command_args.get("status"))
    hostnames = argToList(arg=command_args.get("hostname"))
    platforms = argToList(arg=command_args.get("platform"))

    raw_response = client.do_request(method="GET", url_suffix="/plugin/products/threat-response/api/v1/conns")
    assert offset is not None
    from_idx = min(offset, len(raw_response))
    to_idx = min(offset + limit, len(raw_response))  # type: ignore

    is_resp_filtering_required = ips or statuses or hostnames or platforms
    filter_arguments = [(ips, "ip"), (statuses, "status"), (hostnames, "hostname"), (platforms, "platform")]

    connections = raw_response[from_idx:to_idx]
    filtered_connections = []

    for connection in connections:
        if connected_at := connection.get("connectedAt"):
            connection["connectedAt"] = timestamp_to_datestring(connected_at)
        if initiated_at := connection.get("initiatedAt"):
            connection["initiatedAt"] = timestamp_to_datestring(initiated_at)

        if is_resp_filtering_required and are_filters_match_response_content(
            all_filter_arguments=filter_arguments, api_response=connection
        ):
            filtered_connections.append(connection)

    if is_resp_filtering_required:
        connections = filtered_connections

    context = createContext(data=connections, removeNull=True)
    outputs = {"Tanium.Connection(val.id === obj.id)": context}
    table_headers = ["id", "status", "hostname", "message", "ip", "platform", "connectedAt"]
    output_table = tableToMarkdown(
        name="Connections", t=connections, headers=table_headers, headerTransform=pascalToSpace, removeNull=True
    )
    return output_table, outputs, raw_response


def create_connection(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Create new connection.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    ip = str(data_args.get("ip"))
    client_id = str(data_args.get("client_id"))
    hostname = str(data_args.get("hostname"))
    platform = str(data_args.get("platform"))

    target = assign_params(hostname=hostname, clientId=client_id, ip=ip, platform=platform)
    body = {"target": target}

    connection_id, _ = client.do_request(
        "POST", "/plugin/products/threat-response/api/v1/conns/connect", data=body, resp_type="content"
    )
    outputs = {"Tanium.Connection(val.id === obj.id)": {"id": connection_id.decode("utf-8").strip('"')}}
    return f'Initiated connection request to {connection_id.decode("utf-8")}.', outputs, {}


def close_connection(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Close exsisting connection

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    cid = data_args.get("connection_id")
    client.do_request("DELETE", f"/plugin/products/threat-response/api/v1/conns/close/{cid}")
    return f"Connection `{cid}` closed successfully.", {}, {}


def delete_connection(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Delete exsisting connection

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    cid = data_args.get("connection_id")
    client.do_request("DELETE", f"/plugin/products/threat-response/api/v1/conns/delete/{cid}")
    return f"Connection `{cid}` deleted successfully.", {}, {}


def get_events_by_connection(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """List all events in the given connection.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    limit = arg_to_number(data_args.get("limit"))
    offset = arg_to_number(data_args.get("offset"))
    cid = data_args.get("connection_id")
    sort = data_args.get("sort")
    fields = data_args.get("fields")
    event_type = data_args.get("type").lower()
    filter_dict = filter_to_tanium_api_syntax(data_args.get("filter"))
    match = data_args.get("match")

    params = assign_params(limit=limit, offset=offset, sort=sort, fields=fields, match=match)

    if filter_dict:
        g1 = ",".join([str(i) for i in range(len(filter_dict) // 3)])  # A weird param that must be passed
        params["gm1"] = match
        params["g1"] = g1
        params.update(filter_dict)

    if client.api_version == "4.x":
        params["cid"] = cid
        params["type"] = event_type

    raw_response = client.do_request(
        "GET", f"/plugin/products/threat-response/api/v1/conns/{cid}/views/{event_type}/events", params=params
    )

    context = createContext(raw_response, removeNull=True, keyTransform=lambda x: underscoreToCamelCase(x, upper_camel=False))
    outputs = {"TaniumEvent(val.id === obj.id)": context}
    headers = get_event_header(event_type)
    human_readable = tableToMarkdown(
        f"Events for {cid}", context, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


""" RESPONSE ACTIONS COMMANDS FUNCTIONS"""


def get_response_actions(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """List all Response Actions based on the filters provided

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    limit = arg_to_number(data_args.get("limit", 50))
    offset = arg_to_number(data_args.get("offset", 0))
    sort_order = data_args.get("sort_order", "desc")
    partial_computer_name = data_args.get("partial_computer_name", None)
    status = data_args.get("status", None)
    _type = data_args.get("type", None)

    params = {"limit": limit, "offset": offset, "sortOrder": sort_order}
    if partial_computer_name:
        params["queryPartialComputerName"] = partial_computer_name
    if status:
        params["queryStatus"] = status
    if _type:
        params["queryType"] = _type

    raw_response = client.do_request("GET", "/plugin/products/threat-response/api/v1/response-actions", params=params)
    raw_response_data = normalize_api_response(raw_response)  # This is a list of dicts

    context = createContext(raw_response, removeNull=True, keyTransform=lambda x: underscoreToCamelCase(x, upper_camel=False))
    outputs = {"Tanium.ResponseActions(val.id === obj.id)": context}

    headers = ["id", "type", "status", "computerName", "userId", "userName", "results", "expirationTime"]
    human_readable = tableToMarkdown(
        "Response Actions", raw_response_data, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )

    return human_readable, outputs, raw_response


def response_action_gather_snapshot(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Creates a "gatherSnapshot" Response Action for the specified host.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    payload = {
        "type": "gatherSnapshot",
        "options": {},  # Empty options dict is expected for this type
    }

    payload["computerName"] = data_args.get("computer_name")

    if data_args.get("expiration_time"):
        expiration_time = get_future_date(data_args.get("expiration_time"))
        payload["expirationTime"] = expiration_time

    raw_response = client.do_request("POST", "/plugin/products/threat-response/api/v1/response-actions", data=payload)

    raw_response_data = normalize_api_response(raw_response)
    context = createContext(raw_response, removeNull=True, keyTransform=lambda x: underscoreToCamelCase(x, upper_camel=False))
    outputs = {"Tanium.ResponseActions(val.id === obj.id)": context}

    headers = [
        "id",
        "type",
        "status",
        "computerName",
        "userId",
        "userName",
        "results",
        "expirationTime",
        "createdAt",
        "updatedAt",
    ]
    human_readable = tableToMarkdown(
        "Response Actions", raw_response_data, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )

    return human_readable, outputs, raw_response


""" LABELS COMMANDS FUNCTIONS """


def get_labels(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """List all labels.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    limit = arg_to_number(data_args.get("limit", 50))
    offset = arg_to_number(data_args.get("offset", 0))
    raw_response = client.do_request("GET", "/plugin/products/" f"{client.get_threat_response_endpoint()}" f"/api/v1/labels/")
    assert offset is not None
    raw_response_data = normalize_api_response(raw_response)
    from_idx = min(offset, len(raw_response_data))
    to_idx = min(offset + limit, len(raw_response_data))  # type: ignore

    labels = raw_response_data[from_idx:to_idx]

    context = createContext(labels, removeNull=True)
    outputs = {"Tanium.Label(val.id === obj.id)": context}
    headers = ["name", "description", "id", "indicatorCount", "signalCount", "createdAt", "updatedAt"]
    human_readable = tableToMarkdown("Labels", labels, headers=headers, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_label(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Get label by label id.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    label_id = data_args.get("label_id")
    raw_response = client.do_request(
        "GET", "/plugin/products/" f"{client.get_threat_response_endpoint()}" f"/api/v1/labels/{label_id}"
    )

    raw_response_data = normalize_api_response(raw_response)
    context = createContext(raw_response_data, removeNull=True)
    outputs = {"Tanium.Label(val.id && val.id === obj.id)": context}
    headers = ["name", "description", "id", "indicatorCount", "signalCount", "createdAt", "updatedAt"]
    human_readable = tableToMarkdown(
        "Label information", raw_response_data, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


""" FILES COMMANDS FUNCTIONS """


def get_file_downloads(client, command_args) -> tuple[str, dict, Union[list, dict]]:
    """
    Implement the 'tanium-tr-list-file-downloads' command - get a list of all file evidences.

    Note:
        Given either hash, hostname, process_time_start as command arguments,
        the output of the connections will be filtered.

    Args:
        client (Client): client that connects to the Tanium-Threat-Response API.
        command_args (dict): command arguments entered by the user. (limit, offset, ip, status, hostname, platform).

    Returns:
        tuple (str, dict, list[dict]): table output, context output and raw response by the Tanium-Threat-Response API.
    """
    limit = arg_to_number(command_args.get("limit"))
    offset = arg_to_number(command_args.get("offset"))
    sort = command_args.get("sort")
    hashes = argToList(arg=command_args.get("hash"))
    hostnames = argToList(arg=command_args.get("hostname"))
    process_time_start = command_args.get("process_time_start")

    is_filtering_resp_required = hashes or hostnames or process_time_start
    filter_arguments = [(hostnames, "hostname"), (hashes, "hash"), ([process_time_start], "process_creation_time")]

    params = assign_params(limit=limit, offset=offset, sort=sort)
    raw_response = client.do_request("GET", "/plugin/products/threat-response/api/v1/filedownload", params=params)

    files = raw_response.get("fileEvidence", [])
    filtered_files = []

    for file in files:
        if evidence_type := file.get("evidenceType"):
            file["evidence_type"] = evidence_type
            del file["evidenceType"]
        if is_filtering_resp_required and are_filters_match_response_content(
            all_filter_arguments=filter_arguments, api_response=file
        ):
            filtered_files.append(file)

    if is_filtering_resp_required:
        files = filtered_files

    context = createContext(files, removeNull=True, keyTransform=lambda x: underscoreToCamelCase(x, upper_camel=False))
    outputs = {"Tanium.FileDownload(val.uuid === obj.uuid)": context}
    table_headers = ["uuid", "path", "evidenceType", "hostname", "processCreationTime", "size"]
    table = tableToMarkdown("File downloads", context, headers=table_headers, headerTransform=pascalToSpace, removeNull=True)
    return table, outputs, raw_response


def get_downloaded_file(client, data_args):
    """Download file by file id. Return file result.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    file_id = data_args.get("file_id")
    file_content, content_desc = client.do_request(
        "GET", f"plugin/products/threat-response/api/v1/filedownload/data/{file_id}", resp_type="content"
    )

    filename = re.findall("(?<=filename=)(?s)(.*$)", content_desc)[0]

    demisto.results(fileResult(filename, file_content))


def get_file_download_info(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Get file download info by file id.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    file_id = data_args.get("file_id")
    raw_response = client.do_request("GET", f"/plugin/products/threat-response/api/v1/filedownload/{file_id}")

    file = raw_response.get("evidence", {})
    if evidence_type := file.get("evidenceType"):
        file["evidence_type"] = evidence_type
        del file["evidenceType"]

    context = createContext(file, removeNull=True, keyTransform=lambda x: underscoreToCamelCase(x, upper_camel=False))
    outputs = {"Tanium.FileDownload(val.uuid === obj.uuid)": context}
    headers = ["uuid", "path", "evidenceType", "hostname", "processCreationTime", "size"]
    human_readable = tableToMarkdown("File download", context, headers=headers, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def request_file_download(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Request file download at the given path.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    cid = data_args.get("connection_id")
    path = data_args.get("path")
    body = {
        "path": path,
    }
    raw_response = client.do_request("POST", f"/plugin/products/threat-response/api/v1/conns/{cid}/file", data=body)

    filename = os.path.basename(path)
    hr = f"Download request of file {filename} has been sent successfully."
    context = {}
    if task_id := raw_response.get("taskInfo", {}).get("id"):
        hr += f" Task id: {task_id}."

        context = copy.deepcopy(raw_response.get("taskInfo"))
        context.update(context.get("metadata", {}))
        context["taskId"] = task_id

        del context["id"]
        del context["metadata"]

    outputs = {"Tanium.FileDownloadTask(val.taskId === obj.taskId && val.connection === obj.connection)": context}

    return hr, outputs, raw_response


def delete_file_download(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Delete file download from tanium system.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    file_id = data_args.get("file_id")
    client.do_request("DELETE", f"/plugin/products/threat-response/api/v1/filedownload/{file_id}")
    return f"Delete request of file with ID {file_id} has been sent successfully.", {}, {}


def list_files_in_dir(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """List all files in the given directory path.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    connection_id = data_args.get("connection_id")
    dir_path_name = data_args.get("path")
    dir_path = urllib.parse.quote(dir_path_name, safe="")
    limit = int(data_args.get("limit"))
    offset = int(data_args.get("offset"))

    raw_response = client.do_request("GET", f"/plugin/products/threat-response/api/v1/conns/{connection_id}/file/list/{dir_path}")

    files = raw_response.get("entries", [])
    from_idx = min(offset, len(files))
    to_idx = min(offset + limit, len(files))
    files = files[from_idx:to_idx]

    for file in files:
        file["connectionId"] = connection_id
        file["path"] = dir_path_name
        if created := file.get("createdDate"):
            file["createdDate"] = timestamp_to_datestring(created)
        if created := file.get("modifiedDate"):
            file["modifiedDate"] = timestamp_to_datestring(created)

    context = createContext(files, removeNull=True)
    outputs = {"Tanium.File(val.name === obj.name && val.connectionId === obj.connectionId)": context}
    headers = ["name", "path", "connectionId", "createdDate", "modifiedDate", "permissions", "size"]
    human_readable = tableToMarkdown(
        f"Files in directory `{dir_path_name}`", files, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


def get_file_info(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Get file info by file path.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    cid = data_args.get("connection_id")
    path_name = data_args.get("path")
    path = urllib.parse.quote(path_name, safe="")

    raw_response = client.do_request("GET", f"/plugin/products/threat-response/api/v1/conns/{cid}/file/info/{path}")

    context = copy.deepcopy(raw_response)
    info = context.get("info")
    context["connectionId"] = cid
    try:
        if created := info.get("createdDate"):
            info["createdDate"] = timestamp_to_datestring(created)
        if modified := info.get("modifiedDate"):
            info["modifiedDate"] = timestamp_to_datestring(modified)
    except ValueError:
        pass
    context.update(info)
    if info:
        del context["info"]

    outputs = {"Tanium.File(val.path === obj.path && val.connectionId === obj.connectionId)": context}
    headers = ["path", "name", "connectionId", "type", "createdDate", "modifiedDate"]
    human_readable = tableToMarkdown(
        f"Information for file `{path_name}`", context, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


def delete_file_from_endpoint(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Delete file by file path from connection.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    cid = data_args.get("connection_id")
    full_path = data_args.get("path")
    path = urllib.parse.quote(full_path)
    client.do_request("DELETE", f"/plugin/products/threat-response/api/v1/conns/{cid}/file/delete/{path}")
    return f"Delete request of file {full_path} from endpoint {cid} has been sent successfully.", {}, {}


""" PROCESS COMMANDS FUNCTIONS """


def get_process_info(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Get process info

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    connection_id = data_args.get("connection_id")
    ptid = data_args.get("ptid")
    raw_response = client.do_request(
        "GET", f"/plugin/products/threat-response/api/v1/conns/{connection_id}/processtrees/{ptid}", params={"context": "node"}
    )

    context = createContext(raw_response, removeNull=True, keyTransform=lambda x: underscoreToCamelCase(x, upper_camel=False))
    outputs = {"Tanium.ProcessInfo(val.id === obj.id)": context}
    headers = ["pid", "processTableId", "parentProcessTableId", "processPath"]
    human_readable = tableToMarkdown(
        f"{PROCESS_TEXT} {ptid}", context, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


def get_events_by_process(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Get events by type by proccess.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    limit = arg_to_number(data_args.get("limit"))
    offset = arg_to_number(data_args.get("offset"))
    cid = data_args.get("connection_id")
    ptid = data_args.get("ptid")
    event_type = data_args.get("type").lower()
    params = {"limit": limit, "offset": offset}
    if client.api_version == "4.x":
        params.update({"cid": cid, "ptid": ptid, "type": event_type})

    raw_response = client.do_request(
        "GET",
        f"plugin/products/threat-response/api/v1/conns/{cid}/processevents/{ptid}/{event_type}",
        params={"limit": limit, "offset": offset},
    )

    context = createContext(raw_response, removeNull=True, keyTransform=lambda x: underscoreToCamelCase(x, upper_camel=False))
    outputs = {"Tanium.ProcessEvent(val.id && val.id === obj.id)": context}
    headers = ["id", "detail", "type", "timestamp", "operation"]
    human_readable = tableToMarkdown(
        f"Events for process {ptid}", context, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


def get_process_children(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Get all process childrens data

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    limit = arg_to_number(data_args.get("limit"))
    offset = arg_to_number(data_args.get("offset"))
    connection_id = data_args.get("connection_id")
    ptid = data_args.get("ptid")
    raw_response = client.do_request(
        "GET",
        f"/plugin/products/threat-response/api/v1/conns/{connection_id}/processtrees/{ptid}",
        params={"context": "children", "limit": limit, "offset": offset},
    )

    context = createContext(raw_response, removeNull=True, keyTransform=lambda x: underscoreToCamelCase(x, upper_camel=False))
    outputs = {"Tanium.ProcessChildren(val.id === obj.id)": context}
    headers = ["pid", "processTableId", "parentProcessTableId"]
    human_readable = tableToMarkdown(
        f"{PROCESS_CHILDREN_TEXT} {ptid}", context, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


def get_parent_process(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Get parent process data, using ptid

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    connection_id = data_args.get("connection_id")
    ptid = data_args.get("ptid")
    raw_response = client.do_request(
        "GET", f"/plugin/products/threat-response/api/v1/conns/{connection_id}/processtrees/{ptid}", params={"context": "parent"}
    )

    context = createContext(raw_response, removeNull=True, keyTransform=lambda x: underscoreToCamelCase(x, upper_camel=False))
    outputs = {"Tanium.ProcessParent(val.id === obj.id)": context}
    headers = ["id", "pid", "processTableId", "parentProcessTableId"]
    human_readable = tableToMarkdown(
        f"{PARENT_PROCESS_TEXT} {ptid}", context, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


def get_process_tree(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Get all proccess related data - process tree

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    limit = arg_to_number(data_args.get("limit"))
    offset = arg_to_number(data_args.get("offset"))
    cid = data_args.get("connection_id")
    ptid = data_args.get("ptid")
    context = data_args.get("context")
    params = assign_params(context=context, limit=limit, offset=offset)
    raw_response = client.do_request(
        "GET", f"plugin/products/threat-response/api/v1/conns/{cid}/processtrees/{ptid}", params=params
    )

    headers = ["id", "pid", "processTableId", "parentProcessTableId"]

    context = createContext(raw_response, removeNull=True, keyTransform=lambda x: underscoreToCamelCase(x, upper_camel=False))

    human_readable = tableToMarkdown(
        f"{PROCESS_TEXT} {ptid}", context, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )

    outputs = {"Tanium.ProcessTree(val.id && val.id === obj.id)": context}

    return human_readable, outputs, raw_response


""" EVIDENCE COMMANDS FUNCTIONS """


def list_evidence(client, commands_args) -> tuple[str, dict, Union[list, dict]]:
    """
    Implement the 'tanium-tr-event-evidence-list' command - get combined evidence across all types.

    Note:
        Given either type/hostname as command arguments, the output of the connections will be filtered.

    Args:
        client (Clinet): client that connects to the Tanium-Threat-Response API.
        command_args (dict): command arguments entered by the user. (limit, offset, hostname, sort, type).

    Returns:
        tuple (str, dict, list[dict]): table output, context output and raw response by the Tanium-Threat-Response API.
    """
    limit = arg_to_number(commands_args.get("limit", 50))
    offset = arg_to_number(commands_args.get("offset", 0))
    hostnames = argToList(arg=commands_args.get("hostname"))
    sort = commands_args.get("sort")
    type = commands_args.get("type")

    params = assign_params(sort=sort, type=type)
    raw_response = client.do_request("GET", "/plugin/products/threat-response/api/v1/evidence", params=params)

    filter_arguments = [(hostnames, "hostname")]
    assert offset is not None
    from_idx = min(offset, len(raw_response))
    to_idx = min(offset + limit, len(raw_response))  # type: ignore

    evidences = raw_response[from_idx:to_idx]
    filtered_evidences_by_hostname = []

    for item in evidences:
        if created := item.get("createdAt"):
            try:
                item["createdAt"] = timestamp_to_datestring(created)
            except ValueError:
                pass
        if hostnames and are_filters_match_response_content(all_filter_arguments=filter_arguments, api_response=item):
            filtered_evidences_by_hostname.append(item)

    if hostnames:
        evidences = filtered_evidences_by_hostname

    context = createContext(data=evidences, removeNull=True)
    outputs = {"Tanium.Evidence(val.uuid && val.uuid === obj.uuid)": context}
    table_headers = ["uuid", "name", "evidenceType", "hostname", "createdAt", "username"]
    table_output = tableToMarkdown(
        name="Evidence list", t=evidences, headers=table_headers, headerTransform=pascalToSpace, removeNull=True
    )
    return table_output, outputs, raw_response


def event_evidence_get_properties(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Get evidences properties

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    evidence_properties = client.do_request("GET", "plugin/products/threat-response/api/v1/event-evidence/properties")

    outputs = {"Tanium.EvidenceProperties(val.value === obj.value)": evidence_properties}
    human_readable = tableToMarkdown("Evidence Properties", evidence_properties, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, evidence_properties


def get_evidence_by_id(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Get evidence by id

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    evidence_id = data_args.get("evidence_id")
    raw_response = client.do_request("GET", f"/plugin/products/threat-response/api/v1/event-evidence/{evidence_id}")

    evidence = raw_response.get("evidence", {})
    data = evidence.get("data", {})
    context = copy.deepcopy(evidence)
    context.update(data)
    if data:
        del context["data"]

    context = createContext(context, removeNull=True, keyTransform=lambda x: underscoreToCamelCase(x, upper_camel=False))
    outputs = {"Tanium.Evidence(val.uuid && val.uuid === obj.uuid)": context}
    headers = ["uuid", "timestamp", "hostname", "username", "summary", "evidenceType", "created", "processTableId"]
    human_readable = tableToMarkdown(
        "Evidence information", context, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


def create_evidence(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Create evidence from event, using client id and process table id

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    cid = data_args.get("connection_id")
    ptid = data_args.get("ptid")
    hostname = data_args.get("hostname")
    summary = data_args.get("summary")

    params = {"match": "all", "f1": "process_table_id", "o1": "eq", "v1": ptid}
    # call get-events-by-connection
    process_data = client.do_request(
        "GET", f"/plugin/products/threat-response/api/v1/conns/{cid}/views/process/events", params=params
    )

    if not process_data:
        raise ValueError("Invalid connection_id or ptid.")

    evidence = {
        "recorderId": ptid,
        "connectionId": cid,
        "hostname": hostname,
        "data": process_data[0],
        "eventType": "ProcessEvent",
        "summary": summary if summary else process_data[0].get("process_path"),
    }

    body = {"evidence": evidence}

    client.do_request("POST", "/plugin/products/threat-response/api/v1/event-evidence", data=body)
    return "Evidence have been created.", {}, {}


def delete_evidence(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Delete event evidence from tanuim, using evidence ids.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    evidence_ids = argToList(data_args.get("evidence_ids"))
    body = {"ids": evidence_ids}
    client.do_request("DELETE", "/plugin/products/threat-response/api/v1/event-evidence", data=body)
    return f'Evidence {",".join(evidence_ids)} has been deleted successfully.', {}, {}


def get_task_by_id(client, data_args) -> tuple[str, dict, Union[list, dict]]:
    """Get task status by task id.

    :type client: ``Client``
    :param client: client which connects to api.
    :type data_args: ``dict``
    :param data_args: request arguments.

    :return: human readable format, context output and the original raw response.
    :rtype: ``tuple``

    """
    task_id = data_args.get("task_id")
    raw_response = client.do_request("GET", f"/plugin/products/threat-response/api/v1/tasks/{task_id}")

    data = raw_response.get("data")
    context = copy.deepcopy(raw_response)
    context.update(data)
    if data:
        del context["data"]

    context = createContext(context, removeNull=True)
    outputs = {"Tanium.Task(val.id === obj.id)": context}
    headers = ["id", "status"]
    human_readable = tableToMarkdown("Task information", context, headers=headers, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_system_status(client, command_args) -> tuple[str, dict, Union[list, dict]]:
    """
    Implement the 'tanium-tr-get-system-status' command - get system status, to get client-id for
    `create-connection` command.

    Note:
        Given either ip/status/hostname/platform as command arguments, the output of the connections will be filtered.

    Args:
        client (Client): client that connects to the Tanium-Threat-Response API.
        command_args (dict): command arguments entered by the user. (limit, offset, ip, status, hostname, platform).

    Returns:
        tuple (str, dict, list[dict]): table output, context output and raw response by the Tanium-Threat-Response API.
    """
    limit = arg_to_number(command_args.get("limit", 50))
    offset = arg_to_number(command_args.get("offset", 0))
    statuses = argToList(arg=command_args.get("status"))
    hostnames = argToList(arg=command_args.get("hostname"))
    ipaddrs_client = argToList(arg=command_args.get("ip_client"))
    ipaddrs_server = argToList(arg=command_args.get("ip_server"))
    port = arg_to_number(arg=command_args.get("port"))

    is_resp_filtering_required = statuses or hostnames or ipaddrs_client or ipaddrs_client or ipaddrs_server or port
    filter_arguments = [
        (statuses, "status"),
        (hostnames, "host_name"),
        (ipaddrs_client, "ipaddress_client"),
        (ipaddrs_server, "ipaddress_server"),
        ([port], "port_number"),
    ]

    raw_response = client.do_request("GET", "/api/v2/system_status")
    data = raw_response.get("data", [{}])
    active_computers = []
    assert offset is not None
    from_idx = min(offset, len(data))
    to_idx = min(offset + limit, len(data))  # type: ignore

    for item in data[from_idx:to_idx]:
        if client_id := item.get("computer_id"):
            item["client_id"] = client_id
            if is_resp_filtering_required:
                if are_filters_match_response_content(all_filter_arguments=filter_arguments, api_response=item):
                    active_computers.append(item)
            else:
                active_computers.append(item)

    context = createContext(active_computers, removeNull=True, keyTransform=lambda x: underscoreToCamelCase(x, upper_camel=False))
    outputs = {"Tanium.SystemStatus(val.clientId === obj.clientId)": context}
    headers = ["hostName", "clientId", "ipaddressClient", "ipaddressServer", "portNumber"]
    human_readable = tableToMarkdown(
        "Reporting clients", context, headers=headers, headerTransform=pascalToSpace, removeNull=True
    )
    return human_readable, outputs, raw_response


""" COMMANDS MANAGER / SWITCH PANEL """


def main():
    params = demisto.params()
    username = params.get("credentials", {}).get("identifier")
    password = params.get("credentials", {}).get("password")

    # Remove proxy if not set to true in params
    handle_proxy()
    command = demisto.command()

    client = Client(
        params.get("url").strip("/"),
        username,
        password,
        api_token=password if "_token" in username else None,
        verify=not params.get("insecure", False),
        api_version=params.get("api_version", "3.x"),
    )

    demisto.info(f"Command being called is {command}")

    commands = {
        "test-module": test_module,
        "tanium-tr-get-intel-doc-by-id": get_intel_doc,
        "tanium-tr-list-intel-docs": get_intel_docs,
        "tanium-tr-intel-docs-labels-list": get_intel_docs_labels_list,
        "tanium-tr-intel-docs-add-label": add_intel_docs_label,
        "tanium-tr-intel-docs-remove-label": remove_intel_docs_label,
        "tanium-tr-intel-doc-create": create_intel_doc,
        "tanium-tr-intel-doc-update": update_intel_doc,
        "tanium-tr-intel-doc-delete": delete_intel_doc,
        "tanium-tr-intel-deploy": deploy_intel,
        "tanium-tr-intel-deploy-status": get_deploy_status,
        "tanium-tr-start-quick-scan": start_quick_scan,
        "tanium-tr-list-alerts": get_alerts,
        "tanium-tr-get-alert-by-id": get_alert,
        "tanium-tr-alert-update-state": alert_update_state,
        "tanium-tr-create-snapshot": create_snapshot,
        "tanium-tr-delete-snapshot": delete_snapshot,
        "tanium-tr-list-snapshots": list_snapshots,
        "tanium-tr-delete-local-snapshot": delete_local_snapshot,
        "tanium-tr-list-connections": get_connections,
        "tanium-tr-create-connection": create_connection,
        "tanium-tr-delete-connection": delete_connection,
        "tanium-tr-close-connection": close_connection,
        "tanium-tr-list-labels": get_labels,
        "tanium-tr-get-label-by-id": get_label,
        "tanium-tr-list-events-by-connection": get_events_by_connection,
        "tanium-tr-get-events-by-process": get_events_by_process,
        "tanium-tr-get-process-info": get_process_info,
        "tanium-tr-get-process-children": get_process_children,
        "tanium-tr-get-parent-process": get_parent_process,
        "tanium-tr-get-process-tree": get_process_tree,
        "tanium-tr-event-evidence-list": list_evidence,
        "tanium-tr-event-evidence-get-properties": event_evidence_get_properties,
        "tanium-tr-get-evidence-by-id": get_evidence_by_id,
        "tanium-tr-create-evidence": create_evidence,
        "tanium-tr-delete-evidence": delete_evidence,
        "tanium-tr-list-file-downloads": get_file_downloads,
        "tanium-tr-get-file-download-info": get_file_download_info,
        "tanium-tr-request-file-download": request_file_download,
        "tanium-tr-delete-file-download": delete_file_download,
        "tanium-tr-list-files-in-directory": list_files_in_dir,
        "tanium-tr-get-file-info": get_file_info,
        "tanium-tr-delete-file-from-endpoint": delete_file_from_endpoint,
        "tanium-tr-get-task-by-id": get_task_by_id,
        "tanium-tr-get-system-status": get_system_status,
        "tanium-tr-get-response-actions": get_response_actions,
        "tanium-tr-response-action-gather-snapshot": response_action_gather_snapshot,
    }

    try:
        if command == "fetch-incidents":
            # demisto.getLastRun() will returns an obj with the previous run in it.
            last_run = demisto.getLastRun()
            alerts_states_to_retrieve = demisto.params().get("filter_alerts_by_state")
            filter_label_name = demisto.params().get("filter_by_label_name", "")
            first_fetch = demisto.params().get("first_fetch")
            max_fetch = int(demisto.params().get("max_fetch", "50"))

            incidents, next_run = fetch_incidents(
                client, alerts_states_to_retrieve, filter_label_name, last_run, first_fetch, max_fetch
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        if command == "tanium-tr-get-downloaded-file":
            get_downloaded_file(client, demisto.args())

        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_results(results=CommandResults(readable_output=human_readable, outputs=outputs, raw_response=raw_response))

    except Exception as e:
        if command == "fetch-incidents":
            LOG(traceback.format_exc())
            LOG.print_log()
            raise

        else:
            error_msg = str(e)
            if command in COMMANDS_DEPEND_ON_CONNECTIVITY:
                error_msg += DEPENDENT_COMMANDS_ERROR_MSG
            return_error(f"Error in Tanium Threat Response Integration: {error_msg}", traceback.format_exc())


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import math

from CommonServerUserPython import *

""" IMPORTS """
from typing import Dict, Tuple, List, Optional, Any, Union
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

"""GLOBALS/PARAMS
Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI.

    INTEGRATION_COMMAND_NAME:
        Command names prefix used for all commands.

    INTEGRATION_CONTEXT_NAME:
        Context output name used in most outputs.

    ALERTS_TRANS
        Transformation map for alerts to be used with create_context_result

    ARCHIVE_SEARCH_TRANS
        Transformation map for archive search to be used with create_context_result

    CASES_TRANS
        Transformation map for cases to be used with create_context_result

    ENDPOINTS_TRANS
        Transformation map for endpoints to be used with build_transformation_dict

    EVENTS_TRANS
        Transformation map for events to be used with build_transformation_dict

    LISTS_TRANS
        Transformation map for lists to be used with create_context_result

    LIST_ITEM_TRANS
        Transformation map for list items to be used with create_context_result

    NOTES_TRANS
        Transformation map for notes to be used with create_context_result

    RULES_TRANS
        Transformation map for rules to be used with create_context_result
"""
INTEGRATION_NAME = "FireEye Helix"
INTEGRATION_COMMAND_NAME = "fireeye-helix"
INTEGRATION_CONTEXT_NAME = "FireEyeHelix"
DEFAULT_PAGE_SIZE = 30
ALERTS_TRANS = {
    "id": "ID",
    "alert_type.id": "AlertTypeID",
    "alert_type.name": "Name",
    "assigned_to.id": "AssigneeID",
    "assigned_to.name": "AssigneeName",
    "created_by.id": "CreatorID",
    "created_by.name": "CreatorName",
    "updated_by.id": "UpdaterID",
    "updated_by.name": "UpdaterName",
    "created_at": "CreatedTime",
    "updated_at": "ModifiedTime",
    "alert_type_details.detail.processpath": "ProcessPath",
    "alert_type_details.detail.process": "Process",
    "alert_type_details.detail.pprocess": "ParentProcess",
    "alert_type_details.detail.confidence": "Confidence",
    "alert_type_details.detail.sha1": "SHA1",
    "alert_type_details.detail.md5": "MD5",
    "alert_type_details.detail.hostname": "Hostname",
    "alert_type_details.detail.pid": "PID",
    "alert_type_details.detail.byte": "Size",
    "alert_type_details.detail.virus": "Virus",
    "alert_type_details.detail.result": "Result",
    "alert_type_details.detail.malwaretype": "MalwareType",
    "alert_type_details.detail.filename": "FileName",
    "alert_type_details.detail.regpath": "RegPath",
    "alert_type_details.detail.eventtime": "EventTime",
    "alert_type_details.detail.iocnames": "IOCNames",
    "alert_type_details.detail.srcipv4": "SourceIPv4",
    "alert_type_details.detail.srcipv6": "SourceIPv6",
    "alert_type_details.detail.dstipv4": "DestinationIPv4",
    "alert_type_details.detail.dstipv6": "DestinationIPv6",
    "alert_type_details.detail.dstport": "DestinationPort",
    "alert_type_details.detail.uri": "URI",
    "alert_type_details.detail.domain": "Domain",
    "alert_type_details.detail.useragent": "UserAgent",
    "alert_type_details.detail.httpmethod": "HttpMethod",
    "events_count": "EventsCount",
    "notes_count": "NotesCount",
    "closed_state": "ClosedState",
    "closed_reason": "ClosedReason",
    "description": "Description",
    "first_event_at": "FirstEventTime",
    "last_event_at": "LastEventTime",
    "external_ips": "ExternalIP",
    "internal_ips": "InternalIP",
    "message": "Message",
    "products": "Products",
    "risk": "Risk",
    "severity": "Severity",
    "state": "State",
    "tags": "Tags",
    "type": "Type",
}
ARCHIVE_SEARCH_TRANS = {
    "id": "ID",
    "percentComplete": "PercentComplete",
    "query": "Query",
    "state": "State",
}
CASES_TRANS = {
    "id": "ID",
    "name": "Name",
    "alerts_count": "AlertsCount",
    "assigned_to.id": "AssigneeID",
    "assigned_to.name": "AssigneeName",
    "created_by.id": "CreatorID",
    "created_by.name": "CreatorName",
    "updated_by.id": "UpdaterID",
    "updated_by.name": "UpdaterName",
    "created_at": "CreatedTime",
    "updated_at": "ModifiedTime",
    "description": "Description",
    "events_count": "EventsCount",
    "info_links": "InfoLinks",
    "notes_count": "NotesCount",
    "priority": "Priority",
    "priority_order": "PriorityOrder",
    "severity": "Severity",
    "state": "State",
    "status": "Status",
    "tags": "Tags",
    "total_days_unresolved": "TotalDaysUnresolved",
}
ENDPOINTS_TRANS = {
    "id": "ID",
    "customer_id": "CustomerID",
    "device_id": "DeviceID",
    "domain": "Domain",
    "hostname": "Hostname",
    "mac_address": "MACAddress",
    "operating_system": "OS",
    "primary_ip_address": "IP",
    "updated_at": "UpdatedTime",
    "containment_state": "ContainmentState",
}
EVENTS_TRANS = {
    "eventid": "ID",
    "eventtype": "Type",
    "result": "Result",
    "matched_at": "MatchedAt",
    "confidence": "Confidence",
    "status": "Status",
    "eventtime": "EventTime",
    "detect_ruleids": "DetectedRuleID",
    "pid": "PID",
    "process": "Process",
    "processpath": "ProcessPath",
    "filename": "FileName",
    "filepath": "FilePath",
    "devicename": "DeviceName",
    "bytes": "Size",
    "virus": "Virus",
    "malwaretype": "MalwareType",
    "createdtime": "CreatedTime",
    "class": "Class",
    "md5": "MD5",
    "sha1": "SHA1",
    "protocol": "Protocol",
    "srcipv4": "SourceIPv4",
    "srcipv6": "SourceIPv6",
    "srcport": "SourcePort",
    "srclongitude": "SourceLongitude",
    "dstipv4": "DestinationIPv4",
    "srclatitude": "SourceLatitude",
    "dstipv6": "DestinationIPv6",
    "dstport": "DestinationPort",
    "reported_at": "ReportTime",
    "is_false_positive": "FalsePositive",
    "domain": "Domain",
    "mailfrom": "From",
    "srcdomain": "SourceDomain",
    "srcisp": "SourceISP",
    "dstisp": "DestinationISP",
    "rcptto": "RcpTo",
    "to": "To",
    "inreplyto": "InReplyTo",
    "attachment": "Attachment",
}
LISTS_TRANS = {
    "id": "ID",
    "short_name": "ShortName",
    "name": "Name",
    "type": "Type",
    "description": "Description",
    "types": "ContentTypes",
    "created_by.id": "CreatorID",
    "created_by.name": "CreatorName",
    "updated_by.id": "UpdatedByID",
    "updated_by.name": "UpdatedByName",
    "created_at": "CreatedTime",
    "updated_at": "UpdatedTime",
    "is_internal": "Internal",
    "is_protected": "Protected",
    "is_active": "Active",
}
LIST_ITEM_TRANS = {"id": "ID", "value": "Value", "type": "Type", "risk": "Risk", "notes": "Notes", "list": "ListID"}
NOTES_TRANS = {
    "id": "ID",
    "created_at": "CreatedTime",
    "updated_at": "UpdatedTime",
    "note": "Message",
    "created_by.id": "CreatorID",
    "created_by.name": "CreatorName",
}
RULES_TRANS = {
    "id": "ID",
    "_rulePack": "RulePack",
    "description": "Description",
    "internal": "Internal",
    "deleted": "Deleted",
    "enabled": "Enabled",
    "supported": "Supported",
    "_createdBy.id": "CreatorID",
    "_createdBy.name": "CreatorName",
    "_updatedBy.id": "UpdatedByID",
    "_updatedBy.name": "UpdatedByName",
    "risk": "Risk",
    "confidence": "Confidence",
    "severity": "Severity",
    "tags": "Tags",
    "type": "Type",
}


class Client(BaseClient):
    def test_module(self):
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            Response content
        """
        suffix = "/api/v3/alerts"
        self._http_request("GET", suffix, params={"limit": 1})

    def list_alerts(self, limit: int = None, offset: int = None, created_at__gte: str = None) -> Dict:
        """Returns all alerts by sending a GET request.

        Args:
            limit: The maximum number of alerts to return.
            offset: The initial index from which to return the results.
            created_at__gte: Date time string. Will fetch alerts with a create time greater or equal to this value

        Returns:
            Response from API.
        """
        suffix = "/api/v3/alerts"
        # Dictionary of params for the request
        params = assign_params(limit=limit, offset=offset, created_at__gte=created_at__gte)
        # Send a request using our http_request wrapper
        return self._http_request("GET", suffix, params=params)

    def get_alert_by_id(self, _id: Optional[Any]) -> Dict:
        """Return a single alert by sending a GET request.

        Args:
            _id: ID  of the alert to get.

        Returns:
            Response from API.
        """
        suffix = f"/api/v3/alerts/{_id}"
        return self._http_request("GET", suffix)

    def search(self, query: str = None):
        """Searches for alerts based on query

        Args:
            query: Search query written in mql

        Returns:
            Response from API.
        """
        suffix = "/api/v1/search"
        params = assign_params(query=query)
        return self._http_request("GET", suffix, params=params, timeout=DEFAULT_PAGE_SIZE)

    def archive_search_alert(self, query: str = None):
        """Searches for alerts based on query

        Args:
            query: Search query written in mql

        Returns:
            Response from API.
        """
        suffix = "/api/v1/search/archive"
        params = assign_params(query=query)
        return self._http_request("GET", suffix, params=params)

    def archive_search(self, query: str = None) -> Dict:
        """Searches for events using archive search

        Args:
            query: Search query written in mql

        Returns:
            Response from API.
        """
        suffix = "/api/v1/search/archive"
        params = assign_params(query=query)
        return self._http_request("GET", suffix, params=params)

    def get_archive_search(self, search_id: int = None) -> Dict:
        """Gets archive search

        Args:
            search_id: Search id

        Returns:
            Response from API.
        """
        suffix = f"/api/v1/search/archive/{search_id}"
        return self._http_request("GET", suffix)

    def get_archive_search_results(self, search_id: int = None):
        """Searches for alerts based on query

        Args:
            search_id: Search ID to get

        Returns:
            Response from API.
        """
        suffix = f"/api/v1/search/archive/{search_id}/results"
        return self._http_request("GET", suffix, timeout=DEFAULT_PAGE_SIZE)

    def update_alert_by_id(self, body: Dict) -> Dict:
        """Updates a single alert by sending a POST request.

        Args:
            body: Request body to update dictionary.

        Returns:
            Response from API.
        """
        suffix = "/api/v3/alerts"
        return self._http_request("POST", suffix, json_data=body)

    def get_alert_notes(self, alert_id):
        """Get all notes related to alert by sending a GET request.

        Args:
            alert_id: Alert ID.

        Returns:
            Response from API.
        """
        suffix = f"/api/v3/alerts/{alert_id}/notes"
        return self._http_request("GET", suffix)

    def create_alert_note(self, alert_id: Optional[Any], note: Optional[Any]) -> Dict:
        """Creates a single note for an alert by sending a POST request.

        Args:
            alert_id: Alert ID to create note for.
            note: Note to add to alert.

        Returns:
            Response from API.
        """
        suffix = f"/api/v3/alerts/{alert_id}/notes"
        body = assign_params(note=note)
        return self._http_request("POST", suffix, json_data=body)

    def delete_alert_note(self, alert_id: Optional[Any], note_id: Optional[Any]) -> Dict:
        """Deletes a single note for an alert by sending a DELETE request.

        Args:
            alert_id: Alert ID to delete note for.
            note_id: Note ID.

        Returns:
            Response from API.
        """
        suffix = f"/api/v3/alerts/{alert_id}/notes/{note_id}"
        return self._http_request("DELETE", suffix, resp_type="")

    def get_events_by_alert(self, alert_id: Optional[Any]) -> Dict:
        """Fetches events for an alert by sending a GET request.

        Args:
            alert_id: Alert ID to get events for.

        Returns:
            Response from API.
        """
        suffix = f"/api/v3/alerts/{alert_id}/events"
        return self._http_request("GET", suffix)

    def get_endpoints_by_alert(self, alert_id: Optional[Any], offset: Optional[Any] = None) -> Dict:
        """Fetches endpoints for an alert by sending a GET request.

        Args:
            alert_id: Alert ID to get endpoints for.
            offset: Offset to the result

        Returns:
            Response from API.
        """
        suffix = f"/api/v3/alerts/{alert_id}/endpoints"
        params = assign_params(offset=offset)
        return self._http_request("GET", suffix, params=params)

    def get_cases_by_alert(
        self, alert_id: Optional[Any], limit: Optional[Any] = None, offset: Optional[Any] = None, order_by: Optional[Any] = None
    ) -> Dict:
        """Fetches cases for an alert by sending a GET request.

        Args:
            alert_id: Alert ID to get endpoints for.
            limit: Number of results to return per page.
            offset: The initial index from which to return the results.
            order_by: Which field to use when ordering the results.

        Returns:
            Response from API.
        """
        suffix = f"/api/v3/alerts/{alert_id}/cases"
        body = assign_params(limit=limit, offset=offset, order_by=order_by)
        body = body if body else None
        return self._http_request("GET", suffix, json_data=body)

    def get_event_by_id(self, event_id: Optional[Any]) -> Dict:
        """Fetches an event by id via a GET request.

        Args:
            event_id: ID of an event.

        Returns:
            Response from API.
        """
        suffix = f"/api/v1/events/{event_id}"
        return self._http_request("GET", suffix)

    def get_lists(
        self,
        limit: int = None,
        offset: int = None,
        created_at: str = None,
        description: str = None,
        is_active: bool = None,
        is_internal: bool = None,
        is_protected: bool = None,
        name: str = None,
        short_name: str = None,
        type: str = None,
        updated_at: str = None,
        usage: str = None,
        order_by: str = None,
    ) -> Dict:
        """Fetches lists by a GET request

        Args:
            limit: Number of results to return per page.
            offset: The initial index from which to return the results.
            created_at: Creation date of the list.
            description: Description of the list.
            is_active: Set to true if the list is active.
            is_internal: Set to true if the list is internal.
            is_protected: Set to true if list is protected.
            name: Name of the list.
            short_name: Short name of the list.
            type: Type of the list.
            updated_at: The time the list was last updated at.
            usage: Multiple values may be separated by commas.
            order_by: Which field to use when ordering the results.

        Returns:
            Response from API.
        """
        suffix = "/api/v3/lists"
        params = assign_params(
            limit=limit,
            offset=offset,
            created_at=created_at,
            description=description,
            is_active=is_active,
            is_internal=is_internal,
            is_protected=is_protected,
            name=name,
            short_name=short_name,
            type=type,
            updated_at=updated_at,
            usage=usage,
            order_by=order_by,
        )
        return self._http_request("GET", suffix, params=params)

    def get_list_by_id(self, list_id: Optional[Any]) -> Dict:
        """Get a list by id via a GET request

        Args:
            list_id: ID of the list

        Returns:
            Response from API.
        """
        suffix = f"/api/v3/lists/{list_id}"
        return self._http_request("GET", suffix)

    def create_list(
        self,
        name: Optional[str],
        usage: str = None,
        short_name: str = None,
        is_internal: bool = None,
        is_active: bool = None,
        is_protected: bool = None,
        is_hidden: bool = None,
        type: str = None,
        description: str = None,
    ) -> Dict:
        """Creates a list using a POST request

        Args:
            name: Name of the list.
            short_name: Short name of the list.
            is_internal: Boolean flag for is internal.
            is_active: Boolean flag for is active.
            is_protected: Boolean flag for is protected.
            is_hidden: Boolean flag for is hiddden.
            usage: Usage of the list.
            type: Type of the list.
            description: Description of the list.

        Returns:
            Response from API.
        """
        suffix = "/api/v3/lists"
        body = assign_params(
            name=name,
            short_name=short_name,
            is_internal=is_internal,
            is_active=is_active,
            is_protected=is_protected,
            is_hidden=is_hidden,
            type=type,
            description=description,
        )
        body["usage"] = argToList(usage)
        return self._http_request("POST", suffix, json_data=body)

    def update_list(
        self,
        list_id: int,
        name: str = None,
        usage: str = None,
        short_name: str = None,
        is_internal: bool = None,
        is_active: bool = None,
        is_protected: bool = None,
        is_hidden: bool = None,
        type: str = None,
        description: str = None,
    ) -> Dict:
        """Creates a list using a POST request

        Args:
            list_id: ID of the list.
            name: Name of the list.
            short_name: Short name of the list.
            is_internal: Boolean flag for is internal.
            is_active: Boolean flag for is active.
            is_protected: Boolean flag for is protected.
            is_hidden: Boolean flag for is hiddden.
            usage: Usage of the list.
            type: Type of the list.
            description: Description of the list.

        Returns:
            Response from API.
        """
        suffix = f"/api/v3/lists/{list_id}"
        body = assign_params(
            name=name,
            short_name=short_name,
            is_internal=is_internal != "false" if is_internal else is_internal,
            is_active=is_active != "false" if is_active else is_active,
            is_protected=is_protected != "false" if is_protected else is_protected,
            is_hidden=is_hidden != "false" if is_hidden else is_hidden,
            type=type,
            description=description,
        )
        body["usage"] = argToList(usage)
        return self._http_request("PATCH", suffix, json_data=body)

    def delete_list(self, list_id: Optional[Any]) -> Dict:
        """Deletes a list using DELETE request

        Args:
            list_id: ID of a list.

        Returns:
            Response from API
        """
        suffix = f"/api/v3/lists/{list_id}"
        return self._http_request("DELETE", suffix, resp_type="content")

    def list_sensors(self, limit: int = None, offset: int = None, hostname: str = None, status: str = None) -> Dict:
        """Fetches sensors using GET request

        Args:
            limit: Number of results to return per page.
            offset: The initial index from which to return the results.
            hostname: Host name of the sensor.
            status: Status of the sensor.

        Returns:
            Response from API
        """
        suffix = "/api/v3/sensors"
        params = assign_params(limit=limit, offset=offset, hostname=hostname, status=status)
        return self._http_request("GET", suffix, params=params)

    def list_rules(self, limit: int = None, offset: int = None, sort: str = None) -> Dict:
        """Fetches rules using GET request

        Args:
            limit: Number of results to return per page.
            offset: The initial index from which to return the results.
            sort: Comma-separated list of field names to sort the results by.

        Returns:
            Response from API
        """
        suffix = "/api/v1/rules"
        params = assign_params(limit=limit, offset=offset, sort=sort)
        return self._http_request("GET", suffix, params=params)

    def edit_rule(self, rule_id: str, enabled: bool = None) -> Dict:
        """Edit a single rule using PATCH request

        Args:
            rule_id: ID of the rule.
            enabled: Is the rule enabled.

        Returns:
            Response from API
        """
        suffix = f"/api/v1/rules/{rule_id}"
        body = assign_params(enabled=enabled)
        return self._http_request("PATCH", suffix, json_data=body)

    def add_list_item(self, list_id: Optional[int], type: str, value: str, risk: str = None, notes: str = None) -> Dict:
        """Adds a single item list to a list

        Args:
            list_id: List id.
            type: Type of list item.
            value: Value of list item.
            risk: Risk of list item.
            notes: Notes for list item.

        Returns:
            Respone from API
        """
        suffix = f"/api/v3/lists/{list_id}/items"
        body = assign_params(type=type, value=value, risk=risk, notes=notes)
        return self._http_request("POST", suffix, json_data=body)

    def update_list_item(
        self, list_id: int, item_id: int, type: str = None, value: str = None, risk: str = None, notes: str = None
    ) -> Dict:
        """Updates a single item list

        Args:
            list_id: List id.
            item_id: Item id.
            type: Type of list item.
            value: Value of list item.
            risk: Risk of list item.
            notes: Notes for list item.

        Returns:
            Respone from API
        """
        suffix = f"/api/v3/lists/{list_id}/items/{item_id}"
        body = assign_params(type=type, value=value, risk=risk, notes=notes)
        return self._http_request("PATCH", suffix, json_data=body)

    def get_list_items(self, list_id: Optional[Any], offset: Optional[Any]) -> Dict:
        """Gets items of a list

        Args:
            list_id: List ID.
            offset: Offset in database.

        Returns:
            Response from API
        """
        suffix = f"/api/v3/lists/{list_id}/items"
        params = assign_params(offset=offset)
        return self._http_request("GET", suffix, params=params)

    def remove_list_item(self, list_id: Optional[Any], item_id: Optional[Any]) -> Dict:
        suffix = f"/api/v3/lists/{list_id}/items/{item_id}"
        return self._http_request("DELETE", suffix, resp_type="content")


""" HELPER FUNCTIONS """


def create_context_result(src: Union[Dict, List], trans_dict: Dict) -> Union[Dict, List]:
    """Builds a dictionary according to a transformation map

    Args:
        src (dict): original dictionary to build from
        trans_dict (dict): dict in the format { 'OldKey': 'NewKey', ...}

    Returns: src copy with changed keys
    """
    if isinstance(src, list):
        return [create_context_result(x, trans_dict) for x in src]
    res: Dict[str, Any] = {}
    for key, val in trans_dict.items():
        if isinstance(val, dict):
            # handle nested list
            sub_res = res
            item_val = [create_context_result(item, val) for item in (demisto.get(src, key) or [])]
            key = underscoreToCamelCase(key)
            for sub_key in key.split(".")[:-1]:
                if sub_key not in sub_res:
                    sub_res[sub_key] = {}
                sub_res = sub_res[sub_key]
            sub_res[key.split(".")[-1]] = item_val
        elif "." in val:
            # handle nested vals
            update_nested_value(res, val, to_val=demisto.get(src, key))
        else:
            res[val] = demisto.get(src, key)
    return res


def update_nested_value(src_dict: Dict[str, Any], to_key: str, to_val: Any) -> None:
    """
    Updates nested value according to transformation dict structure where 'a.b' key will create {'a': {'b': val}}
    Args:
        src_dict (dict): The original dict
        to_key (str): Key to transform to (expected to contain '.' to mark nested)
        to_val (any): The value that'll be put under the nested key
    """
    sub_res = src_dict
    to_key_lst = to_key.split(".")
    for sub_to_key in to_key_lst[:-1]:
        if sub_to_key not in sub_res:
            sub_res[sub_to_key] = {}
        sub_res = sub_res[sub_to_key]
    sub_res[to_key_lst[-1]] = to_val


def alert_severity_to_dbot_score(severity_str):
    """Converts an severity string to DBot score representation
        alert severity. Can be one of:
        Low    ->  1
        Medium ->  2
        High   ->  3

    Args:
        severity_str: String representation of severity.

    Returns:
        Dbot representation of severity
    """
    severity_str = severity_str.lower()
    if severity_str == "low":
        return 1
    if severity_str == "medium":
        return 2
    elif severity_str == "high":
        return 3
    return 0


def build_mql_query(
    query: str,
    start: str = None,
    end: str = None,
    page_size: Union[int, str] = None,
    limit: Union[str, int] = None,
    offset: Union[int, str] = None,
    groupby: str = None,
    sort_by: str = None,
    sort_order: str = None,
) -> str:
    """Builds MQL query from given arguments

    Args:
        query: Query to execute. This is the search clause in an MQL.
        start: Start time of the event in date format yyyy-mm-dd or yyyy-mm.
        end: End time of the event in date format yyyy-mm-dd or yyyy-mm.
        page_size: Max amount of results to return.
        limit: Number of events to search.
        offset: Offset of the result.
        groupby: Returns the unique values for the specified field and groups them together.
        sort_by: Sorts results by this field.
        sort_order: Controls the order of the results sorted.

    Returns:
        MQL query
    """
    # Filter section
    if start:
        query += f' start="{start}"'
    if end:
        query += f' end="{end}"'
    if page_size or offset or limit:
        query += " {"
        if page_size:
            query += f" page_size={page_size}"
        if offset:
            query += f" offset={offset}"
        if limit:
            query += f" limit={limit}"
        query += "}"
    # Transform section
    if groupby:
        query += f"| groupby [{groupby}]"
    if sort_by:
        sort_order = ">" if sort_order != "asc" else "<"
        query += f"| sort {sort_order} {sort_by}"
    return query


def build_search_groupby_result(aggregations: Dict, separator: str) -> List:
    """Builds groupby result from search aggregations

    Args:
        aggregations: Group object
        separator: Separator used in query and result

    Returns:
        Groupby result
    """
    res = []
    for key, aggregation in aggregations.items():
        if key.startswith("groupby"):
            groupby_fields = demisto.get(aggregation, "meta.field") or demisto.get(aggregation, "meta.fields")
            if groupby_fields:
                if isinstance(groupby_fields, str):
                    groupby_fields = [groupby_fields]
                for bucket in aggregation.get("buckets", []):
                    bucket_vals = bucket.get("key", "").split(separator)
                    group_set = {groupby_field: bucket_vals[idx] for idx, groupby_field in enumerate(groupby_fields)}
                    group_set["DocCount"] = bucket.get("doc_count")
                    res.append(group_set)
    return res


def build_search_result(raw_response: dict, search_id: Union[str, int] = None, headers: List = None):
    """Builds search result from search raw_response

    Args:
        raw_response: Search raw response
        search_id: Search ID (relevant for archive search)
        headers: Headers to show in hr table

    Returns:
        Search result
    """
    results = raw_response.get("results")
    context = {"MQL": raw_response.get("mql")}
    if search_id:
        dt_query = "val.ID && val.ID === obj.ID"
        context["ID"] = search_id
    else:
        dt_query = "val.ID && val.ID === obj.ID" if search_id else "val.MQL && val.MQL === obj.MQL"
    if results:
        # Search results
        hits = demisto.get(results, "hits.hits")
        if hits:
            context["Result"] = []
            for hit in hits:
                context["Result"].append(create_context_result(hit.get("_source"), EVENTS_TRANS))  # type: ignore
        # Human readable value is ok for both no result found and result found cases
        hr = tableToMarkdown(
            f'{INTEGRATION_NAME} - Search result for {context["MQL"]}',
            context.get("Result"),
            headers,
            headerTransform=pascalToSpace,
            removeNull=True,
        )
        # Group by results
        aggregations = results.get("aggregations")
        if aggregations:
            separator = demisto.get(raw_response, "options.groupby.separator") or "|%$,$%|"
            context["GroupBy"] = build_search_groupby_result(aggregations, separator)
            if context["GroupBy"]:
                group_by_keys = list(context["GroupBy"][0].keys())  # type: ignore
                # move DocCount to tail
                group_by_keys.remove("DocCount")
                group_by_keys.append("DocCount")
                hr += tableToMarkdown("Group By", context["GroupBy"], headers=group_by_keys)

        return hr, {f"{INTEGRATION_CONTEXT_NAME}Search({dt_query})": context}, raw_response
    else:
        # API should not return an empty result matching this case, this is a fail safe
        return f"{INTEGRATION_NAME} - Search did not find any result.", {}, {}


def build_title_with_page_numbers(title: str, count: int, limit: int, offset: int) -> str:
    """Tries to build a title with page numbers from raw response and given title

    Args:
        title: Title without page numbers
        count: Total number of entries
        limit: Max amount of entries returned
        offset:

    Returns:

    """
    try:
        tot_pages = math.ceil(count / limit)
        page = math.floor((offset / count) * tot_pages) + 1
        # In case offset > count
        if page > tot_pages:
            page = tot_pages
        return f"{title}\n### Page {page}/{tot_pages}"
    except (TypeError, ValueError, ZeroDivisionError):
        return title


def build_single_list_result(raw_response):
    """Builds a list result from API response

    Args:
        raw_response: API response to alert call

    Returns:
        List result
    """
    list_id = raw_response.get("id")
    title = f"{INTEGRATION_NAME} - List {list_id}:"
    context_entry = create_context_result(raw_response, LISTS_TRANS)
    context = {f"{INTEGRATION_CONTEXT_NAME}.List(val.ID && val.ID === obj.ID)": context_entry}
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, context_entry, headerTransform=pascalToSpace)
    # Return data to Demisto
    return human_readable, context, raw_response


""" COMMANDS """


def test_module(
    client: Client, test_fetch: bool = False, fetch_time: Optional[str] = None, last_run: Dict = None, *_
) -> Tuple[str, Dict, Dict]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        test_fetch: If set to true will test fetch_incidents
        fetch_time: If fetch is set, will pass to fetch_incidents to test
        last_run: Last fetch object.
        args: Usually demisto.args()

    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """
    client.test_module()
    if test_fetch:
        fetch_incidents(client, fetch_time, last_run)  # type: ignore
    return "ok", {}, {}


def fetch_incidents(client: Client, fetch_time: Optional[str], last_run: Dict) -> Tuple[List, Dict]:
    """Uses to fetch incidents into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_incidents

    Args:
        client: Client object with request
        fetch_time: From when to fetch if first time, e.g. `3 days`
        last_run: Last fetch object.

    Returns:
        incidents, new last_run
    """
    timestamp_format = "%Y-%m-%dT%H:%M:%S.%fZ"
    # Get incidents from API
    if not last_run:  # if first time running
        new_last_run = {"time": parse_date_range(fetch_time, date_format=timestamp_format)[0]}
    else:
        new_last_run = last_run
    incidents: List = list()
    raw_response = client.list_alerts(created_at__gte=new_last_run.get("time"))
    alerts = raw_response.get("results")
    if alerts:
        last_incident_id = last_run.get("id", 0)
        # Creates incident entry
        incidents = [
            {
                "name": f"{INTEGRATION_NAME}: {alert.get('id')}",
                "occurred": alert.get("created_at"),
                "severity": alert_severity_to_dbot_score(alert.get("severity")),
                "rawJSON": json.dumps(alert),
            }
            for alert in alerts
            if alert.get("id") > last_incident_id
        ]
        # New incidents fetched
        if incidents:
            last_incident_timestamp = incidents[-1].get("occurred")
            last_incident_id = alerts[-1].get("id")
            new_last_run = {"time": last_incident_timestamp, "id": last_incident_id}
    # Return results
    return incidents, new_last_run


def list_alerts_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Lists all alerts and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    limit = int(args.get("page_size") or DEFAULT_PAGE_SIZE)
    headers = argToList(args.get("headers"))
    # api response for limit=0 is equivalent to limit=30
    if limit == 0:
        limit = DEFAULT_PAGE_SIZE
    offset = int(args.get("offset") or 0)
    raw_response = client.list_alerts(limit=limit, offset=offset)
    alerts = raw_response.get("results")
    if alerts:
        count = demisto.get(raw_response, "meta.count")
        title = f"{INTEGRATION_NAME} - List alerts:"
        try:
            count = int(count)
            title = build_title_with_page_numbers(title, count, limit, offset)
        except (TypeError, ValueError):
            # don't change title if count ins't an int
            pass
        context_entry = create_context_result(alerts, ALERTS_TRANS)
        context = {
            f"{INTEGRATION_CONTEXT_NAME}.Alert(val.ID && val.ID === obj.ID)": context_entry,
            f"{INTEGRATION_CONTEXT_NAME}.Alert(val.Count).Count": count,
        }
        if not headers:
            headers = ["ID", "Name", "Description", "State", "Severity"]
        human_readable = tableToMarkdown(title, context_entry, headers)
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - Could not find any alerts.", {}, {}


def get_alert_by_id_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get alert by id and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    _id = args.get("id")
    headers = argToList(args.get("headers"))
    raw_response = client.get_alert_by_id(_id=_id)
    if raw_response:
        title = f"{INTEGRATION_NAME} - Alert {_id}:"
        context_entry = create_context_result(raw_response, ALERTS_TRANS)
        context = {f"{INTEGRATION_CONTEXT_NAME}.Alert(val.ID && val.ID === obj.ID)": context_entry}
        human_readable = tableToMarkdown(title, context_entry, headers=headers, removeNull=True)
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - Could not find any alerts.", {}, {}


def get_alert_notes_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get all notes related to alert

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    alert_id = args.get("alert_id")
    raw_response = client.get_alert_notes(alert_id=alert_id)
    raw_notes = raw_response.get("results")
    if raw_notes:
        title = f"{INTEGRATION_NAME} - Notes for Alert {alert_id}:"
        context_entry = create_context_result(raw_notes, NOTES_TRANS)
        if isinstance(context_entry, dict):
            context_entry["AlertID"] = alert_id
        else:
            for note in context_entry:
                note["AlertID"] = alert_id
        count = demisto.get(raw_response, "meta.count")
        context = {
            f"{INTEGRATION_CONTEXT_NAME}.Note(val.ID && val.ID === obj.ID)": context_entry,
            f"{INTEGRATION_CONTEXT_NAME}.Note(val.Count && val.AlertID === {alert_id}).Count": count,
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(
            title, context_entry, ["ID", "CreatorName", "Message", "CreatedTime"], headerTransform=pascalToSpace
        )
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - No notes were found for alert {alert_id}.", {}, {}


def create_alert_note_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Create a note for an alert

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    alert_id = args.get("alert_id")
    note = args.get("note")
    raw_response = client.create_alert_note(alert_id=alert_id, note=note)
    if raw_response:
        title = f"{INTEGRATION_NAME} - Created Note for Alert {alert_id}:"
        context_entry = create_context_result(raw_response, NOTES_TRANS)
        if isinstance(context_entry, dict):
            context_entry["AlertID"] = alert_id
        context = {f"{INTEGRATION_CONTEXT_NAME}.Note(val.ID && val.ID === obj.ID)": context_entry}
        # Creating human readable for War room
        human_readable = tableToMarkdown(
            title, context_entry, ["ID", "CreatorName", "Message", "CreatedTime"], headerTransform=pascalToSpace
        )
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - Could not create a note.", {}, {}


def delete_alert_note_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Delete a note for an alert

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    alert_id = args.get("alert_id")
    note_id = args.get("note_id")
    client.delete_alert_note(alert_id=alert_id, note_id=note_id)
    return f"{INTEGRATION_NAME} - Deleted note {note_id} for Alert {alert_id} successfully.", {}, {}


def get_events_by_alert_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get events for a specific alert

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    alert_id = args.get("alert_id")
    headers = argToList(args.get("headers"))
    raw_response = client.get_events_by_alert(alert_id=alert_id)
    events = raw_response.get("results")
    if events:
        title = f"{INTEGRATION_NAME} - Events for alert {alert_id}:"
        context_entry = create_context_result(events, EVENTS_TRANS)
        count = demisto.get(raw_response, "meta.count")
        context = {
            f"{INTEGRATION_CONTEXT_NAME}.Event(val.ID && val.ID === obj.ID)": context_entry,
            f"{INTEGRATION_CONTEXT_NAME}.Event(val.Count).Count": count,
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry, headers, headerTransform=pascalToSpace, removeNull=True)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - Could not find any events.", {}, {}


def get_endpoints_by_alert_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Fetch endpoints of a specific alert

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    alert_id = args.get("alert_id")
    raw_response = client.get_endpoints_by_alert(alert_id=alert_id, offset=args.get("offset"))
    endpoints = demisto.get(raw_response, "results.endpoints")
    if endpoints:
        title = f"{INTEGRATION_NAME} - Endpoints for alert {alert_id}:"
        context_entry = create_context_result(endpoints, ENDPOINTS_TRANS)
        count = demisto.get(raw_response, "meta.count")
        context = {
            f"{INTEGRATION_CONTEXT_NAME}.Endpoint(val.ID && val.ID === obj.ID)": context_entry,
            f"{INTEGRATION_CONTEXT_NAME}.Endpoint(val.Count).Count": count,
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(
            title, context_entry, ["ID", "DeviceID", "Hostname", "IP", "MACAddress", "UpdatedTime"], headerTransform=pascalToSpace
        )
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - Could not find any endpoints.", {}, {}


def get_cases_by_alert_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Fetch cases of a specific alert

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    alert_id = args.get("alert_id")
    raw_response = client.get_cases_by_alert(
        alert_id=alert_id, limit=args.get("page_size"), offset=args.get("offset"), order_by=args.get("order_by")
    )
    cases = raw_response.get("results")
    if cases:
        title = f"{INTEGRATION_NAME} - Cases for alert {alert_id}:"
        context_entry = create_context_result(cases, CASES_TRANS)
        context = {f"{INTEGRATION_CONTEXT_NAME}.Case(val.ID && val.ID === obj.ID)": context_entry}
        # Creating human readable for War room
        human_readable = tableToMarkdown(
            title,
            context_entry,
            ["ID", "Name", "AssigneeName", "Priority", "Severity", "State", "Status", "ModifiedTime"],
            removeNull=True,
        )
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - Could not find any cases.", {}, {}


def get_lists_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get lists return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    is_active = args.get("is_active")
    is_internal = args.get("is_internal")
    is_protected = args.get("is_protected")
    raw_response = client.get_lists(
        limit=args.get("page_size"),
        offset=args.get("offset"),
        created_at=args.get("created_at"),
        description=args.get("description"),
        is_active=is_active and is_active != "false",
        is_internal=is_internal and is_internal != "false",
        is_protected=is_protected and is_protected != "false",
        name=args.get("name"),
        short_name=args.get("short_name"),
        type=args.get("type"),
        updated_at=args.get("updated_at"),
        usage=args.get("usage"),
        order_by=args.get("order_by"),
    )
    lists = raw_response.get("results")
    if lists:
        title = f"{INTEGRATION_NAME} - Lists:"
        context_entry = create_context_result(lists, LISTS_TRANS)
        count = demisto.get(raw_response, "meta.count")
        context = {
            f"{INTEGRATION_CONTEXT_NAME}.List(val.ID && val.ID === obj.ID)": context_entry,
            f"{INTEGRATION_CONTEXT_NAME}.List(val.Count).Count": count,
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(
            title, context_entry, ["ID", "Name", "ContentTypes", "UpdatedTime"], headerTransform=pascalToSpace
        )
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - Could not find any lists.", {}, {}


def get_list_by_id_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get a list by ID return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    list_id = args.get("id")
    raw_response = client.get_list_by_id(list_id)
    if raw_response:
        return build_single_list_result(raw_response)
    else:
        return f"{INTEGRATION_NAME} - Could not find the list.", {}, raw_response


def create_list_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Create a list. return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    is_internal = args.get("is_internal")
    is_active = args.get("is_active")
    is_protected = args.get("is_protected")
    is_hidden = args.get("is_hidden")
    raw_response = client.create_list(
        name=args.get("name"),
        short_name=args.get("short_name"),
        is_internal=is_internal != "false" if is_internal else is_internal,
        is_active=is_active != "false" if is_active else is_active,
        is_protected=is_protected != "false" if is_protected else is_protected,
        is_hidden=is_hidden != "false" if is_hidden else is_hidden,
        type=args.get("type"),
        description=args.get("description"),
    )
    if raw_response:
        return build_single_list_result(raw_response)
    else:
        return f"{INTEGRATION_NAME} - Created list successfully.", {}, raw_response


def update_list_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Update a list. return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    is_internal = args.get("is_internal")
    is_active = args.get("is_active")
    is_protected = args.get("is_protected")
    is_hidden = args.get("is_hidden")
    raw_response = client.update_list(
        list_id=int(args.get("list_id")),  # type: ignore
        name=args.get("name"),
        short_name=args.get("short_name"),
        is_internal=is_internal != "false" if is_internal else is_internal,
        is_active=is_active != "false" if is_active else is_active,
        is_protected=is_protected != "false" if is_protected else is_protected,
        is_hidden=is_hidden != "false" if is_hidden else is_hidden,
        type=args.get("type"),
        description=args.get("description"),
    )
    if raw_response:
        return build_single_list_result(raw_response)
    else:
        return f"{INTEGRATION_NAME} - Updated list successfully.", {}, raw_response


def delete_list_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Update a list. return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    list_id = args.get("list_id")
    raw_response = client.delete_list(list_id)
    return f"{INTEGRATION_NAME} - Deleted list successfully.", {}, raw_response


def add_list_item_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Adds a list item. return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    list_id = args.get("list_id")
    raw_response = client.add_list_item(
        list_id=list_id, type=str(args.get("type")), value=str(args.get("value")), risk=args.get("risk"), notes=args.get("notes")
    )
    if raw_response:
        item_id = raw_response.get("id")
        title = f"{INTEGRATION_NAME} - List item {item_id} was added successfully to {list_id}"
        context_entry = create_context_result(raw_response, LIST_ITEM_TRANS)
        context = {f"{INTEGRATION_CONTEXT_NAME}List(val.ID && val.ID === {list_id}).Item": context_entry}
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - Could not create list item.", {}, raw_response


def update_list_item_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Updates a list item. return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    list_id = int(args.get("list_id"))  # type: ignore
    item_id = int(args.get("item_id"))  # type: ignore
    raw_response = client.update_list_item(
        list_id=list_id,
        item_id=item_id,
        type=args.get("type"),
        value=args.get("value"),
        risk=args.get("risk"),
        notes=args.get("notes"),
    )
    if raw_response:
        title = f"{INTEGRATION_NAME} - List item {item_id} from list {list_id} was updated successfully"
        context_entry = create_context_result(raw_response, LIST_ITEM_TRANS)
        context = {f"{INTEGRATION_CONTEXT_NAME}List(val.ID && val.ID === {list_id}).Item(val.ID === obj.ID)": context_entry}
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - Could not update list item.", {}, raw_response


def remove_list_item_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Updates a list item. return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    list_id = args.get("list_id")
    item_id = args.get("item_id")
    raw_response = client.remove_list_item(list_id=list_id, item_id=item_id)
    return f"{INTEGRATION_NAME} - Removed item {item_id} from list {list_id} successfully", {}, raw_response


def get_list_items_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Fetches list items

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    list_id = args.get("list_id")
    raw_response = client.get_list_items(list_id, args.get("offset"))
    results = raw_response.get("results")
    if results:
        title = f"{INTEGRATION_NAME} - List items for list {list_id}"
        context_entry = create_context_result(results, LIST_ITEM_TRANS)
        count = demisto.get(raw_response, "meta.count")
        context = {
            f"{INTEGRATION_CONTEXT_NAME}List(val.ID && val.ID === {list_id}).Item(val.ID === obj.ID)": context_entry,
            f"{INTEGRATION_CONTEXT_NAME}List(val.ID && val.ID === {list_id}).Count(val.Count)": count,
        }
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - No items were found for list {list_id}.", {}, raw_response


def list_sensors_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Lists all sensors and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    raw_response = client.list_sensors(
        limit=int(args.get("page_size") or 0),
        offset=int(args.get("offset") or 0),
        hostname=args.get("hostname"),
        status=args.get("status"),
    )
    sensors = raw_response.get("results")
    if sensors:
        title = f"{INTEGRATION_NAME} - List sensors:"
        context = {f"{INTEGRATION_CONTEXT_NAME}.Sensor(val.id && val.ID === obj.id)": sensors}
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, sensors)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - Could not find any sensors.", {}, {}


def list_rules_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Lists all rules and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    limit = int(args.get("page_size") or DEFAULT_PAGE_SIZE)
    offset = int(args.get("offset") or 0)
    raw_response = client.list_rules(limit=limit, offset=offset, sort=args.get("sort"))
    rules = raw_response.get("rules")
    if rules:
        count = demisto.get(raw_response, "meta.totalCount")
        title = f"{INTEGRATION_NAME} - List rules:"
        try:
            count = int(count)
            title = build_title_with_page_numbers(title, count, limit, offset)
        except (TypeError, ValueError):
            # don't change title if count ins't an int
            pass
        context_entry = create_context_result(rules, RULES_TRANS)
        context = {
            f"{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)": context_entry,
            f"{INTEGRATION_CONTEXT_NAME}.Rule(val.Count)": count,
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(
            title, context_entry, ["ID", "Type", "Description", "Risk", "Confidence", "Severity", "Enabled"]
        )
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - Could not find any rules.", {}, {}


def edit_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Edit a single rule and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    rule_id = str(args.get("rule_id"))
    enabled = args.get("enabled")
    raw_response = client.edit_rule(rule_id, enabled != "false" if enabled else None)
    rules = raw_response.get("rules")
    if rules:
        title = f"{INTEGRATION_NAME} - Successfully updated rule {rule_id}:"
        context_entry = create_context_result(rules, RULES_TRANS)
        context = {f"{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)": context_entry}
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry, ["ID", "Type", "Description", "Risk", "Confidence", "Severity"])
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - Could not find matching rule.", {}, {}


def search_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Searches FireEye Helix database using MQL

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    query = build_mql_query(
        query=args.get("query", ""),
        start=args.get("start"),
        end=args.get("end"),
        page_size=args.get("page_size"),
        limit=args.get("limit"),
        offset=args.get("offset"),
        groupby=args.get("groupby"),
        sort_by=args.get("sort_by"),
        sort_order=args.get("sort_order"),
    )
    raw_response = client.search(query)
    headers = argToList(args.get("headers"))
    return build_search_result(raw_response, headers=headers)


def archive_search_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Searches FireEye Helix database using MQL

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    query = build_mql_query(**args)
    raw_response = client.archive_search(query)
    data = raw_response.get("data")
    if data:
        title = f"{INTEGRATION_NAME} - Successfully created archive search"
        context_entry = create_context_result(data, ARCHIVE_SEARCH_TRANS)
        context = {f"{INTEGRATION_CONTEXT_NAME}Search(val.ID === obj.ID)": context_entry}
        human_readable = tableToMarkdown(title, context_entry, headerTransform=pascalToSpace)
        return human_readable, context, raw_response
    else:
        return f"{INTEGRATION_NAME} - Failed to create archive search", {}, raw_response


def archive_search_status_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Fetches the status of an archive search

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    search_ids = argToList(args.get("search_id"))
    raw_res_lst = []
    context_entry = []
    for s_id in search_ids:
        i_s_id = int(s_id)
        raw_res = client.get_archive_search(i_s_id)
        if raw_res:
            data = raw_res.get("data")
            if isinstance(data, list):
                context_entry.append(create_context_result(data[0], ARCHIVE_SEARCH_TRANS))
            raw_res_lst.append(raw_res)
    if raw_res_lst:
        title = f"{INTEGRATION_NAME} - Search status"
        human_readable = tableToMarkdown(title, context_entry, headerTransform=pascalToSpace)
        context = {f"{INTEGRATION_CONTEXT_NAME}Search(val.ID === obj.ID)": context_entry}
        return human_readable, context, raw_res_lst  # type: ignore
    else:
        return f"{INTEGRATION_NAME} - Failed to get archive search details", {}, {}


def archive_search_results_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Fetches an archive search result

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    search_id = int(args.get("search_id"))  # type: ignore
    raw_response = client.get_archive_search_results(search_id)
    return build_search_result(raw_response.get("results"), search_id)


""" COMMANDS MANAGER / SWITCH PANEL """


def main():  # pragma: no cover
    params = demisto.params()
    base_url = f"{params.get('url', '').rstrip('/')}"
    if not base_url.endswith("/helix/id"):
        base_url += "/helix/id"
    base_url += f"/{params.get('h_id_creds', {}).get('identifier') or params.get('h_id')}"
    verify_ssl = not params.get("insecure", False)
    proxy = params.get("proxy")
    headers = {
        "accept": "application/json",
        "x-fireeye-api-key": params.get("h_id_creds", {}).get("password") or params.get("token"),
    }
    client = Client(base_url=base_url, verify=verify_ssl, proxy=proxy, headers=headers)
    command = demisto.command()
    demisto.info(f"Command being called is {command}")

    # Switch case
    commands = {
        f"{INTEGRATION_COMMAND_NAME}-list-alerts": list_alerts_command,
        f"{INTEGRATION_COMMAND_NAME}-get-alert-by-id": get_alert_by_id_command,
        f"{INTEGRATION_COMMAND_NAME}-alert-get-notes": get_alert_notes_command,
        f"{INTEGRATION_COMMAND_NAME}-alert-create-note": create_alert_note_command,
        f"{INTEGRATION_COMMAND_NAME}-alert-delete-note": delete_alert_note_command,
        f"{INTEGRATION_COMMAND_NAME}-get-events-by-alert": get_events_by_alert_command,
        f"{INTEGRATION_COMMAND_NAME}-get-endpoints-by-alert": get_endpoints_by_alert_command,
        f"{INTEGRATION_COMMAND_NAME}-get-cases-by-alert": get_cases_by_alert_command,
        f"{INTEGRATION_COMMAND_NAME}-get-lists": get_lists_command,
        f"{INTEGRATION_COMMAND_NAME}-get-list-by-id": get_list_by_id_command,
        f"{INTEGRATION_COMMAND_NAME}-create-list": create_list_command,
        f"{INTEGRATION_COMMAND_NAME}-update-list": update_list_command,
        f"{INTEGRATION_COMMAND_NAME}-delete-list": delete_list_command,
        f"{INTEGRATION_COMMAND_NAME}-get-list-items": get_list_items_command,
        f"{INTEGRATION_COMMAND_NAME}-add-list-item": add_list_item_command,
        f"{INTEGRATION_COMMAND_NAME}-update-list-item": update_list_item_command,
        f"{INTEGRATION_COMMAND_NAME}-remove-list-item": remove_list_item_command,
        f"{INTEGRATION_COMMAND_NAME}-list-sensors": list_sensors_command,
        f"{INTEGRATION_COMMAND_NAME}-list-rules": list_rules_command,
        f"{INTEGRATION_COMMAND_NAME}-edit-rule": edit_rule_command,
        f"{INTEGRATION_COMMAND_NAME}-search": search_command,
        f"{INTEGRATION_COMMAND_NAME}-archive-search": archive_search_command,
        f"{INTEGRATION_COMMAND_NAME}-archive-search-get-status": archive_search_status_command,
        f"{INTEGRATION_COMMAND_NAME}-archive-search-get-results": archive_search_results_command,
    }
    try:
        if command == "test-module":
            fetch_time = params.get("fetch_time")
            is_fetch = params.get("isFetch")
            last_run = demisto.getLastRun()
            readable_output, outputs, raw_response = test_module(client, bool(is_fetch), fetch_time, last_run)
            return_outputs(readable_output, outputs, raw_response)
        elif command == "fetch-incidents":
            fetch_time = params.get("fetch_time")
            incidents, last_run = fetch_incidents(client, fetch_time, last_run=demisto.getLastRun())  # type: ignore
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)
        elif command in commands:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())  # type: ignore
            return_outputs(readable_output, outputs, raw_response)
    # Log exceptions
    except Exception as e:
        err_msg = str(e)
        if "[401]" in err_msg:
            return_error(
                "Encountered an issue accessing the API. Please make sure you entered the right Helix ID and " "API Token."
            )
        elif "requests.exceptions" in err_msg:
            return_error(
                "Encountered an error reaching the endpoint, please verify that the server URL parameter"
                " is correct and that you have access to the server from your host."
            )
        else:
            return_error(f"Error in {INTEGRATION_NAME} Integration [{e}]", error=e)


if __name__ == "builtins":  # pragma: no cover
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""
CiscoAMP (Advanced Malware Protection) API Integration for Cortex XSOAR (aka Demisto).
"""
import copy
import math
from typing import Any
from collections.abc import Callable, MutableMapping, MutableSequence
from http import HTTPStatus
from collections import namedtuple
from CommonServerUserPython import *  # pylint: disable=wildcard-import


""" GLOBAL/PARAMS """  # pylint: disable=pointless-string-statement


INTEGRATION_NAME = "Cisco AMP v2"
DEFAULT_INTERVAL = 30
DEFAULT_TIMEOUT = 600
FETCH_LIMIT = 200
MAX_PAGE_SIZE = 100

FILENAME_REGEX = r"[\w\-\.]+[\w\-\. ]*"
ISO_8601_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"

XSOAR_SEVERITY_BY_AMP_SEVERITY = {
    "Low": IncidentSeverity.LOW,
    "Medium": IncidentSeverity.MEDIUM,
    "High": IncidentSeverity.HIGH,
    "Critical": IncidentSeverity.CRITICAL,
}

PAGINATION_FIELDS = (
    "page",
    "page_size",
    "limit",
    "offset",
    "number_of_requests",
    "offset_multiplier",
    "is_automatic",
    "is_manual",
)
Pagination = namedtuple(
    "Pagination",
    (
        "page",
        "page_size",
        "limit",
        "offset",
        "number_of_requests",
        "offset_multiplier",
        "is_automatic",
        "is_manual",
    ),
    defaults=(None, None, None, None, None, None, None, None),
)

TRAJECTORY_TITLE = "Event Information"
TRAJECTORY_HEADERS_BY_KEYS = {
    "ID": ["id"],
    "Date": ["date"],
    "Event Type": ["event_type"],
    "Detection": ["detection"],
    "Severity": ["severity"],
    "Group GUIDs": ["group_guids"],
}
ACTIVITY_TITLE = "Activity Information"
ACTIVITY_HEADERS_BY_KEYS = {
    "Connector GUID": ["connector_guid"],
    "Host Name": ["hostname"],
    "Windows Processor ID": ["windows_processor_id"],
    "Active": ["active"],
}
VULNERABILITY_TITLE = "Vulnerabilities Information"
VULNERABILITY_HEADERS_BY_KEYS = {
    "Application": ["application"],
    "Version": ["version"],
    "Latest Date": ["latest_date"],
    "File Name": ["file", "filename"],
    "SHA-256": ["file", "identity", "sha256"],
}
EVENT_TYPE_TITLE = "Event Type Information"
EVENT_TYPE_HEADERS_BY_KEYS = {
    "ID": ["id"],
    "Name": ["name"],
    "Description": ["description"],
}
EVENT_TITLE = "Event Information"
EVENT_HEADERS_BY_KEYS = {
    "ID": ["id"],
    "Date": ["date"],
    "Event Type": ["event_type"],
    "Detection": ["detection"],
    "Connector GUID": ["connector_guid"],
    "Severity": ["severity"],
}
GROUPS_TITLE = "Groups Information"
GROUPS_HEADERS_BY_KEYS = {
    "Name": ["name"],
    "Description": ["description"],
    "GUID": ["guid"],
    "Source": ["source"],
}
GROUP_TITLE = "Group Information"
GROUP_HEADERS_BY_KEYS = {
    "Name": ["name"],
    "Description": ["description"],
    "Creator": ["creator"],
    "Created At": ["created_at"],
    "Computers Count": ["computers_count"],
    "Descendant Computers Count": ["descendant_computers_count"],
}
VULNERABLE_COMPUTER_TITLE = "Vulnerable Computers Information"
VULNERABLE_COMPUTER_HEADERS_BY_KEYS = {
    "Connector GUID": ["connector_guid"],
    "Hostname": ["hostname"],
    "Windows Processor ID": ["windows_processor_id"],
    "Active": ["active"],
    "Group GUID": ["group_guid"],
}
POLICY_TITLE = "Policy Information"
POLICY_HEADERS_BY_KEYS = {
    "GUID": ["guid"],
    "Name": ["name"],
    "Description": ["description"],
    "Product": ["product"],
    "Serial Number": ["serial_number"],
}
FILE_LIST_TITLE = "File List Information"
FILE_LIST_HEADERS_BY_KEYS = {
    "GUID": ["guid"],
    "Name": ["name"],
    "Type": ["type"],
}
FILE_LIST_ITEM_TITLE = "File List Item Information"
FILE_LIST_ITEM_HEADERS_BY_KEYS = {
    "SHA-256": ["sha256"],
    "Source": ["source"],
    "Description": ["description"],
}
ISOLATION_TITLE = "Isolation Information"
ISOLATION_HEADERS_BY_KEYS = {
    "Available": ["available"],
    "Status": ["status"],
    "Unlock Code": ["unlock_code"],
    "Comment": ["comment"],
    "Isolated By": ["isolated_by"],
}
APP_TRAJECTORY_TITLE = "App Trajectory Information"
APP_TRAJECTORY_HEADERS_BY_KEYS = {
    "Connector GUID": ["connector_guid"],
    "Date": ["date"],
    "Query Type": ["query_type"],
    "Dirty URL": ["network_info", "dirty_url"],
}
INDICATOR_TITLE = "Indicator Information"
INDICATOR_HEADERS_BY_KEYS = {
    "GUID": ["guid"],
    "Name": ["name"],
    "Description": ["description"],
    "Severity": ["severity"],
    "Observed Compromises": ["observed_compromises"],
}
MITRE_TACTIC_TITLE = "Mitre Tactic Information"
MITRE_TECHNIQUE_TITLE = "Mitre Technique Information"
MITRE_HEADERS_BY_KEYS = {
    "External ID": ["external_id"],
    "Name": ["name"],
    "Mitre URL": ["mitre_url"],
}


""" CLIENT CLASS """


class Client(BaseClient):
    """
    API Client to communicate with CiscoAMP API.
    """

    API_VERSION = "v1"

    def __init__(
        self,
        server_url: str,
        api_key: str,
        client_id: str,
        reliability: str,
        verify: bool = False,
        proxy: bool = False,
        should_create_relationships: bool = True,
    ):
        """
        Build URL with authorization arguments to provide the required Basic Authentication.

        Args:
            server_url (str): CiscoAMP API URL.
            api_key (str): API key to connect to the server.
            client_id (str): 3rd Party API Client ID.
            reliability (str): Reliability of the source providing the intelligence data.
            verify (bool, optional): SSL verification handled by BaseClient. Defaults to False.
            proxy (bool, optional): System proxy is handled by BaseClient. Defaults to False.
        """
        super().__init__(
            base_url=urljoin(server_url, self.API_VERSION),
            verify=verify,
            proxy=proxy,
            auth=(client_id, api_key),
        )

        self.reliability = reliability
        self.should_create_relationships = should_create_relationships

    def computer_list_request(
        self,
        limit: int = None,
        offset: int = None,
        hostnames: List[str] = None,
        internal_ip: str = None,
        external_ip: str = None,
        group_guids: List[str] = None,
        last_seen_within: int = None,
        last_seen_over: int = None,
    ) -> dict[str, Any]:
        """
        Return a single computer with a connector_guid or a list filtered by the other arguments.

        Args:
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.
            hostnames (List[str], optional): Hostname to filter by.
                Defaults to None.
            internal_ip (str, optional): Internal IP to filter by.
                Defaults to None.
            external_ip (str, optional): External IP to filter by.
                Defaults to None.
            group_guid (List[str], optional): Group GUID to filter by.
                Defaults to None.
            last_seen_within (str, optional): Number of days the last time the computer has been seen within.
                Defaults to None.
            last_seen_over (str, optional): Number of days the last time the computer has been seen.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about a list of computers or a single computer.
        """
        params = remove_empty_elements(
            {
                "limit": limit,
                "offset": offset,
                "hostname[]": hostnames,
                "internal_ip": internal_ip,
                "external_ip": external_ip,
                "group_guid[]": group_guids,
                "last_seen_within": last_seen_within,
                "last_seen_over": last_seen_over,
            }
        )

        return self._http_request(
            method="GET",
            url_suffix="/computers",
            params=params,
        )

    def computer_get_request(
        self,
        connector_guid: str,
    ) -> dict[str, Any]:
        """
        Return a single computer with a connector_guid.

        Args:
            connector_guid (str): Specific computer to return.

        Returns:
            Dict[str, Any]: Information about a computer.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/computers/{connector_guid}",
        )

    def computer_trajectory_list_request(
        self, connector_guid: str, limit: int = None, query_string: str = None
    ) -> dict[str, Any]:
        """
        Get information about a computer and its trajectory which be set in a list of events.

        Args:
            connector_guid (str): Specific computer to return.
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            query_string (str, optional): Freeform query string which accepts: IP address, SHA-256 or URL.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about a computer and its trajectory.
        """
        params = remove_empty_elements(
            {
                "limit": limit,
                "q": query_string,
            }
        )

        return self._http_request(
            method="GET",
            url_suffix=f"/computers/{connector_guid}/trajectory",
            params=params,
        )

    def computer_user_activity_get_request(
        self,
        username: str,
        limit: int = None,
        offset: int = None,
    ) -> dict[str, Any]:
        """
        Get computers that have observed activity by given username.

        Args:
            username (str): Username to filter by.
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.

        Returns:
            Dict[str, Any]: List of computers.
        """
        params = remove_empty_elements(
            {"q": username, "limit": limit, "offset": offset}
        )

        return self._http_request(
            method="GET",
            url_suffix="/computers/user_activity",
            params=params,
        )

    def computer_user_trajectory_list_request(
        self, connector_guid: str, limit: int = None, username: str = None
    ) -> dict[str, Any]:
        """
        Get information about a computer and its trajectory which be set in a list of events.

        Args:
            connector_guid (str): Specific computer to return.
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            username (str, optional): Username to filter by.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about a computer and its trajectory.
        """
        params = remove_empty_elements(
            {
                "limit": limit,
                "q": username,
            }
        )

        return self._http_request(
            method="GET",
            url_suffix=f"/computers/{connector_guid}/user_trajectory",
            params=params,
        )

    def computer_vulnerabilities_list_request(
        self,
        connector_guid: str,
        start_time: str = None,
        end_time: str = None,
        limit: int = None,
        offset: int = None,
    ) -> dict[str, Any]:
        """
        Return vulnerabilities observed on a specific computer.

        Args:
            connector_guid (str): Specific computer to return.
            start_time (str, optional): Inclusive, include vulnerable programs detected at start_time.
                Defaults to None.
            end_time (str, optional): Exclusive if end_time is a time, inclusive if end_time is a date,
                include vulnerable programs detected before end_time.
                Defaults to None.
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about a computer and its vulnerabilities.
        """
        params = remove_empty_elements(
            {
                "start_time": start_time,
                "end_time": end_time,
                "limit": limit,
                "offset": offset,
            }
        )

        return self._http_request(
            method="GET",
            url_suffix=f"/computers/{connector_guid}/vulnerabilities",
            params=params,
        )

    def computer_move_request(
        self, connector_guid: str, group_guid: str
    ) -> dict[str, Any]:
        """
        Moves the computer with the input connector_guid to a group with the input group_guid.

        Args:
            connector_guid (str): Connector GUID of the selected computer.
            group_guid (str): Group GUID of the group to move the computer to.s

        Returns:
            Dict[str, Any]: Information about the computer.
        """
        return self._http_request(
            method="PATCH",
            url_suffix=f"/computers/{connector_guid}",
            json_data={
                "group_guid": group_guid,
            },
        )

    def computer_delete_request(self, connector_guid: str) -> dict[str, Any]:
        """
        Deletes the computer with the connector_guid.

        Args:
            connector_guid (str): Connector GUID of the selected computer.

        Returns:
            Dict[str, Any]: Information about the delete operation, if it has succeeded.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=f"/computers/{connector_guid}",
        )

    def computer_activity_list_request(
        self, query_string: str, limit: int = None, offset: str = None
    ) -> dict[str, Any]:
        """
        Get computers that have observed activity by given username.

        Args:
            query_string (str): Query string which accepts: IPv4 address, SHA-256, File Name and a URL Fragment.
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.

        Returns:
            Dict[str, Any]: List of computers.
        """
        params = remove_empty_elements(
            {
                "q": query_string,
                "limit": limit,
                "offset": offset,
            }
        )

        return self._http_request(
            method="GET",
            url_suffix="/computers/activity",
            params=params,
        )

    def computer_isolation_feature_availability_get_request(
        self, connector_guid: str
    ) -> requests.Response:
        """
        Get information about available options for a computer's isolation.

        Args:
            connector_guid (str): Computer to get information about.

        Returns:
            requests.Response: Information about a computer's isolation.
        """
        return self._http_request(
            method="OPTIONS",
            url_suffix=f"/computers/{connector_guid}/isolation",
            resp_type="response",
        )

    def computer_isolation_get_request(self, connector_guid: str) -> dict[str, Any]:
        """
        Get information about a computer's isolation.

        Args:
            connector_guid (str): Computer to get information about.

        Returns:
            Dict[str, Any]: Information about a computer's isolation.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/computers/{connector_guid}/isolation",
        )

    def computer_isolation_create_request(
        self, connector_guid: str, comment: str, unlock_code: str
    ) -> dict[str, Any]:
        """
        Put a computer in isolation.

        Args:
            connector_guid (str): Computer to put in isolation.
            comment (str): Computer to put in isolation.
            unlock_code (str): Unlock code.

        Returns:
            Dict[str, Any]: Information about the computer's isolation.
        """
        body = remove_empty_elements(
            {
                "comment": comment,
                "unlock_code": unlock_code,
            }
        )

        return self._http_request(
            method="PUT",
            url_suffix=f"/computers/{connector_guid}/isolation",
            json_data=body,
        )

    def computer_isolation_delete_request(
        self,
        connector_guid: str,
        comment: str = None,
    ) -> dict[str, Any]:
        """
        Stop a computer in isolation.

        Args:
            connector_guid (str): Computer to put in isolation.
            comment (str): Computer to put in isolation.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about the computer's isolation.
        """
        body = remove_empty_elements(
            {
                "comment": comment,
            }
        )

        return self._http_request(
            method="DELETE",
            url_suffix=f"/computers/{connector_guid}/isolation",
            json_data=body,
        )

    def event_list_request(
        self,
        detection_sha256: str = None,
        application_sha256: str = None,
        connector_guids: List[str] = None,
        group_guids: List[str] = None,
        start_date: str = None,
        event_types: List[int] = None,
        limit: int = None,
        offset: int = None,
    ) -> dict[str, Any]:
        """
        Get a list of events that can be filtered by the input parameters.

        Args:
            detection_sha256 (str, optional): Detection  SHA-256 to filter by..
                Defaults to None.
            application_sha256 (str, optional): Application SHA-256 to filter by.
                Defaults to None.
            connector_guids (List[str], optional): connector_guid for specific computer.
                Defaults to None.
            group_guids (List[str], optional): Group GUID to filter by.
                Defaults to None.
            start_date (str, optional): Fetch events that are newer than given time.
                Defaults to None.
            event_types (List[int], optional): Event type to filter by.
                Defaults to None.
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.

        Returns:
            Dict[str, Any]: A list of events.
        """
        params = remove_empty_elements(
            {
                "detection_sha256": detection_sha256,
                "application_sha256": application_sha256,
                "connector_guid[]": connector_guids,
                "group_guid[]": group_guids,
                "start_date": start_date,
                "event_type[]": event_types,
                "limit": limit,
                "offset": offset,
            }
        )
        demisto.debug(f"Sending request: {params}")
        return self._http_request(
            method="GET",
            url_suffix="/events",
            params=params,
        )

    def event_type_list_request(self) -> dict[str, Any]:
        """
        Get a list of event types.

        Returns:
            Dict[str, Any]: List of event types.
        """
        return self._http_request(
            method="GET",
            url_suffix="/event_types",
        )

    def file_list_application_blocking_list_request(
        self, names: List[str] = None, limit: int = None, offset: int = None
    ) -> dict[str, Any]:
        """
        Get a file list of application blocking type.

        Args:
            names (List[str], optional): Name to filter by.
                Defaults to None.
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.

        Returns:
            Dict[str, Any]: File list of application blocking type.
        """
        params = remove_empty_elements(
            {
                "name[]": names,
                "limit": limit,
                "offset": offset,
            }
        )

        return self._http_request(
            method="GET",
            url_suffix="/file_lists/application_blocking",
            params=params,
        )

    def file_list_get_request(self, file_list_guid: str) -> dict[str, Any]:
        """
        Get a file list.

        Args:
            file_list_guid (str): GUID of the file list to get.

        Returns:
            Dict[str, Any]: Information about a policy.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/file_lists/{file_list_guid}",
        )

    def file_list_simple_custom_detections_list_request(
        self, names: List[str] = None, limit: int = None, offset: int = None
    ) -> dict[str, Any]:
        """
        Get a file list of simple custom detections type.

        Args:
            names (List[str], optional): Name to filter by.
                Defaults to None.
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.

        Returns:
            Dict[str, Any]: File list of simple custom detections type.
        """
        params = remove_empty_elements(
            {
                "name[]": names,
                "limit": limit,
                "offset": offset,
            }
        )

        return self._http_request(
            method="GET",
            url_suffix="/file_lists/simple_custom_detections",
            params=params,
        )

    def file_list_item_list_request(
        self, file_list_guid: str, limit: int = None, offset: int = None
    ) -> dict[str, Any]:
        """
        Get information about a file list items.

        Args:
            file_list_guid (str): GUID of the file list to get its items.
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about a file list items.
        """
        params = remove_empty_elements(
            {
                "limit": limit,
                "offset": offset,
            }
        )

        return self._http_request(
            method="GET",
            url_suffix=f"/file_lists/{file_list_guid}/files",
            params=params,
        )

    def file_list_item_get_request(
        self, file_list_guid: str, sha256: str
    ) -> dict[str, Any]:
        """
        Get information about a file list item.

        Args:
            file_list_guid (str): GUID of the file list to get its items.
            sha256 (str): sha256 of item to get.

        Returns:
            Dict[str, Any]: Information about a file list item.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/file_lists/{file_list_guid}/files/{sha256}",
        )

    def file_list_item_create_request(
        self, file_list_guid: str, sha256: str, description: str = None
    ) -> dict[str, Any]:
        """
        Create a new file list item.

        Args:
            file_list_guid (str): GUID of the file list to add the new item.
            sha256 (str): sha256 of the item to create.

        Returns:
            Dict[str, Any]: Information about the new file list item.
        """
        body = remove_empty_elements(
            {
                "description": description,
            }
        )

        return self._http_request(
            method="POST",
            url_suffix=f"/file_lists/{file_list_guid}/files/{sha256}",
            json_data=body,
        )

    def file_list_item_delete_request(
        self, file_list_guid: str, sha256: str
    ) -> dict[str, Any]:
        """
        Delete an item from a file list item.

        Args:
            file_list_guid (str): GUID of the file list to delete item.
            sha256 (str): sha256 of the item to delete.

        Returns:
            Dict[str, Any]: Information about the deletion result.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=f"/file_lists/{file_list_guid}/files/{sha256}",
        )

    def group_list_request(
        self, name: str = None, limit: int = None, offset: int = None
    ) -> dict[str, Any]:
        """
        Get a list of groups information that can be filtered by a name.

        Args:
            name (str, optional): Name to filter by.
                Defaults to None.
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.

        Returns:
            Dict[str, Any]: List of group information.
        """
        params = remove_empty_elements(
            {
                "name": name,
                "limit": limit,
                "offset": offset,
            }
        )

        return self._http_request(
            method="GET",
            url_suffix="/groups",
            params=params,
        )

    def group_get_request(self, group_guid: str) -> dict[str, Any]:
        """
        Get information about a group.

        Args:
            group_guid (str): GUID of the group to get information about.

        Returns:
            Dict[str, Any]: Information about a group.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/groups/{group_guid}",
        )

    def group_policy_update_request(
        self,
        group_guid: str,
        windows_policy_guid: str = None,
        mac_policy_guid: str = None,
        android_policy_guid: str = None,
        linux_policy_guid: str = None,
    ) -> dict[str, Any]:
        """
        Update a group's Policy to given Policy GUID.

        Args:
            group_guid (str): The group to update.
            windows_policy_guid (str, optional): Policy GUID for Windows.
                Defaults to None.
            mac_policy_guid (str, optional): Policy GUID for MAC.
                Defaults to None.
            android_policy_guid (str, optional): Policy GUID for Android.
                Defaults to None.
            linux_policy_guid (str, optional): Policy GUID for Linux.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about the updated group.
        """
        body = remove_empty_elements(
            {
                "windows_policy_guid": windows_policy_guid,
                "mac_policy_guid": mac_policy_guid,
                "android_policy_guid": android_policy_guid,
                "linux_policy_guid": linux_policy_guid,
            }
        )

        return self._http_request(
            method="PATCH",
            url_suffix=f"groups/{group_guid}",
            json_data=body,
        )

    def group_parent_update_request(
        self,
        child_guid: str,
        parent_group_guid: str = None,
    ) -> dict[str, Any]:
        """
        Converts an existing group to a child of another group or an existing
        child group to a root group (that is, one with no parent groups).

        Args:
            child_guid (str): Groups GUID to set as child or make as root.
            parent_group_guid (str, optional): Group parent to set to child group.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about the updated group.
        """
        return self._http_request(
            method="PATCH",
            url_suffix=f"groups/{child_guid}/parent",
            json_data=remove_empty_elements({"parent_group_guid": parent_group_guid}),
        )

    def group_create_request(self, name: str, description: str) -> dict[str, Any]:
        """
        Create a new group and get its information.

        Args:
            name (str): Name of the new group.
            description (str): Description of the new group.

        Returns:
            Dict[str, Any]: Information about the new group.
        """
        body = {
            "name": name,
            "description": description,
        }

        return self._http_request(
            method="POST",
            url_suffix="/groups",
            json_data=body,
        )

    def group_delete_request(self, group_guid: str) -> dict[str, Any]:
        """
        Deletes the group with the group_guid.

        Args:
            group_guid (str): Group GUID of the selected group to delete.

        Returns:
            Dict[str, Any]: Information about the delete operation, if it has succeeded.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=f"groups/{group_guid}",
        )

    def indicator_get_request(self, indicator_guid: str) -> dict[str, Any]:
        """
        Get information about a indicator.

        Args:
            indicator_guid (str): GUID of the indicator to get.

        Returns:
            Dict[str, Any]: Information about a indicator.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/indicators/{indicator_guid}",
        )

    def indicator_list_request(
        self, limit: int = None, offset: int = None
    ) -> dict[str, Any]:
        """
        Get a list of indicators information.

        Args:
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.

        Returns:
            Dict[str, Any]: List of indicators information.
        """
        params = remove_empty_elements(
            {
                "limit": limit,
                "offset": offset,
            }
        )

        return self._http_request(
            method="GET",
            url_suffix="/indicators",
            params=params,
        )

    def policy_list_request(
        self,
        products: List[str] = None,
        names: List[str] = None,
        limit: int = None,
        offset: int = None,
    ) -> dict[str, Any]:
        """
        Get a list of policies information.

        Args:
            product (List[str], optional): OS product to filter by.
                Defaults to None.
            name (List[str], optional): Name to filter by.
                Defaults to None.
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.

        Returns:
            Dict[str, Any]: List of policies information.
        """
        params = remove_empty_elements(
            {
                "product[]": products,
                "name[]": names,
                "limit": limit,
                "offset": offset,
            }
        )

        return self._http_request(
            method="GET",
            url_suffix="/policies",
            params=params,
        )

    def policy_get_request(self, policy_guid: str) -> dict[str, Any]:
        """
        Get information about a policy.

        Args:
            policy_guid (str): GUID of the policy to get.

        Returns:
            Dict[str, Any]: Information about a policy.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/policies/{policy_guid}",
        )

    def app_trajectory_query_list_request(self, ios_bid: str) -> dict[str, Any]:
        """
        Get app trajectory query for a given IOS bundle ID.

        Args:
            ios_bid (str): IOS bundle ID.

        Returns:
            Dict[str, Any]: App Trajectory for IOS bundle ID.
        """
        params = {
            "ios_bid": ios_bid,
        }

        return self._http_request(
            method="GET", url_suffix="/app_trajectory/queries", params=params
        )

    def version_get_request(self) -> dict[str, Any]:
        """
        Get the current version of the API.

        Returns:
            Dict[str, Any]: Current version of the API.
        """
        return self._http_request(
            method="GET",
            url_suffix="/version",
        )

    def vulnerability_list_request(
        self,
        group_guids: List[str] = None,
        start_time: str = None,
        end_time: str = None,
        limit: int = None,
        offset: int = None,
    ) -> dict[str, Any]:
        """
        Get a list of vulnerabilities.

        Args:
            group_guids (List[str], optional): Group GUIDs to filter by.
                Defaults to None.
            start_time (str, optional): Inclusive (The list will include vulnerable programs detected at start_time).
                Defaults to None.
            end_time (str, optional): Exclusive - if end_time is a time (The list will only include vulnerable
                programs detected before end_time); Inclusive - if end_time is a date (The
                list will include vulnerable programs detected on the date).
                Defaults to None.
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.

        Returns:
            Dict[str, Any]: List of vulnerabilities.
        """
        params = remove_empty_elements(
            {
                "group_guid[]": group_guids,
                "start_time": start_time,
                "end_time": end_time,
                "limit": limit,
                "offset": offset,
            }
        )

        return self._http_request(
            method="GET",
            url_suffix="/vulnerabilities",
            params=params,
        )

    def vulnerable_computers_list_request(
        self,
        sha256: str,
        group_guids: List[str] = None,
        start_time: str = None,
        end_time: str = None,
        limit: int = None,
        offset: int = None,
    ) -> dict[str, Any]:
        """
        Get a list of computers observed with given SHA-256.

        Args:
            sha256 (str): SHA-256 that has been observed as a vulnerability.
            group_guid (List[str], optional): Group GUIDs to filter by.
                Defaults to None.
            start_time (str, optional): Inclusive (The list will include vulnerable programs detected at start_time).
                Defaults to None.
            end_time (str, optional): Exclusive - if end_time is a time (The list will only include vulnerable
                programs detected before end_time); Inclusive - if end_time is a date (The
                list will include vulnerable programs detected on the date).
                Defaults to None.
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.

        Returns:
            Dict[str, Any]: List of vulnerable computers.
        """
        params = remove_empty_elements(
            {
                "group_guid[]": group_guids,
                "start_time": start_time,
                "end_time": end_time,
                "limit": limit,
                "offset": offset,
            }
        )

        return self._http_request(
            method="GET",
            url_suffix=f"/vulnerabilities/{sha256}/computers",
            params=params,
        )


""" COMMAND FUNCTIONS """  # pylint: disable=pointless-string-statement


def fetch_incidents(
    client: Client,
    last_run: dict[str, Any],
    first_fetch_time: str,
    incident_severities: list[str | None],
    event_types: list[int] = None,
    max_incidents_to_fetch: int = FETCH_LIMIT,
    include_null_severities: bool = False,
) -> tuple[dict[str, int], list[dict]]:
    """
    Retrieves new alerts every interval (default is 1 minute).
    Implements the logic of making sure that incidents are fetched only once.
    By default it's invoked by XSOAR every minute.
    It will use last_run to save the time of the last incident it processed and previous incident IDs.
    If last_run is not provided, first_fetch_time will be used to determine when to start fetching the first time.

    Args:
        client (Client): Cisco AMP client to run desired requests
        last_run (Dict[str, Any]):
            last_fetch: Time of the last processed incident.
            previous_ids: list of incident IDs to that would not be repeated.
        first_fetch_time (str): Determines the time of when fetching has been started.
        event_types (list[int], optional): Event types to filter by.
            Defaults to None.
        incident_severities (list[str], optional): Incident severities to filter by.
            Defaults to None.
        max_incidents_to_fetch (int, optional): Max number of incidents to fetch in a single run.
            Defaults to FETCH_LIMIT.
        include_null_severities (bool): Whether to include incidents without any severity.

    Returns:
        tuple[dict[str, int], list[dict]]:
            next_run: Contains information that will be used in the next run.
            incidents: List of incidents that will be created in XSOAR.
    """
    last_fetch = last_run.get("last_fetch")

    # The list of event ids that are suspected of being duplicates
    previous_ids = set(last_run.get("previous_ids", []))

    # Copy the previous_ids list to manage the events list suspectedof
    # being duplicates for the next fetch
    new_previous_ids = previous_ids.copy()

    demisto.debug(f"Running fetch with previous ids: {','.join(previous_ids)}")

    # If a last fetch run doesn't exist, use the first fetch time.
    if last_fetch is None:
        demisto.debug("First fetch, setting last run with first_fetch_time.")
        last_fetch = first_fetch_time

    last_fetch_timestamp = date_to_timestamp(last_fetch, ISO_8601_FORMAT)

    items: list[dict] = []
    offset: int = 0

    # A loop of fetching the events,
    # fetches all the events from the current time up
    # to the provided start_time or last_fetch
    counter = 1
    while True:
        demisto.debug(f"looping on page #{counter}")
        response = client.event_list_request(start_date=last_fetch,
                                             event_types=event_types,
                                             limit=500,
                                             offset=offset)

        demisto.debug(f"Received {len(response['data'])}. Adding.")

        items = items + response["data"]

        # Check if there are more pages to fetch
        if "next" not in response.get("metadata", {}).get("links"):
            # Reverses the list of events so that the list is in ascending order
            # so that the earliest event will be the first in the list
            demisto.debug("found last page, returning results.")
            items.reverse()
            break

        demisto.debug(f"setting offset to: {len(items)}")
        offset = len(items)
        counter += 1

    demisto.debug(f"Received total of {len(items)}. IDs: {','.join(str(item.get('id')) for item in items)}")
    incidents: list[dict[str, Any]] = []
    incident_name = 'Cisco AMP Event ID:"{event_id}"'

    # Incase the severity acceptance list is empty, initialize it with all values.
    if not incident_severities:
        incident_severities.extend(XSOAR_SEVERITY_BY_AMP_SEVERITY.keys())

    # Whether to accept an incident without a severity.
    if include_null_severities:
        incident_severities.append(None)

    for item in items:
        demisto.debug("Looping on results to filter.")

        item_id = str(item.get("id"))
        # Break once the maximum number of incidents has been achieved.
        if len(incidents) >= max_incidents_to_fetch:
            break

        severity = item.get("severity")

        # Skip if the incident severity isn't in the requested severities.
        if severity not in incident_severities:
            demisto.debug(f"incident {item_id} filtered due to severity: {severity}")
            continue

        # Skip if the incident ID has been fetched already.
        if (incident_id := item_id) in previous_ids:
            demisto.debug(f"incident {item_id} filtered due to duplication: {severity}")
            continue

        incident_timestamp = item["timestamp"] * 1000
        incident = remove_empty_elements(
            {
                "name": incident_name.format(
                    event_id=incident_id,
                ),
                "occurred": timestamp_to_datestring(incident_timestamp),
                "rawJSON": json.dumps(item),
                "severity": XSOAR_SEVERITY_BY_AMP_SEVERITY.get(
                    str(severity), IncidentSeverity.UNKNOWN
                ),
                "details": str(item.get("event_type")),
                "dbotMirrorId": incident_id,
            }
        )

        incidents.append(incident)
        demisto.debug(f"incident {item_id} inserted to system.")

        # Update the latest incident time that was fetched.
        # And accordingly initializing the list of `previous_ids`
        # to the ids that belong to the time of the last incident received
        if incident_timestamp > last_fetch_timestamp:
            new_previous_ids = {incident_id}
            last_fetch_timestamp = incident_timestamp

        # Adding the event ID when the event time is equal to the last received event
        elif incident_timestamp == last_fetch_timestamp:
            new_previous_ids.add(incident_id)

    next_run = {
        "last_fetch": timestamp_to_datestring(last_fetch_timestamp),
        "previous_ids": list(new_previous_ids),
    }
    demisto.debug(f"Setting last run: {next_run}")

    return next_run, incidents


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Cisco AMP client to run desired requests

    Returns:
        str: 'ok' if test passed, anything else will fail the test.
    """
    try:
        client.version_get_request()

    except DemistoException as exc:
        if exc.res and exc.res.status_code == HTTPStatus.UNAUTHORIZED:
            return "Authorization Error: Unknown API key or Client ID"

        return exc.message

    return "ok"


def computer_list_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """
    Get information about computers.
    The command can get a list of filtered computers or a specific computer with connector_guid.
    The command supports pagination.
    If needed the response will be concatenated.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: If there is a connector_guid other arguments must not exist.

    Returns:
        List[CommandResults]: Information about a list of computers or a specific computer.
    """
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))
    connector_guid = args.get("connector_guid", "")
    hostnames = argToList(args.get("hostname"))
    internal_ip = args.get("internal_ip")
    external_ip = args.get("external_ip")
    group_guids = argToList(args.get("group_guid"))
    last_seen_within = arg_to_number(args.get("last_seen_within"))
    last_seen_over = arg_to_number(args.get("last_seen_over"))

    is_get_request = bool(connector_guid)
    is_list_request = any(
        (
            page,
            page_size,
            limit,
            hostnames,
            internal_ip,
            external_ip,
            group_guids,
            last_seen_within,
            last_seen_over,
        )
    )

    if is_get_request and is_list_request:
        raise ValueError(
            "connector_guid must be the only input, when fetching a specific computer."
        )

    if not is_get_request:
        pagination = get_pagination_parameters(page, page_size, limit)
        raw_response_list: List[dict[str, Any]] = []

        # Run multiple requests according to pagination inputs.
        for request_number in pagination_range(pagination):
            raw_response_list.append(
                client.computer_list_request(
                    limit=pagination.limit,
                    offset=None
                    if pagination.offset is None
                    else pagination.offset * request_number,
                    hostnames=hostnames,
                    internal_ip=internal_ip,
                    external_ip=external_ip,
                    group_guids=group_guids,
                    last_seen_within=last_seen_within,
                    last_seen_over=last_seen_over,
                )
            )

            if not raw_response_list[-1]["data"]:
                break

        raw_response: dict[str, Any] = combine_response_results(
            raw_response_list, pagination.is_automatic
        )

    else:
        raw_response = client.computer_get_request(
            connector_guid=connector_guid,
        )

    context_outputs = get_context_output(raw_response, ["links"])

    readable_output = get_results_readable_output(raw_response)
    readable_output += get_computer_readable_output(raw_response)

    command_results = []

    for context_output in context_outputs:
        endpoint_indicator = Common.Endpoint(
            id=context_output["connector_guid"],
            ip_address=context_output["internal_ips"][0],
            hostname=context_output["hostname"],
            mac_address=context_output["network_addresses"][0]["mac"],
            os=context_output["operating_system"],
            os_version=context_output["os_version"],
            status="Online" if context_output["active"] else "Offline",
            vendor="CiscoAMP Response",
        )

        command_results.append(
            CommandResults(
                outputs_prefix="CiscoAMP.Computer",
                outputs_key_field="connector_guid",
                outputs=context_output,
                raw_response=raw_response,
                indicator=endpoint_indicator,
            )
        )

    command_results.append(CommandResults(readable_output=readable_output))

    return command_results


def computer_trajectory_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Get information about a computer's trajectory.
    The command supports pagination.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: If the user hasn't entered one of the required query options wrong.

    Returns:
        CommandResults: Information about a computer's trajectory.
    """
    connector_guid = args["connector_guid"]
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))
    query_string = args.get("query_string")

    if not validate_query(
        query=query_string,
        accept_ipv4=True,
        accept_sha256=True,
        accept_url=True,
        accept_filename=False,
    ):
        raise ValueError("query_string must be: SHA-256/IPv4/URL")

    pagination = get_pagination_parameters(page, page_size, limit)

    raw_response = client.computer_trajectory_list_request(
        connector_guid=connector_guid,
        limit=pagination.page * pagination.page_size
        if pagination.is_manual
        else (limit or None),
        query_string=query_string,
    )

    context_output, readable_output = extract_pagination_from_response(
        pagination, raw_response
    )

    return CommandResults(
        outputs_prefix="CiscoAMP.ComputerTrajectory",
        outputs_key_field="id",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def computer_user_activity_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Get information about computers with user activity on them.
    The command supports pagination.
    If needed the response will be concatenated.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about computers with user activity on them.
    """
    username = args["username"]
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))

    pagination = get_pagination_parameters(page, page_size, limit)
    raw_response_list: List[dict[str, Any]] = []

    # Run multiple requests according to pagination inputs.
    for request_number in pagination_range(pagination):
        raw_response_list.append(
            client.computer_user_activity_get_request(
                username=username,
                limit=pagination.limit,
                offset=None
                if pagination.offset is None
                else pagination.offset * request_number,
            )
        )

        if not raw_response_list[-1]["data"]:
            break

    raw_response: dict[str, Any] = combine_response_results(
        raw_response_list, pagination.is_automatic
    )

    context_output = get_context_output(raw_response, ["links"])

    readable_output = get_results_readable_output(raw_response)
    readable_output += get_readable_output(
        response=raw_response,
        header_by_keys=ACTIVITY_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=ACTIVITY_TITLE,
    )

    return CommandResults(
        outputs_prefix="CiscoAMP.ComputerUserActivity",
        outputs_key_field="connector_guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def computer_user_trajectory_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Get information about a computer's trajectory with the option filter by username.
    The command supports pagination.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about a computer's trajectory.
    """
    connector_guid = args["connector_guid"]
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))
    username = args.get("username")

    pagination = get_pagination_parameters(page, page_size, limit)

    raw_response = client.computer_user_trajectory_list_request(
        connector_guid=connector_guid,
        limit=pagination.page * pagination.page_size
        if pagination.is_manual
        else (limit or None),
        username=username,
    )

    context_output, readable_output = extract_pagination_from_response(
        pagination, raw_response
    )

    return CommandResults(
        outputs_prefix="CiscoAMP.ComputerUserTrajectory",
        outputs_key_field="id",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def computer_vulnerabilities_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Get information about a computer's vulnerabilities.
    The command supports pagination.
    If needed the response will be concatenated.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about a computer's vulnerabilities.
    """
    connector_guid = args["connector_guid"]
    start_time = args.get("start_time")
    end_time = args.get("end_time")
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))

    pagination = get_pagination_parameters(page, page_size, limit)
    raw_response_list: List[dict[str, Any]] = []

    # Run multiple requests according to pagination inputs.
    for request_number in pagination_range(pagination):
        raw_response_list.append(
            client.computer_vulnerabilities_list_request(
                connector_guid=connector_guid,
                start_time=start_time,
                end_time=end_time,
                limit=pagination.limit,
                offset=None
                if pagination.offset is None
                else pagination.offset * request_number,
            )
        )

        if not raw_response_list[-1]["data"]:
            break

    raw_response: dict[str, Any] = combine_response_results(
        raw_response_list, pagination.is_automatic
    )

    context_output = get_context_output(raw_response, ["links"])
    context_output = context_output[0]["vulnerabilities"]
    add_item_to_all_dictionaries(
        context_output,
        "connector_guid",
        dict_safe_get(raw_response, ["data", "connector_guid"]),
    )

    readable_output = get_results_readable_output(raw_response)
    readable_output += get_computer_readable_output(raw_response)
    readable_output += get_readable_output(
        response=raw_response,
        header_by_keys=VULNERABILITY_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data", "vulnerabilities"],
        keys_to_items_option_2=["data"],
        title=VULNERABILITY_TITLE,
    )

    return CommandResults(
        outputs_prefix="CiscoAMP.ComputerVulnerability",
        outputs_key_field="connector_guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def computer_move_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Move a computer to another group.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the moved computer.
    """
    connector_guid = args["connector_guid"]
    group_guid = args["group_guid"]

    raw_response = client.computer_move_request(
        connector_guid=connector_guid,
        group_guid=group_guid,
    )

    context_output = get_context_output(raw_response, ["links"])
    readable_output = get_computer_readable_output(raw_response)

    return CommandResults(
        outputs_prefix="CiscoAMP.Computer",
        outputs_key_field="connector_guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def computer_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Deletes a computer and returns a result if the deletion has succeeded.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: Incase the deletion has failed, raise an error.

    Returns:
        CommandResults: Success message of the deleted computer.
    """
    connector_guid = args["connector_guid"]

    raw_response = client.computer_delete_request(connector_guid=connector_guid)

    is_deleted = dict_safe_get(raw_response, ["data", "deleted"])

    if not is_deleted:
        raise DemistoException(
            message=f'Failed to delete Connector GUID: "{connector_guid}".',
            res=raw_response,
        )

    readable_output = f'Connector GUID: "{connector_guid}"\nSuccessfully deleted.'

    return CommandResults(
        readable_output=readable_output,
        raw_response=raw_response,
    )


def computer_activity_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Get information about computers with query activity on them.
    The command supports pagination.
    If needed the response will be concatenated.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: If the input query isn't an IP, URL

    Returns:
        CommandResults: Information about computers with query activity on them.
    """
    query_string = args["query_string"]
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))

    # Check if the query is empty or of one of the following formats: SHA256, IPv4, URL or Filename.
    if not validate_query(
        query=query_string,
        accept_ipv4=True,
        accept_filename=True,
        accept_sha256=True,
        accept_url=True,
    ):
        raise ValueError("query_string must be: SHA-256/IPv4/URL/Filename")

    pagination = get_pagination_parameters(page, page_size, limit)
    raw_response_list: List[dict[str, Any]] = []

    # Run multiple requests according to pagination inputs.
    for request_number in pagination_range(pagination):
        raw_response_list.append(
            client.computer_activity_list_request(
                query_string=query_string,
                limit=pagination.limit,
                offset=None
                if pagination.offset is None
                else pagination.offset * request_number,
            )
        )

        if not raw_response_list[-1]["data"]:
            break

    raw_response: dict[str, Any] = combine_response_results(
        raw_response_list, pagination.is_automatic
    )

    context_output = get_context_output(raw_response, ["links"])

    readable_output = get_results_readable_output(raw_response)
    readable_output += get_readable_output(
        response=raw_response,
        header_by_keys=ACTIVITY_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=ACTIVITY_TITLE,
    )

    return CommandResults(
        outputs_prefix="CiscoAMP.ComputerActivity",
        outputs_key_field="connector_guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def computers_isolation_feature_availability_get_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Get information about available isolation options for a computer.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about a computer's isolation options.
    """
    connector_guid = args["connector_guid"]

    try:
        raw_response = client.computer_isolation_feature_availability_get_request(
            connector_guid=connector_guid,
        )
        readable_output = get_isolation_options_readable_output(raw_response)

    except DemistoException as exc:
        # this is an expected behavior, when isolation is not allowed.
        if exc.res and exc.res.status_code == HTTPStatus.METHOD_NOT_ALLOWED:
            readable_output = "Isolation is not allowed on policy."

        else:
            raise  # if there's a different HTTP status code, it's not an expected behavior.

    return CommandResults(readable_output=readable_output)


def computer_isolation_get_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Get information about a computer's isolation.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about a computer's isolation.
    """
    connector_guid = args["connector_guid"]

    raw_response = client.computer_isolation_get_request(
        connector_guid=connector_guid,
    )

    readable_output = get_readable_output(
        response=raw_response,
        header_by_keys=ISOLATION_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=ISOLATION_TITLE,
    )
    context_output = get_context_output(
        response=raw_response,
        contexts_to_delete=["links"],
        item_to_add=("connector_guid", connector_guid),
    )[0]

    return CommandResults(
        outputs_prefix="CiscoAMP.ComputerIsolation",
        outputs_key_field="connector_guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def computer_isolation_create_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Put a computer in isolation.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the computer's isolation.
    """
    connector_guid = args["connector_guid"]
    comment = args["comment"]
    unlock_code = args["unlock_code"]

    raw_response = client.computer_isolation_create_request(
        connector_guid=connector_guid,
        comment=comment,
        unlock_code=unlock_code,
    )

    readable_output = get_readable_output(
        response=raw_response,
        header_by_keys=ISOLATION_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=ISOLATION_TITLE,
    )
    context_output = get_context_output(
        response=raw_response,
        contexts_to_delete=["links"],
        item_to_add=("connector_guid", connector_guid),
    )[0]

    return CommandResults(
        outputs_prefix="CiscoAMP.ComputerIsolation",
        outputs_key_field="connector_guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@polling_function(
    name="cisco-amp-computer-isolation-create",
    interval=arg_to_number(demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL)),
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", DEFAULT_TIMEOUT)),
    requires_polling_arg=False,
)
def computer_isolation_create_polling_command(
    args: dict[str, Any], **kwargs
) -> PollResult:
    """
    Polling command to display the progress of computer isolation create command.
    After the first run, progress will be shown through the computer isolation get command.
    Computer isolation create command will run till its status is 'isolated' or 'pending_start'.

    Args:
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request and a Client.

    Returns:
        PollResult: A result to return to the user which will be set as a CommandResults.
            The result itself will depend on the stage of polling.
    """
    return computer_isolation_polling_command(
        client=kwargs["client"],
        args=args,
        computer_isolation_command=computer_isolation_create_command,
        result_isolation_status=("isolated", "pending_start"),
    )


def computer_isolation_delete_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Stop a computer's in isolation.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the computer's isolation.
    """
    connector_guid = args["connector_guid"]
    comment = args.get("comment")

    raw_response = client.computer_isolation_delete_request(
        connector_guid=connector_guid,
        comment=comment,
    )

    readable_output = get_readable_output(
        response=raw_response,
        header_by_keys=ISOLATION_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=ISOLATION_TITLE,
    )
    context_output = get_context_output(raw_response, ["links"])

    return CommandResults(
        outputs_prefix="CiscoAMP.ComputerIsolation",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@polling_function(
    name="cisco-amp-computer-isolation-delete",
    interval=arg_to_number(demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL)),
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", DEFAULT_TIMEOUT)),
    requires_polling_arg=False,
)
def computer_isolation_delete_polling_command(
    args: dict[str, Any], **kwargs
) -> PollResult:
    """
    Polling command to display the progress of computer isolation delete command.
    After the first run, progress will be shown through the computer isolation get command.
    Computer isolation delete command will run till its status is 'not_isolated' or 'pending_stop'.

    Args:
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request and a Client.

    Returns:
        PollResult: A result to return to the user which will be set as a CommandResults.
            The result itself will depend on the stage of polling.
    """
    return computer_isolation_polling_command(
        client=kwargs["client"],
        args=args,
        computer_isolation_command=computer_isolation_delete_command,
        result_isolation_status=("not_isolated", "pending_stop"),
    )


def computer_isolation_polling_command(
    client: Client,
    args: dict[str, Any],
    computer_isolation_command: Callable,
    result_isolation_status: tuple[str, str],
) -> PollResult:
    """
    _summary_

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.
        computer_isolation_command (Callable): can be one of the two functions:
            computer_isolation_create_command
            computer_isolation_delete_command
        result_isolation_status (Tuple[str, str]): Result status to end polling function, can be on of the two options:
            ('isolated', 'pending_start')
            ('not_isolated', 'pending_stop')

    Returns:
        PollResult: A result to return to the user which will be set as a CommandResults.
            The result itself will depend on the stage of polling.
    """
    if "status" not in args:
        command_results = computer_isolation_command(client, args)

    else:
        command_results = computer_isolation_get_command(client, args)

    status = dict_safe_get(command_results.raw_response, ["data", "status"])

    if status in result_isolation_status:
        return PollResult(
            response=command_results,
            continue_to_poll=False,
        )

    args_for_next_run = {"status": status, **args}

    return PollResult(
        response=command_results,
        continue_to_poll=True,
        args_for_next_run=args_for_next_run,
    )


def create_relationships(
    client: Client, indicator: str, relationship: dict[str, str | int | dict]
):
    '''
    Creates relationships only when the event has a parent file for the file attached to the event
    '''
    if not client.should_create_relationships or not relationship:
        return None

    if not (identity := relationship.get("identity", {})) or not isinstance(
        identity, dict
    ):
        return None

    if (
        not (entity_b := identity.get("sha256"))
        or auto_detect_indicator_type(entity_b) != FeedIndicatorType.File
    ):
        return None

    relationships = [
        EntityRelationship(
            name=EntityRelationship.Relationships.RELATED_TO,
            entity_a=indicator,
            entity_a_type=FeedIndicatorType.File,
            entity_b=entity_b,
            entity_b_type=FeedIndicatorType.File,
            brand=INTEGRATION_NAME,
            source_reliability=client.reliability,
        )
    ]

    return relationships if relationships else None


def event_list_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """
    Get information about events with the option to filter them.
    The command supports pagination.
    If needed the response will be concatenated.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: If detection_sha256 isn't a SHA-256 value.
        ValueError: If application_sha256 isn't a SHA-256 value.

    Returns:
        List[CommandResults]: Information about events.
    """
    detection_sha256 = args.get("detection_sha256")
    application_sha256 = args.get("application_sha256")
    connector_guid = argToList(args.get("connector_guid"))
    group_guid = argToList(args.get("group_guid"))
    start_date = args.get("start_date")
    event_type = argToList(args.get("event_type"))
    event_type = [arg_to_number(et) for et in event_type if et is not None]
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))

    if detection_sha256 and not sha256Regex.match(detection_sha256):
        raise ValueError("detection_sha256 must be: SHA-256")

    if application_sha256 and not sha256Regex.match(application_sha256):
        raise ValueError("application_sha256 must be: SHA-256")

    pagination = get_pagination_parameters(page, page_size, limit)
    raw_response_list: List[dict[str, Any]] = []

    # Run multiple requests according to pagination inputs.
    for request_number in pagination_range(pagination):
        raw_response_list.append(
            client.event_list_request(
                detection_sha256=detection_sha256,
                application_sha256=application_sha256,
                connector_guids=connector_guid,
                group_guids=group_guid,
                start_date=start_date,
                event_types=event_type,  # type: ignore # List[Optional[int]] arg_to_number; expected Optional[List[int]]
                limit=pagination.limit,
                offset=None
                if pagination.offset is None
                else pagination.offset * request_number,
            )
        )

    raw_response: dict[str, Any] = combine_response_results(
        raw_response_list, pagination.is_automatic
    )

    context_outputs = get_context_output(raw_response, ["links"])

    readable_output = get_results_readable_output(raw_response)
    readable_output += get_readable_output(
        response=raw_response,
        header_by_keys=EVENT_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=EVENT_TITLE,
    )

    command_results = []

    for context_output in context_outputs:
        file_indicator = None

        if "file" in context_output:
            sha256 = dict_safe_get(context_output, ["file", "identity", "sha256"])
            disposition = dict_safe_get(context_output, ["file", "disposition"])

            dbot_score = get_dbotscore(client.reliability, sha256, disposition)

            # Create relationships for the file indicator
            relationships = (
                create_relationships(
                    client=client,
                    indicator=sha256,
                    relationship=dict_safe_get(context_output, ["file", "parent"]),
                )
            )

            file_indicator = Common.File(
                md5=dict_safe_get(context_output, ["file", "identity", "md5"]),
                sha1=dict_safe_get(context_output, ["file", "identity", "sha1"]),
                sha256=sha256,
                path=dict_safe_get(context_output, ["file", "file_path"]),
                name=dict_safe_get(context_output, ["file", "file_name"]),
                hostname=dict_safe_get(context_output, ["computer", "hostname"]),
                relationships=relationships,
                dbot_score=dbot_score,
            )

        command_results.append(
            CommandResults(
                outputs_prefix="CiscoAMP.Event",
                outputs_key_field="id",
                outputs=context_output,
                raw_response=raw_response,
                indicator=file_indicator,
            )
        )

    command_results.append(CommandResults(readable_output=readable_output))

    return command_results


def event_type_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get information about event types.
    The command supports pagination.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about event types.
    """
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))

    pagination = get_pagination_parameters(page, page_size, limit)
    raw_response = client.event_type_list_request()

    if pagination.is_manual:
        start = (pagination.page - 1) * pagination.page_size
        stop = pagination.page * pagination.page_size

        raw_response["data"] = raw_response["data"][start:stop]

    else:
        raw_response["data"] = raw_response["data"][: pagination.limit]

    context_output = get_context_output(raw_response, ["links"])

    readable_output = get_results_readable_output(raw_response)
    readable_output += get_readable_output(
        response=raw_response,
        header_by_keys=EVENT_TYPE_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=EVENT_TYPE_TITLE,
    )

    return CommandResults(
        outputs_prefix="CiscoAMP.EventType",
        outputs_key_field="id",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def file_list_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get information about policies.
    The command supports pagination.
    If needed the response will be concatenated.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about policies.
    """
    file_list_type = args.get("file_list_type", "Application Blocking")
    names = argToList(args.get("name"))
    file_list_guid = args.get("file_list_guid")
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))

    file_list_request_by_type = {
        "Application Blocking": client.file_list_application_blocking_list_request,
        "Simple Custom Detection": client.file_list_simple_custom_detections_list_request,
    }

    if not file_list_guid:
        pagination = get_pagination_parameters(page, page_size, limit)
        raw_response_list: List[dict[str, Any]] = []

        # Run multiple requests according to pagination inputs.
        for request_number in pagination_range(pagination):
            raw_response_list.append(
                file_list_request_by_type[file_list_type](
                    names=names,
                    limit=pagination.limit,
                    offset=None
                    if pagination.offset is None
                    else pagination.offset * request_number,
                )
            )

            if not raw_response_list[-1]["data"]:
                break

        raw_response: dict[str, Any] = combine_response_results(
            raw_response_list, pagination.is_automatic
        )

    else:
        raw_response = client.file_list_get_request(
            file_list_guid=file_list_guid,
        )

    readable_output = get_results_readable_output(raw_response)
    readable_output += get_readable_output(
        response=raw_response,
        header_by_keys=FILE_LIST_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=FILE_LIST_TITLE,
    )

    context_output = get_context_output(raw_response, ["links"])

    return CommandResults(
        outputs_prefix="CiscoAMP.FileList",
        outputs_key_field="guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def file_list_item_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get information about file list items.
    The command supports pagination.
    If needed the response will be concatenated.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about file list items.
    """
    file_list_guid = args["file_list_guid"]
    sha256 = args.get("sha256")
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))

    if not sha256:
        pagination = get_pagination_parameters(page, page_size, limit)
        raw_response_list: List[dict[str, Any]] = []

        # Run multiple requests according to pagination inputs.
        for request_number in pagination_range(pagination):
            raw_response_list.append(
                client.file_list_item_list_request(
                    file_list_guid=file_list_guid,
                    limit=pagination.limit,
                    offset=None
                    if pagination.offset is None
                    else pagination.offset * request_number,
                )
            )

            if not raw_response_list[-1]["data"]:
                break

        raw_response: dict[str, Any] = combine_response_results(
            raw_response_list, pagination.is_automatic
        )

    else:
        raw_response = client.file_list_item_get_request(
            file_list_guid=file_list_guid,
            sha256=sha256,
        )

    readable_output = get_results_readable_output(raw_response)
    readable_output += get_readable_output(
        response=raw_response,
        header_by_keys=FILE_LIST_ITEM_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data", "items"],
        keys_to_items_option_2=["data"],
        title=FILE_LIST_ITEM_TITLE,
    )

    if dict_safe_get(raw_response, ["data", "policies"]):
        readable_output += get_readable_output(
            response=raw_response,
            header_by_keys=POLICY_HEADERS_BY_KEYS,
            keys_to_items_option_1=["data", "policies"],
            title=POLICY_TITLE,
        )

    context_output = get_context_output(raw_response, ["links"])

    return CommandResults(
        outputs_prefix="CiscoAMP.FileListItem",
        outputs_key_field="sha256",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def file_list_item_create_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Create a new item for a file list.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the new file list item.
    """
    file_list_guid = args["file_list_guid"]
    sha256 = args["sha256"]
    description = args.get("description")

    raw_response = client.file_list_item_create_request(
        file_list_guid=file_list_guid,
        sha256=sha256,
        description=description,
    )

    readable_output = get_readable_output(
        response=raw_response,
        header_by_keys=FILE_LIST_ITEM_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data", "items"],
        keys_to_items_option_2=["data"],
        title=FILE_LIST_ITEM_TITLE,
    )

    if dict_safe_get(raw_response, ["data", "policies"]):
        readable_output += get_readable_output(
            response=raw_response,
            header_by_keys=POLICY_HEADERS_BY_KEYS,
            keys_to_items_option_1=["data", "policies"],
            title=POLICY_TITLE,
        )

    context_output = get_context_output(raw_response, ["links"])

    return CommandResults(
        outputs_prefix="CiscoAMP.FileListItem",
        outputs_key_field="sha256",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def file_list_item_delete_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Delete an item from a file list.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Success message of the deleted item.
    """
    file_list_guid = args["file_list_guid"]
    sha256 = args["sha256"]

    raw_response = client.file_list_item_delete_request(
        file_list_guid=file_list_guid,
        sha256=sha256,
    )

    if "errors" in raw_response:
        raise DemistoException(
            message=f'Failed to delete-\nFile List GUID: "{file_list_guid}"\nSHA-256: "{sha256}" not found.',
            res=raw_response,
        )

    readable_output = f'SHA-256: "{sha256}" Successfully deleted from File List GUID: "{file_list_guid}".'

    return CommandResults(
        readable_output=readable_output,
        raw_response=raw_response,
    )


def group_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get information about groups with the option to filter by name.
    The command supports pagination.
    If needed the response will be concatenated.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about groups.
    """
    group_guid = args.get("group_guid")
    name = args.get("name")
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))

    if not group_guid:
        pagination = get_pagination_parameters(page, page_size, limit)
        raw_response_list: List[dict[str, Any]] = []

        # Run multiple requests according to pagination inputs.
        for request_number in pagination_range(pagination):
            raw_response_list.append(
                client.group_list_request(
                    name=name,
                    limit=pagination.limit,
                    offset=None
                    if pagination.offset is None
                    else pagination.offset * request_number,
                )
            )

            if not raw_response_list[-1]["data"]:
                break

        raw_response: dict[str, Any] = combine_response_results(
            raw_response_list, pagination.is_automatic
        )

        readable_output = get_results_readable_output(raw_response)
        readable_output += get_readable_output(
            response=raw_response,
            header_by_keys=GROUPS_HEADERS_BY_KEYS,
            keys_to_items_option_1=["data"],
            title=GROUPS_TITLE,
        )

    else:
        raw_response = client.group_get_request(
            group_guid=group_guid,
        )

        readable_output = get_readable_output(
            response=raw_response,
            header_by_keys=GROUP_HEADERS_BY_KEYS,
            keys_to_items_option_1=["data"],
            title=GROUP_TITLE,
        )

    context_output = get_context_output(raw_response, ["links"])

    return CommandResults(
        outputs_prefix="CiscoAMP.Group",
        outputs_key_field="guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def group_policy_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Update a groups Policy and get information about the group.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: Incase the user hasn't entered at least one policy GUID.

    Returns:
        CommandResults: Information about the updated group.
    """
    group_guid = args["group_guid"]
    windows_policy_guid = args.get("windows_policy_guid")
    mac_policy_guid = args.get("mac_policy_guid")
    android_policy_guid = args.get("android_policy_guid")
    linux_policy_guid = args.get("linux_policy_guid")

    has_no_policy_guid = not (
        any(
            (
                windows_policy_guid,
                mac_policy_guid,
                android_policy_guid,
                linux_policy_guid,
            )
        )
    )

    if has_no_policy_guid:
        raise ValueError("At least one Policy GUID must be entered.")

    raw_response = client.group_policy_update_request(
        group_guid=group_guid,
        windows_policy_guid=windows_policy_guid,
        mac_policy_guid=mac_policy_guid,
        android_policy_guid=android_policy_guid,
        linux_policy_guid=linux_policy_guid,
    )

    context_output = get_context_output(raw_response, ["links"])
    readable_output = get_readable_output(
        response=raw_response,
        header_by_keys=GROUP_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=GROUP_TITLE,
    )

    return CommandResults(
        outputs_prefix="CiscoAMP.Group",
        outputs_key_field="guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def group_parent_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Update a groups Policy and get information about the group.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: Incase the user hasn't entered at least one policy GUID.

    Returns:
        CommandResults: Information about the updated group.
    """
    child_guid = args["child_guid"]
    parent_group_guid = args.get("parent_group_guid")

    raw_response = client.group_parent_update_request(
        child_guid=child_guid,
        parent_group_guid=parent_group_guid,
    )

    context_output = get_context_output(raw_response, ["links"])
    readable_output = get_readable_output(
        response=raw_response,
        header_by_keys=GROUP_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=GROUP_TITLE,
    )

    return CommandResults(
        outputs_prefix="CiscoAMP.Group",
        outputs_key_field="guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def group_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Create a new group and get information about it.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the new group.
    """
    name = args["name"]
    description = args["description"]

    raw_response = client.group_create_request(
        name=name,
        description=description,
    )

    context_output = get_context_output(raw_response, ["links"])
    readable_output = get_readable_output(
        response=raw_response,
        header_by_keys=GROUP_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=GROUP_TITLE,
    )

    return CommandResults(
        outputs_prefix="CiscoAMP.Group",
        outputs_key_field="guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def groups_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Deletes a group and returns a result if the deletion has succeeded.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: Incase the deletion has failed, raise an error.

    Returns:
        CommandResults: Success message of the deleted group.
    """
    group_guid = args["group_guid"]

    raw_response = client.group_delete_request(group_guid=group_guid)

    is_deleted = dict_safe_get(raw_response, ["data", "deleted"])

    if not is_deleted:
        raise DemistoException(
            message=f'Failed to delete Group GUID: "{group_guid}".',
            res=raw_response,
        )

    readable_output = f'Group GUID: "{group_guid}"\nSuccessfully deleted.'

    return CommandResults(
        readable_output=readable_output,
        raw_response=raw_response,
    )


def indicator_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get information about indicators.
    The command supports pagination.
    If needed the response will be concatenated.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about indicators.
    """
    indicator_guid = args.get("indicator_guid")
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))

    if not indicator_guid:
        pagination = get_pagination_parameters(page, page_size, limit)
        raw_response_list: List[dict[str, Any]] = []

        # Run multiple requests according to pagination inputs.
        for request_number in pagination_range(pagination):
            raw_response_list.append(
                client.indicator_list_request(
                    limit=pagination.limit,
                    offset=None
                    if pagination.offset is None
                    else pagination.offset * request_number,
                )
            )

            if not raw_response_list[-1]["data"]:
                break

        raw_response: dict[str, Any] = combine_response_results(
            raw_response_list, pagination.is_automatic
        )

    else:
        raw_response = client.indicator_get_request(
            indicator_guid=indicator_guid,
        )

    readable_output = get_results_readable_output(raw_response)
    readable_output += get_readable_output(
        response=raw_response,
        header_by_keys=INDICATOR_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=INDICATOR_TITLE,
    )

    if dict_safe_get(raw_response, ["data", "mitre", "tactics"]):
        readable_output += get_readable_output(
            response=raw_response,
            header_by_keys=MITRE_HEADERS_BY_KEYS,
            keys_to_items_option_1=["data", "mitre", "tactics"],
            title=MITRE_TACTIC_TITLE,
        )

    if dict_safe_get(raw_response, ["data", "mitre", "techniques"]):
        readable_output += get_readable_output(
            response=raw_response,
            header_by_keys=MITRE_HEADERS_BY_KEYS,
            keys_to_items_option_1=["data", "mitre", "techniques"],
            title=MITRE_TECHNIQUE_TITLE,
        )

    context_output = get_context_output(raw_response, ["links"])

    return CommandResults(
        outputs_prefix="CiscoAMP.Indicator",
        outputs_key_field="guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def policy_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get information about policies.
    The command supports pagination.
    If needed the response will be concatenated.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about policies.
    """
    policy_guid = args.get("policy_guid")
    products = argToList(args.get("product"))
    names = argToList(args.get("name"))
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))

    if not policy_guid:
        pagination = get_pagination_parameters(page, page_size, limit)
        raw_response_list: List[dict[str, Any]] = []

        # Run multiple requests according to pagination inputs.
        for request_number in pagination_range(pagination):
            raw_response_list.append(
                client.policy_list_request(
                    products=products,
                    names=names,
                    limit=pagination.limit,
                    offset=None
                    if pagination.offset is None
                    else pagination.offset * request_number,
                )
            )

            if not raw_response_list[-1]["data"]:
                break

        raw_response: dict[str, Any] = combine_response_results(
            raw_response_list, pagination.is_automatic
        )

    else:
        raw_response = client.policy_get_request(
            policy_guid=policy_guid,
        )

    readable_output = get_results_readable_output(raw_response)
    readable_output += get_readable_output(
        response=raw_response,
        header_by_keys=POLICY_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=POLICY_TITLE,
    )

    context_output = get_context_output(raw_response, ["links"])

    return CommandResults(
        outputs_prefix="CiscoAMP.Policy",
        outputs_key_field="guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def app_trajectory_query_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Get app trajectory query for a given IOS bundle ID..
    The command supports pagination.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about an app trajectory.
    """
    ios_bid = args["ios_bid"]
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))

    pagination = get_pagination_parameters(page, page_size, limit)

    raw_response = client.app_trajectory_query_list_request(ios_bid=ios_bid)

    if pagination.is_manual:
        start = (pagination.page - 1) * pagination.page_size
        stop = pagination.page * pagination.page_size

        raw_response["data"] = raw_response["data"][start:stop]

    else:
        raw_response["data"] = raw_response["data"][: pagination.limit]

    context_output = get_context_output(raw_response, ["links"])
    readable_output = get_readable_output(
        response=raw_response,
        header_by_keys=APP_TRAJECTORY_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data"],
        title=APP_TRAJECTORY_TITLE,
    )

    return CommandResults(
        outputs_prefix="CiscoAMP.AppTrajectoryQuery",
        outputs_key_field="connector_guid",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def version_get_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:  # pylint: disable=unused-argument
    """
    Get the current version of the API.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Current version of the API.
    """
    raw_response = client.version_get_request()

    version = raw_response.get("version")

    readable_output = f"Version: {version}"
    context_output = {"version": version}

    return CommandResults(
        outputs_prefix="CiscoAMP.Version",
        outputs_key_field="version",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def vulnerability_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get information about vulnerabilities within computers.
    The command supports pagination.
    If needed the response will be concatenated.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Vulnerabilities of computers.
    """
    sha256 = args.get("sha256")
    group_guid = argToList(args.get("group_guid"))
    start_time = args.get("start_time")
    end_time = args.get("end_time")
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 0))
    limit = arg_to_number(args.get("limit", 0))

    pagination = get_pagination_parameters(page, page_size, limit)
    raw_response_list: List[dict[str, Any]] = []

    # Run multiple requests according to pagination inputs.
    for request_number in pagination_range(pagination):
        if not sha256:
            raw_response_list.append(
                client.vulnerability_list_request(
                    group_guids=group_guid,
                    start_time=start_time,
                    end_time=end_time,
                    limit=pagination.limit,
                    offset=None
                    if pagination.offset is None
                    else pagination.offset * request_number,
                )
            )

        else:
            raw_response_list.append(
                client.vulnerable_computers_list_request(
                    sha256=sha256,
                    group_guids=group_guid,
                    start_time=start_time,
                    end_time=end_time,
                    limit=pagination.limit,
                    offset=None
                    if pagination.offset is None
                    else pagination.offset * request_number,
                )
            )

        if not raw_response_list[-1]["data"]:
            break

    raw_response: dict[str, Any] = combine_response_results(
        raw_response_list, pagination.is_automatic
    )

    readable_output = get_results_readable_output(raw_response)
    if sha256:
        readable_output += get_readable_output(
            response=raw_response,
            header_by_keys=VULNERABLE_COMPUTER_HEADERS_BY_KEYS,
            keys_to_items_option_1=["data"],
            title=VULNERABLE_COMPUTER_TITLE,
        )
    else:
        readable_output += get_readable_output(
            response=raw_response,
            header_by_keys=VULNERABILITY_HEADERS_BY_KEYS,
            keys_to_items_option_1=["data"],
            title=VULNERABILITY_TITLE,
        )

    context_output = get_context_output(raw_response, ["links"])

    return CommandResults(
        outputs_prefix="CiscoAMP.Vulnerability",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def endpoint_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """
    Generic command that returns information about an endpoint.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        DemistoException: Incase ID, IP or an hostname wasn't inserted

    Returns:
        List[CommandResults]: A list of endpoint indicators.
    """
    endpoint_ids = argToList(args.get("id"))
    endpoint_ips = argToList(args.get("ip"))
    endpoint_hostnames = argToList(args.get("hostname"))

    if not any((endpoint_ids, endpoint_ips, endpoint_hostnames)):
        raise DemistoException(
            "CiscoAMP - In order to run this command, please provide a valid id, ip or hostname"
        )

    responses = []

    if endpoint_ids:
        for endpoint_id in endpoint_ids:
            response = client.computer_get_request(connector_guid=endpoint_id)

            responses.append(response)

    elif endpoint_ips:
        for endpoint_ip in endpoint_ips:
            response = client.computer_list_request(internal_ip=endpoint_ip)

        responses.append(response)

    else:
        responses.append(client.computer_list_request(hostnames=endpoint_hostnames))

    endpoints: List = []

    for response in responses:
        data_list = response["data"]

        if endpoint_ids:
            data_list = [data_list]

        for data in data_list:
            endpoint = Common.Endpoint(
                id=data["connector_guid"],
                ip_address=data["internal_ips"][0],
                hostname=data["hostname"],
                mac_address=data["network_addresses"][0]["mac"],
                os=data["operating_system"],
                os_version=data["os_version"],
                status="Online" if data["active"] else "Offline",
                vendor="CiscoAMP Response",
            )

            endpoint_context = endpoint.to_context().get(Common.Endpoint.CONTEXT_PATH)
            readable_output = tableToMarkdown(
                f'CiscoAMP - Endpoint {data["hostname"]}', endpoint_context
            )

            endpoints.append(
                CommandResults(
                    readable_output=readable_output,
                    raw_response=response,
                    outputs_key_field="_id",
                    indicator=endpoint,
                )
            )

    return endpoints


def file_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """
    Generic command that returns information about files.

    Args:
        client (Client): Cisco AMP client to run desired requests
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: In case the file_hash isn't SHA256

    Returns:
        List[CommandResults]: Indicator for every file_hash
    """
    files = argToList(args["file"])
    command_results: List[CommandResults] = []

    for file_hash in files:
        hash_type = get_hash_type(file_hash)

        if hash_type != "sha256":
            raise ValueError(f'Cisco AMP: Hash "{file_hash}" is not of type SHA-256')

        raw_response = client.event_list_request(detection_sha256=file_hash)

        data_list = raw_response["data"]

        if data_list:
            disposition = dict_safe_get(data_list[0], ["file", "disposition"])
            dbot_score = get_dbotscore(client.reliability, file_hash, disposition)

            file_indicator = Common.File(
                md5=dict_safe_get(data_list[0], ["file", "identity", "md5"]),
                sha1=dict_safe_get(data_list[0], ["file", "identity", "sha1"]),
                sha256=file_hash,
                path=dict_safe_get(data_list[0], ["file", "file_path"]),
                name=dict_safe_get(data_list[0], ["file", "file_name"]),
                hostname=dict_safe_get(data_list[0], ["computer", "hostname"]),
                dbot_score=dbot_score,
            )

            for data in data_list[1:]:
                disposition = dict_safe_get(data, ["file", "disposition"])
                dbot_score = get_dbotscore(client.reliability, file_hash, disposition)

                file_indicator.md5 = file_indicator.md5 or dict_safe_get(
                    data, ["file", "identity", "md5"]
                )
                file_indicator.sha1 = file_indicator.sha1 or dict_safe_get(
                    data, ["file", "identity", "sha1"]
                )
                file_indicator.path = file_indicator.path or dict_safe_get(
                    data, ["file", "file_path"]
                )
                file_indicator.name = file_indicator.name or dict_safe_get(
                    data, ["file", "file_name"]
                )
                file_indicator.hostname = file_indicator.hostname or dict_safe_get(
                    data, ["computer", "hostname"]
                )
                file_indicator.dbot_score = file_indicator.dbot_score or dbot_score

                is_all_filled = (
                    file_indicator.md5
                    and file_indicator.sha1
                    and file_indicator.sha256
                    and file_indicator.path
                    and file_indicator.name
                    and file_indicator.hostname
                    and file_indicator.dbot_score
                )

                if is_all_filled:
                    break

            file_context = file_indicator.to_context().get(Common.File.CONTEXT_PATH)
            readable_output = tableToMarkdown(
                f"Cisco AMP - Hash Reputation for: {file_hash}", file_context
            )

        else:  # an empty list
            readable_output = f"Cisco AMP: {file_hash} not found in Cisco AMP v2."
            raw_response, file_indicator = {}, None

        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix="",
                raw_response=raw_response,
                outputs_key_field="SHA256",
                indicator=file_indicator,
            )
        )

    return command_results


""" HELPER FUNCTIONS """  # pylint: disable=pointless-string-statement


def pagination_range(pagination: Pagination) -> range:
    """
    Generate a range according to pagination parameters.

    Args:
        pagination (Pagination): parameters to be used to calculate the start and stop index.

    Returns:
        range: A range according to pagination parameters
    """
    return range(
        pagination.offset_multiplier,
        pagination.number_of_requests + pagination.offset_multiplier,
    )


def get_pagination_parameters(
    page: int | None = 0,
    page_size: int | None = 0,
    limit: int | None = 0,
) -> Pagination:
    """
    Get the limit and offset required for the http request,
    number of requests required and if the pagination is automatic, manual or none of them.

    Args:
        page (Optional[int]): Page number to view. Defaults to None.
        page_size (Optional[int]): Number of elements in each page. Defaults to None.
        limit (Optional[int]): Total number of elements to return. Defaults to None.

    Raises:
        ValueError: If both manual and automatic arguments have been filled.

    Returns:
        Pagination:
            page (int): Page number to view.
            page_size (int): Number of elements in each page.
            limit (int): Total number of elements to return.
            offset (int): Number of 1st element to return.
            number_of_requests (int): Number of http requests to make.
            offset_multiplier (int): Multiply by 1 when number of requests is 1, otherwise 0.
            is_automatic (bool): Whether the pagination type is automatic.
            is_manual (bool): Whether the pagination type is manual.
    """
    is_automatic: bool = limit != 0
    is_manual: bool = page != 0 or page_size != 0

    if is_manual and is_automatic:
        raise ValueError("page or page_size can not be entered with limit.")

    # Automatic Pagination
    if is_automatic:
        if limit > MAX_PAGE_SIZE:  # type: ignore[operator]
            number_of_requests = math.ceil(limit / MAX_PAGE_SIZE)  # type: ignore[operator]
            limit = MAX_PAGE_SIZE
            offset = MAX_PAGE_SIZE
            offset_multiplier = 0

        else:
            number_of_requests = 1
            offset = None
            offset_multiplier = 1

    # Manual Pagination
    elif is_manual:
        page = page or 1
        page_size = page_size or 1
        number_of_requests = 1
        limit = page_size
        offset = (page - 1) * page_size
        offset_multiplier = 1

    # No Pagination
    else:
        number_of_requests = 1
        limit = MAX_PAGE_SIZE
        offset = None
        offset_multiplier = 1

    return Pagination(
        page,
        page_size,
        limit,
        offset,
        number_of_requests,
        offset_multiplier,
        is_automatic,
        is_manual,
    )


def extract_pagination_from_response(
    pagination: Pagination, raw_response: dict[str, Any]
) -> tuple[List, str]:
    """
    Extract values from the response according to pagination parameters.

    Args:
        pagination (Pagination): Pagination parameters to extract values according to.
        raw_response (Dict[str, Any]): Raw response to extract values from.

    Returns:
        Tuple[List, str]: Context output and Readable output.
    """
    if pagination.is_manual:
        start = (pagination.page - 1) * pagination.page_size
        stop = pagination.page * pagination.page_size

        raw_response["data"]["events"] = raw_response["data"]["events"][start:stop]

    else:
        raw_response["data"]["events"] = raw_response["data"]["events"][
            : pagination.limit
        ]

    context_output = get_context_output(raw_response, ["links"])
    context_output = context_output[0]["events"]
    add_item_to_all_dictionaries(
        context_output,
        "connector_guid",
        dict_safe_get(raw_response, ["data", "computer", "connector_guid"]),
    )

    readable_output = get_computer_readable_output(raw_response)
    readable_output += get_readable_output(
        response=raw_response,
        header_by_keys=TRAJECTORY_HEADERS_BY_KEYS,
        keys_to_items_option_1=["data", "events"],
        title=TRAJECTORY_TITLE,
    )

    return context_output, readable_output


def delete_keys_from_dict(
    dictionary: MutableMapping, keys_to_delete: List[str] | Set[str]
) -> dict[str, Any]:
    """
    Get a modified dictionary without the requested keys

    Args:
        dictionary (Dict[str, Any]): Dictionary to modify according to.
        keys_to_delete (List[str]): Keys to not include in the modified dictionary.

    Returns:
        Dict[str, Any]: Modified dictionary without requested keys.
    """
    keys_set = set(keys_to_delete)
    modified_dict: dict[str, Any] = {}

    for key, value in dictionary.items():
        if key not in keys_set:
            if isinstance(value, MutableMapping):
                modified_dict[key] = delete_keys_from_dict(value, keys_set)

            elif (
                isinstance(value, MutableSequence)
                and len(value) > 0
                and isinstance(value[0], MutableMapping)
            ):
                modified_dict[key] = [
                    delete_keys_from_dict(val, keys_set) for val in value
                ]

            else:
                modified_dict[key] = copy.deepcopy(value)

    return modified_dict


def add_item_to_all_dictionaries(
    dictionaries: List[dict[str, Any]], key: str, value: Any
) -> None:
    for dictionary in dictionaries:
        dictionary[key] = value


def validate_query(
    accept_ipv4: bool,
    accept_url: bool,
    accept_sha256: bool,
    accept_filename: bool,
    query: str = None,
) -> bool:
    """
    Check if the query is empty or the format is correct.

    Args:
        accept_ipv4 (bool): Validate IPv4.
        accept_url (bool): Validate URL.
        accept_sha256 (bool): Validate SHA256.
        accept_filename (bool): Validate Filename.
        query (str, optional): Query string in some format.
            Defaults to None.

    Returns:
        bool: Whether the query is correct or not.
    """
    if not query:
        return True

    is_sha256 = accept_sha256 and sha256Regex.match(query)
    is_ipv4 = accept_ipv4 and re.match(ipv4Regex, query)
    is_url = accept_url and re.match(urlRegex, query)
    is_filename = accept_filename and re.match(FILENAME_REGEX, query)

    return any(
        (
            is_sha256,
            is_ipv4,
            is_url,
            is_filename,
        )
    )


def get_dbotscore(
    reliability: str, sha256: str = None, disposition: str = None
) -> Common.DBotScore:
    """
    Get XSOAR score for the file's disposition.

    Args:
        reliability (str): Reliability of the source providing the intelligence data.
        sha256 (str, optional): SHA256 of the file.
            Defaults to None.
        disposition (str, optional): 3rd party score of the file's disposition.
            Defaults to None.

    Returns:
        Common.DBotScore: DBot Score according to the disposition.
    """
    if disposition == "Malicious":
        score = Common.DBotScore.BAD

    elif disposition == "Clean":
        score = Common.DBotScore.GOOD

    else:
        score = Common.DBotScore.NONE

    return Common.DBotScore(
        indicator=sha256,
        indicator_type=DBotScoreType.FILE,
        integration_name="CiscoAMP",
        malicious_description=disposition,
        reliability=reliability,
        score=score,
    )


def combine_response_results(
    raw_response_list: List[dict[str, Any]], is_automatic: bool = False
) -> dict[str, Any]:
    """
    If the pagination is automatic combine the results returned from all the http requests.

    Args:
        raw_response_list (List[Dict[str, Any]]): List of responses from the server.
        is_automatic (bool, optional): Whether the pagination is automatic. Defaults to False.

    Returns:
        Dict[str, Any]: Concatenated response from the server.
    """
    concatenated_raw_response: dict[str, Any] = raw_response_list[0]

    if not is_automatic:
        return concatenated_raw_response

    for raw_response in raw_response_list[1:]:
        concatenated_raw_response["metadata"]["results"][
            "current_item_count"
        ] += dict_safe_get(raw_response, ["metadata", "results", "current_item_count"])
        concatenated_raw_response["data"].extend(raw_response["data"])

    concatenated_raw_response["metadata"]["results"][
        "items_per_page"
    ] = concatenated_raw_response["metadata"]["results"]["current_item_count"]

    return concatenated_raw_response


def get_context_output(
    response: dict[str, Any],
    contexts_to_delete: List[str],
    item_to_add: tuple[str, Any] = None,
) -> List[dict[str, Any]]:
    """
    Get context output from the response.
    Loop through each value and create a modified response without the contexts_to_delete.

    Args:
        response (List[Dict[str, Any]] | Dict[str, Any]): Raw response from the API.
        contexts_to_delete (List[str]): Context outputs to leave out.

    Returns:
        List[Dict[str, Any]]: Context output for the response.
    """
    data_list = response.get("data")

    if not isinstance(data_list, List):
        data_list = [data_list]

    context_outputs: List[dict[str, Any]] = []

    for data in data_list:
        modified_data = delete_keys_from_dict(data, contexts_to_delete)
        context_outputs.append(modified_data)

    if item_to_add:
        for context_output in context_outputs:
            context_output |= {
                item_to_add[0]: item_to_add[1],
            }

    return context_outputs


def get_results_readable_output(response: dict[str, Any]) -> str:
    """
    Get relevant information for the readable output.

    Args:
        response (Dict[str, Any]): Raw response from the API.

    Returns:
        str: Readable output for results in tableToMarkdown value.
    """
    results = dict_safe_get(response, ["metadata", "results"])

    if not results:
        return ""

    readable_output = tableToMarkdown(
        "Results",
        results,
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return readable_output


def get_readable_output(
    response: dict[str, Any],
    header_by_keys: dict[str, List[str]],
    keys_to_items_option_1: List[str],
    keys_to_items_option_2: List[str] = [],
    title: str = "",
) -> str:
    """
    Get a response's readable output by formatting it through its headers.

    Args:
        response (Dict[str, Any]): API response.
        header_by_keys (Dict[str, List[str]]): headers by a list of keys to the response value.
        keys_to_items_option_1 (List[str]): list of keys 1st option to the response value.
        keys_to_items_option_2 (List[str], optional): list of keys to the response value, incase 1st failed.
            Defaults to None.
        title (str, optional): readable output title.
            Defaults to ''.

    Returns:
        str: readable output of the API response.
    """
    if not (items := dict_safe_get(response, keys_to_items_option_1)):
        items = dict_safe_get(response, keys_to_items_option_2)

    if not items:
        return ""

    item_readable_arguments: List[dict[str, Any]] = []
    headers = list(header_by_keys)

    if not isinstance(items, List):
        items = [items]

    for item in items:
        dictionary: dict[str, Any] = {}

        for key, value in header_by_keys.items():
            dictionary[key] = dict_safe_get(item, value)

        item_readable_arguments.append(dictionary)

    readable_output = tableToMarkdown(
        title,
        item_readable_arguments,
        headers=headers,
        removeNull=True,
    )

    return readable_output


def get_computer_readable_output(response: dict[str, Any]) -> str:
    """
    Get relevant information for the readable output.
    If the raw response is of a single computer, cast it to a list.

    Args:
        response (Dict[str, Any]): Raw response from the API.

    Returns:
        str: Readable output for computers in tableToMarkdown value.
    """
    if not (computers := dict_safe_get(response, ["data", "computer"])):
        computers = response.get("data")

    if not isinstance(computers, List):
        computers = [computers]

    operating_system_format = "{operating_system} (Build {os_version})"
    readable_arguments: List[dict[str, Any]] = []

    for computer in computers:
        readable_arguments.append(
            {
                "Host Name": computer.get("hostname"),
                "Connector GUID": computer.get("connector_guid"),
                "Operating System": operating_system_format.format(
                    operating_system=computer.get("operating_system"),
                    os_version=computer.get("os_version"),
                ),
                "External IP": computer.get("external_ip"),
                "Group GUID": computer.get("group_guid"),
                "Policy GUID": dict_safe_get(computer, ["policy", "guid"]),
            }
        )

    headers = [
        "Host Name",
        "Connector GUID",
        "Operating System",
        "External IP",
        "Group GUID",
        "Policy GUID",
    ]

    readable_output = tableToMarkdown(
        "Computer Information",
        readable_arguments,
        headers=headers,
        removeNull=True,
    )

    return readable_output


def get_isolation_options_readable_output(response: requests.Response) -> str:
    """
    Get relevant information for the readable output.

    Args:
        response (requests.Response): Raw response from the API.

    Returns:
        str: Readable output for isolation options.
    """
    readable_output: str = ""
    options_string = response.headers.get("Allow")

    if not options_string:
        return readable_output

    options = options_string.split(", ")

    message_by_option = {
        "GET": "Can get information about an isolation with computer-isolation-get",
        "PUT": "Can request to create a new isolation with computer-isolation-create",
        "DELETE": "Can request to stop the isolation with computer-isolation-delete",
    }

    for option in options:
        if message := message_by_option.get(option):
            readable_output += f"{message}\n"

    return readable_output


""" MAIN FUNCTION """  # pylint: disable=pointless-string-statement


def main() -> None:
    """
    Get the needed user's input params and initialize a Client with them.
    Check the user's input command with if statements and a dictionary.

    Raises:
        NotImplementedError: An error if the input command hasn't been implemented
    """
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    command = demisto.command()

    server_url = params["server_url"]
    client_id = params["credentials"]["identifier"]
    api_key = params["credentials"]["password"]
    verify_certificate = not params.get("insecure", False)
    reliability = params.get("integrationReliability", DBotScoreReliability.C)
    proxy = params.get("proxy", False)
    include_null_severities = params.get("include_null_severities", False)

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(
            reliability
        )
    else:
        raise Exception(
            "Please provide a valid value for the Source Reliability parameter."
        )

    commands = {
        "cisco-amp-computer-list": computer_list_command,
        "cisco-amp-computer-trajectory-list": computer_trajectory_list_command,
        "cisco-amp-computer-user-activity-list": computer_user_activity_list_command,
        "cisco-amp-computer-user-trajectory-list": computer_user_trajectory_list_command,
        "cisco-amp-computer-vulnerabilities-list": computer_vulnerabilities_list_command,
        "cisco-amp-computer-move": computer_move_command,
        "cisco-amp-computer-delete": computer_delete_command,
        "cisco-amp-computer-activity-list": computer_activity_list_command,
        "cisco-amp-computer-isolation-feature-availability-get": computers_isolation_feature_availability_get_command,
        "cisco-amp-computer-isolation-get": computer_isolation_get_command,
        "cisco-amp-computer-isolation-create": computer_isolation_create_polling_command,
        "cisco-amp-computer-isolation-delete": computer_isolation_delete_polling_command,
        "cisco-amp-event-list": event_list_command,
        "cisco-amp-event-type-list": event_type_list_command,
        "cisco-amp-file-list-list": file_list_list_command,
        "cisco-amp-file-list-item-list": file_list_item_list_command,
        "cisco-amp-file-list-item-create": file_list_item_create_command,
        "cisco-amp-file-list-item-delete": file_list_item_delete_command,
        "cisco-amp-group-list": group_list_command,
        "cisco-amp-group-policy-update": group_policy_update_command,
        "cisco-amp-group-parent-update": group_parent_update_command,
        "cisco-amp-group-create": group_create_command,
        "cisco-amp-group-delete": groups_delete_command,
        "cisco-amp-indicator-list": indicator_list_command,
        "cisco-amp-policy-list": policy_list_command,
        "cisco-amp-app-trajectory-query-list": app_trajectory_query_list_command,
        "cisco-amp-version-get": version_get_command,
        "cisco-amp-vulnerability-list": vulnerability_list_command,
        "endpoint": endpoint_command,
        "file": file_command,
    }

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            server_url=server_url,
            api_key=api_key,
            client_id=client_id,
            verify=verify_certificate,
            reliability=reliability,
            proxy=proxy,
            should_create_relationships=argToBoolean(params.get("create_relationships", True))
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "fetch-incidents":
            incident_severities = argToList(params.get("incident_severities"))
            max_incidents_to_fetch = arg_to_number(params.get("max_fetch", FETCH_LIMIT))
            event_types = argToList(params.get("event_types"))
            first_fetch_datetime = arg_to_datetime(
                arg=params["first_fetch"], arg_name="First fetch time", required=True
            )

            if not isinstance(max_incidents_to_fetch, int):
                raise ValueError("Failed to get max fetch.")

            if not isinstance(first_fetch_datetime, datetime):
                raise ValueError("Failed to get first fetch time.")

            first_fetch_time = first_fetch_datetime.strftime(ISO_8601_FORMAT)
            last_run = demisto.getLastRun()

            demisto.debug(f"Starting fetch. {last_run=}")
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=last_run,
                first_fetch_time=first_fetch_time,
                incident_severities=incident_severities,
                max_incidents_to_fetch=max_incidents_to_fetch,
                event_types=event_types,
                include_null_severities=include_null_severities,
            )
            demisto.debug("Fetch was finished. Updating server.")
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command in commands:
            return_results(commands[command](args=args, client=client))

        else:
            raise NotImplementedError(f"Command doesn't exist - {command}")

    except Exception as exc:  # pylint: disable=broad-except
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(exc)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

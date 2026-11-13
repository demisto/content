import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
An integration module for the Google Threat Intelligence Agentic API.
API Documentation:
    https://gtidocs.virustotal.com/reference/flows-overview
"""

import copy
import itertools
import os
from collections.abc import Callable
from typing import Any

""" CONSTANTS """

COMMAND_PREFIX = "gti-agentic"
BASE_URL = "https://www.virustotal.com/api/v3"
PLATFORM_URL = "https://www.virustotal.com/gui"
INTEGRATION_TOOL = "CortexGTIAgentic"
# The API responds with 201 for the operations that create an object, such as a session created from a share token.
OK_CODES = (200, 201)
STATUS_CODE_TO_RETRY = [429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500)]  # type: ignore
MAX_RETRIES = 4
BACKOFF_FACTOR = 7.5
# The agent answers synchronously and can take up to 10 minutes, hence the request waits as long as the 'timeout' of the
# command in the integration YML, rather than the default timeout of 60 seconds.
SESSION_MESSAGE_TIMEOUT = 600
TEST_MODULE_LIMIT = 1
DEFAULT_LIMIT = 10
MAX_LIMIT = 40
# The API returns 5 agentic sessions per page by default, and up to 50 per page.
DEFAULT_SESSION_LIMIT = 5
MAX_SESSION_LIMIT = 50
# The maximum allowed size of a file that is attached to a session message.
MAX_SESSION_FILE_SIZE_MB = 32
DEFAULT_SORT_FIELD = "Last Run At"
DEFAULT_FLOW_EXECUTION_SORT_FIELD = "Creation Date"
DEFAULT_SORT_ORDER = "Desc"
DEFAULT_ENABLED = "True"
DEFAULT_SCHEDULE_TIMEZONE = "UTC"
DEFAULT_REUSE_SESSION = "False"
DEFAULT_SCHEDULE_FREQUENCY = "Daily"
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

ENDPOINTS = {
    # The Flow collection serves both the list and the create requests.
    "flows": "/flows",
    "flow_by_id": "/flows/{}",
    "flow_execute": "/flows/{}/execute",
    "flow_relationship": "/flows/{}/{}",
    "flow_relationship_descriptor": "/flows/{}/relationships/{}",
    "flow_executions": "/flow_executions",
    "flow_execution_by_id": "/flow_executions/{}",
    "flow_execution_relationship": "/flow_executions/{}/{}",
    "flow_execution_relationship_descriptor": "/flow_executions/{}/relationships/{}",
    "flow_execution_cancel": "/flow_executions/{}/cancel",
    "sessions": "/agentspace/sessions",
    "session_by_id": "/agentspace/sessions/{}",
    "session_token": "/agentspace/sessions/{}/token",
    "session_from_token": "/agentspace/sessions/token",
}

OUTPUT_PREFIX = {
    "FLOW": "GoogleThreatIntelligenceAgentic.Flow",
    "FLOW_PAGE_TOKEN": "GoogleThreatIntelligenceAgentic.PageToken.Flow",
    "FLOW_EXECUTION": "GoogleThreatIntelligenceAgentic.FlowExecution",
    "FLOW_EXECUTION_PAGE_TOKEN": "GoogleThreatIntelligenceAgentic.PageToken.FlowExecution",
    "FLOW_RELATIONSHIP": "GoogleThreatIntelligenceAgentic.FlowRelationship",
    "FLOW_RELATIONSHIP_PAGE_TOKEN": "GoogleThreatIntelligenceAgentic.PageToken.FlowRelationship",
    "FLOW_RELATIONSHIP_DESCRIPTOR": "GoogleThreatIntelligenceAgentic.FlowRelationshipDescriptor",
    "FLOW_RELATIONSHIP_DESCRIPTOR_PAGE_TOKEN": "GoogleThreatIntelligenceAgentic.PageToken.FlowRelationshipDescriptor",
    "FLOW_EXECUTION_RELATIONSHIP": "GoogleThreatIntelligenceAgentic.FlowExecutionRelationship",
    "FLOW_EXECUTION_RELATIONSHIP_DESCRIPTOR": "GoogleThreatIntelligenceAgentic.FlowExecutionRelationshipDescriptor",
    "SESSION": "GoogleThreatIntelligenceAgentic.Session",
    "SESSION_PAGE_TOKEN": "GoogleThreatIntelligenceAgentic.PageToken.Session",
    "SESSION_TOKEN": "GoogleThreatIntelligenceAgentic.SessionToken",
}
# The related objects are merged by the Flow and by the type of the objects.
FLOW_RELATIONSHIP_CONTEXT_KEY = "(val.flow_id && val.flow_id == obj.flow_id && val.type && val.type == obj.type)"
# The related objects are merged by the Flow Execution and by the relationship, as the Flow and its snapshot share a type.
FLOW_EXECUTION_RELATIONSHIP_CONTEXT_KEY = (
    "(val.execution_id && val.execution_id == obj.execution_id && val.relationship && val.relationship == obj.relationship)"
)

BOOLEAN_HR_LIST = ["True", "False"]
SORT_ORDER_HR_LIST = ["Asc", "Desc"]
# The API expresses the sort order as the suffix of the value of the 'order' query parameter.
SORT_ORDER_API_MAP = {
    "asc": "+",
    "desc": "-",
}
FLOW_SORT_FIELD_HR_LIST = ["Name", "Creation Date", "Last Modification Date", "Last Run At"]
FLOW_SORT_FIELD_API_MAP = {
    "name": "name",
    "creation date": "creation_date",
    "last modification date": "last_modification_date",
    "last run at": "trigger_state.last_run_at",
}
# The link of a Flow object on the Google Threat Intelligence platform.
FLOW_UI_URL = PLATFORM_URL + "/agentic/flows/{}"
# The link of a Flow Execution on the Google Threat Intelligence platform, which filters the execution log by its ID.
FLOW_EXECUTION_UI_URL = PLATFORM_URL + "/agentic/flows/execution-log?filter={}"
# The type of a Flow Execution object.
FLOW_EXECUTION_TYPE = "flow_execution"
# The epoch timestamps of a Flow and of a Flow Execution, which the API reports in seconds.
FLOW_TIMESTAMP_FIELDS = ["creation_date", "last_modification_date"]
# The timestamps of a step of a Flow Execution. The API documents them as epoch seconds, which are converted, while
# the live API reports them as RFC 3339 strings, which are kept as received.
FLOW_EXECUTION_STEP_TIMESTAMP_FIELDS = ["enqueued_at", "started_at", "ended_at", "expires_at"]
# The neutral title of a single Flow Execution, whose status is not known in advance.
FLOW_EXECUTION_HR_TITLE = "GTI Agentic Flow Execution"
FLOW_EXECUTION_HR_HEADERS = ["Execution ID", "Flow ID", "Status", "Duration (Seconds)", "Creation Date", "Last Modification Date"]
FLOW_EXECUTION_STEP_HR_HEADERS = ["Step ID", "Node Type", "Status", "Duration (Seconds)"]
FLOW_EXECUTION_LIST_HR_HEADERS = [*FLOW_EXECUTION_HR_HEADERS[:4], "Steps", *FLOW_EXECUTION_HR_HEADERS[4:]]
# A single Flow Execution reports its steps in a dedicated table, along with the output of every step.
FLOW_EXECUTION_STEP_DETAIL_HR_HEADERS = [
    "Step ID",
    "Node ID",
    "Node Type",
    "Status",
    "Input JSON",
    "Started At",
    "Ended At",
    "Duration (Seconds)",
    "Output",
]
# The cancellation reports every timestamp of the steps, so that the steps that the cancellation stopped are visible.
FLOW_EXECUTION_CANCEL_STEP_HR_HEADERS = [
    "Step ID",
    "Node ID",
    "Node Type",
    "Status",
    "Duration (Seconds)",
    "Enqueued At",
    "Started At",
    "Ended At",
    "Expires At",
    "Output",
]
FLOW_EXECUTION_STATUS_CANCELLED = "EXECUTION_STATUS_CANCELLED"
FLOW_EXECUTION_STATUS_HR_LIST = ["Running", "Completed", "Failed", "Cancelled"]
FLOW_EXECUTION_SORT_FIELD_HR_LIST = ["Creation Date", "Last Modification Date"]
FLOW_EXECUTION_SORT_FIELD_API_MAP = {
    "creation date": "creation_date",
    "last modification date": "last_modification_date",
}
FLOW_HR_HEADERS = ["Flow ID", "Name", "Enabled", "Nodes", "Last Run At", "Creation Date", "Last Modification Date"]
# The graph of a single Flow is reported in a dedicated table for the nodes and one for the connections.
FLOW_NODE_HR_HEADERS = [
    "Node ID",
    "Type",
    "Name",
    "Cron Expression",
    "Timezone",
    "Prompt",
    "Reuse Session",
    "Notification Emails",
    "Email Subject",
    "Email Message",
]
FLOW_CONNECTION_HR_HEADERS = ["Source Node ID", "Target Node ID", "Source Handle"]
# The email addresses of a node are joined with this separator in the human readable output.
FLOW_EMAIL_SEPARATOR = ", "
# The node types of a Flow graph, along with the key of the object that carries the configuration of every type
# and the display name of the nodes that the gti-agentic-flow-create command builds.
FLOW_NODE_TYPE_SCHEDULE = "NODE_TYPE_SCHEDULE_TIME"
FLOW_NODE_TYPE_PROMPT = "NODE_TYPE_RUN_PROMPT"
FLOW_NODE_TYPE_EMAIL = "NODE_TYPE_SEND_EMAIL"
FLOW_NODE_BODY_KEY = {
    FLOW_NODE_TYPE_SCHEDULE: "schedule_node",
    FLOW_NODE_TYPE_PROMPT: "run_prompt_node",
    FLOW_NODE_TYPE_EMAIL: "send_email_node",
}
# The field that every node type requires inside the object that carries its configuration.
FLOW_NODE_REQUIRED_FIELD = {
    FLOW_NODE_TYPE_SCHEDULE: "cron_expression",
    FLOW_NODE_TYPE_PROMPT: "prompt",
    FLOW_NODE_TYPE_EMAIL: "notification_emails",
}
# A Flow runs a prompt on a schedule, hence its graph requires a node of every one of these types.
FLOW_REQUIRED_NODE_TYPES = [FLOW_NODE_TYPE_SCHEDULE, FLOW_NODE_TYPE_PROMPT]
FLOW_NODE_DEFAULT_NAME = {
    FLOW_NODE_TYPE_SCHEDULE: "Schedule",
    FLOW_NODE_TYPE_PROMPT: "Run Prompt",
    FLOW_NODE_TYPE_EMAIL: "Send Email",
}
# The identifiers of the nodes that the gti-agentic-flow-create command builds, for example 'n1'.
FLOW_NODE_ID_PREFIX = "n"
# The cron expression that every schedule frequency builds from the 'schedule_time' argument. Cron counts the
# weekdays from Sunday, which is 0.
FLOW_SCHEDULE_FREQUENCY_CRON = {
    "daily": "{minute} {hour} * * *",
    "weekdays": "{minute} {hour} * * 1-5",
    "weekends": "{minute} {hour} * * 0,6",
    "weekly": "{minute} {hour} * * {weekday}",
    "monthly": "{minute} {hour} {day} * *",
}
SCHEDULE_FREQUENCY_HR_LIST = ["Daily", "Weekdays", "Weekends", "Weekly", "Monthly"]
# The relationships of a Flow whose objects the API returns, keyed by the value of the 'relationship' argument.
FLOW_RELATIONSHIP_HR_LIST = ["Group", "Flow Executions"]
FLOW_RELATIONSHIP_API_MAP = {
    "group": "group",
    "flow executions": "flow_executions",
}
FLOW_RELATED_OBJECT_HR_HEADERS = ["Object ID", "Type", "Status", "Duration (Seconds)", "Creation Date", "Last Modification Date"]
# The group object reports neither a status nor any timestamp, hence it is reported with its own columns.
FLOW_GROUP_TYPE = "group"
FLOW_GROUP_HR_HEADERS = [
    "Group ID",
    "Organization",
    "Domain Name",
    "Country",
    "Industry",
    "GTI GCP Project",
    "Role",
    "Active Flows (Used/Allowed)",
]
# The title of the related objects table names the type of the objects and links the Flow they belong to.
FLOW_RELATED_OBJECT_HR_TITLE = "{} of the GTI Agentic Flow [{}]({})"
FLOW_RELATED_OBJECT_TYPE_HR_NAME = {
    FLOW_EXECUTION_TYPE: "Flow Executions",
    FLOW_GROUP_TYPE: "Group",
}
FLOW_RELATED_DESCRIPTOR_TYPE_HR_NAME = {
    FLOW_EXECUTION_TYPE: "Flow Execution Descriptors",
    FLOW_GROUP_TYPE: "Group Descriptor",
}
FLOW_RELATED_DESCRIPTOR_HR_HEADERS = ["Object ID", "Type"]
# The relationships of a Flow Execution, every one of which reports a single object.
FLOW_EXECUTION_RELATIONSHIP_HR_LIST = ["Flow", "Flow Snapshot", "Owner", "Group"]
# The name of every relationship of a Flow Execution in the API, keyed by the value of the 'relationship' argument.
FLOW_EXECUTION_RELATIONSHIP_API_MAP = {
    "flow": "flow",
    "flow snapshot": "flow_snapshot",
    "owner": "owner",
    "group": "group",
}
FLOW_EXECUTION_RELATED_OBJECT_HR_TITLE = "{} Information of the GTI Agentic Flow Execution [{}]({})"
FLOW_EXECUTION_RELATED_DESCRIPTOR_HR_TITLE = "{} Descriptor of the GTI Agentic Flow Execution [{}]({})"
# The descriptor of a Flow also reports the role of the caller, and the columns that no descriptor populates are removed.
FLOW_EXECUTION_RELATED_DESCRIPTOR_HR_HEADERS = ["Object ID", "Type", "Role", "Shared With Me"]
# The Flow and its snapshot are reported with the columns of the Flow, and the other objects with their identity only.
# The API reports the snapshot with the 'flow' type, and 'flow_snapshot' covers a snapshot reported with its own type.
FLOW_EXECUTION_RELATED_FLOW_TYPES = ["flow", "flow_snapshot"]
FLOW_EXECUTION_RELATED_OBJECT_HR_HEADERS = ["Object ID", "Type"]
# The owner of a Flow Execution is a user object.
FLOW_EXECUTION_OWNER_TYPE = "user"
FLOW_EXECUTION_OWNER_HR_HEADERS = ["User ID", "First Name", "Last Name", "Email", "Status", "User Since", "Last Login"]
# The secret attributes of a related object, keyed by the type of the object, which are removed before the object
# reaches the context or the raw response.
RELATED_OBJECT_SECRET_FIELDS = {
    FLOW_GROUP_TYPE: ["group_token", "scim_token"],
    FLOW_EXECUTION_OWNER_TYPE: ["apikey"],
}
# The fields of a connection that refer to a node of the Flow graph.
FLOW_CONNECTION_NODE_FIELDS = ["source_node_id", "target_node_id"]
# The link of an agentic session on the Google Threat Intelligence platform.
SESSION_UI_URL = PLATFORM_URL + "/agentic/sessions/{}"
SESSION_HR_HEADERS = ["Session ID", "Title", "Creation Date", "Last Modification Date"]
# A single agentic session also reports the number of its events, which the list response does not carry.
SESSION_DETAIL_HR_HEADERS = ["Session ID", "Title", "Events", "Creation Date", "Last Modification Date"]
SESSION_DETAIL_HR_TITLE = "GTI Agentic Session Information"
SESSION_EVENT_HR_HEADERS = ["Event ID", "Message Type", "Agent ID", "Message"]
SESSION_EVENT_TYPE_AGENT_FINAL_RESPONSE = "AGENT_FINAL_RESPONSE"
SESSION_EVENT_TYPE_FUNCTION_CALL = "FUNCTION_CALL"
SESSION_EVENT_TYPE_FUNCTION_RESPONSE = "FUNCTION_RESPONSE"
SESSION_TOKEN_HR_TITLE = "GTI Agentic Session Share Token"
SESSION_TOKEN_HR_HEADERS = ["Session ID", "Token"]

ERROR_MESSAGES = {
    "INVALID_OBJECT": "Failed to parse {} object from response: {}",
    "UNAUTHORIZED_REQUEST": "{} Unauthorized request: Invalid API key provided {}.",
    "BAD_REQUEST": "{} Bad Request: {}",
    "FORBIDDEN": "{} Forbidden: {}",
    "NOT_FOUND": "{} Not Found: {}",
    "EXECUTION_NOT_IN_PROGRESS": "{} Conflict: The Flow Execution with ID {} is not in progress, hence it cannot be cancelled.",
    "GENERIC_ERROR": "{} Error: {}",
    "REQUIRED_ARGUMENT": "'{}' is required and cannot be empty.",
    "INVALID_ARGUMENT": "'{}' is an invalid value for '{}'. Value must be in {}.",
    "INVALID_LIMIT": "'{}' is an invalid value for 'limit'. Value must be a positive integer, and the maximum value is {}.",
    "INVALID_JSON_LIST": "The '{}' argument is invalid. Value must be a JSON formatted list of objects.{}",
    "INVALID_EMAIL": "'{}' is an invalid value for 'notification_emails'. Value must be a valid email address.",
    "INVALID_CONNECTION_NODE": "'{}' is an invalid value for '{}'. The node is not present in the 'nodes' argument.",
    "MISSING_NODE_ID": "The 'id' field is required for every node of the 'nodes' argument.",
    "DUPLICATE_NODE_ID": "'{}' is a duplicate value for the 'id' field. Every node of the 'nodes' argument requires a "
    "unique identifier.",
    "MISSING_CONNECTIONS": "The 'connections' argument is required when the 'nodes' argument is provided.",
    "INVALID_CONNECTION_FIELD_TYPE": "The '{}' field of every connection of the 'connections' argument must be a string.",
    "UNREACHABLE_PROMPT_NODE": "The 'connections' argument is required to connect a node of the 'NODE_TYPE_SCHEDULE_TIME' "
    "type to a node of the 'NODE_TYPE_RUN_PROMPT' type.",
    "MISSING_CONNECTION_FIELD": "The '{}' field is required for every connection of the 'connections' argument.",
    "INVALID_NODE_TYPE": "'{}' is an invalid value for the 'type' field of the node {}. Value must be in {}.",
    "MISSING_NODE_FIELD": "The '{}' field of the '{}' object is required for the node {}.",
    "INVALID_NODE_FIELD_TYPE": "The '{}' field of the node {} must be {}.",
    "MISSING_NODE_TYPE": "The 'type' field is required for the node {}.",
    "INVALID_ENTRY_ID": "'{}' is an invalid value for 'entry_id'. The War Room entry does not exist or does not hold a file.",
    "INVALID_ENTRY_FILE_SIZE": "'{}' is an invalid value for 'entry_id'. The maximum allowed size of a file is {} MB.",
    "MISSING_REQUIRED_NODE": "A node of the '{}' type is required in the 'nodes' argument.",
    "MISSING_FLOW_GRAPH": "Either the 'nodes' argument or both the 'schedule_time' and the 'prompt' arguments are required, "
    "as a Flow requires a schedule node and a prompt node.",
    "INVALID_SCHEDULE_TIME": "'{}' is an invalid value for 'schedule_time'. Value must be a valid date or time, for example "
    "'2026-09-25T09:00:00Z' or '9am'.",
    "MISSING_NOTIFICATION_EMAILS": "The 'notification_emails' argument is required when the 'email_subject' or the "
    "'email_message' argument is provided.",
    "MISSING_UPDATE_ARGUMENT": "At least one argument other than 'flow_id' is required, as there is nothing to update.",
    "MISSING_SCHEDULE_ARGUMENT": "The 'schedule_time' and the 'schedule_frequency' arguments are required together, as the "
    "cron expression of the schedule node is built from both of them.",
    "MISSING_FLOW_NODE": "The Flow has no node of the '{}' type to update. Use the 'nodes' argument to replace the graph "
    "of the Flow.",
    "MULTIPLE_FLOW_NODES": "The Flow has more than one node of the '{}' type. Use the 'nodes' argument to replace the graph "
    "of the Flow.",
    "MISSING_EMAIL_NODE": "The 'notification_emails' argument is required to add an email node, as the Flow has no node "
    "of the 'NODE_TYPE_SEND_EMAIL' type.",
    "INVALID_EXISTING_CONNECTIONS": "The existing connections of the Flow do not match the 'nodes' argument. Provide the "
    "'connections' argument along with the 'nodes' argument.\n\n{}",
}

MESSAGES = {
    "NO_RECORDS_FOUND": "No {} were found for the given argument(s).",
    "NO_RECORD_FOUND": "No {} was found for the given argument(s).",
    "NEXT_CURSOR": "Run the command with the 'cursor' argument set to `{}` to retrieve the next page of results.",
    "FLOW_DELETED": "The Flow with ID {} is deleted successfully.",
    "FLOW_CREATED": "Flow created successfully.",
    "FLOW_UPDATED": "Flow updated successfully.",
    "FLOW_EXECUTION_STARTED": "Flow execution started successfully.",
    "FLOW_EXECUTION_CANCELLED": "Flow execution cancelled successfully.",
    "FLOW_EXECUTION_CANCEL_REQUESTED": "The cancellation of the Flow Execution with ID {} is requested successfully.",
    "AGENT_RESPONSE_BELOW": "See the agent response below.",
    "SESSION_CREATED": "Session created successfully.",
    "SESSION_MESSAGE_POSTED": "Message posted successfully.",
    "SESSION_UPDATED": "Session marked as {} successfully.",
    "SESSION_DELETED": "The session with ID {} is deleted successfully.",
    "SESSION_CREATED_FROM_TOKEN": "Session created successfully from the shared token.",
}


""" CLIENT CLASS """


class Client(BaseClient):
    """Client for Google Threat Intelligence Agentic API."""

    def __init__(self, verify_certificate: bool, proxy: bool, api_key: str, group_id: str = ""):
        headers = {
            "x-apikey": api_key,
            "x-tool": INTEGRATION_TOOL,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        # The quota of the request is charged to the group only when the Group ID parameter is configured.
        if group_id:
            headers["X-Active-Group"] = group_id

        super().__init__(
            BASE_URL,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers,
        )

    def http_request(
        self,
        method: str,
        url_suffix: str = "",
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        response_type: str = "response",
        **kwargs,
    ):
        """
        Makes an HTTP request to the Google Threat Intelligence Agentic API.

        Args:
            method (str): The HTTP method (e.g., GET, POST, PATCH, DELETE).
            url_suffix (str): The URL suffix to be appended to the base URL. Defaults to an empty string.
            params (dict): Query parameters to be appended to the URL. Defaults to None.
            data (object): Data to be sent in the request body. Defaults to None.
            json_data (dict): JSON data to be sent in the request body. Defaults to None.
            response_type (str): The expected response type. Defaults to "response".
            **kwargs: Additional keyword arguments.

        Returns:
            object: The parsed JSON body or the response object.
        """
        headers = self._headers
        if kwargs.get("files"):
            # The multipart boundary is set by the requests library, hence the JSON content type is not sent.
            headers = {key: value for key, value in headers.items() if key != "Content-Type"}  # type: ignore[union-attr]

        log_header = {**headers, "x-apikey": "***********"}  # type: ignore
        body = data or json_data
        # The request body can carry the notification emails and the prompt, hence only its keys are logged.
        log_body = list(body.keys()) if isinstance(body, dict) else body
        demisto.debug(
            f"Making API request at {method} {url_suffix} with headers:{log_header}, params:{params} and body keys:{log_body}"
        )

        res = self._http_request(
            method=method,
            url_suffix=url_suffix,
            headers=headers,
            data=data,
            json_data=json_data,
            params=params,
            retries=MAX_RETRIES,
            status_list_to_retry=STATUS_CODE_TO_RETRY,
            ok_codes=OK_CODES,
            backoff_factor=BACKOFF_FACTOR,
            resp_type="response",
            raise_on_status=True,
            error_handler=handle_error_response,
            **kwargs,
        )

        if response_type == "json":
            # The API responds with an empty body for the operations that return no content, such as a deletion.
            if not res.content:
                return {}
            try:
                return res.json()
            except ValueError as e:
                raise DemistoException(ERROR_MESSAGES["INVALID_OBJECT"].format(response_type, res.content), e, res)
        return res

    def list_flows(self, query_params: dict, response_type: str = "json"):
        """
        List the GTI Agentic Flows that are visible to the caller.

        See Also:
            https://gtidocs.virustotal.com/reference/list-flows
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["flows"],
            params=query_params,
            response_type=response_type,
        )

    def create_flow(self, payload: dict, response_type: str = "json"):
        """
        Create a new GTI Agentic Flow with the provided node and connection graph.

        See Also:
            https://gtidocs.virustotal.com/reference/create-flow
        """
        return self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["flows"],
            json_data=payload,
            response_type=response_type,
        )

    def get_flow(self, flow_id: str, response_type: str = "json"):
        """
        Retrieve a single GTI Agentic Flow by its ID.

        See Also:
            https://gtidocs.virustotal.com/reference/get-flow
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["flow_by_id"].format(flow_id),
            response_type=response_type,
        )

    def update_flow(self, flow_id: str, payload: dict, response_type: str = "json"):
        """
        Partially update a single GTI Agentic Flow by its ID.

        See Also:
            https://gtidocs.virustotal.com/reference/update-flow
        """
        return self.http_request(
            method="PATCH",
            url_suffix=ENDPOINTS["flow_by_id"].format(flow_id),
            json_data=payload,
            response_type=response_type,
        )

    def delete_flow(self, flow_id: str, response_type: str = "json"):
        """
        Permanently delete a single GTI Agentic Flow by its ID.

        The API responds with an empty body on success, although its documentation reports an empty
        data object, hence an empty dictionary is returned in that case.

        See Also:
            https://gtidocs.virustotal.com/reference/delete-flow
        """
        return self.http_request(
            method="DELETE",
            url_suffix=ENDPOINTS["flow_by_id"].format(flow_id),
            response_type=response_type,
        )

    def list_flow_related_objects(self, flow_id: str, relationship: str, query_params: dict, response_type: str = "json"):
        """
        List the objects that are related to a single GTI Agentic Flow through the given relationship.

        See Also:
            https://gtidocs.virustotal.com/reference/get-flow-relationships
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["flow_relationship"].format(flow_id, relationship),
            params=query_params,
            response_type=response_type,
        )

    def list_flow_related_descriptors(self, flow_id: str, relationship: str, query_params: dict, response_type: str = "json"):
        """
        List the descriptors, which carry the type and the ID only, of the objects that are related to a single
        GTI Agentic Flow through the given relationship.

        See Also:
            https://gtidocs.virustotal.com/reference/get-flow-related-descriptors
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["flow_relationship_descriptor"].format(flow_id, relationship),
            params=query_params,
            response_type=response_type,
        )

    def list_flow_executions(self, query_params: dict, response_type: str = "json"):
        """
        List the GTI Agentic Flow Executions that are owned by the caller.

        See Also:
            https://gtidocs.virustotal.com/reference/list-flow-executions
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["flow_executions"],
            params=query_params,
            response_type=response_type,
        )

    def list_sessions(self, query_params: dict, response_type: str = "json"):
        """
        List the GTI Agentic Sessions of the user that owns the API key.

        See Also:
            https://gtidocs.virustotal.com/reference/list-sessions
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["sessions"],
            params=query_params,
            response_type=response_type,
        )

    def create_session(self, message: str, attachments: list | None = None, response_type: str = "json"):
        """
        Create a new GTI Agentic Session by sending the first message to the Google Threat Intelligence agent.

        Args:
            message (str): The message to send to the agent.
            attachments (list): The name and the path of every file to attach to the message as an artifact.
            response_type (str): The expected response type.

        See Also:
            https://gtidocs.virustotal.com/reference/create-session
        """
        # Every request creates a new session, hence a failed request is not retried.
        return self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["sessions"],
            files=build_session_message_files(message, attachments),
            timeout=SESSION_MESSAGE_TIMEOUT,
            response_type=response_type,
        )

    def post_session_message(self, session_id: str, message: str, attachments: list | None = None, response_type: str = "json"):
        """
        Post a message to an existing GTI Agentic Session, to continue the conversation with the Google Threat
        Intelligence agent.

        Args:
            session_id (str): The ID of the agentic session.
            message (str): The message to send to the agent.
            attachments (list): The name and the path of every file to attach to the message as an artifact.
            response_type (str): The expected response type.

        See Also:
            https://gtidocs.virustotal.com/reference/post-session-message
        """
        return self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["session_by_id"].format(session_id),
            files=build_session_message_files(message, attachments),
            timeout=SESSION_MESSAGE_TIMEOUT,
            response_type=response_type,
        )

    def get_session(self, session_id: str, response_type: str = "json"):
        """
        Retrieve a single GTI Agentic Session, along with its conversation, by its ID.

        See Also:
            https://gtidocs.virustotal.com/reference/get-session
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["session_by_id"].format(session_id),
            response_type=response_type,
        )

    def update_session(self, session_id: str, payload: dict, response_type: str = "json"):
        """
        Update the properties of a single GTI Agentic Session by its ID.

        See Also:
            https://gtidocs.virustotal.com/reference/update-session
        """
        return self.http_request(
            method="PATCH",
            url_suffix=ENDPOINTS["session_by_id"].format(session_id),
            json_data=payload,
            response_type=response_type,
        )

    def delete_session(self, session_id: str, response_type: str = "json"):
        """
        Permanently delete a single GTI Agentic Session by its ID.

        The API responds with an empty body on success, hence an empty dictionary is returned in that case.

        See Also:
            https://gtidocs.virustotal.com/reference/delete-session
        """
        return self.http_request(
            method="DELETE",
            url_suffix=ENDPOINTS["session_by_id"].format(session_id),
            response_type=response_type,
        )

    def get_session_token(self, session_id: str, response_type: str = "json"):
        """
        Retrieve a share token of a single GTI Agentic Session, which allows another user to import the session.

        See Also:
            https://gtidocs.virustotal.com/reference/get-session-token
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["session_token"].format(session_id),
            response_type=response_type,
        )

    def create_session_from_token(self, token: str, response_type: str = "json"):
        """
        Create a new GTI Agentic Session by copying the content of the source session that is identified in a share token.

        See Also:
            https://gtidocs.virustotal.com/reference/create-session-from-token
        """
        return self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["session_from_token"],
            json_data={"token": token},
            response_type=response_type,
        )

    def cancel_flow_execution(self, execution_id: str, response_type: str = "json"):
        """
        Cancel a single GTI Agentic Flow Execution that is in progress.

        See Also:
            https://gtidocs.virustotal.com/reference/cancel-flow-execution
        """
        return self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["flow_execution_cancel"].format(execution_id),
            response_type=response_type,
        )

    def get_flow_execution(self, execution_id: str, response_type: str = "json"):
        """
        Retrieve a single GTI Agentic Flow Execution by its ID.

        See Also:
            https://gtidocs.virustotal.com/reference/info-flow-execution
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["flow_execution_by_id"].format(execution_id),
            response_type=response_type,
        )

    def list_flow_execution_related_descriptors(self, execution_id: str, relationship: str, response_type: str = "json"):
        """
        List the descriptors, which carry the type and the ID only, of the objects that are related to a single
        GTI Agentic Flow Execution through the given relationship.

        See Also:
            https://gtidocs.virustotal.com/reference/get-flow-execution-related-descriptors
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["flow_execution_relationship_descriptor"].format(execution_id, relationship),
            response_type=response_type,
        )

    def get_flow_execution_related_object(self, execution_id: str, relationship: str, response_type: str = "json"):
        """
        Retrieve the object that is related to a single GTI Agentic Flow Execution through the given relationship.

        See Also:
            https://gtidocs.virustotal.com/reference/get-flow-execution-relationships
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["flow_execution_relationship"].format(execution_id, relationship),
            response_type=response_type,
        )

    def execute_flow(self, flow_id: str, response_type: str = "json"):
        """
        Trigger an immediate run of a single GTI Agentic Flow by its ID, bypassing its schedule.

        See Also:
            https://gtidocs.virustotal.com/reference/execute-flow
        """
        return self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["flow_execute"].format(flow_id),
            response_type=response_type,
        )


""" HELPER FUNCTIONS """


def get_error_reason(res) -> str:
    """
    Extract the failure reason from an error response of the Google Threat Intelligence API.

    The API reports the failures in the 'error.message' field of the response body. The raw body is
    returned when the response is not a valid JSON or when the field is absent.

    Args:
        res: The response object returned by the API.

    Returns:
        str: The reason to display to the user.
    """
    try:
        body = res.json()
    except ValueError:
        return res.text

    if isinstance(body, dict):
        error = body.get("error") or {}
        if isinstance(error, dict) and error.get("message"):
            return str(error["message"])
    return res.text


def handle_error_response(res):
    """
    Raise a descriptive DemistoException for the error responses of the Google Threat Intelligence API.

    Args:
        res: The response object returned by the API.

    Raises:
        DemistoException: Always, with a message that matches the status code of the response.
    """
    status_code = res.status_code

    if status_code == 401:
        # The complete body is reported for a 401, as the API does not always populate the 'error.message' field.
        try:
            details = str(res.json())
        except ValueError:
            details = res.text
        raise DemistoException(ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(status_code, details), res=res)

    reason = get_error_reason(res)
    error_message_key = {
        400: "BAD_REQUEST",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
    }.get(status_code, "GENERIC_ERROR")

    # The response is attached, so that a command can report a dedicated message for a status code of its operation.
    raise DemistoException(ERROR_MESSAGES[error_message_key].format(status_code, reason), res=res)


def trim_spaces_from_args(args: dict) -> dict:
    """
    Trim the leading and the trailing spaces from the values of the given dictionary.

    Args:
        args (dict): The arguments or the parameters to trim.

    Returns:
        dict: The dictionary with the trimmed values.
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


def get_required_arg(args: dict, arg_name: str) -> str:
    """
    Retrieve the value of a required command argument.

    Args:
        args (dict): The arguments obtained from demisto.args().
        arg_name (str): The name of the required argument.

    Returns:
        str: The value of the argument.

    Raises:
        ValueError: If the argument is absent or empty.
    """
    value = args.get(arg_name) or ""

    if not value:
        raise ValueError(ERROR_MESSAGES["REQUIRED_ARGUMENT"].format(arg_name))

    return value


def convert_epoch_to_iso(epoch: Any) -> Any:
    """
    Convert an epoch timestamp, which the API reports in seconds, into an ISO 8601 date string.

    Args:
        epoch (Any): The epoch timestamp in seconds.

    Returns:
        Any: The ISO 8601 representation of the timestamp, or the received value when it is not an epoch timestamp.
    """
    if isinstance(epoch, bool) or not isinstance(epoch, (int, float)):
        return epoch

    return timestamp_to_datestring(int(epoch) * 1000, DATE_TIME_FORMAT)


def build_search_modifier(modifier: str, value: str) -> str:
    """
    Build a single search modifier expression.

    Args:
        modifier (str): The name of the search modifier.
        value (str): The value of the search modifier.

    Returns:
        str: The search modifier expression, with the value quoted and the embedded double quotes
            escaped so that the value cannot break out of the quoted literal.
    """
    escaped_value = value.replace('"', '\\"')
    return f'{modifier}:"{escaped_value}"'


def validate_boolean_arg(value: str, arg_name: str) -> bool:
    """
    Convert the value of a boolean argument.

    Args:
        value (str): The value of the argument.
        arg_name (str): The name of the argument.

    Returns:
        bool: The boolean representation of the value.

    Raises:
        ValueError: If the value is not one of the supported values.
    """
    try:
        return argToBoolean(value)
    except ValueError:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(value, arg_name, BOOLEAN_HR_LIST))


def parse_json_list_arg(value: str | list | dict, arg_name: str) -> list:
    """
    Parse the value of an argument that carries a JSON formatted list of objects.

    Args:
        value (str | list | dict): The value of the argument, which is already parsed when taken from the context.
        arg_name (str): The name of the argument.

    Returns:
        list: The parsed objects, or an empty list when the argument is not provided.

    Raises:
        ValueError: If the value is not a JSON formatted list of objects.
    """
    if not value:
        return []

    # A value taken from the context reaches the command already parsed, and a single object is not wrapped in a list.
    if isinstance(value, dict):
        value = [value]

    if isinstance(value, list):
        parsed = value
    else:
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as e:
            # The parser position is reported rather than the value, which can be large.
            raise ValueError(ERROR_MESSAGES["INVALID_JSON_LIST"].format(arg_name, f" Error: {e.msg} at position {e.pos}."))

    if not isinstance(parsed, list) or not all(isinstance(item, dict) for item in parsed):
        raise ValueError(ERROR_MESSAGES["INVALID_JSON_LIST"].format(arg_name, ""))

    return parsed


def parse_notification_emails(value: str) -> list:
    """
    Parse the comma separated email addresses that receive the result of a Flow.

    Args:
        value (str): The value of the 'notification_emails' argument.

    Returns:
        list: The email addresses.

    Raises:
        ValueError: If any of the values is not a valid email address.
    """
    emails = argToList(value)

    for email in emails:
        if not re.fullmatch(emailRegex, email):
            raise ValueError(ERROR_MESSAGES["INVALID_EMAIL"].format(email))

    return emails


def validate_flow_nodes(nodes: list) -> None:
    """
    Validate the structure of the nodes of the Flow graph.

    Every node is required to report its identifier, a supported type and the field that the type
    requires, and the graph is required to carry a schedule node and a prompt node.

    Args:
        nodes (list): The nodes of the Flow graph.

    Raises:
        ValueError: If a node is malformed, or if a required node type is not present.
    """
    errors = []
    node_types = set()
    seen_ids: set[str] = set()

    for index, node in enumerate(nodes):
        node_id = node.get("id") or ""
        node_type = node.get("type") or ""
        # A readable reference to the node for the error messages, even when its identifier is absent or malformed.
        node_ref = f"'{node_id}'" if node_id and isinstance(node_id, str) else f"at index {index}"

        if not isinstance(node_id, str):
            errors.append(ERROR_MESSAGES["INVALID_NODE_FIELD_TYPE"].format("id", node_ref, "a string"))
            continue

        if not isinstance(node_type, str):
            errors.append(ERROR_MESSAGES["INVALID_NODE_FIELD_TYPE"].format("type", node_ref, "a string"))
            continue

        node_types.add(node_type)

        if not node_id:
            errors.append(ERROR_MESSAGES["MISSING_NODE_ID"])
        elif node_id in seen_ids:
            errors.append(ERROR_MESSAGES["DUPLICATE_NODE_ID"].format(node_id))
        else:
            seen_ids.add(node_id)

        if not node_type:
            errors.append(ERROR_MESSAGES["MISSING_NODE_TYPE"].format(node_ref))
            continue

        if node_type not in FLOW_NODE_BODY_KEY:
            errors.append(ERROR_MESSAGES["INVALID_NODE_TYPE"].format(node_type, node_ref, list(FLOW_NODE_BODY_KEY)))
            continue

        body_key = FLOW_NODE_BODY_KEY[node_type]
        required_field = FLOW_NODE_REQUIRED_FIELD[node_type]
        node_body = node.get(body_key) or {}

        if not isinstance(node_body, dict):
            errors.append(ERROR_MESSAGES["INVALID_NODE_FIELD_TYPE"].format(body_key, node_ref, "a JSON object"))
            continue

        required_value = node_body.get(required_field)

        if not required_value:
            errors.append(ERROR_MESSAGES["MISSING_NODE_FIELD"].format(required_field, body_key, node_ref))
        elif node_type == FLOW_NODE_TYPE_EMAIL:
            # The addresses are validated as strictly as the ones of the 'notification_emails' argument.
            if not isinstance(required_value, list):
                errors.append(ERROR_MESSAGES["INVALID_NODE_FIELD_TYPE"].format(required_field, node_ref, "a list"))
            else:
                errors.extend(
                    ERROR_MESSAGES["INVALID_EMAIL"].format(email)
                    for email in required_value
                    if not isinstance(email, str) or not re.fullmatch(emailRegex, email)
                )

    for required_type in FLOW_REQUIRED_NODE_TYPES:
        if required_type not in node_types:
            errors.append(ERROR_MESSAGES["MISSING_REQUIRED_NODE"].format(required_type))

    if errors:
        raise ValueError("\n\n".join(errors))


def validate_flow_connections(nodes: list, connections: list) -> None:
    """
    Validate that every connection of the Flow graph refers to a provided node.

    Every connection is required to report the node it starts from and the node it points to.

    Args:
        nodes (list): The nodes of the Flow graph.
        connections (list): The connections of the Flow graph.

    Raises:
        ValueError: If a connection does not report both its nodes, or refers to a node that is not
            present in the nodes.
    """
    node_ids = {node.get("id") for node in nodes}
    errors = []

    for connection in connections:
        for field in FLOW_CONNECTION_NODE_FIELDS:
            node_id = connection.get(field) or ""

            if not node_id:
                errors.append(ERROR_MESSAGES["MISSING_CONNECTION_FIELD"].format(field))
            elif not isinstance(node_id, str):
                errors.append(ERROR_MESSAGES["INVALID_CONNECTION_FIELD_TYPE"].format(field))
            elif node_id not in node_ids:
                errors.append(ERROR_MESSAGES["INVALID_CONNECTION_NODE"].format(node_id, field))

    if errors:
        raise ValueError("\n\n".join(errors))


def validate_flow_reachability(nodes: list, connections: list) -> None:
    """
    Validate that the schedule of the Flow graph triggers a prompt node, directly or through other nodes.

    The nodes and the connections are expected to be validated already, hence every identifier is a string.

    Args:
        nodes (list): The nodes of the Flow graph.
        connections (list): The connections of the Flow graph.

    Raises:
        ValueError: If no prompt node is reachable from a schedule node.
    """
    node_types = {node["id"]: node["type"] for node in nodes}
    targets: dict[str, set] = {}

    for connection in connections:
        targets.setdefault(connection["source_node_id"], set()).add(connection["target_node_id"])

    # The nodes that the schedule triggers, directly or through other nodes.
    pending = [node_id for node_id, node_type in node_types.items() if node_type == FLOW_NODE_TYPE_SCHEDULE]
    reached = set(pending)

    while pending:
        for target in targets.get(pending.pop(), set()) - reached:
            reached.add(target)
            pending.append(target)

    if not any(node_types[node_id] == FLOW_NODE_TYPE_PROMPT for node_id in reached):
        raise ValueError(ERROR_MESSAGES["UNREACHABLE_PROMPT_NODE"])


def validate_flow_list_args(limit: int | None, enabled: str, sort_field: str, sort_order: str) -> None:
    """
    Validate the arguments of the gti-agentic-flow-list command.

    Args:
        limit (int): The maximum number of Flows to return.
        enabled (str): Whether the Flow is enabled.
        sort_field (str): The sort field.
        sort_order (str): The sort order.

    Raises:
        ValueError: If any of the arguments contains an invalid value.
    """
    errors = []

    if limit is not None and not 1 <= limit <= MAX_LIMIT:
        errors.append(ERROR_MESSAGES["INVALID_LIMIT"].format(limit, MAX_LIMIT))

    if enabled:
        try:
            argToBoolean(enabled)
        except ValueError:
            errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(enabled, "enabled", BOOLEAN_HR_LIST))

    if sort_field and sort_field.lower() not in FLOW_SORT_FIELD_API_MAP:
        errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(sort_field, "sort_field", FLOW_SORT_FIELD_HR_LIST))

    if sort_order and sort_order.lower() not in SORT_ORDER_API_MAP:
        errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(sort_order, "sort_order", SORT_ORDER_HR_LIST))

    if errors:
        raise ValueError("\n\n".join(errors))


def validate_flow_execution_list_args(limit: int | None, status: str, sort_field: str, sort_order: str) -> None:
    """
    Validate the arguments of the gti-agentic-flow-execution-list command.

    Args:
        limit (int): The maximum number of Flow Executions to return.
        status (str): The status of the Flow Executions.
        sort_field (str): The sort field.
        sort_order (str): The sort order.

    Raises:
        ValueError: If any of the arguments contains an invalid value.
    """
    errors = []

    if limit is not None and not 1 <= limit <= MAX_LIMIT:
        errors.append(ERROR_MESSAGES["INVALID_LIMIT"].format(limit, MAX_LIMIT))

    if status and status.lower() not in (value.lower() for value in FLOW_EXECUTION_STATUS_HR_LIST):
        errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(status, "status", FLOW_EXECUTION_STATUS_HR_LIST))

    if sort_field.lower() not in FLOW_EXECUTION_SORT_FIELD_API_MAP:
        errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(sort_field, "sort_field", FLOW_EXECUTION_SORT_FIELD_HR_LIST))

    if sort_order.lower() not in SORT_ORDER_API_MAP:
        errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(sort_order, "sort_order", SORT_ORDER_HR_LIST))

    if errors:
        raise ValueError("\n\n".join(errors))


def build_flow_execution_filter(flow_id: str, status: str, filter_expression: str) -> str:
    """
    Build the search modifier expression that filters the GTI Agentic Flow Executions.

    The API applies an AND operator to the space separated modifiers of the 'filter' query parameter, hence
    the conditions of the 'flow_id' and the 'status' arguments are combined with the provided expression.
    The provided expression is parenthesized when it follows those conditions, so that an OR operator in it
    cannot absorb them.

    Args:
        flow_id (str): The ID of the Flow that the executions belong to.
        status (str): The status of the Flow Executions.
        filter_expression (str): The search modifier expression provided by the user.

    Returns:
        str: The search modifier expression to send in the 'filter' query parameter.
    """
    modifiers = []

    if flow_id:
        modifiers.append(f"flow_id:{flow_id}")

    if status:
        modifiers.append(f"status:{status.lower()}")

    if filter_expression:
        modifiers.append(f"({filter_expression})" if modifiers else filter_expression)

    return " ".join(modifiers)


def validate_flow_execution_relationship_args(relationship: str) -> str:
    """
    Validate the arguments of the commands that retrieve the objects related to a GTI Agentic Flow Execution.

    Args:
        relationship (str): The relationship of the related objects.

    Returns:
        str: The relationship to send to the API.

    Raises:
        ValueError: If the relationship contains an invalid value.
    """
    api_relationship = FLOW_EXECUTION_RELATIONSHIP_API_MAP.get(relationship.lower(), "")
    if not api_relationship:
        raise ValueError(
            ERROR_MESSAGES["INVALID_ARGUMENT"].format(relationship, "relationship", FLOW_EXECUTION_RELATIONSHIP_HR_LIST)
        )

    return api_relationship


def validate_flow_relationship_args(limit: int | None, relationship: str) -> None:
    """
    Validate the arguments of the commands that list the objects related to a GTI Agentic Flow.

    Args:
        limit (int): The maximum number of related objects to return.
        relationship (str): The relationship of the related objects.

    Raises:
        ValueError: If any of the arguments contains an invalid value.
    """
    errors = []

    if limit is not None and not 1 <= limit <= MAX_LIMIT:
        errors.append(ERROR_MESSAGES["INVALID_LIMIT"].format(limit, MAX_LIMIT))

    if relationship.lower() not in FLOW_RELATIONSHIP_API_MAP:
        errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(relationship, "relationship", FLOW_RELATIONSHIP_HR_LIST))

    if errors:
        raise ValueError("\n\n".join(errors))


def build_flow_relationship_request(args: dict) -> tuple[str, str, dict]:
    """
    Build the request of the commands that list the objects related to a GTI Agentic Flow.

    Args:
        args (dict): The arguments obtained from demisto.args().

    Returns:
        tuple: The ID of the Flow, the relationship to send to the API and the query parameters.

    Raises:
        ValueError: If any of the arguments is absent or contains an invalid value.
    """
    flow_id = get_required_arg(args, "flow_id")
    relationship_arg = get_required_arg(args, "relationship")
    limit = arg_to_number(args.get("limit") or DEFAULT_LIMIT, arg_name="limit")
    cursor = args.get("cursor") or ""

    validate_flow_relationship_args(limit=limit, relationship=relationship_arg)

    query_params: dict[str, Any] = {"limit": limit}

    if cursor:
        query_params["cursor"] = cursor

    return flow_id, FLOW_RELATIONSHIP_API_MAP[relationship_arg.lower()], query_params


def get_flow_related_objects(raw_response: dict) -> list:
    """
    Retrieve the objects or the descriptors of a relationship of a GTI Agentic Flow from the API response.

    Args:
        raw_response (dict): The API response.

    Returns:
        list: The related objects or descriptors, without the items of an unexpected shape.
    """
    related_objects = raw_response.get("data") or []

    # A relationship to a single object, such as the group, reports the object rather than a list.
    if isinstance(related_objects, dict):
        return [related_objects]

    return [item for item in related_objects if isinstance(item, dict)] if isinstance(related_objects, list) else []


def build_flow_relationship_outputs(
    output_prefix: str, page_token_prefix: str, flow_id: str, related_objects: list, page_token: dict
) -> dict:
    """
    Build the context outputs of the commands that list the objects related to a GTI Agentic Flow.

    The related objects are stored as they are received, under the Flow and the type of the objects that the
    API reports. Two prefixes are written in a single result, and the page token is replaced on every run,
    hence the raw dict.

    Args:
        output_prefix (str): The context prefix of the related objects.
        page_token_prefix (str): The context prefix of the page token.
        flow_id (str): The ID of the Flow.
        related_objects (list): The related objects or descriptors.
        page_token (dict): The page token built from the metadata of the API response.

    Returns:
        dict: The context outputs.
    """
    return {
        f"{output_prefix}{FLOW_RELATIONSHIP_CONTEXT_KEY}": {
            "flow_id": flow_id,
            # Every object of a relationship shares the same type.
            "type": related_objects[0].get("type", "") if related_objects else "",
            "data": related_objects,
        },
        # Replaced on every run, so that a cursor of an earlier run never outlives its page.
        f"{page_token_prefix}(true)": page_token,
    }


def build_flow_filter(name: str, enabled: bool | None, filter_expression: str) -> str:
    """
    Build the search modifier expression that filters the GTI Agentic Flows.

    The conditions that are built from the 'name' and the 'enabled' arguments are combined with an
    OR operator, and the group is parenthesized so that the search modifier expression of the
    'filter' argument is not absorbed into it. The group and the expression are then combined with
    an AND operator, which the API applies to the space separated modifiers of the 'filter' query
    parameter.

    Args:
        name (str): The name of the Flow, which supports a partial match.
        enabled (bool): Whether the Flow is enabled, or None when the argument is not provided.
        filter_expression (str): The search modifier expression provided by the user.

    Returns:
        str: The search modifier expression to send in the 'filter' query parameter.
    """
    conditions = []

    if name:
        conditions.append(build_search_modifier("name", name))

    if enabled is not None:
        conditions.append(f"enabled:{str(enabled).lower()}")

    modifiers = []

    if len(conditions) > 1:
        modifiers.append(f"({' OR '.join(conditions)})")
    elif conditions:
        modifiers.append(conditions[0])

    if filter_expression:
        modifiers.append(filter_expression)

    return " ".join(modifiers)


def build_schedule_cron_expression(schedule_time: str, schedule_frequency: str) -> str:
    """
    Build the cron expression of the schedule node from a date or time and a frequency.

    The date or time is converted into UTC, which is the timezone of the schedule node, and the frequency
    selects its fields that the cron expression repeats on.

    Args:
        schedule_time (str): The value of the 'schedule_time' argument.
        schedule_frequency (str): The value of the 'schedule_frequency' argument.

    Returns:
        str: The cron expression of the schedule node.

    Raises:
        ValueError: If the date or time cannot be parsed, or if the frequency is not supported.
    """
    cron_template = FLOW_SCHEDULE_FREQUENCY_CRON.get(schedule_frequency.lower())
    if not cron_template:
        raise ValueError(
            ERROR_MESSAGES["INVALID_ARGUMENT"].format(schedule_frequency, "schedule_frequency", SCHEDULE_FREQUENCY_HR_LIST)
        )

    try:
        schedule_datetime = arg_to_datetime(schedule_time, arg_name="schedule_time", required=True)
    except ValueError:
        raise ValueError(ERROR_MESSAGES["INVALID_SCHEDULE_TIME"].format(schedule_time))

    return cron_template.format(
        minute=schedule_datetime.minute,  # type: ignore[union-attr]
        hour=schedule_datetime.hour,  # type: ignore[union-attr]
        day=schedule_datetime.day,  # type: ignore[union-attr]
        # Python counts the weekdays from Monday, which is 0.
        weekday=(schedule_datetime.weekday() + 1) % 7,  # type: ignore[union-attr]
    )


def build_flow_node(node_type: str, node_id: str, node_body: dict) -> dict:
    """
    Build a single node of a Flow graph.

    Args:
        node_type (str): The type of the node.
        node_id (str): The identifier of the node inside the Flow graph.
        node_body (dict): The configuration of the node type.

    Returns:
        dict: The node of the Flow graph.
    """
    return {
        "id": node_id,
        "type": node_type,
        "name": FLOW_NODE_DEFAULT_NAME[node_type],
        FLOW_NODE_BODY_KEY[node_type]: node_body,
    }


def build_flow_graph(
    prompt: str,
    reuse_session: bool,
    cron_expression: str,
    notification_emails: list,
    email_subject: str,
    email_message: str,
) -> tuple[list, list]:
    """
    Build the nodes and the connections of a Flow graph from the individual arguments.

    The schedule node and the prompt node are always built, the email node is built only when its
    arguments are provided, and the nodes are chained in the order in which they are executed.

    Args:
        prompt (str): The prompt that the Flow sends to the Google Threat Intelligence agent.
        reuse_session (bool): Whether the prompt node reuses the existing agentic session.
        cron_expression (str): The cron expression of the schedule node.
        notification_emails (list): The email addresses that receive the result of the Flow.
        email_subject (str): The subject of the notification email.
        email_message (str): The body of the notification email.

    Returns:
        tuple: The nodes and the connections of the Flow graph.
    """
    # The node types and their configuration, in the order in which the Flow executes them.
    node_specs: list[tuple[str, dict]] = [
        (FLOW_NODE_TYPE_SCHEDULE, {"cron_expression": cron_expression, "timezone": DEFAULT_SCHEDULE_TIMEZONE}),
        (FLOW_NODE_TYPE_PROMPT, {"prompt": prompt, "reuse_session": reuse_session}),
    ]

    if notification_emails:
        # The optional fields of the email node are omitted, as the API rejects the empty values.
        email_body: dict[str, Any] = {"notification_emails": notification_emails}

        if email_subject:
            email_body["email_subject"] = email_subject

        if email_message:
            email_body["message"] = email_message

        node_specs.append((FLOW_NODE_TYPE_EMAIL, email_body))

    nodes = [
        build_flow_node(node_type, f"{FLOW_NODE_ID_PREFIX}{index}", body)
        for index, (node_type, body) in enumerate(node_specs, start=1)
    ]

    connections = [
        {"source_node_id": source["id"], "target_node_id": target["id"], "source_handle": ""}
        for source, target in itertools.pairwise(nodes)
    ]

    return nodes, connections


def get_single_flow_node(nodes: list, node_type: str) -> dict | None:
    """
    Retrieve the only node of the given type from the nodes of a Flow graph.

    Args:
        nodes (list): The nodes of the Flow graph.
        node_type (str): The type of the node.

    Returns:
        dict: The node of the given type, or None when the graph has no such node.

    Raises:
        ValueError: If the graph has more than one node of the given type, as the node to update is ambiguous.
    """
    matches = [node for node in nodes if node.get("type") == node_type]

    if len(matches) > 1:
        raise ValueError(ERROR_MESSAGES["MULTIPLE_FLOW_NODES"].format(node_type))

    return matches[0] if matches else None


def update_flow_graph(
    nodes: list,
    connections: list,
    cron_expression: str,
    prompt: str,
    reuse_session: bool | None,
    notification_emails: list,
    email_subject: str,
    email_message: str,
) -> tuple[list, list]:
    """
    Update the existing nodes of a Flow graph with the individual arguments.

    Only the provided fields are changed in the node of the matching type, and the timezone of the schedule
    node is set to UTC along with its cron expression. An email node is added and connected after the prompt
    node when the Flow has none and the notification emails are provided.

    Args:
        nodes (list): The existing nodes of the Flow graph.
        connections (list): The connections of the Flow graph.
        cron_expression (str): The cron expression of the schedule node.
        prompt (str): The prompt that the Flow sends to the Google Threat Intelligence agent.
        reuse_session (bool): Whether the prompt node reuses the existing agentic session, or None when not provided.
        notification_emails (list): The email addresses that receive the result of the Flow.
        email_subject (str): The subject of the notification email.
        email_message (str): The body of the notification email.

    Returns:
        tuple: The nodes and the connections of the updated Flow graph.

    Raises:
        ValueError: If the node to update is absent or ambiguous, or if an email node is added without a prompt node.
    """
    node_updates: dict[str, dict[str, Any]] = {
        # The cron expression is built in UTC, hence the timezone of the node is aligned with it.
        FLOW_NODE_TYPE_SCHEDULE: {
            "cron_expression": cron_expression,
            "timezone": DEFAULT_SCHEDULE_TIMEZONE if cron_expression else None,
        },
        FLOW_NODE_TYPE_PROMPT: {"prompt": prompt, "reuse_session": reuse_session},
        FLOW_NODE_TYPE_EMAIL: {
            "notification_emails": notification_emails,
            "email_subject": email_subject,
            "message": email_message,
        },
    }

    # The retrieved graph is copied, so that the function does not change the caller's objects.
    nodes = copy.deepcopy(nodes)
    connections = list(connections)

    for node_type, fields in node_updates.items():
        # The fields that are not provided are left unchanged, and the API rejects the empty values.
        provided_fields = {key: value for key, value in fields.items() if value not in (None, "", [])}
        if not provided_fields:
            continue

        body_key = FLOW_NODE_BODY_KEY[node_type]
        node = get_single_flow_node(nodes, node_type)

        if node:
            node[body_key] = {**(node.get(body_key) or {}), **provided_fields}
            continue

        if node_type != FLOW_NODE_TYPE_EMAIL:
            raise ValueError(ERROR_MESSAGES["MISSING_FLOW_NODE"].format(node_type))

        if not notification_emails:
            raise ValueError(ERROR_MESSAGES["MISSING_EMAIL_NODE"])

        prompt_node = get_single_flow_node(nodes, FLOW_NODE_TYPE_PROMPT)
        if not prompt_node:
            # The email node is connected after the prompt node, hence it would never run without one.
            raise ValueError(ERROR_MESSAGES["MISSING_FLOW_NODE"].format(FLOW_NODE_TYPE_PROMPT))

        # The new node takes the first free identifier, as the existing ones are not required to be sequential.
        node_ids = {existing_node.get("id") for existing_node in nodes}
        node_index = len(nodes) + 1
        while f"{FLOW_NODE_ID_PREFIX}{node_index}" in node_ids:
            node_index += 1

        email_node = build_flow_node(FLOW_NODE_TYPE_EMAIL, f"{FLOW_NODE_ID_PREFIX}{node_index}", provided_fields)
        nodes = [*nodes, email_node]
        connections = [
            *connections,
            {"source_node_id": prompt_node.get("id"), "target_node_id": email_node["id"], "source_handle": ""},
        ]

    return nodes, connections


def build_flow_graph_update(client: Client, flow_id: str, args: dict) -> dict:
    """
    Build the graph attributes of the partial update of a GTI Agentic Flow.

    The provided 'nodes' and 'connections' arguments replace the existing ones as they are, and the
    individual node arguments are ignored along with the 'nodes' argument. The Flow is retrieved when
    either of the graph arguments is absent, so that the provided part of the graph is validated
    against the existing one and the individual node arguments change only the existing nodes.

    Args:
        client (Client): Client object to use.
        flow_id (str): The ID of the Flow.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        dict: The 'nodes' and the 'connections' attributes to send, only when they change.

    Raises:
        ValueError: If a graph argument is invalid, or if the updated graph is not valid.
    """
    nodes_arg = args.get("nodes") or ""
    connections_arg = args.get("connections") or ""
    schedule_time = args.get("schedule_time") or ""
    reuse_session_arg = args.get("reuse_session") or ""

    # The arguments are validated before the Flow is retrieved, so that an invalid value fails fast.
    nodes = parse_json_list_arg(nodes_arg, "nodes") if nodes_arg else None
    connections = parse_json_list_arg(connections_arg, "connections") if connections_arg else None

    if nodes is not None:
        validate_flow_nodes(nodes)
        node_fields: dict[str, Any] = {}
    else:
        node_fields = {
            "cron_expression": build_schedule_cron_expression(schedule_time, args.get("schedule_frequency") or "")
            if schedule_time
            else "",
            "prompt": args.get("prompt") or "",
            "reuse_session": validate_boolean_arg(reuse_session_arg, "reuse_session") if reuse_session_arg else None,
            "notification_emails": parse_notification_emails(args.get("notification_emails") or ""),
            "email_subject": args.get("email_subject") or "",
            "email_message": args.get("email_message") or "",
        }

    existing_attributes: dict[str, Any] = {}
    if nodes is None or connections is None:
        existing_attributes = dict_safe_get(client.get_flow(flow_id), ["data", "attributes"], {}) or {}

    graph_nodes = nodes if nodes is not None else existing_attributes.get("nodes") or []
    graph_connections = connections if connections is not None else existing_attributes.get("connections") or []
    graph: dict[str, Any] = {}

    if nodes is not None:
        graph["nodes"] = nodes
    elif any(value not in (None, "", []) for value in node_fields.values()):
        updated_nodes, updated_connections = update_flow_graph(graph_nodes, graph_connections, **node_fields)
        graph["nodes"] = updated_nodes

        if updated_connections != graph_connections:
            # The connections change along with a new email node, hence the complete list is sent.
            graph["connections"] = updated_connections

        graph_nodes, graph_connections = updated_nodes, updated_connections

    if connections is not None:
        graph["connections"] = graph_connections

    if nodes is not None or connections is not None:
        # The structure of the graph changes, hence the schedule node is required to still trigger a prompt node.
        try:
            validate_flow_connections(graph_nodes, graph_connections)
            validate_flow_reachability(graph_nodes, graph_connections)
        except ValueError as e:
            if connections is None:
                raise ValueError(ERROR_MESSAGES["INVALID_EXISTING_CONNECTIONS"].format(e))
            raise

    return graph


def build_flow_output(flow: dict) -> dict:
    """
    Build the context output of a single GTI Agentic Flow.

    The attributes of the Flow are flattened into the Flow object, and the epoch timestamps are
    converted into the ISO 8601 format.

    Args:
        flow (dict): The Flow object of the API response.

    Returns:
        dict: The context output of the Flow.
    """
    attributes = flow.get("attributes") or {}
    context = {key: value for key, value in flow.items() if key not in ("attributes", "context_attributes")}
    context.update(attributes)

    for field in FLOW_TIMESTAMP_FIELDS:
        if field in context:
            context[field] = convert_epoch_to_iso(context[field])

    trigger_state = context.get("trigger_state") or {}
    if "last_run_at" in trigger_state:
        context["trigger_state"] = {**trigger_state, "last_run_at": convert_epoch_to_iso(trigger_state["last_run_at"])}

    return remove_empty_elements(context)


def build_flow_hr(flow_context: dict, nodes_display: Any) -> dict:
    """
    Build the human readable row of a single GTI Agentic Flow.

    Args:
        flow_context (dict): The context output of the Flow.
        nodes_display (Any): The value to report in the 'Nodes' column.

    Returns:
        dict: The human readable row of the Flow.
    """
    flow_id = flow_context.get("id", "")
    # The Flow ID redirects the user to the Flow page of the Google Threat Intelligence platform.
    flow_id_display = f"[{flow_id}]({FLOW_UI_URL.format(flow_id)})" if flow_id else ""

    return {
        "Flow ID": flow_id_display,
        "Name": flow_context.get("name", ""),
        "Enabled": flow_context.get("enabled", False),
        "Nodes": nodes_display,
        "Last Run At": dict_safe_get(flow_context, ["trigger_state", "last_run_at"], ""),
        "Creation Date": flow_context.get("creation_date", ""),
        "Last Modification Date": flow_context.get("last_modification_date", ""),
    }


def build_flow_node_hr(nodes: list) -> list:
    """
    Build the human readable rows of the nodes of a GTI Agentic Flow.

    Every node type populates its own object, hence the fields of all the node types are flattened
    into a single row, and the columns that no node populates are removed from the table.

    Args:
        nodes (list): The nodes of the Flow graph.

    Returns:
        list: The human readable rows of the nodes.
    """
    hr_content = []

    for node in nodes:
        schedule_node = node.get("schedule_node") or {}
        run_prompt_node = node.get("run_prompt_node") or {}
        send_email_node = node.get("send_email_node") or {}
        notification_emails = send_email_node.get("notification_emails") or []

        hr_content.append(
            {
                "Node ID": node.get("id", ""),
                "Type": node.get("type", ""),
                "Name": node.get("name", ""),
                "Cron Expression": schedule_node.get("cron_expression", ""),
                "Timezone": schedule_node.get("timezone", ""),
                "Prompt": run_prompt_node.get("prompt", ""),
                "Reuse Session": run_prompt_node.get("reuse_session", ""),
                "Notification Emails": FLOW_EMAIL_SEPARATOR.join(notification_emails),
                "Email Subject": send_email_node.get("email_subject", ""),
                "Email Message": send_email_node.get("message", ""),
            }
        )

    return hr_content


def build_flow_connection_hr(connections: list) -> list:
    """
    Build the human readable rows of the connections of a GTI Agentic Flow.

    Args:
        connections (list): The connections of the Flow graph.

    Returns:
        list: The human readable rows of the connections.
    """
    return [
        {
            "Source Node ID": connection.get("source_node_id", ""),
            "Target Node ID": connection.get("target_node_id", ""),
            "Source Handle": connection.get("source_handle", ""),
        }
        for connection in connections
    ]


def build_flow_detail_output(flow: dict, title: str) -> tuple[dict, str]:
    """
    Build the context output and the human readable output of a single GTI Agentic Flow.

    A single Flow is small enough to report its complete graph, hence the nodes and the connections
    are reported in a dedicated table below the details of the Flow.

    Args:
        flow (dict): The Flow object of the API response.
        title (str): The title of the table of the details of the Flow.

    Returns:
        tuple: The context output and the human readable output.
    """
    context = build_flow_output(flow)

    nodes = context.get("nodes") or []
    connections = context.get("connections") or []

    tables = [tableToMarkdown(title, build_flow_hr(context, len(nodes)), headers=FLOW_HR_HEADERS, removeNull=True)]

    if nodes:
        tables.append(tableToMarkdown("Nodes", build_flow_node_hr(nodes), headers=FLOW_NODE_HR_HEADERS, removeNull=True))

    if connections:
        tables.append(
            tableToMarkdown(
                "Connections", build_flow_connection_hr(connections), headers=FLOW_CONNECTION_HR_HEADERS, removeNull=True
            )
        )

    return context, "\n".join(tables)


def build_page_token(raw_response: dict) -> dict:
    """
    Build the page token context output of a paginated command from the metadata of the API response.

    Args:
        raw_response (dict): The API response.

    Returns:
        dict: The cursor of the next page and the total number of the records, for the fields that the API reports.
    """
    meta = raw_response.get("meta") or {}
    page_token: dict[str, Any] = {}

    if meta.get("cursor"):
        page_token["next_cursor"] = meta["cursor"]

    if meta.get("count") is not None:
        page_token["total_count"] = meta["count"]

    return page_token


def build_flow_list_output(flows: list, next_cursor: str = "") -> tuple[list, str]:
    """
    Build the context output and the human readable output of the GTI Agentic Flow list.

    Args:
        flows (list): The Flow objects of the API response.
        next_cursor (str): The cursor of the next page of results, when the API reports one.

    Returns:
        tuple: The context output and the human readable output.
    """
    context = []
    hr_content = []

    for flow in flows:
        flow_context = build_flow_output(flow)
        context.append(flow_context)

        # The number of the nodes is reported, as the graph of every Flow of the page would be too verbose.
        hr_content.append(build_flow_hr(flow_context, len(flow_context.get("nodes") or [])))

    readable_output = tableToMarkdown("GTI Agentic Flow List", hr_content, headers=FLOW_HR_HEADERS, removeNull=True)

    if next_cursor:
        readable_output += f"\n{MESSAGES['NEXT_CURSOR'].format(next_cursor)}\n"

    return context, readable_output


def build_flow_execution_output(flow_execution: dict) -> dict:
    """
    Build the context output of a single GTI Agentic Flow Execution.

    The attributes of the Flow Execution are flattened into the Flow Execution object, and the epoch
    timestamps of the Flow Execution and of its steps are converted into the ISO 8601 format.

    Args:
        flow_execution (dict): The Flow Execution object of the API response.

    Returns:
        dict: The context output of the Flow Execution.
    """
    attributes = flow_execution.get("attributes") or {}
    context = {key: value for key, value in flow_execution.items() if key != "attributes"}
    context.update(attributes)

    for field in FLOW_TIMESTAMP_FIELDS:
        if field in context:
            context[field] = convert_epoch_to_iso(context[field])

    if context.get("steps"):
        context["steps"] = [
            {
                **step,
                **{field: convert_epoch_to_iso(step[field]) for field in FLOW_EXECUTION_STEP_TIMESTAMP_FIELDS if field in step},
            }
            for step in context["steps"]
        ]

    return remove_empty_elements(context)


def build_flow_execution_hr(flow_execution_context: dict) -> dict:
    """
    Build the human readable row of a single GTI Agentic Flow Execution.

    Args:
        flow_execution_context (dict): The context output of the Flow Execution.

    Returns:
        dict: The human readable row of the Flow Execution.
    """
    flow_id = flow_execution_context.get("flow_id", "")
    # The Flow ID redirects the user to the Flow page of the Google Threat Intelligence platform.
    flow_id_display = f"[{flow_id}]({FLOW_UI_URL.format(flow_id)})" if flow_id else ""
    execution_id = flow_execution_context.get("id", "")
    # The Execution ID redirects the user to the execution log of the Google Threat Intelligence platform.
    execution_id_display = f"[{execution_id}]({FLOW_EXECUTION_UI_URL.format(execution_id)})" if execution_id else ""

    return {
        "Execution ID": execution_id_display,
        "Flow ID": flow_id_display,
        "Status": flow_execution_context.get("status", ""),
        "Duration (Seconds)": flow_execution_context.get("duration_seconds", ""),
        "Creation Date": flow_execution_context.get("creation_date", ""),
        "Last Modification Date": flow_execution_context.get("last_modification_date", ""),
    }


def build_flow_execution_step_hr(steps: list) -> list:
    """
    Build the human readable rows of the steps of a GTI Agentic Flow Execution.

    Args:
        steps (list): The steps of the Flow Execution.

    Returns:
        list: The human readable rows of the steps.
    """
    return [
        {
            "Step ID": step.get("step_id", ""),
            "Node Type": step.get("node_type", ""),
            "Status": step.get("status", ""),
            "Duration (Seconds)": step.get("duration_seconds", ""),
        }
        for step in steps
    ]


def remove_related_object_secrets(related_objects: list) -> None:
    """
    Remove, in place, the secrets of the objects related to a GTI Agentic Flow or a GTI Agentic Flow Execution.

    The objects are shared with the raw response, hence the secrets reach neither the context nor the raw response.

    Args:
        related_objects (list): The related objects of the API response.
    """
    for related_object in related_objects:
        attributes = related_object.get("attributes") or {}
        for field in RELATED_OBJECT_SECRET_FIELDS.get(related_object.get("type", ""), []):
            attributes.pop(field, None)


def build_flow_related_object_hr(related_objects: list) -> list:
    """
    Build the human readable rows of the Flow Execution objects related to a GTI Agentic Flow.

    Args:
        related_objects (list): The related objects of the API response.

    Returns:
        list: The human readable rows of the related objects.
    """
    hr_content = []

    for related_object in related_objects:
        attributes = related_object.get("attributes") or {}
        object_id = related_object.get("id", "")

        if object_id and related_object.get("type") == FLOW_EXECUTION_TYPE:
            object_id = f"[{object_id}]({FLOW_EXECUTION_UI_URL.format(object_id)})"

        hr_content.append(
            {
                "Object ID": object_id,
                "Type": related_object.get("type", ""),
                "Status": attributes.get("status", ""),
                "Duration (Seconds)": attributes.get("duration_seconds", ""),
                "Creation Date": convert_epoch_to_iso(attributes.get("creation_date", "")),
                "Last Modification Date": convert_epoch_to_iso(attributes.get("last_modification_date", "")),
            }
        )

    return hr_content


def build_flow_related_descriptor_hr(descriptors: list) -> list:
    """
    Build the human readable rows of the descriptors of the objects related to a GTI Agentic Flow.

    The ID of a Flow Execution redirects the user to the execution log of the Google Threat Intelligence platform.

    Args:
        descriptors (list): The descriptors of the API response.

    Returns:
        list: The human readable rows of the descriptors.
    """
    hr_content = []

    for descriptor in descriptors:
        object_id = descriptor.get("id", "")
        object_type = descriptor.get("type", "")

        if object_id and object_type == FLOW_EXECUTION_TYPE:
            object_id = f"[{object_id}]({FLOW_EXECUTION_UI_URL.format(object_id)})"

        hr_content.append({"Object ID": object_id, "Type": object_type})

    return hr_content


def build_flow_group_hr(groups: list) -> list:
    """
    Build the human readable rows of the group objects related to a GTI Agentic Flow.

    Only the identifying fields of the group, the role of the caller and the quota of the active Flows are
    reported, as the other attributes are either too large for a table or carry the secrets of the group.

    Args:
        groups (list): The group objects of the API response.

    Returns:
        list: The human readable rows of the groups.
    """
    hr_content = []

    for group in groups:
        attributes = group.get("attributes") or {}
        active_flows = dict_safe_get(attributes, ["quotas", "active_flows"], {}) or {}
        used, allowed = active_flows.get("used"), active_flows.get("allowed")

        hr_content.append(
            {
                "Group ID": group.get("id", ""),
                "Organization": attributes.get("organization", ""),
                "Domain Name": attributes.get("domain_name", ""),
                "Country": attributes.get("country", ""),
                "Industry": attributes.get("industry", ""),
                "GTI GCP Project": attributes.get("gti_gcp_project", ""),
                "Role": dict_safe_get(group, ["context_attributes", "role"], ""),
                "Active Flows (Used/Allowed)": f"{used}/{allowed}" if used is not None and allowed is not None else "",
            }
        )

    return hr_content


def get_flow_execution_step_output(step: dict) -> str:
    """
    Retrieve the output of a single step of a GTI Agentic Flow Execution for the human readable output.

    Args:
        step (dict): The step of the Flow Execution.

    Returns:
        str: The session ID and a pointer to the agent response section for a prompt step, whether the notification
            email was dispatched for an email step, or an empty string for the other steps.
    """
    run_prompt_output = step.get("run_prompt_output") or {}
    if run_prompt_output:
        output = []
        session_id = run_prompt_output.get("session_id")
        if session_id:
            # The Session ID redirects the user to the session page of the Google Threat Intelligence platform.
            output.append(f"Session ID: [{session_id}]({SESSION_UI_URL.format(session_id)})")
        # The agent response can be several KB of markdown, hence it is rendered in its own section below the steps table.
        if run_prompt_output.get("gti_agentic_response"):
            output.append(MESSAGES["AGENT_RESPONSE_BELOW"])
        return "\n".join(output)

    dispatched = dict_safe_get(step, ["send_email_output", "dispatched"])
    if dispatched is not None:
        return f"dispatched: {str(dispatched).lower()}"

    return ""


def build_flow_execution_step_detail_hr(steps: list) -> list:
    """
    Build the human readable rows of the steps of a single GTI Agentic Flow Execution, along with their output.

    The rows carry every step field; each caller picks the visible columns through the headers of tableToMarkdown.

    Args:
        steps (list): The steps of the Flow Execution.

    Returns:
        list: The human readable rows of the steps.
    """
    return [
        {
            "Step ID": step.get("step_id", ""),
            "Node ID": step.get("node_id", ""),
            "Node Type": step.get("node_type", ""),
            "Status": step.get("status", ""),
            "Input JSON": step.get("input_json", ""),
            "Duration (Seconds)": step.get("duration_seconds", ""),
            "Enqueued At": step.get("enqueued_at", ""),
            "Started At": step.get("started_at", ""),
            "Ended At": step.get("ended_at", ""),
            "Expires At": step.get("expires_at", ""),
            "Output": get_flow_execution_step_output(step),
        }
        for step in steps
    ]


def build_flow_execution_agent_response_hr(steps: list) -> str:
    """
    Build the human readable sections of the Google Threat Intelligence agent responses of a GTI Agentic Flow Execution.

    Args:
        steps (list): The steps of the Flow Execution.

    Returns:
        str: One markdown section per prompt step that has an agent response, or an empty string if there is none.
    """
    sections = []
    for step in steps:
        agent_response = dict_safe_get(step, ["run_prompt_output", "gti_agentic_response"])
        if agent_response:
            sections.append(f"### Agent Response of Step {step.get('step_id', '')}\n{agent_response}\n")

    return "\n".join(sections)


def build_flow_execution_readable_output(
    flow_execution_context: dict, title: str, steps_title: str, step_rows: list, step_headers: list
) -> str:
    """
    Build the human readable output of a single GTI Agentic Flow Execution, along with its steps when present.

    Args:
        flow_execution_context (dict): The context output of the Flow Execution.
        title (str): The title of the Flow Execution table.
        steps_title (str): The title of the steps table.
        step_rows (list): The human readable rows of the steps.
        step_headers (list): The headers of the steps table.

    Returns:
        str: The human readable output of the Flow Execution.
    """
    tables = [
        tableToMarkdown(
            title, build_flow_execution_hr(flow_execution_context), headers=FLOW_EXECUTION_HR_HEADERS, removeNull=True
        )
    ]

    if step_rows:
        tables.append(tableToMarkdown(steps_title, step_rows, headers=step_headers, removeNull=True))

    return "\n".join(tables)


def build_flow_execution_list_output(flow_executions: list, next_cursor: str = "") -> tuple[list, str]:
    """
    Build the context output and the human readable output of the GTI Agentic Flow Execution list.

    Args:
        flow_executions (list): The Flow Execution objects of the API response.
        next_cursor (str): The cursor of the next page of results, when the API reports one.

    Returns:
        tuple: The context output and the human readable output.
    """
    context = []
    hr_content = []

    for flow_execution in flow_executions:
        flow_execution_context = build_flow_execution_output(flow_execution)
        context.append(flow_execution_context)
        hr_content.append(
            {**build_flow_execution_hr(flow_execution_context), "Steps": len(flow_execution_context.get("steps") or [])}
        )

    readable_output = tableToMarkdown(
        "GTI Agentic Flow Execution List", hr_content, headers=FLOW_EXECUTION_LIST_HR_HEADERS, removeNull=True
    )

    if next_cursor:
        readable_output += f"\n{MESSAGES['NEXT_CURSOR'].format(next_cursor)}\n"

    return context, readable_output


def build_flow_execution_related_object_hr(related_objects: list) -> tuple[list, list]:
    """
    Build the human readable rows and headers of the objects related to a GTI Agentic Flow Execution.

    The Flow and its snapshot reuse the columns of the Flow, the group reuses the columns of the group of a Flow,
    and the other objects are reported with their identity only.

    Args:
        related_objects (list): The related objects of the API response.

    Returns:
        tuple: The human readable rows and headers.
    """
    related_type = related_objects[0].get("type", "")

    if related_type in FLOW_EXECUTION_RELATED_FLOW_TYPES:
        rows = []
        for related_object in related_objects:
            # The epoch timestamps are converted for the human readable output only, as the context keeps the object.
            flow_context = build_flow_output(related_object)
            rows.append(build_flow_hr(flow_context, len(flow_context.get("nodes") or [])))
        return rows, FLOW_HR_HEADERS

    if related_type == FLOW_GROUP_TYPE:
        return build_flow_group_hr(related_objects), FLOW_GROUP_HR_HEADERS

    if related_type == FLOW_EXECUTION_OWNER_TYPE:
        rows = []
        for user in related_objects:
            attributes = user.get("attributes") or {}
            rows.append(
                {
                    "User ID": user.get("id", ""),
                    "First Name": attributes.get("first_name", ""),
                    "Last Name": attributes.get("last_name", ""),
                    "Email": attributes.get("email", ""),
                    "Status": attributes.get("status", ""),
                    "User Since": convert_epoch_to_iso(attributes.get("user_since", "")),
                    "Last Login": convert_epoch_to_iso(attributes.get("last_login", "")),
                }
            )
        return rows, FLOW_EXECUTION_OWNER_HR_HEADERS

    rows = [{"Object ID": obj.get("id", ""), "Type": obj.get("type", "")} for obj in related_objects]
    return rows, FLOW_EXECUTION_RELATED_OBJECT_HR_HEADERS


def build_flow_execution_related_descriptor_hr(descriptors: list) -> list:
    """
    Build the human readable rows of the descriptors of the objects related to a GTI Agentic Flow Execution.

    The ID of a Flow redirects the user to the Flow page of the Google Threat Intelligence platform.

    Args:
        descriptors (list): The related object descriptors of the API response.

    Returns:
        list: The human readable rows of the descriptors.
    """
    hr_content = []

    for descriptor in descriptors:
        object_id = descriptor.get("id", "")
        object_type = descriptor.get("type", "")
        context_attributes = descriptor.get("context_attributes") or {}

        if object_id and object_type in FLOW_EXECUTION_RELATED_FLOW_TYPES:
            object_id = f"[{object_id}]({FLOW_UI_URL.format(object_id)})"

        hr_content.append(
            {
                "Object ID": object_id,
                "Type": object_type,
                "Role": context_attributes.get("role"),
                "Shared With Me": context_attributes.get("shared_with_me"),
            }
        )

    return hr_content


def build_session_output(session: dict) -> dict:
    """
    Build the context output of a single GTI Agentic Session.

    The attributes of the session are flattened into the session object. The API reports the timestamps of a
    session in the ISO 8601 format, hence they are kept as received. The context attributes are not kept, as the
    API reports no session context attributes, and a session belongs only to the user that owns the API key.

    Args:
        session (dict): The agentic session object of the API response.

    Returns:
        dict: The context output of the agentic session.
    """
    attributes = session.get("attributes") or {}
    context = {key: value for key, value in session.items() if key not in ("attributes", "context_attributes")}
    context.update(attributes)

    return remove_empty_elements(context)


def build_session_hr(session_context: dict) -> dict:
    """
    Build the human readable row of a single GTI Agentic Session.

    Args:
        session_context (dict): The context output of the agentic session.

    Returns:
        dict: The human readable row of the agentic session.
    """
    session_id = session_context.get("id", "")
    # The Session ID redirects the user to the session page of the Google Threat Intelligence platform.
    session_id_display = f"[{session_id}]({SESSION_UI_URL.format(session_id)})" if session_id else ""

    return {
        "Session ID": session_id_display,
        "Title": session_context.get("title", ""),
        "Creation Date": session_context.get("creation_date", ""),
        "Last Modification Date": session_context.get("last_modification_date", ""),
    }


def get_session_event_payload(event: dict) -> dict:
    """
    Retrieve the payload of a single event of a GTI Agentic Session.

    The API reports the payload of an event under the lower case name of its message type, such as 'user_message' for
    the 'USER_MESSAGE' events and 'agent_final_response' for the 'AGENT_FINAL_RESPONSE' events.

    Args:
        event (dict): The event of the agentic session.

    Returns:
        dict: The payload of the event, or an empty dictionary when the event reports none.
    """
    return event.get(str(event.get("message_type") or "").lower()) or {}


def get_session_event_text(event: dict) -> str:
    """
    Retrieve the markdown text of a single event of a GTI Agentic Session, joined across the widgets of the event.

    Args:
        event (dict): The event of the agentic session.

    Returns:
        str: The markdown text of the event, or an empty string when no widget reports any text.
    """
    widgets = get_session_event_payload(event).get("widgets") or []
    texts = [dict_safe_get(widget, ["markdown_text_widget", "text"]) for widget in widgets]

    return "\n\n".join(text for text in texts if text)


def get_session_event_message(event: dict) -> str:
    """
    Retrieve the message of a single event of a GTI Agentic Session for the conversation table.

    The function call and function response events report no widgets of their own, hence the called function, its
    arguments and the response of the function are reported instead.

    Args:
        event (dict): The event of the agentic session.

    Returns:
        str: The message of the event, or an empty string when the event reports none.
    """
    payload = get_session_event_payload(event)
    message_type = event.get("message_type")

    if message_type == SESSION_EVENT_TYPE_FUNCTION_CALL:
        details = {
            "Function": payload.get("name"),
            "Call ID": payload.get("function_call_id"),
            "Arguments": payload.get("args_json"),
        }
    elif message_type == SESSION_EVENT_TYPE_FUNCTION_RESPONSE:
        # The response of a function is reported as the messages of the agent that served the function call.
        responses = [get_session_event_text(message) for message in payload.get("displayable_ui_messages") or []]
        details = {
            "Call ID": payload.get("function_call_id"),
            "Response": "\n\n".join(response for response in responses if response),
        }
    else:
        message = get_session_event_text(event)
        # The agent response can be several KB of markdown, hence it is rendered in its own section below the table.
        if message and message_type == SESSION_EVENT_TYPE_AGENT_FINAL_RESPONSE:
            return MESSAGES["AGENT_RESPONSE_BELOW"]
        return message

    return "\n".join(f"{key}: {value}" for key, value in details.items() if value)


def build_session_event_hr(events: list) -> list:
    """
    Build the human readable rows of the conversation of a GTI Agentic Session.

    Args:
        events (list): The events of the agentic session.

    Returns:
        list: The human readable rows of the events.
    """
    return [
        {
            "Event ID": event.get("id", ""),
            "Message Type": event.get("message_type", ""),
            "Agent ID": get_session_event_payload(event).get("agent_id", ""),
            "Message": get_session_event_message(event),
        }
        for event in events
    ]


def build_session_agent_response_hr(events: list) -> str:
    """
    Build the human readable sections of the responses of the Google Threat Intelligence agent in a GTI Agentic Session.

    Args:
        events (list): The events of the agentic session.

    Returns:
        str: One markdown section per agent response, or an empty string if there is none.
    """
    sections = []
    for event in events:
        agent_response = get_session_event_text(event)
        if agent_response and event.get("message_type") == SESSION_EVENT_TYPE_AGENT_FINAL_RESPONSE:
            sections.append(f"### Agent Response of Event {event.get('id', '')}\n\n{agent_response}\n")

    return "\n".join(sections)


def build_session_detail_table(session_context: dict, title: str) -> str:
    """
    Build the human readable table of a single GTI Agentic Session, along with the number of its events.

    Args:
        session_context (dict): The context output of the agentic session.
        title (str): The title of the agentic session table.

    Returns:
        str: The human readable table of the agentic session.
    """
    session_hr = {**build_session_hr(session_context), "Events": len(session_context.get("events") or [])}

    return tableToMarkdown(title, session_hr, headers=SESSION_DETAIL_HR_HEADERS, removeNull=True)


def build_session_readable_output(session_context: dict, title: str) -> str:
    """
    Build the human readable output of a single GTI Agentic Session, along with its conversation when present.

    Args:
        session_context (dict): The context output of the agentic session.
        title (str): The title of the agentic session table.

    Returns:
        str: The human readable output of the agentic session.
    """
    events = session_context.get("events") or []

    tables = [build_session_detail_table(session_context, title)]

    if events:
        tables.append(
            tableToMarkdown(
                "Session Conversation", build_session_event_hr(events), headers=SESSION_EVENT_HR_HEADERS, removeNull=True
            )
        )

    agent_response_hr = build_session_agent_response_hr(events)
    if agent_response_hr:
        tables.append(agent_response_hr)

    return "\n".join(tables)


def build_session_result(
    raw_response: dict, success_message: str, hr_builder: Callable = build_session_readable_output
) -> CommandResults:
    """
    Build the result of a command which the API answers with the created or updated session.

    Args:
        raw_response (dict): The response of the API.
        success_message (str): The title of the agentic session table, also reported when the API did not report the session.
        hr_builder (Callable): The builder of the human readable output from the session context and the title.

    Returns:
        CommandResults: CommandResults object.
    """
    session = raw_response.get("data") or {}
    if not session:
        # The request is accepted, although the API did not report the session.
        return CommandResults(raw_response=raw_response, readable_output=success_message)

    context = build_session_output(session)

    return CommandResults(
        outputs=context,
        outputs_prefix=OUTPUT_PREFIX["SESSION"],
        outputs_key_field="id",
        raw_response=raw_response,
        readable_output=hr_builder(context, success_message),
    )


def get_session_attachments(entry_ids: list) -> list:
    """
    Retrieve the name and the path of the files of the given War Room entries, to attach them to a session message.

    Args:
        entry_ids (list): The War Room entry IDs of the files.

    Returns:
        list: The name and the path of every file.

    Raises:
        ValueError: If an entry does not exist, does not hold a file or holds a file larger than the maximum allowed size.
    """
    attachments = []
    for entry_id in entry_ids:
        try:
            file_info = demisto.getFilePath(entry_id) or {}
        except ValueError as e:
            raise ValueError(ERROR_MESSAGES["INVALID_ENTRY_ID"].format(entry_id)) from e

        if not file_info.get("path"):
            raise ValueError(ERROR_MESSAGES["INVALID_ENTRY_ID"].format(entry_id))

        if os.path.getsize(file_info["path"]) > MAX_SESSION_FILE_SIZE_MB * 1024 * 1024:
            raise ValueError(ERROR_MESSAGES["INVALID_ENTRY_FILE_SIZE"].format(entry_id, MAX_SESSION_FILE_SIZE_MB))

        attachments.append((file_info.get("name") or entry_id, file_info["path"]))

    return attachments


def build_session_message_files(message: str, attachments: list | None = None) -> list:
    """
    Build the multipart form of a message to the Google Threat Intelligence agent, along with its attached files.

    Args:
        message (str): The message to send to the agent.
        attachments (list): The name and the path of every file to attach to the message as an artifact.

    Returns:
        list: The parts of the multipart form.
    """
    # The API reads the message from a multipart form, hence the message is sent as a form part without a file.
    files: list[tuple[str, tuple]] = [("message", (None, message))]
    for name, path in attachments or []:
        with open(path, "rb") as file:
            files.append(("files", (name, file.read())))

    return files


def build_session_list_output(sessions: list, next_cursor: str = "") -> tuple[list, str]:
    """
    Build the context output and the human readable output of the GTI Agentic Session list.

    Args:
        sessions (list): The agentic session objects of the API response.
        next_cursor (str): The cursor of the next page of results, when the API reports one.

    Returns:
        tuple: The context output and the human readable output.
    """
    context = [build_session_output(session) for session in sessions]
    hr_content = [build_session_hr(session_context) for session_context in context]

    readable_output = tableToMarkdown("GTI Agentic Session List", hr_content, headers=SESSION_HR_HEADERS, removeNull=True)

    if next_cursor:
        readable_output += f"\n{MESSAGES['NEXT_CURSOR'].format(next_cursor)}\n"

    return context, readable_output


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Validate the configuration parameters by listing a single GTI Agentic Flow.

    Args:
        client (Client): Client object.

    Returns:
        str: "ok" when the connection with Google Threat Intelligence is successful.
    """
    client.list_flows({"limit": TEST_MODULE_LIMIT})

    return "ok"


def gti_agentic_flow_list_command(client: Client, args: dict) -> CommandResults:
    """
    List the GTI Agentic Flows that are accessible to the configured API key.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    limit = arg_to_number(args.get("limit") or DEFAULT_LIMIT, arg_name="limit")
    name = args.get("name") or ""
    enabled = args.get("enabled") or ""
    filter_expression = args.get("filter") or ""
    sort_field = args.get("sort_field") or DEFAULT_SORT_FIELD
    sort_order = args.get("sort_order") or DEFAULT_SORT_ORDER
    cursor = args.get("cursor") or ""

    validate_flow_list_args(limit=limit, enabled=enabled, sort_field=sort_field, sort_order=sort_order)

    # The argument is validated above, hence the conversion of a provided value cannot fail here.
    enabled_flag = argToBoolean(enabled) if enabled else None

    query_params: dict[str, Any] = {
        "limit": limit,
        "order": f"{FLOW_SORT_FIELD_API_MAP[sort_field.lower()]}{SORT_ORDER_API_MAP[sort_order.lower()]}",
    }

    flow_filter = build_flow_filter(name, enabled_flag, filter_expression)
    if flow_filter:
        query_params["filter"] = flow_filter

    if cursor:
        query_params["cursor"] = cursor

    raw_response = client.list_flows(query_params)

    flows = raw_response.get("data") or []
    if not flows:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("GTI Agentic Flows"))

    next_cursor = dict_safe_get(raw_response, ["meta", "cursor"], "")

    context, readable_output = build_flow_list_output(flows, next_cursor)

    # Two prefixes are written in a single result, and the page token uses the '(true)' key so that it is
    # replaced on every run rather than appended. outputs_prefix cannot express either, hence the raw dict.
    outputs: dict[str, Any] = {f"{OUTPUT_PREFIX['FLOW']}(val.id && val.id == obj.id)": context}

    page_token = build_page_token(raw_response)
    if page_token:
        outputs[f"{OUTPUT_PREFIX['FLOW_PAGE_TOKEN']}(true)"] = page_token

    return CommandResults(
        outputs=outputs,
        raw_response=raw_response,
        readable_output=readable_output,
    )


def gti_agentic_flow_get_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve the details of a specific GTI Agentic Flow by its ID.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    flow_id = get_required_arg(args, "flow_id")

    raw_response = client.get_flow(flow_id)

    flow = raw_response.get("data") or {}
    if not flow:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("GTI Agentic Flows"))

    context, readable_output = build_flow_detail_output(flow, "GTI Agentic Flow Information")

    return CommandResults(
        outputs=context,
        outputs_prefix=OUTPUT_PREFIX["FLOW"],
        outputs_key_field="id",
        raw_response=raw_response,
        readable_output=readable_output,
    )


def gti_agentic_flow_create_command(client: Client, args: dict) -> CommandResults:
    """
    Create a new GTI Agentic Flow with the provided node and connection graph.

    The graph is either provided as it is through the 'nodes' and the 'connections' arguments, or it
    is built from the schedule, the prompt and the email arguments.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    name = args.get("name") or ""
    nodes_arg = args.get("nodes") or ""
    prompt = args.get("prompt") or ""
    schedule_time = args.get("schedule_time") or ""

    if not name:
        raise ValueError(ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("name"))

    if not nodes_arg and not (schedule_time and prompt):
        raise ValueError(ERROR_MESSAGES["MISSING_FLOW_GRAPH"])

    enabled = validate_boolean_arg(args.get("enabled") or DEFAULT_ENABLED, "enabled")

    if nodes_arg:
        # The provided graph is sent as it is, hence the individual node arguments are ignored.
        nodes = parse_json_list_arg(nodes_arg, "nodes")
        connections = parse_json_list_arg(args.get("connections") or "", "connections")
        validate_flow_nodes(nodes)

        # Without connections the schedule node never triggers the prompt node, hence the Flow never runs.
        if not connections:
            raise ValueError(ERROR_MESSAGES["MISSING_CONNECTIONS"])

        validate_flow_connections(nodes, connections)
        validate_flow_reachability(nodes, connections)
    else:
        cron_expression = build_schedule_cron_expression(
            schedule_time, args.get("schedule_frequency") or DEFAULT_SCHEDULE_FREQUENCY
        )
        notification_emails = parse_notification_emails(args.get("notification_emails") or "")
        email_subject = args.get("email_subject") or ""
        email_message = args.get("email_message") or ""

        # Without the addresses no email node is built, hence the subject and the message would be dropped.
        if (email_subject or email_message) and not notification_emails:
            raise ValueError(ERROR_MESSAGES["MISSING_NOTIFICATION_EMAILS"])

        nodes, connections = build_flow_graph(
            prompt=prompt,
            reuse_session=validate_boolean_arg(args.get("reuse_session") or DEFAULT_REUSE_SESSION, "reuse_session"),
            cron_expression=cron_expression,
            notification_emails=notification_emails,
            email_subject=email_subject,
            email_message=email_message,
        )

    attributes: dict[str, Any] = {"name": name, "enabled": enabled, "nodes": nodes}

    if connections:
        attributes["connections"] = connections

    raw_response = client.create_flow({"data": {"type": "flow", "attributes": attributes}})

    flow = raw_response.get("data") or {}
    if not flow:
        # The Flow is created, although the API did not report its details.
        return CommandResults(raw_response=raw_response, readable_output=MESSAGES["FLOW_CREATED"])

    context, readable_output = build_flow_detail_output(flow, MESSAGES["FLOW_CREATED"])

    return CommandResults(
        outputs=context,
        outputs_prefix=OUTPUT_PREFIX["FLOW"],
        outputs_key_field="id",
        raw_response=raw_response,
        readable_output=readable_output,
    )


def gti_agentic_flow_update_command(client: Client, args: dict) -> CommandResults:
    """
    Partially update a GTI Agentic Flow with the provided arguments.

    The provided 'nodes' and 'connections' arguments replace the graph of the Flow as they are. Otherwise,
    the Flow is retrieved first and only the provided schedule, prompt and email fields are changed in
    its existing nodes. The name and the enabled state are updated independently of the graph.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    flow_id = get_required_arg(args, "flow_id")
    name = args.get("name") or ""
    enabled = args.get("enabled") or ""
    nodes_arg = args.get("nodes") or ""
    connections_arg = args.get("connections") or ""
    schedule_time = args.get("schedule_time") or ""
    prompt = args.get("prompt") or ""
    reuse_session_arg = args.get("reuse_session") or ""
    notification_emails_arg = args.get("notification_emails") or ""
    email_subject = args.get("email_subject") or ""
    email_message = args.get("email_message") or ""

    # The cron expression is built from both the time and the frequency, hence either of them alone would reset the
    # other one of the existing schedule. The individual node arguments are ignored along with the 'nodes' argument.
    if bool(args.get("schedule_frequency")) != bool(schedule_time) and not nodes_arg:
        raise ValueError(ERROR_MESSAGES["MISSING_SCHEDULE_ARGUMENT"])

    node_args = [schedule_time, prompt, reuse_session_arg, notification_emails_arg, email_subject, email_message]

    if not any([name, enabled, nodes_arg, connections_arg, *node_args]):
        raise ValueError(ERROR_MESSAGES["MISSING_UPDATE_ARGUMENT"])

    attributes: dict[str, Any] = {}

    if name:
        attributes["name"] = name

    if enabled:
        attributes["enabled"] = validate_boolean_arg(enabled, "enabled")

    if nodes_arg or connections_arg or any(node_args):
        attributes.update(build_flow_graph_update(client, flow_id, args))

    raw_response = client.update_flow(flow_id, {"data": {"type": "flow", "attributes": attributes}})

    flow = raw_response.get("data") or {}
    if not flow:
        # The Flow is updated, although the API did not report its details.
        return CommandResults(raw_response=raw_response, readable_output=MESSAGES["FLOW_UPDATED"])

    context, readable_output = build_flow_detail_output(flow, MESSAGES["FLOW_UPDATED"])

    return CommandResults(
        outputs=context,
        outputs_prefix=OUTPUT_PREFIX["FLOW"],
        outputs_key_field="id",
        raw_response=raw_response,
        readable_output=readable_output,
    )


def gti_agentic_flow_delete_command(client: Client, args: dict) -> CommandResults:
    """
    Permanently delete a specific GTI Agentic Flow by its ID.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    flow_id = get_required_arg(args, "flow_id")

    raw_response = client.delete_flow(flow_id)

    # The API returns no content on success, hence no context output is published.
    return CommandResults(
        raw_response=raw_response,
        readable_output=MESSAGES["FLOW_DELETED"].format(flow_id),
    )


def gti_agentic_flow_object_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve the full objects that are related to a GTI Agentic Flow through the given relationship.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    flow_id, relationship, query_params = build_flow_relationship_request(args)

    raw_response = client.list_flow_related_objects(flow_id, relationship, query_params)

    related_objects = get_flow_related_objects(raw_response)
    page_token = build_page_token(raw_response)

    if not related_objects:
        # The page token is still written, so that the next cursor of an earlier run is cleared.
        return CommandResults(
            outputs={f"{OUTPUT_PREFIX['FLOW_RELATIONSHIP_PAGE_TOKEN']}(true)": page_token},
            raw_response=raw_response,
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("related objects"),
        )

    remove_related_object_secrets(related_objects)

    next_cursor = page_token.get("next_cursor", "")
    # Every object of a relationship shares the same type.
    related_type = related_objects[0].get("type", "")

    if related_type == FLOW_GROUP_TYPE:
        hr_content, hr_headers = build_flow_group_hr(related_objects), FLOW_GROUP_HR_HEADERS
    else:
        hr_content, hr_headers = build_flow_related_object_hr(related_objects), FLOW_RELATED_OBJECT_HR_HEADERS

    hr_title = FLOW_RELATED_OBJECT_HR_TITLE.format(
        FLOW_RELATED_OBJECT_TYPE_HR_NAME.get(related_type, "Related Objects"), flow_id, FLOW_UI_URL.format(flow_id)
    )
    readable_output = tableToMarkdown(hr_title, hr_content, headers=hr_headers, removeNull=True)

    if next_cursor:
        readable_output += f"\n{MESSAGES['NEXT_CURSOR'].format(next_cursor)}\n"

    # The secrets are removed above, before the related objects reach the context.
    outputs = build_flow_relationship_outputs(
        OUTPUT_PREFIX["FLOW_RELATIONSHIP"],
        OUTPUT_PREFIX["FLOW_RELATIONSHIP_PAGE_TOKEN"],
        flow_id,
        related_objects,
        page_token,
    )

    return CommandResults(
        outputs=outputs,
        raw_response=raw_response,
        readable_output=readable_output,
    )


def gti_agentic_flow_object_descriptor_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve the descriptors, which carry the type and the ID only, of the objects that are related to a GTI
    Agentic Flow through the given relationship.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    flow_id, relationship, query_params = build_flow_relationship_request(args)

    raw_response = client.list_flow_related_descriptors(flow_id, relationship, query_params)

    descriptors = get_flow_related_objects(raw_response)
    page_token = build_page_token(raw_response)

    if not descriptors:
        # The page token is still written, so that the next cursor of an earlier run is cleared.
        return CommandResults(
            outputs={f"{OUTPUT_PREFIX['FLOW_RELATIONSHIP_DESCRIPTOR_PAGE_TOKEN']}(true)": page_token},
            raw_response=raw_response,
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("related object descriptors"),
        )

    next_cursor = page_token.get("next_cursor", "")
    related_type = descriptors[0].get("type", "")

    hr_title = FLOW_RELATED_OBJECT_HR_TITLE.format(
        FLOW_RELATED_DESCRIPTOR_TYPE_HR_NAME.get(related_type, "Related Object Descriptors"),
        flow_id,
        FLOW_UI_URL.format(flow_id),
    )
    readable_output = tableToMarkdown(
        hr_title, build_flow_related_descriptor_hr(descriptors), headers=FLOW_RELATED_DESCRIPTOR_HR_HEADERS, removeNull=True
    )

    if next_cursor:
        readable_output += f"\n{MESSAGES['NEXT_CURSOR'].format(next_cursor)}\n"

    outputs = build_flow_relationship_outputs(
        OUTPUT_PREFIX["FLOW_RELATIONSHIP_DESCRIPTOR"],
        OUTPUT_PREFIX["FLOW_RELATIONSHIP_DESCRIPTOR_PAGE_TOKEN"],
        flow_id,
        descriptors,
        page_token,
    )

    return CommandResults(
        outputs=outputs,
        raw_response=raw_response,
        readable_output=readable_output,
    )


def gti_agentic_flow_execution_list_command(client: Client, args: dict) -> CommandResults:
    """
    List the GTI Agentic Flow Executions that are owned by the configured API key.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    limit = arg_to_number(args.get("limit") or DEFAULT_LIMIT, arg_name="limit")
    flow_id = args.get("flow_id") or ""
    status = args.get("status") or ""
    filter_expression = args.get("filter") or ""
    sort_field = args.get("sort_field") or DEFAULT_FLOW_EXECUTION_SORT_FIELD
    sort_order = args.get("sort_order") or DEFAULT_SORT_ORDER
    cursor = args.get("cursor") or ""

    validate_flow_execution_list_args(limit=limit, status=status, sort_field=sort_field, sort_order=sort_order)

    query_params: dict[str, Any] = {
        "limit": limit,
        "order": f"{FLOW_EXECUTION_SORT_FIELD_API_MAP[sort_field.lower()]}{SORT_ORDER_API_MAP[sort_order.lower()]}",
    }

    flow_execution_filter = build_flow_execution_filter(flow_id, status, filter_expression)
    if flow_execution_filter:
        query_params["filter"] = flow_execution_filter

    if cursor:
        query_params["cursor"] = cursor

    raw_response = client.list_flow_executions(query_params)

    flow_executions = raw_response.get("data") or []
    page_token = build_page_token(raw_response)

    if not flow_executions:
        # The page token is still written, so that the next cursor of an earlier run is cleared.
        return CommandResults(
            outputs={f"{OUTPUT_PREFIX['FLOW_EXECUTION_PAGE_TOKEN']}(true)": page_token},
            raw_response=raw_response,
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("GTI Agentic Flow Executions"),
        )

    context, readable_output = build_flow_execution_list_output(
        flow_executions, dict_safe_get(raw_response, ["meta", "cursor"], "")
    )

    # Two prefixes are written in a single result, and the page token is replaced on every run, hence the raw dict.
    outputs: dict[str, Any] = {
        f"{OUTPUT_PREFIX['FLOW_EXECUTION']}(val.id && val.id == obj.id)": context,
        f"{OUTPUT_PREFIX['FLOW_EXECUTION_PAGE_TOKEN']}(true)": page_token,
    }

    return CommandResults(
        outputs=outputs,
        raw_response=raw_response,
        readable_output=readable_output,
    )


def gti_agentic_flow_execution_get_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve the details of a specific GTI Agentic Flow Execution by its ID, along with the output of its steps.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    execution_id = get_required_arg(args, "execution_id")

    raw_response = client.get_flow_execution(execution_id)

    flow_execution = raw_response.get("data") or {}
    if not flow_execution:
        return CommandResults(readable_output=MESSAGES["NO_RECORD_FOUND"].format("GTI Agentic Flow Execution"))

    context = build_flow_execution_output(flow_execution)
    steps = context.get("steps") or []
    readable_output = build_flow_execution_readable_output(
        context,
        "GTI Agentic Flow Execution Information",
        "Flow Execution Steps",
        build_flow_execution_step_detail_hr(steps),
        FLOW_EXECUTION_STEP_DETAIL_HR_HEADERS,
    )

    agent_response_hr = build_flow_execution_agent_response_hr(steps)
    if agent_response_hr:
        readable_output += f"\n{agent_response_hr}"

    return CommandResults(
        outputs=context,
        outputs_prefix=OUTPUT_PREFIX["FLOW_EXECUTION"],
        outputs_key_field="id",
        raw_response=raw_response,
        readable_output=readable_output,
    )


def gti_agentic_flow_execution_object_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve the full object that is related to a GTI Agentic Flow Execution through the given relationship.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    execution_id = get_required_arg(args, "execution_id")
    relationship_arg = get_required_arg(args, "relationship")

    relationship = validate_flow_execution_relationship_args(relationship=relationship_arg)

    raw_response = client.get_flow_execution_related_object(execution_id, relationship)

    related_objects = get_flow_related_objects(raw_response)
    # The owner reports the API key of the user and the group reports its tokens, hence they are removed.
    remove_related_object_secrets(related_objects)
    if not related_objects:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("related objects"))

    hr_content, hr_headers = build_flow_execution_related_object_hr(related_objects)
    # The title names the requested relationship, as the Flow and its snapshot can share the same object type.
    hr_title = FLOW_EXECUTION_RELATED_OBJECT_HR_TITLE.format(
        relationship_arg.title(), execution_id, FLOW_EXECUTION_UI_URL.format(execution_id)
    )

    # The related objects are stored as they are received, without their secrets.
    outputs = {
        f"{OUTPUT_PREFIX['FLOW_EXECUTION_RELATIONSHIP']}{FLOW_EXECUTION_RELATIONSHIP_CONTEXT_KEY}": {
            "execution_id": execution_id,
            "relationship": relationship,
            "type": related_objects[0].get("type", ""),
            "data": related_objects,
        }
    }

    return CommandResults(
        outputs=outputs,
        raw_response=raw_response,
        readable_output=tableToMarkdown(hr_title, hr_content, headers=hr_headers, removeNull=True),
    )


def gti_agentic_flow_execution_object_descriptor_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve the descriptors, which carry the type and the ID only, of the objects that are related to a GTI
    Agentic Flow Execution through the given relationship.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    execution_id = get_required_arg(args, "execution_id")
    relationship_arg = get_required_arg(args, "relationship")

    relationship = validate_flow_execution_relationship_args(relationship=relationship_arg)

    # Every relationship of a Flow Execution reports a single object, hence no pagination is offered.
    raw_response = client.list_flow_execution_related_descriptors(execution_id, relationship)

    descriptors = get_flow_related_objects(raw_response)
    if not descriptors:
        return CommandResults(
            raw_response=raw_response,
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("related object descriptors"),
        )

    hr_title = FLOW_EXECUTION_RELATED_DESCRIPTOR_HR_TITLE.format(
        relationship_arg.title(), execution_id, FLOW_EXECUTION_UI_URL.format(execution_id)
    )

    outputs = {
        f"{OUTPUT_PREFIX['FLOW_EXECUTION_RELATIONSHIP_DESCRIPTOR']}{FLOW_EXECUTION_RELATIONSHIP_CONTEXT_KEY}": {
            "execution_id": execution_id,
            "relationship": relationship,
            "type": descriptors[0].get("type", ""),
            "data": descriptors,
        }
    }

    return CommandResults(
        outputs=outputs,
        raw_response=raw_response,
        readable_output=tableToMarkdown(
            hr_title,
            build_flow_execution_related_descriptor_hr(descriptors),
            headers=FLOW_EXECUTION_RELATED_DESCRIPTOR_HR_HEADERS,
            removeNull=True,
        ),
    )


def gti_agentic_flow_execution_cancel_command(client: Client, args: dict) -> CommandResults:
    """
    Cancel a specific GTI Agentic Flow Execution that is in progress.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    execution_id = get_required_arg(args, "execution_id")

    try:
        raw_response = client.cancel_flow_execution(execution_id)
    except DemistoException as e:
        # The API responds with a conflict when the Flow Execution already reached a terminal status. The reason of the
        # API is kept, so that a conflict for any other reason is not hidden behind the message.
        if e.res is not None and e.res.status_code == 409:
            message = ERROR_MESSAGES["EXECUTION_NOT_IN_PROGRESS"].format(409, execution_id)
            raise DemistoException(f"{message} Reason: {get_error_reason(e.res)}", res=e.res)
        raise

    flow_execution = raw_response.get("data") or {}
    if not flow_execution:
        # The cancellation is requested, although the API did not report the Flow Execution.
        return CommandResults(
            raw_response=raw_response, readable_output=MESSAGES["FLOW_EXECUTION_CANCEL_REQUESTED"].format(execution_id)
        )

    context = build_flow_execution_output(flow_execution)

    # The success title is reported only for the cancelled status, as the API can report the status of a Flow
    # Execution that is still stopping.
    hr_title = (
        MESSAGES["FLOW_EXECUTION_CANCELLED"]
        if context.get("status") == FLOW_EXECUTION_STATUS_CANCELLED
        else FLOW_EXECUTION_HR_TITLE
    )
    # The steps show which of them ran and which of them the cancellation skipped.
    steps = context.get("steps") or []
    readable_output = build_flow_execution_readable_output(
        context,
        hr_title,
        "Flow Execution Steps",
        build_flow_execution_step_detail_hr(steps),
        FLOW_EXECUTION_CANCEL_STEP_HR_HEADERS,
    )

    # The prompt steps point to their agent response, which is rendered in its own section below the steps table.
    agent_response_hr = build_flow_execution_agent_response_hr(steps)
    if agent_response_hr:
        readable_output += f"\n{agent_response_hr}"

    return CommandResults(
        outputs=context,
        outputs_prefix=OUTPUT_PREFIX["FLOW_EXECUTION"],
        outputs_key_field="id",
        raw_response=raw_response,
        readable_output=readable_output,
    )


def gti_agentic_session_list_command(client: Client, args: dict) -> CommandResults:
    """
    List the GTI Agentic Sessions of the user that owns the configured API key.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    limit = arg_to_number(args.get("limit") or DEFAULT_SESSION_LIMIT, arg_name="limit")
    cursor = args.get("cursor") or ""

    if limit is not None and not 1 <= limit <= MAX_SESSION_LIMIT:
        raise ValueError(ERROR_MESSAGES["INVALID_LIMIT"].format(limit, MAX_SESSION_LIMIT))

    query_params: dict[str, Any] = {"limit": limit}
    if cursor:
        query_params["cursor"] = cursor

    raw_response = client.list_sessions(query_params)

    sessions = raw_response.get("data") or []
    page_token = build_page_token(raw_response)

    if not sessions:
        # The page token is still written, so that the next cursor of an earlier run is cleared.
        return CommandResults(
            outputs={f"{OUTPUT_PREFIX['SESSION_PAGE_TOKEN']}(true)": page_token},
            raw_response=raw_response,
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("GTI Agentic Sessions"),
        )

    context, readable_output = build_session_list_output(sessions, page_token.get("next_cursor", ""))

    # Two prefixes are written in a single result, and the page token is replaced on every run, hence the raw dict.
    outputs: dict[str, Any] = {
        f"{OUTPUT_PREFIX['SESSION']}(val.id && val.id == obj.id)": context,
        f"{OUTPUT_PREFIX['SESSION_PAGE_TOKEN']}(true)": page_token,
    }

    return CommandResults(
        outputs=outputs,
        raw_response=raw_response,
        readable_output=readable_output,
    )


def gti_agentic_flow_execute_command(client: Client, args: dict) -> CommandResults:
    """
    Trigger an immediate run of a specific GTI Agentic Flow, bypassing its schedule.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    flow_id = get_required_arg(args, "flow_id")

    raw_response = client.execute_flow(flow_id)

    flow_execution = raw_response.get("data") or {}
    if not flow_execution:
        # The run is triggered, although the API did not report the Flow Execution.
        return CommandResults(raw_response=raw_response, readable_output=MESSAGES["FLOW_EXECUTION_STARTED"])

    context = build_flow_execution_output(flow_execution)
    # The title is neutral, as the returned Flow Execution can already be failed or cancelled. The steps are reported so
    # that a failed step is visible without opening the context.
    readable_output = build_flow_execution_readable_output(
        context,
        FLOW_EXECUTION_HR_TITLE,
        "Steps",
        build_flow_execution_step_hr(context.get("steps") or []),
        FLOW_EXECUTION_STEP_HR_HEADERS,
    )

    return CommandResults(
        outputs=context,
        outputs_prefix=OUTPUT_PREFIX["FLOW_EXECUTION"],
        outputs_key_field="id",
        raw_response=raw_response,
        readable_output=readable_output,
    )


def gti_agentic_session_create_command(client: Client, args: dict) -> CommandResults:
    """
    Create a new GTI Agentic Session by sending the first message to the Google Threat Intelligence agent, and report
    the answer of the agent, which the API returns synchronously.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    message = get_required_arg(args, "message")
    # The entries are resolved before the request, so that a missing file fails the command without creating a session.
    attachments = get_session_attachments(argToList(args.get("entry_id")))

    raw_response = client.create_session(message, attachments)

    return build_session_result(raw_response, MESSAGES["SESSION_CREATED"])


def gti_agentic_session_get_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve a specific GTI Agentic Session, along with its complete conversation, by its ID.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    session_id = get_required_arg(args, "session_id")

    raw_response = client.get_session(session_id)

    session = raw_response.get("data") or {}
    if not session:
        return CommandResults(
            raw_response=raw_response,
            readable_output=MESSAGES["NO_RECORD_FOUND"].format("GTI Agentic Session"),
        )

    context = build_session_output(session)

    return CommandResults(
        outputs=context,
        outputs_prefix=OUTPUT_PREFIX["SESSION"],
        outputs_key_field="id",
        raw_response=raw_response,
        readable_output=build_session_readable_output(context, SESSION_DETAIL_HR_TITLE),
    )


def gti_agentic_session_message_post_command(client: Client, args: dict) -> CommandResults:
    """
    Continue the conversation with the Google Threat Intelligence agent in an existing GTI Agentic Session, and report
    the updated session, which the API returns synchronously along with the latest answer of the agent.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    session_id = get_required_arg(args, "session_id")
    message = get_required_arg(args, "message")
    # The entries are resolved before the request, so that a missing file fails the command without posting the message.
    attachments = get_session_attachments(argToList(args.get("entry_id")))

    raw_response = client.post_session_message(session_id, message, attachments)

    return build_session_result(raw_response, MESSAGES["SESSION_MESSAGE_POSTED"])


def gti_agentic_session_update_command(client: Client, args: dict) -> CommandResults:
    """
    Update the properties of a specific GTI Agentic Session, such as whether it is marked as seen.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    session_id = get_required_arg(args, "session_id")
    seen = validate_boolean_arg(get_required_arg(args, "seen"), "seen")

    raw_response = client.update_session(session_id, {"data": {"seen": seen}})

    # The response does not echo the seen flag, hence the applied value is reported in the title.
    title = MESSAGES["SESSION_UPDATED"].format("seen" if seen else "unseen")

    # The conversation of the session is not changed by the update, hence only the session details are reported.
    return build_session_result(raw_response, title, build_session_detail_table)


def gti_agentic_session_delete_command(client: Client, args: dict) -> CommandResults:
    """
    Permanently delete a specific GTI Agentic Session by its ID.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    session_id = get_required_arg(args, "session_id")

    raw_response = client.delete_session(session_id)

    # The API returns no content on success, hence no context output is published.
    return CommandResults(
        raw_response=raw_response,
        readable_output=MESSAGES["SESSION_DELETED"].format(session_id),
    )


def gti_agentic_session_token_get_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve a share token of a specific GTI Agentic Session, which allows another user to import the session.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    session_id = get_required_arg(args, "session_id")

    raw_response = client.get_session_token(session_id)

    token = raw_response.get("token")
    if not token:
        return CommandResults(
            raw_response=raw_response,
            readable_output=MESSAGES["NO_RECORD_FOUND"].format("GTI Agentic Session share token"),
        )

    # The API reports the token only, hence the session ID is added to relate the token to its session.
    context = {"id": session_id, "token": token}
    hr_content = {**build_session_hr(context), "Token": token}

    return CommandResults(
        outputs=context,
        outputs_prefix=OUTPUT_PREFIX["SESSION_TOKEN"],
        outputs_key_field="id",
        raw_response=raw_response,
        readable_output=tableToMarkdown(SESSION_TOKEN_HR_TITLE, hr_content, headers=SESSION_TOKEN_HR_HEADERS, removeNull=True),
    )


def gti_agentic_session_from_token_create_command(client: Client, args: dict) -> CommandResults:
    """
    Create a new GTI Agentic Session by copying the content of the source session that is identified in a share token,
    and report the new session along with its copied conversation.

    Args:
        client (Client): Client object to use.
        args (dict): The arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResults object.
    """
    token = get_required_arg(args, "token")

    raw_response = client.create_session_from_token(token)

    return build_session_result(raw_response, MESSAGES["SESSION_CREATED_FROM_TOKEN"])


""" MAIN FUNCTION """


def main():
    params = demisto.params()
    params = trim_spaces_from_args(params)
    remove_nulls_from_dictionary(params)

    # get connectivity parameters
    api_key = str(dict_safe_get(params, ["credentials", "password"]) or "").strip()
    group_id = str(params.get("group_id") or "").strip()
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    commands: dict[str, Callable] = {
        f"{COMMAND_PREFIX}-flow-list": gti_agentic_flow_list_command,
        f"{COMMAND_PREFIX}-flow-get": gti_agentic_flow_get_command,
        f"{COMMAND_PREFIX}-flow-delete": gti_agentic_flow_delete_command,
        f"{COMMAND_PREFIX}-flow-create": gti_agentic_flow_create_command,
        f"{COMMAND_PREFIX}-flow-update": gti_agentic_flow_update_command,
        f"{COMMAND_PREFIX}-flow-execute": gti_agentic_flow_execute_command,
        f"{COMMAND_PREFIX}-flow-object-list": gti_agentic_flow_object_list_command,
        f"{COMMAND_PREFIX}-flow-object-descriptor-list": gti_agentic_flow_object_descriptor_list_command,
        f"{COMMAND_PREFIX}-flow-execution-list": gti_agentic_flow_execution_list_command,
        f"{COMMAND_PREFIX}-flow-execution-get": gti_agentic_flow_execution_get_command,
        f"{COMMAND_PREFIX}-flow-execution-object-list": gti_agentic_flow_execution_object_list_command,
        f"{COMMAND_PREFIX}-flow-execution-object-descriptor-list": gti_agentic_flow_execution_object_descriptor_list_command,
        f"{COMMAND_PREFIX}-flow-execution-cancel": gti_agentic_flow_execution_cancel_command,
        f"{COMMAND_PREFIX}-session-list": gti_agentic_session_list_command,
        f"{COMMAND_PREFIX}-session-create": gti_agentic_session_create_command,
        f"{COMMAND_PREFIX}-session-get": gti_agentic_session_get_command,
        f"{COMMAND_PREFIX}-session-message-post": gti_agentic_session_message_post_command,
        f"{COMMAND_PREFIX}-session-update": gti_agentic_session_update_command,
        f"{COMMAND_PREFIX}-session-delete": gti_agentic_session_delete_command,
        f"{COMMAND_PREFIX}-session-token-get": gti_agentic_session_token_get_command,
        f"{COMMAND_PREFIX}-session-from-token-create": gti_agentic_session_from_token_create_command,
    }

    try:
        result = None
        # Creates client
        client = Client(verify_certificate, proxy, api_key, group_id)
        # Get Command args
        args = demisto.args()
        if command == "test-module":
            result = test_module(client)
        elif command in commands:
            # remove nulls from dictionary and trim space from args
            args = trim_spaces_from_args(args)
            remove_nulls_from_dictionary(args)
            result = commands[command](client, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

        return_results(result)  # Returns either str, CommandResults and a list of CommandResults

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()

import json

import demistomock as demisto  # noqa: F401
import parse_emails
import urllib3
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, UTC
from typing import Any
from collections.abc import Callable

# Disable insecure warnings
urllib3.disable_warnings()


# region Constants - Chat / Email
# =================================
# Existing GPT chat / email constants
# =================================
INTEGRATION_NAME = "OpenAI GPT"


class Config:
    """Global static configuration shared across all integration features."""

    DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    # XSIAM dataset routing: each stream lands in `<vendor>_<product>_raw`.
    VENDOR = "openai"
    PRODUCT_AUDIT = "chatgpt_audit"
    PRODUCT_COMPLIANCE = "chatgpt_compliance"
    AUDIT_DATASET = "openai_chatgpt_audit_raw"
    COMPLIANCE_DATASET = "openai_chatgpt_compliance_raw"

    DEFAULT_COMPLIANCE_URL = "https://api.chatgpt.com"

    DEFAULT_AUDIT_MAX_FETCH = 1000
    DEFAULT_COMPLIANCE_MAX_FETCH = 900
    DEFAULT_GET_EVENTS_LIMIT = 50
    AUDIT_PAGE_SIZE = 100  # Hard ceiling enforced by the Audit Logs API.
    MAX_PAGES_PER_FETCH = 50  # Safety cap on pagination loops.

    DEFAULT_FIRST_FETCH = "1 minute ago"


class Stream:
    """Stream identifiers used by the parallel fetch dispatcher and dataset routing."""

    AUDIT = "audit"
    COMPLIANCE = "compliance"


EML_FILE_PREFIX = ".eml"


class ApiPaths:
    """Centralized OpenAI API endpoint paths.

    The chat-completions endpoint is hosted on the OpenAI Platform (`api.openai.com`),
    while the audit/compliance endpoints live on the ChatGPT Platform (`api.chatgpt.com`).
    Use the classmethods for parameterized routes (e.g., a workspace-scoped log).
    """

    CHAT_COMPLETIONS = "v1/chat/completions"
    AUDIT_LOGS = "v1/organization/audit_logs"

    @classmethod
    def compliance_logs(cls, workspace_id: str) -> str:
        """Return the path for the compliance logs list endpoint of a given workspace."""
        return f"v1/compliance/workspaces/{workspace_id}/logs"

    @classmethod
    def compliance_log_content(cls, workspace_id: str, log_id: str) -> str:
        """Return the path for the compliance log content endpoint of a given log id."""
        return f"v1/compliance/workspaces/{workspace_id}/logs/{log_id}"

    @classmethod
    def compliance_users(cls, workspace_id: str) -> str:
        """Return the path for the compliance users endpoint of a given workspace."""
        return f"v1/compliance/workspaces/{workspace_id}/users"


class EventType:
    """User-facing event-type labels used by the multi-select fetch parameter."""

    AUDIT = "OpenAI Audit logs"
    CONVERSATION_MESSAGE = "Conversation Messages"
    APP_LOG = "Apps"
    APP_AUTH_LOG = "Apps Auth"
    AUDIT_LOG = "Compliance Audit"
    AUTH_LOG = "Auth"
    CODEX_LOG = "Codex"
    CHATGPT_PLUGIN_SPREADSHEET = "ChatGPT"
    CODEX_SECURITY_LOG = "Codex Security"
    CUSTOM_AGENTS_LOG = "Workspace Agents"


class ComplianceEvent:
    """Upstream `event_type` query values used by `/v1/compliance/.../logs`.

    These are the canonical strings sent on the wire and stored as `_event_type` on
    the resulting events; they map to the user-facing `EventType` labels above.
    """

    CONVERSATION_MESSAGE = "CONVERSATION_MESSAGE"
    APP_LOG = "APP_LOG"
    APP_AUTH_LOG = "APP_AUTH_LOG"
    AUDIT_LOG = "AUDIT_LOG"
    AUTH_LOG = "AUTH_LOG"
    CODEX_LOG = "CODEX_LOG"
    CHATGPT_PLUGIN_SPREADSHEET = "CHATGPT_PLUGIN_SPREADSHEET"
    CODEX_SECURITY_LOG = "CODEX_SECURITY_LOG"
    CUSTOM_AGENTS_LOG = "CUSTOM_AGENTS_LOG"


class SourceLogType:
    """`source_log_type` values written to events for downstream parsing/modeling rules."""

    AUDIT = "openai_audit_logs"
    USERS = "users"
    CONVERSATION_MESSAGE = "conversation_message"
    COMPLIANCE_AUDIT_LOG = "compliance_audit_log"
    AUTH_LOG = "auth_log"
    APP_AUTH_LOG = "app_auth_log"
    APP_LOG = "app_log"
    CODEX_LOG = "codex_log"
    CHATGPT_PLUGIN_SPREADSHEET = "chatgpt_plugin_spreadsheet"
    CODEX_SECURITY_LOG = "codex_security_log"
    CUSTOM_AGENT_LOG = "custom_agent_log"


# Mapping: user-facing label -> upstream event_type query value (for /v1/compliance/.../logs).
EVENT_TYPE_LABEL_TO_API: dict[str, str] = {
    EventType.CONVERSATION_MESSAGE: ComplianceEvent.CONVERSATION_MESSAGE,
    EventType.APP_LOG: ComplianceEvent.APP_LOG,
    EventType.APP_AUTH_LOG: ComplianceEvent.APP_AUTH_LOG,
    EventType.AUDIT_LOG: ComplianceEvent.AUDIT_LOG,
    EventType.AUTH_LOG: ComplianceEvent.AUTH_LOG,
    EventType.CODEX_LOG: ComplianceEvent.CODEX_LOG,
    EventType.CHATGPT_PLUGIN_SPREADSHEET: ComplianceEvent.CHATGPT_PLUGIN_SPREADSHEET,
    EventType.CODEX_SECURITY_LOG: ComplianceEvent.CODEX_SECURITY_LOG,
    EventType.CUSTOM_AGENTS_LOG: ComplianceEvent.CUSTOM_AGENTS_LOG,
}

# Mapping: upstream event_type value -> source_log_type used downstream by parsing/modeling rules.
COMPLIANCE_EVENT_TYPE_TO_SOURCE_LOG_TYPE: dict[str, str] = {
    ComplianceEvent.CONVERSATION_MESSAGE: SourceLogType.CONVERSATION_MESSAGE,
    ComplianceEvent.AUDIT_LOG: SourceLogType.COMPLIANCE_AUDIT_LOG,
    ComplianceEvent.AUTH_LOG: SourceLogType.AUTH_LOG,
    ComplianceEvent.APP_AUTH_LOG: SourceLogType.APP_AUTH_LOG,
    ComplianceEvent.APP_LOG: SourceLogType.APP_LOG,
    ComplianceEvent.CODEX_LOG: SourceLogType.CODEX_LOG,
    ComplianceEvent.CHATGPT_PLUGIN_SPREADSHEET: SourceLogType.CHATGPT_PLUGIN_SPREADSHEET,
    ComplianceEvent.CODEX_SECURITY_LOG: SourceLogType.CODEX_SECURITY_LOG,
    ComplianceEvent.CUSTOM_AGENTS_LOG: SourceLogType.CUSTOM_AGENT_LOG,
}


class LastRunKey:
    """Keys used to persist per-stream pagination state across fetch cycles.

    The Audit and Compliance streams use *separate* keys so each stream's pagination state
    is independent (one stream failing or being disabled never affects the other).
    """

    # --- Audit stream (cursor-based pagination via the `after` query param) ---
    AUDIT_AFTER = "audit_after"  # opaque cursor (last_id from API), passed verbatim as `after=` next run.

    # --- Compliance stream (time-based pagination via the `after` query param + per-id dedup) ---
    COMPLIANCE_LAST_END_TIME = "compliance_last_end_time"  # ISO timestamp echoed by the listing response.
    COMPLIANCE_LAST_IDS = "compliance_last_ids"  # listing IDs seen at last_end_time, deduped on next run.


CHECK_EMAIL_HEADERS_PROMPT = """
I have a set of email headers.
Analyze these headers for any potential security issues such as spoofing, phishing attempts, or other malicious activity.
Please identify any suspicious fields, explain why they might be concerning, and suggest any further actions that could be taken \
to investigate or mitigate these issues.
Additional instructions: {}

'''
{}
'''

Please, review each header, highlighting any red flags and explaining the potential risks associated with them.
Make you answer very concise and easily readable, with references to the email headers if there are, otherwise do not refer to \
hypothetical problems.
"""

CHECK_EMAIL_BODY_PROMPT = """
I have this email body that I suspect may contain security risks such as phishing links, suspicious attachments,
or signs of social engineering. Please analyze the content of this email body, identify any elements that may pose security
threats, and explain why these elements are concerning. Also, suggest any steps that could be taken to further verify these risks
or protect against these threats.
{}
'''
{}
'''

Highlight potential security risks, and explain the implications of such risks.
Make you answer very concise and easily readable, with references to the email body if there are, otherwise do not refer to \
hypothetical problems.
"""

CREATE_SOC_EMAIL_TEMPLATE_PROMPT = """
Based on the details provided in our conversation and any specific instructions you have been given,
create a professional email template suitable for a Security Operations Center (SOC).
The template should be adaptable, clearly structured, and include placeholders for specific incident details,
recommendations for action, and any necessary escalation points.
Please ensure the tone is appropriate for communication within a cybersecurity context.
{}
"""


class ArgAndParamNames:
    MODEL = "model"
    MESSAGE = "message"
    RESET_CONVERSATION_HISTORY = "reset_conversation_history"
    ENTRY_ID = "entry_id"
    ADDITIONAL_INSTRUCTIONS = "additional_instructions"
    MAX_TOKENS = "max_tokens"
    TEMPERATURE = "temperature"
    TOP_P = "top_p"


class Roles:
    ASSISTANT = "assistant"
    USER = "user"


class EmailParts:
    HEADERS = "headers"
    BODY = "body"


""" CLIENT CLASS """


class OpenAiClient(BaseClient):
    """OpenAI HTTP client.

    Wraps three logically distinct API surfaces under a single client:
        - Chat Completions (`api.openai.com/v1/chat/completions`) - existing GPT functionality.
        - Audit Logs (`api.openai.com/v1/organization/audit_logs`) - admin API key required.
        - Compliance Logs/Users (`api.chatgpt.com/v1/compliance/...`) - compliance API key required.
    Each surface uses its own bearer token; `BaseClient.base_url` defaults to the chat URL,
    while audit/compliance calls pass an absolute URL via `full_url=`.
    """

    CHAT_COMPLETIONS_ENDPOINT = "v1/chat/completions"

    def __init__(
        self,
        url: str,
        api_key: str,
        model: str,
        proxy: bool,
        verify: bool,
        admin_api_key: str = "",
        compliance_api_key: str = "",
        compliance_base_url: str = Config.DEFAULT_COMPLIANCE_URL,
    ):
        super().__init__(base_url=url, proxy=proxy, verify=verify)

        self.api_key = api_key
        self.model = model
        self.admin_api_key = admin_api_key
        self.compliance_api_key = compliance_api_key
        self.compliance_base_url = compliance_base_url.rstrip("/") + "/"
        self.headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def get_chat_completions(
        self, chat_context: List[dict[str, str]], completion_params: dict[str, str | None]
    ) -> dict[str, Any]:
        """Gets the response to a chat_completions request using the OpenAI API."""

        options: Dict[str, Any] = {ArgAndParamNames.MODEL: self.model}
        max_tokens = completion_params.get(ArgAndParamNames.MAX_TOKENS, None)
        if max_tokens:
            options[ArgAndParamNames.MAX_TOKENS] = int(max_tokens)

        temperature = completion_params.get(ArgAndParamNames.TEMPERATURE, None)
        if temperature:
            options[ArgAndParamNames.TEMPERATURE] = float(temperature)

        top_p = completion_params.get(ArgAndParamNames.TOP_P, None)
        if top_p:
            options[ArgAndParamNames.TOP_P] = float(top_p)

        options["messages"] = chat_context
        demisto.debug(f"openai-gpt Using options for chat completion: {options=}")
        return self._http_request(
            method="POST", url_suffix=OpenAiClient.CHAT_COMPLETIONS_ENDPOINT, json_data=options, headers=self.headers
        )

    # region Event Collector - Audit Logs (Admin API)
    def get_audit_logs(
        self,
        after: str | None = None,
        limit: int = Config.AUDIT_PAGE_SIZE,
        effective_at_gt: int | None = None,
    ) -> dict[str, Any]:
        """Fetch a single page of audit logs (cursor-based pagination).

        The Admin API exposes a native cursor: every response contains `last_id`, which the
        caller passes back as `after=` to fetch the next page (and to dedupe across runs).

        Args:
            after: Opaque cursor (the `last_id` from the previous response). When omitted on
                the very first run, the API returns the oldest available logs.
            limit: Number of results per page (capped at `Config.AUDIT_PAGE_SIZE`).
            effective_at_gt: Optional initial-seed lower bound (Unix seconds) - used only on
                the first run to constrain how far back the cursor walk starts.

        Returns:
            The full JSON response dict, typically containing `data` (list), `has_more` (bool), `last_id` (str).
        """
        if not self.admin_api_key:
            raise DemistoException("Admin API Key is required to fetch OpenAI Audit logs.")

        params: dict[str, Any] = {"limit": min(limit, Config.AUDIT_PAGE_SIZE), "order": "asc"}
        if after:
            params["after"] = after
        elif effective_at_gt is not None:
            # No cursor yet (first ever run) - constrain the starting point by time.
            params["effective_at[gt]"] = effective_at_gt

        headers = {"Authorization": f"Bearer {self.admin_api_key}", "Accept": "application/json"}
        demisto.debug(
            f"[API Audit] Fetching audit logs page | limit={params['limit']} | "
            f"after_cursor_set={bool(after)} | effective_at_gt_set={effective_at_gt is not None}"
        )

        response = self._http_request(
            method="GET",
            url_suffix=ApiPaths.AUDIT_LOGS,
            params=params,
            headers=headers,
        )
        page_size_returned = len(response.get("data") or [])
        demisto.debug(
            f"[API Audit] Page received | events_count={page_size_returned} | "
            f"has_more={response.get('has_more')} | last_id_set={bool(response.get('last_id'))}"
        )
        return response

    # endregion

    # region Event Collector - Compliance Logs (ChatGPT Platform)
    def list_compliance_logs(
        self,
        workspace_id: str,
        event_types: list[str],
        after: str,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """List available compliance log entries (step 1 of the two-step compliance flow).

        Args:
            workspace_id: The compliance workspace identifier.
            event_types: Upstream `event_type` values to include (e.g., ['APP_LOG', 'AUDIT_LOG']).
            after: ISO 8601 timestamp; only entries newer than this are returned.
            limit: Optional limit on the number of entries to request.

        Returns:
            A normalized response dict with two keys:
              - `data`: list of log-entry descriptors (each contains at least `id`, `event_type`, `end_time`).
              - `last_end_time`: ISO 8601 timestamp echoed by the API marking the upper bound of this page;
                used as the `after=` value on the next run (and for per-id dedup at that timestamp).
        """
        if not self.compliance_api_key:
            raise DemistoException("Compliance API Key is required to fetch OpenAI Compliance logs.")
        if not workspace_id:
            raise DemistoException("Workspace ID is required to fetch OpenAI Compliance logs.")

        # Build query params; `event_type` repeats per value.
        params: list[tuple[str, Any]] = [("after", after)]
        for et in event_types:
            params.append(("event_type", et))
        if limit is not None:
            params.append(("limit", limit))

        full_url = self.compliance_base_url + ApiPaths.compliance_logs(workspace_id)
        headers = {"Authorization": self.compliance_api_key, "Accept": "application/json"}
        demisto.debug(
            f"[API Compliance List] Listing logs | event_types_count={len(event_types)} | "
            f"after_set={bool(after)} | limit={limit}"
        )

        response = self._http_request(method="GET", full_url=full_url, params=params, headers=headers)
        # Normalize the response shape - the API may return either a bare list or a dict with `data`/`last_end_time`.
        if isinstance(response, list):
            normalized: dict[str, Any] = {"data": response, "last_end_time": None}
        elif isinstance(response, dict):
            normalized = {
                "data": response.get("data", []) or [],
                "last_end_time": response.get("last_end_time"),
                "has_more": response.get("has_more"),
            }
        else:
            normalized = {"data": [], "last_end_time": None}
        demisto.debug(
            f"[API Compliance List] Listing returned {len(normalized['data'])} entry(ies) | "
            f"last_end_time_set={bool(normalized.get('last_end_time'))}"
        )
        return normalized

    def get_compliance_log_content(self, workspace_id: str, log_id: str) -> list[dict[str, Any]]:
        """Fetch the content for a specific compliance log entry (step 2 of the two-step flow).

        IMPORTANT (per design doc): the response body is **NOT valid JSON** - it is a stream
        of concatenated JSON objects (and/or a JSONL file). This method retrieves the raw
        body and parses it into a list of dicts using `parse_concatenated_json`.

        Args:
            workspace_id: The compliance workspace identifier.
            log_id: The unique identifier (a.k.a. `log_file_id`) of the log entry to fetch.

        Returns:
            A list of record dicts parsed from the concatenated-JSON / JSONL response body.
        """
        if not self.compliance_api_key:
            raise DemistoException("Compliance API Key is required to fetch OpenAI Compliance log content.")

        full_url = self.compliance_base_url + ApiPaths.compliance_log_content(workspace_id, log_id)
        headers = {"Authorization": self.compliance_api_key, "Accept": "application/json"}
        demisto.debug("[API Compliance Content] Fetching content for one log entry.")

        # The response body is a stream of concatenated JSON objects (or a JSONL file) - fetch raw text.
        raw_body = self._http_request(method="GET", full_url=full_url, headers=headers, resp_type="text")
        records = parse_concatenated_json(raw_body)
        demisto.debug(f"[API Compliance Content] Parsed {len(records)} record(s) from response body.")
        return records

    def list_compliance_users(self, workspace_id: str, limit: int = 200) -> list[dict[str, Any]]:
        """List users in a compliance workspace.

        Args:
            workspace_id: The compliance workspace identifier.
            limit: Maximum number of users to return per request.

        Returns:
            A list of user records.
        """
        if not self.compliance_api_key:
            raise DemistoException("Compliance API Key is required to list OpenAI Compliance users.")
        if not workspace_id:
            raise DemistoException("Workspace ID is required to list OpenAI Compliance users.")

        full_url = self.compliance_base_url + ApiPaths.compliance_users(workspace_id)
        headers = {"Authorization": self.compliance_api_key, "Accept": "application/json"}
        params = {"limit": limit}
        demisto.debug(f"[API Compliance Users] Listing users | limit={limit}")

        response = self._http_request(method="GET", full_url=full_url, params=params, headers=headers)
        if isinstance(response, list):
            users = response
        elif isinstance(response, dict):
            users = response.get("data", [])
        else:
            users = []
        demisto.debug(f"[API Compliance Users] Returned {len(users)} user(s).")
        return users

    # endregion

    # region Event Collector - XSIAM ingestion
    def send_events(self, events: list[dict], product: str) -> None:
        """Send events to XSIAM under `Config.VENDOR` and the given `product` (dataset suffix).

        Args:
            events: List of event dicts to send.
            product: One of `Config.PRODUCT_AUDIT` or `Config.PRODUCT_COMPLIANCE`.
        """
        if not events:
            demisto.debug(f"[API Send] No events to send for product={product}.")
            return
        demisto.debug(f"[API Send] Sending {len(events)} event(s) to XSIAM | vendor={Config.VENDOR} | product={product}")
        send_events_to_xsiam(events=events, vendor=Config.VENDOR, product=product)
        demisto.debug(f"[API Send] Successfully sent {len(events)} event(s) | vendor={Config.VENDOR} | product={product}")

    # endregion


""" HELPER FUNCTIONS """


def setup_args(args: Dict[str, Any], params: Dict[str, Any]):
    """Using instance params for model configuration, if command args were not provided."""
    if not args.get(ArgAndParamNames.MAX_TOKENS, None) and params.get(ArgAndParamNames.MAX_TOKENS, None):
        args[ArgAndParamNames.MAX_TOKENS] = params.get(ArgAndParamNames.MAX_TOKENS)
    if not args.get(ArgAndParamNames.TEMPERATURE, None) and params.get(ArgAndParamNames.TEMPERATURE, None):
        args[ArgAndParamNames.TEMPERATURE] = params.get(ArgAndParamNames.TEMPERATURE)
    if not args.get(ArgAndParamNames.TOP_P, None) and params.get(ArgAndParamNames.TOP_P, False):
        args[ArgAndParamNames.TOP_P] = params.get(ArgAndParamNames.TOP_P)


def conversation_to_chat_context(conversation: List[dict[str, str]]) -> List[dict[str, str]]:
    """A 'Conversation' list that was retrieved from 'demisto.context()' is formatted to be more intuitive for XSOAR users
    and is formatted as: [
                            {'user': '<USER_MESSAGE_0>, 'assistant': '<ASSISTANT_MESSAGE_0>},
                            {'user': '<USER_MESSAGE_1>', 'assistant': '<ASSISTANT_MESSAGE_1>'},
                             ...
                        ].

    The conversational format that is supported by the 'Chat Completions' endpoint is a sequence of messages,
     labeled with roles:
        [
            {'role': 'user', 'content': '<USER_MESSAGE_0>'},
            {'role': 'assistant', 'content': '<ASSISTANT_MESSAGE_0>'},
            {'role': 'user', 'content': '<USER_MESSAGE_1>'},
            {'role': 'assistant', 'content': '<ASSISTANT_MESSAGE_1>'},
            ...
        ]

    Therefore, it has to be transformed.
    """

    chat_context = []
    for element in conversation:
        demisto.debug(f"openai-gpt conversation_to_chat_context reading {element=} from conversation")
        chat_context.append({"role": Roles.USER, "content": element.get(Roles.USER, "")})
        chat_context.append({"role": Roles.ASSISTANT, "content": element.get(Roles.ASSISTANT, "")})

    return chat_context


def get_chat_context(reset_conversation_history: bool, message: str) -> List[dict[str, str]]:
    """
    Retrieves the existing chat conversation history from the incident context, if exists.
    If `reset_conversation_history` is True, or if no conversation history exists, it initializes a new conversation list
    with the given message and returns it.

    Args:
        reset_conversation_history (bool): Flag to determine whether to reset the existing conversation history.
        message (str): The new message to be added to the conversation.

    Returns:
        List[Dict[str, str]]: The updated conversation history with the new message appended.
    """
    # Retrieve or initialize conversation history based on the context and reset flag
    conversation = demisto.context().get("OpenAiChatGPTV3", {}).get("Conversation")

    if reset_conversation_history or not conversation:
        conversation = []
        demisto.debug("openai-gpt get_chat_context conversation history reset or initialized as empty.")
    else:
        demisto.debug(
            f"openai-gpt get_chat_context using conversation history from context:"
            f" [type(conversation)={type(conversation)}]{conversation=}"
        )

    # Create the chat context which is suitable with the required format for a 'chat-completions' request.
    chat_context = conversation_to_chat_context(conversation)
    chat_context.append({"role": Roles.USER, "content": message})
    demisto.debug(f"openai-gpt get_chat_context updated chat_context with new message: {chat_context=}")
    return chat_context


def extract_assistant_message(response: dict[str, Any]) -> str:
    """
    Extracts the assistant message from a response.
    Returns:
    The assistant message as a string.
    """

    choices: list = response.get("choices", [])
    if not choices:
        return_error("Could not retrieve message from response.")

    message = choices[0].get("message", {})
    if not message:
        return_error("Could not retrieve message from response.")

    response_content = message.get("content", "")
    if not response_content:
        return_error("Could not retrieve message from response.")

    return response_content


def get_email_parts(entry_id: str) -> tuple[List[dict[str, str]] | None, str | None, str | None, str | None]:
    """
    Extracts and parses the headers, text body, and HTML body from an .eml file identified by a given entry ID.

    Args:
    - entry_id (str): The unique identifier for the uploaded .eml file in the war room.

    Returns:
    - tuple[List[Dict[str, str]] | None, str | None, str | None]: A tuple containing three elements:
        - headers (List[Dict[str, str]] | None): A list of dictionaries where each dictionary represents an email header.
        - text_body (str | None): The plain text body of the email, if available.
        - html_body (str | None): The HTML body of the email, if available.
    """
    if not entry_id:
        DemistoException("Provide an entryId of an uploaded '.eml' file.")

    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res["path"]
    file_name = get_file_path_res["name"]

    if not file_name.endswith(EML_FILE_PREFIX):
        DemistoException("Provided 'entry_id' does not point to a valid '.eml' file.")

    email_parser = parse_emails.EmailParser(file_path=file_path)
    email_parser.parse()

    headers, text_body, html_body = (
        email_parser.parsed_email.get("Headers", None),
        email_parser.parsed_email.get("Text", None),
        email_parser.parsed_email.get("HTML", None),
    )
    return headers, text_body, html_body, file_name


def check_email_part(email_part: str, client: OpenAiClient, args: dict[str, Any]) -> CommandResults:
    """
    Checks email parts (headers/body) for potential security issues using predefined prompts
    ('CHECK_EMAIL_HEADERS_PROMPT', 'CHECK_EMAIL_BODY_PROMPT') that are sent to the GPT model.
    """
    entry_id: str = args.get(ArgAndParamNames.ENTRY_ID, "")
    email_headers, email_text_body, email_html_body, file_name = get_email_parts(entry_id)
    additional_instructions = (
        (f"openai-gpt check_email_part Additional instructions: {ArgAndParamNames.ADDITIONAL_INSTRUCTIONS}\n")
        if args.get(ArgAndParamNames.ADDITIONAL_INSTRUCTIONS, "")
        else ""
    )

    if email_part == EmailParts.HEADERS:
        demisto.debug(f"openai-gpt checking email headers: {email_headers=}")
        if email_headers:
            email_headers_formatted = {
                header["name"]: header["value"] for header in email_headers if "name" in header and "value" in header
            }
            readable_input = tableToMarkdown(name=f"{file_name} headers:", t=email_headers_formatted, sort_headers=False)
            check_email_part_message = CHECK_EMAIL_HEADERS_PROMPT.format(additional_instructions, readable_input)

        else:
            raise DemistoException("'parse_emails' did not extract any email headers from the provided file..")
    elif email_part == EmailParts.BODY:
        demisto.debug(f"openai-gpt checking email body: {email_text_body=} {email_html_body=}")

        if not email_text_body and not email_html_body:
            raise DemistoException("'email_parser' did not extract any email body from the provided file.")

        email_text_body = email_text_body if email_text_body else ""
        email_html_body = email_html_body if email_html_body else ""

        email_body = {"Body/Text": email_text_body, "HTML/Text": email_html_body}

        readable_input = tableToMarkdown(name=f"{file_name} body:", t=email_body, sort_headers=False)
        check_email_part_message = CHECK_EMAIL_BODY_PROMPT.format(additional_instructions, readable_input)
    else:
        raise DemistoException("Invalid email part to check provided.")

    demisto.debug(f"openai-gpt check_email_part {check_email_part_message=}")

    # Starting a new conversation as of a new topic discussed.
    args.update({ArgAndParamNames.RESET_CONVERSATION_HISTORY: "yes", ArgAndParamNames.MESSAGE: check_email_part_message})
    send_message_command_results, response = send_message_command(client, args)

    # Displaying the analyzed email part to the war room and setting the context for the email checking response
    # prior to returning the 'send-message-command' results and the entire conversation to the context.
    return_results(
        CommandResults(
            readable_output=readable_input,
            outputs_prefix="OpenAiChatGPTV3.Email" + email_part.capitalize(),
            outputs={"Email" + email_part.capitalize(): readable_input, "Response": response},
            replace_existing=True,
        )
    )
    return send_message_command_results


""" COMMAND FUNCTIONS """


def test_module(client: OpenAiClient, params: dict) -> str:
    """Tests API connectivity and authentication along with model compatability with 'Chat Completions' endpoint.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``OpenAiClient``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    message = ""
    try:
        chat_message = {"role": "user", "content": ""}
        completion_params = {
            ArgAndParamNames.MAX_TOKENS: params.get(ArgAndParamNames.MAX_TOKENS, None),
            ArgAndParamNames.TEMPERATURE: params.get(ArgAndParamNames.TEMPERATURE, None),
            ArgAndParamNames.TOP_P: params.get(ArgAndParamNames.TOP_P, None),
        }
        client.get_chat_completions(chat_context=[chat_message], completion_params=completion_params)
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return message


def send_message_command(client: OpenAiClient, args: dict[str, Any]) -> tuple[CommandResults, dict[str, Any]]:
    """
    Sending a message with conversation context to an OpenAI GPT model and retrieving the generated response.
    """
    message = args.get(ArgAndParamNames.MESSAGE, "")
    if not message:
        raise ValueError("Message not provided")

    completion_params = {
        ArgAndParamNames.MAX_TOKENS: args.get(ArgAndParamNames.MAX_TOKENS, None),
        ArgAndParamNames.TEMPERATURE: args.get(ArgAndParamNames.TEMPERATURE, None),
        ArgAndParamNames.TOP_P: args.get(ArgAndParamNames.TOP_P, None),
    }

    reset_conversation_history = args.get(ArgAndParamNames.RESET_CONVERSATION_HISTORY, "") == "yes"
    chat_context = get_chat_context(reset_conversation_history, message)
    demisto.debug(f"openai-gpt send_message_command {chat_context=}, {completion_params=}")

    response = client.get_chat_completions(chat_context=chat_context, completion_params=completion_params)
    demisto.debug(f"openai-gpt send_message_command {response=}")

    assistant_message = extract_assistant_message(response)
    conversation_step = [{Roles.USER: message, Roles.ASSISTANT: assistant_message}]

    usage: dict[str, str] = response.get("usage", {})

    readable_output = (
        assistant_message
        + "\n"
        + tableToMarkdown(
            name=f'{response.get(ArgAndParamNames.MODEL, "")} response:',
            sort_headers=False,
            t={
                "Prompt tokens": usage.get("prompt_tokens", ""),
                "Completion tokens": usage.get("completion_tokens", ""),
                "Total tokens": usage.get("total_tokens", ""),
                "Context messages": str(len(chat_context)),
            },
        )
    )
    return CommandResults(
        outputs_prefix="OpenAiChatGPTV3.Conversation",
        outputs=conversation_step,
        replace_existing=reset_conversation_history,
        readable_output=readable_output,
    ), response


def check_email_headers_command(client: OpenAiClient, args: dict[str, Any]) -> CommandResults:
    return check_email_part(EmailParts.HEADERS, client, args)


def check_email_body_command(client: OpenAiClient, args: dict[str, Any]) -> CommandResults:
    return check_email_part(EmailParts.BODY, client, args)


def create_soc_email_template_command(client: OpenAiClient, args: dict[str, Any]) -> CommandResults:
    additional_instructions = (
        f"Additional instructions: {args.get(ArgAndParamNames.ADDITIONAL_INSTRUCTIONS)}\n"
        if args.get(ArgAndParamNames.ADDITIONAL_INSTRUCTIONS, "")
        else ""
    )
    create_soc_email_template_message = CREATE_SOC_EMAIL_TEMPLATE_PROMPT.format(additional_instructions)
    args.update({ArgAndParamNames.MESSAGE: create_soc_email_template_message})
    send_message_command_results, response = send_message_command(client, args)
    # Setting the SOCEmailTemplate context prior to returning the 'send-message-command' results
    # and setting the entire conversation in the context.
    return_results(
        CommandResults(outputs_prefix="OpenAiChatGPTV3.SocEmailTemplate", outputs={"Response": response}, replace_existing=True)
    )
    return send_message_command_results


# region Helpers - JSON parsing
# =================================
# Parsers for non-standard response shapes (concatenated JSON / JSONL)
# =================================
def parse_concatenated_json(body: str) -> list[dict[str, Any]]:
    """Parse a stream of concatenated JSON objects (and/or JSONL lines) into a list of dicts.

    The OpenAI Compliance log-content endpoint returns a body that is NOT valid JSON -
    objects are concatenated with optional whitespace/newlines between them. Uses
    `json.JSONDecoder().raw_decode()` to walk the buffer object-by-object. Non-dict
    top-level values are dropped because they cannot represent an event record.

    Args:
        body: The raw response body text.

    Returns:
        A list of dicts parsed from the body, or `[]` for empty/undecodable input.
    """
    if not body:
        demisto.debug("[Parse] Empty body received - returning [].")
        return []

    body_length = len(body)
    decoder = json.JSONDecoder()
    records: list[dict[str, Any]] = []
    skipped_non_dict = 0
    buffer = body.lstrip()
    while buffer:
        try:
            obj, end = decoder.raw_decode(buffer)
        except json.JSONDecodeError as exc:
            # Stop on first decode failure rather than silently truncate.
            demisto.debug(f"[Parse] Failed to decode concatenated-JSON: {exc.msg} (so far: {len(records)} records).")
            break
        if isinstance(obj, dict):
            records.append(obj)
        else:
            skipped_non_dict += 1
        buffer = buffer[end:].lstrip()

    demisto.debug(
        f"[Parse] Decoded concatenated JSON | body_size={body_length} bytes | "
        f"records={len(records)} | skipped_non_dict={skipped_non_dict}"
    )
    return records


# endregion


# region Helpers - Integration Params
# =================================
# Integration parameter parsing & validation
# =================================
def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate integration configuration parameters.

    Extracts connection settings, credentials and Event Collector options from the raw
    `demisto.params()` dictionary into a single, validated config dict that `main()`
    can hand straight to the `OpenAiClient` constructor.

    Args:
        params: Raw parameters from `demisto.params()`.

    Returns:
        Validated configuration dictionary with keys:
        `base_url`, `api_key`, `model`, `verify`, `proxy`,
        `admin_api_key`, `compliance_api_key`, `compliance_base_url`.

    Raises:
        DemistoException: If `event_types_to_fetch` contains values that are not
            recognized as either an Audit or Compliance event type.
    """
    demisto.debug("[Config] Parsing integration parameters...")

    base_url = (params.get("url") or "https://api.openai.com/").rstrip("/") + "/"

    api_key_raw = params.get("apikey") or {}
    api_key = api_key_raw.get("password", "") if isinstance(api_key_raw, dict) else str(api_key_raw)

    admin_raw = params.get("admin_api_key") or {}
    admin_api_key = admin_raw.get("password", "") if isinstance(admin_raw, dict) else str(admin_raw)

    compliance_raw = params.get("compliance_api_key") or {}
    compliance_api_key = compliance_raw.get("password", "") if isinstance(compliance_raw, dict) else str(compliance_raw)

    compliance_base_url = params.get("compliance_url") or Config.DEFAULT_COMPLIANCE_URL
    model = params.get("model-freetext") or params.get("model-select") or ""

    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    valid_labels = {EventType.AUDIT, *EVENT_TYPE_LABEL_TO_API.keys()}
    event_types_to_fetch = argToList(params.get("event_types_to_fetch") or [])
    invalid = [t for t in event_types_to_fetch if t not in valid_labels]
    if invalid:
        raise DemistoException(f"Invalid event type(s) selected: {invalid}. Valid options: {sorted(valid_labels)}")

    validate_event_types_credentials_correlation(
        event_types_to_fetch=event_types_to_fetch,
        admin_api_key=admin_api_key,
        compliance_api_key=compliance_api_key,
    )

    demisto.debug(f"[Config] URL: {base_url} | Compliance URL: {compliance_base_url}")
    demisto.debug(f"[Config] Model: {model or '<none>'} | verify={verify} | proxy={proxy}")
    demisto.debug(
        f"[Config] Credentials present: chat={bool(api_key)} | "
        f"admin={bool(admin_api_key)} | compliance={bool(compliance_api_key)}"
    )
    demisto.debug(f"[Config] event_types_to_fetch={event_types_to_fetch or '<none>'}")

    return {
        "base_url": base_url,
        "api_key": api_key,
        "model": model,
        "verify": verify,
        "proxy": proxy,
        "admin_api_key": admin_api_key,
        "compliance_api_key": compliance_api_key,
        "compliance_base_url": compliance_base_url,
    }


def validate_event_types_credentials_correlation(
    event_types_to_fetch: list[str],
    admin_api_key: str,
    compliance_api_key: str,
) -> None:
    """Validate that each selected event-type group has its required API key.

    The OpenAI Audit Logs stream uses the Admin API key, while every Compliance
    stream uses the Compliance API key. If the user selects a stream without
    providing the matching key, raise an informative `DemistoException`
    naming the exact selected types and the missing parameter.

    Args:
        event_types_to_fetch: User-facing event-type labels selected in the integration parameters.
        admin_api_key: The Admin API Key (may be empty).
        compliance_api_key: The Compliance API Key (may be empty).

    Raises:
        DemistoException: If a selected stream is missing its required API key.
    """
    audit_selected = EventType.AUDIT in event_types_to_fetch
    selected_compliance = sorted(label for label in event_types_to_fetch if label in EVENT_TYPE_LABEL_TO_API)
    demisto.debug(
        f"[Validation] Cross-check credentials | audit_selected={audit_selected} | "
        f"compliance_selected_count={len(selected_compliance)} | "
        f"admin_key_present={bool(admin_api_key)} | compliance_key_present={bool(compliance_api_key)}"
    )

    if audit_selected and not admin_api_key:
        raise DemistoException(
            f"'{EventType.AUDIT}' is selected in 'Events types to fetch', "
            "but no 'Admin API Key' is provided. The Admin API Key is required to fetch the OpenAI Audit logs. "
            "Either provide the Admin API Key or remove 'OpenAI Audit logs' from the selected event types."
        )

    if selected_compliance and not compliance_api_key:
        raise DemistoException(
            f"Compliance event type(s) {selected_compliance} are selected in 'Events types to fetch', "
            "but no 'Compliance API Key' is provided. The Compliance API Key is required to fetch the "
            "ChatGPT Compliance logs. "
            "Either provide the Compliance API Key or remove the Compliance event types from the selection."
        )

    demisto.debug("[Validation] Credentials cover all selected event-type groups.")


# endregion


# region Event Collector - Helpers
# =================================
# Helpers for the audit + compliance event collector
# =================================
def parse_first_fetch_to_unix_seconds(first_fetch: str) -> int:
    """Parse a first-fetch string (e.g., '1 day') into a Unix-seconds integer (UTC).

    Falls back to "1 day ago" on any parse failure (`arg_to_datetime` raises `ValueError`
    for unparseable input, so the fallback is wrapped in try/except).
    """
    parsed: datetime | None = None
    try:
        parsed = arg_to_datetime(first_fetch, is_utc=True)
    except ValueError:
        demisto.debug(f"[First Fetch] arg_to_datetime raised on '{first_fetch}' - using '1 day ago' fallback.")
    if not parsed:
        parsed = datetime.now(UTC) - timedelta(days=1)
    unix_seconds = int(parsed.timestamp())
    demisto.debug(f"[First Fetch] Resolved '{first_fetch}' to unix_seconds={unix_seconds}.")
    return unix_seconds


def parse_first_fetch_to_iso(first_fetch: str) -> str:
    """Parse a first-fetch string into an ISO 8601 timestamp (UTC, no microseconds).

    Falls back to "1 day ago" on any parse failure (`arg_to_datetime` raises `ValueError`
    for unparseable input, so the fallback is wrapped in try/except).
    """
    parsed: datetime | None = None
    try:
        parsed = arg_to_datetime(first_fetch, is_utc=True)
    except ValueError:
        demisto.debug(f"[First Fetch] arg_to_datetime raised on '{first_fetch}' - using '1 day ago' fallback.")
    if not parsed:
        parsed = datetime.now(UTC) - timedelta(days=1)
    # Drop microseconds for a clean wire format that round-trips with the Compliance API.
    iso = parsed.replace(microsecond=0).strftime(Config.DATE_FORMAT)
    demisto.debug(f"[First Fetch] Resolved '{first_fetch}' to ISO={iso}.")
    return iso


def event_id(event: dict[str, Any]) -> str | None:
    """Extract a stable event identifier from a record.

    Tries common identifier keys in order of preference: `id`, `log_id`, `event_id`, `uuid`.
    The first non-empty value found is coerced to a string and returned.

    Args:
        event: An event/listing dict from any of the OpenAI API surfaces.

    Returns:
        The first identifier found as a string, or None if none of the known keys are present.
    """
    for key in ("id", "log_id", "event_id", "uuid"):
        value = event.get(key)
        if value:
            return str(value)
    return None


def deduplicate_events(events: list[dict[str, Any]], previous_ids: list[str]) -> list[dict[str, Any]]:
    """Filter out events whose identifier was ingested in a previous fetch cycle.

    Used by the Compliance stream's tie-dedup at the persisted `last_end_time` cursor.
    Audit dedup uses the API's native cursor and does not need this helper.

    Args:
        events: Candidate events from the current fetch.
        previous_ids: Identifiers that were already ingested last run.

    Returns:
        A new list containing only events whose `event_id` is not in `previous_ids`.
        Returns the input unchanged when either list is empty (fast path).
    """
    if not events or not previous_ids:
        return events
    previous_set = set(previous_ids)
    new_events = [e for e in events if event_id(e) not in previous_set]
    skipped = len(events) - len(new_events)
    if skipped:
        demisto.debug(f"[Dedup] Skipped {skipped} previously-seen events; {len(new_events)} remaining.")
    return new_events


def enrich_audit_event(event: dict[str, Any]) -> dict[str, Any]:
    """Add `_time` (from `effective_at`) and `source_log_type` to an Audit Logs event."""
    effective_at = event.get("effective_at")
    if isinstance(effective_at, int | float):
        event["_time"] = datetime.fromtimestamp(effective_at, tz=UTC).strftime(Config.DATE_FORMAT)
    else:
        demisto.debug("[Enrich Audit] Event missing 'effective_at' - _time not set.")
    event["source_log_type"] = SourceLogType.AUDIT
    return event


def enrich_compliance_event(event: dict[str, Any], api_event_type: str) -> dict[str, Any]:
    """Add `_time` (from `timestamp`) and `source_log_type` (per `event_type`) to a Compliance event."""
    timestamp = event.get("timestamp")
    if timestamp:
        event["_time"] = timestamp
    else:
        demisto.debug("[Enrich Compliance] Event missing 'timestamp' - _time not set.")

    if api_event_type in COMPLIANCE_EVENT_TYPE_TO_SOURCE_LOG_TYPE:
        event["source_log_type"] = COMPLIANCE_EVENT_TYPE_TO_SOURCE_LOG_TYPE[api_event_type]
    else:
        demisto.debug(
            f"[Enrich Compliance] Unknown event_type='{api_event_type}' - falling back to lowercase as source_log_type."
        )
        event["source_log_type"] = api_event_type.lower()
    event["_event_type"] = api_event_type
    return event


def selected_audit_enabled(event_types_to_fetch: list[str]) -> bool:
    """Return True if the user selected the Audit Logs stream in `event_types_to_fetch`."""
    return EventType.AUDIT in event_types_to_fetch


def selected_compliance_event_types(event_types_to_fetch: list[str]) -> list[str]:
    """Return the upstream `event_type` values for compliance streams the user selected."""
    return [EVENT_TYPE_LABEL_TO_API[label] for label in event_types_to_fetch if label in EVENT_TYPE_LABEL_TO_API]


# endregion


# region Event Collector - Fetch logic
# =================================
# Fetch logic for Audit & Compliance streams
# =================================
def fetch_audit_logs(
    client: OpenAiClient,
    last_run: dict[str, Any],
    max_fetch: int,
    first_fetch: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch the next batch of OpenAI Audit logs (cursor-based dedup).

    Audit dedup is delegated to the API's native cursor: every response carries `last_id`,
    which is persisted as `audit_after` and replayed verbatim as `after=` on the next run.
    No timestamp HWM, no per-id dedup list - the cursor guarantees no duplicates.

    The very first run (no stored cursor) is seeded by `first_fetch` (e.g. "1 day"), which
    is converted to a Unix-second `effective_at[gt]` lower bound for that single request.

    Returns:
        A tuple of (enriched_events, last_run_updates).
    """
    demisto.debug(f"[Audit Fetch] Starting | max_fetch={max_fetch} | first_fetch='{first_fetch}'")

    stored_cursor: str | None = last_run.get(LastRunKey.AUDIT_AFTER)
    initial_effective_at_gt: int | None = None
    if stored_cursor:
        demisto.debug("[Audit Fetch] Resuming from stored cursor.")
    else:
        initial_effective_at_gt = parse_first_fetch_to_unix_seconds(first_fetch)
        demisto.debug(f"[Audit Fetch] No cursor in last_run - first fetch using effective_at>{initial_effective_at_gt}.")

    collected: list[dict[str, Any]] = []
    after: str | None = stored_cursor
    last_cursor: str | None = stored_cursor
    pages = 0
    while len(collected) < max_fetch and pages < Config.MAX_PAGES_PER_FETCH:
        # On every request after the first, `after=` is the cursor; `effective_at_gt` is only
        # honored on the very first ever request (when no cursor has been persisted yet).
        response = client.get_audit_logs(
            after=after,
            effective_at_gt=initial_effective_at_gt if after is None else None,
        )
        page = response.get("data") or []
        if not page:
            demisto.debug(f"[Audit Fetch] Page {pages + 1}: empty - stopping pagination.")
            break
        collected.extend(page)
        pages += 1
        page_last_id = response.get("last_id")
        if page_last_id:
            last_cursor = page_last_id
        demisto.debug(
            f"[Audit Fetch] Page {pages}: +{len(page)} events | total_collected={len(collected)} | "
            f"max_fetch={max_fetch} | has_more={response.get('has_more')} | new_cursor_set={bool(page_last_id)}"
        )
        if not response.get("has_more"):
            demisto.debug(f"[Audit Fetch] Page {pages}: has_more=false - stopping pagination.")
            break
        if not page_last_id:
            demisto.debug(f"[Audit Fetch] Page {pages}: no last_id cursor returned - stopping pagination.")
            break
        after = page_last_id

    # When over `max_fetch`, trim and advance the persisted cursor to the LAST kept event's id
    # so the next run resumes precisely after this batch (no gap, no overlap).
    if len(collected) > max_fetch:
        demisto.debug(f"[Audit Fetch] Trimming {len(collected)} collected events down to max_fetch={max_fetch}.")
        collected = collected[:max_fetch]
        last_cursor = event_id(collected[-1]) or last_cursor

    # Enrich with `_time` / `source_log_type` (cursor pagination guarantees no duplicates already).
    for event in collected:
        enrich_audit_event(event)

    # Persist the latest cursor so the next run picks up exactly after this batch.
    last_run_updates: dict[str, Any] = {}
    if last_cursor:
        last_run_updates[LastRunKey.AUDIT_AFTER] = last_cursor
        demisto.debug("[Audit Fetch] Persisting new cursor for next run.")

    demisto.debug(
        f"[Audit Fetch] Done | new_events={len(collected)} | pages_fetched={pages} | " f"updates={list(last_run_updates.keys())}"
    )
    return collected, last_run_updates


def fetch_compliance_logs(
    client: OpenAiClient,
    workspace_id: str,
    api_event_types: list[str],
    last_run: dict[str, Any],
    max_fetch: int,
    first_fetch: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch the next batch of OpenAI Compliance logs (two-step list + content per id).

    Compliance dedup is timestamp-based with a per-timestamp ID set:
      - The listing API returns `last_end_time` directly in its response - we use that as the
        `after=` value on the next run (and persist it as `compliance_last_end_time`).
      - At any given `last_end_time`, multiple listings may share that exact timestamp.
        The IDs of those listings are persisted as `compliance_last_ids`, so on the next run
        any listing whose id is in that set is filtered out (preventing tie-duplicates).

    Returns:
        A tuple of (enriched_events, last_run_updates).
    """
    demisto.debug(
        f"[Compliance Fetch] Starting | event_types_count={len(api_event_types)} | "
        f"max_fetch={max_fetch} | first_fetch='{first_fetch}'"
    )

    cursor: str = last_run.get(LastRunKey.COMPLIANCE_LAST_END_TIME) or parse_first_fetch_to_iso(first_fetch)
    previous_ids: list[str] = list(last_run.get(LastRunKey.COMPLIANCE_LAST_IDS) or [])
    demisto.debug(f"[Compliance Fetch] Resolved cursor | cursor_set={bool(cursor)} | prev_ids_count={len(previous_ids)}")

    listing_response = client.list_compliance_logs(
        workspace_id=workspace_id,
        event_types=api_event_types,
        after=cursor,
        limit=max_fetch,
    )
    listings: list[dict[str, Any]] = listing_response.get("data") or []
    response_last_end_time: str | None = listing_response.get("last_end_time")

    # Empty listing - the API may still have advanced its cursor; persist it if so.
    if not listings:
        demisto.debug("[Compliance Fetch] No new compliance log entries returned.")
        updates: dict[str, Any] = {}
        if response_last_end_time and response_last_end_time != cursor:
            updates[LastRunKey.COMPLIANCE_LAST_END_TIME] = response_last_end_time
            updates[LastRunKey.COMPLIANCE_LAST_IDS] = []
        return [], updates

    if len(listings) > max_fetch:
        demisto.debug(f"[Compliance Fetch] Trimming {len(listings)} listings down to max_fetch={max_fetch}.")
        listings = listings[:max_fetch]

    # Dedupe against IDs that were already seen at the persisted `last_end_time` (tie-dedup).
    new_listings = deduplicate_events(listings, previous_ids)
    demisto.debug(f"[Compliance Fetch] Listings ready | listings_total={len(listings)} | new_listings={len(new_listings)}")

    # Step 2: for each new listing, fetch its content payload.
    events: list[dict[str, Any]] = []
    failed_content_fetches = 0
    for listing in new_listings:
        log_id = event_id(listing)
        api_event_type = listing.get("event_type", "")
        if not log_id:
            demisto.debug("[Compliance Fetch] Skipping listing entry with missing id.")
            continue
        try:
            content = client.get_compliance_log_content(workspace_id=workspace_id, log_id=log_id)
        except Exception as exc:
            failed_content_fetches += 1
            demisto.debug(f"[Compliance Fetch] Failed to fetch content for one log entry: {exc}")
            continue

        # The content endpoint returns a list of records (parsed from a concatenated-JSON / JSONL body).
        # Carry forward listing metadata so each event is self-describing downstream.
        for record in content:
            record.setdefault("id", log_id)
            record.setdefault("end_time", listing.get("end_time"))
            enrich_compliance_event(record, api_event_type)
            events.append(record)

    if failed_content_fetches:
        demisto.debug(f"[Compliance Fetch] {failed_content_fetches} content fetch(es) failed and were skipped.")

    # Persist the API-reported `last_end_time` and the IDs of listings sharing that exact timestamp.
    # Falls back to the max `end_time` across listings if the API omits `last_end_time`.
    last_run_updates: dict[str, Any] = {}
    new_end_time: str | None = response_last_end_time or max(
        (et for listing in listings if (et := listing.get("end_time"))), default=None
    )
    if new_end_time:
        ids_at_end_time = [eid for listing in listings if listing.get("end_time") == new_end_time and (eid := event_id(listing))]
        # If the cursor didn't move, merge with previously-seen IDs to keep the dedup set complete.
        if new_end_time == cursor:
            ids_at_end_time = list(set(previous_ids) | set(ids_at_end_time))
        last_run_updates[LastRunKey.COMPLIANCE_LAST_END_TIME] = new_end_time
        last_run_updates[LastRunKey.COMPLIANCE_LAST_IDS] = ids_at_end_time
        demisto.debug(f"[Compliance Fetch] New cursor last_end_time advanced | ids_at_end_time_count={len(ids_at_end_time)}")

    demisto.debug(
        f"[Compliance Fetch] Done | events={len(events)} | listings_processed={len(new_listings)} | "
        f"updates={list(last_run_updates.keys())}"
    )
    return events, last_run_updates


# endregion


# region Event Collector - Commands
# =================================
# fetch-events / openai-get-events commands
# =================================
def fetch_events_command(client: OpenAiClient, params: dict[str, Any]) -> None:
    """Scheduled XSIAM fetch: pulls Audit + Compliance events and sends them to ingestion.

    Reads `last_run` once at the start, fetches each enabled stream sequentially, merges
    the per-stream `last_run` updates, sends all events in one batch, and writes
    `last_run` once at the end.
    """
    demisto.debug("[Command fetch-events] triggered")

    event_types_to_fetch = argToList(params.get("event_types_to_fetch") or [])
    audit_max_fetch = arg_to_number(params.get("audit_max_fetch")) or Config.DEFAULT_AUDIT_MAX_FETCH
    compliance_max_fetch = arg_to_number(params.get("compliance_max_fetch")) or Config.DEFAULT_COMPLIANCE_MAX_FETCH
    workspace_id = params.get("workspace_id") or ""
    first_fetch = params.get("first_fetch") or Config.DEFAULT_FIRST_FETCH

    last_run = demisto.getLastRun() or {}
    demisto.debug(
        f"[Command fetch-events] event_types_count={len(event_types_to_fetch)} | "
        f"audit_max_fetch={audit_max_fetch} | compliance_max_fetch={compliance_max_fetch} | "
        f"last_run_keys={list(last_run.keys())}"
    )

    # Each thread gets a copy of last_run; the main thread merges results (no race condition).
    audit_events: list[dict[str, Any]] = []
    compliance_events: list[dict[str, Any]] = []
    updated_last_run: dict[str, Any] = dict(last_run)

    audit_selected = selected_audit_enabled(event_types_to_fetch)
    api_event_types = selected_compliance_event_types(event_types_to_fetch)
    compliance_selected = bool(api_event_types)

    streams_to_run: list[str] = []
    if audit_selected:
        streams_to_run.append(Stream.AUDIT)
    if compliance_selected:
        streams_to_run.append(Stream.COMPLIANCE)
    if not streams_to_run:
        demisto.debug("[Command fetch-events] No event-type group selected. Nothing to fetch.")
        demisto.setLastRun(updated_last_run)
        return

    demisto.debug(f"[Command fetch-events] Launching {len(streams_to_run)} stream(s) in parallel: {streams_to_run}")

    futures: dict[Future, str] = {}
    with ThreadPoolExecutor(max_workers=len(streams_to_run)) as executor:
        if audit_selected:
            demisto.debug("[Command fetch-events] Submitting audit stream to executor.")
            futures[
                executor.submit(
                    fetch_audit_logs,
                    client=client,
                    last_run=dict(last_run),
                    max_fetch=audit_max_fetch,
                    first_fetch=first_fetch,
                )
            ] = Stream.AUDIT
        if compliance_selected:
            demisto.debug("[Command fetch-events] Submitting compliance stream to executor.")
            futures[
                executor.submit(
                    fetch_compliance_logs,
                    client=client,
                    workspace_id=workspace_id,
                    api_event_types=api_event_types,
                    last_run=dict(last_run),
                    max_fetch=compliance_max_fetch,
                    first_fetch=first_fetch,
                )
            ] = Stream.COMPLIANCE

        for future in as_completed(futures):
            stream_name = futures[future]
            demisto.debug(f"[Command fetch-events] Future completed for stream='{stream_name}' - collecting result.")
            try:
                events, stream_updates = future.result()
            except Exception as exc:
                demisto.error(f"[Command fetch-events] {stream_name} stream failed: {exc}")
                continue
            if stream_name == Stream.AUDIT:
                audit_events = events
            else:
                compliance_events = events
            updated_last_run.update(stream_updates)
            demisto.debug(
                f"[Command fetch-events] {stream_name} stream produced {len(events)} events | "
                f"last_run_updates={list(stream_updates.keys())}"
            )

    demisto.debug(
        f"[Command fetch-events] All streams done | audit_events={len(audit_events)} | "
        f"compliance_events={len(compliance_events)}"
    )

    # Each stream is pushed independently so a failure in one does not block the other.
    if audit_events:
        try:
            client.send_events(audit_events, product=Config.PRODUCT_AUDIT)
        except Exception as exc:
            demisto.error(f"[Command fetch-events] Failed to push audit events: {exc}")
    else:
        demisto.debug("[Command fetch-events] No audit events to push.")
    if compliance_events:
        try:
            client.send_events(compliance_events, product=Config.PRODUCT_COMPLIANCE)
        except Exception as exc:
            demisto.error(f"[Command fetch-events] Failed to push compliance events: {exc}")
    else:
        demisto.debug("[Command fetch-events] No compliance events to push.")

    demisto.setLastRun(updated_last_run)
    demisto.debug(
        f"[Command fetch-events] done | audit_sent={len(audit_events)} | "
        f"compliance_sent={len(compliance_events)} | last_run_keys={list(updated_last_run.keys())}"
    )


def get_events_command(client: OpenAiClient, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    """Manual `openai-get-events` command for development/debugging.

    Pulls a bounded number of events from the selected streams without persisting last_run,
    so it can be invoked safely against production tenants.
    """
    demisto.debug("[Command openai-get-events] triggered")

    event_type_arg = argToList(args.get("event_type")) or argToList(params.get("event_types_to_fetch") or [])
    limit = arg_to_number(args.get("limit")) or Config.DEFAULT_GET_EVENTS_LIMIT
    should_push_events = argToBoolean(args.get("should_push_events", False))
    workspace_id = params.get("workspace_id") or ""
    first_fetch = args.get("start_time") or params.get("first_fetch") or Config.DEFAULT_FIRST_FETCH

    demisto.debug(
        f"[Command openai-get-events] event_type_count={len(event_type_arg)} | limit={limit} | "
        f"should_push_events={should_push_events} | first_fetch='{first_fetch}'"
    )

    audit_events: list[dict[str, Any]] = []
    compliance_events: list[dict[str, Any]] = []

    if selected_audit_enabled(event_type_arg):
        # Run Audit fetch with a fresh, in-memory last_run so we don't mutate persistent state.
        audit_events, _ = fetch_audit_logs(client=client, last_run={}, max_fetch=limit, first_fetch=first_fetch)

    api_event_types = selected_compliance_event_types(event_type_arg)
    if api_event_types:
        if not workspace_id:
            demisto.debug(
                "[Command openai-get-events] Compliance event types selected but no workspace_id configured - "
                "skipping the compliance fetch."
            )
        else:
            compliance_events, _ = fetch_compliance_logs(
                client=client,
                workspace_id=workspace_id,
                api_event_types=api_event_types,
                last_run={},
                max_fetch=limit,
                first_fetch=first_fetch,
            )

    all_events: list[dict[str, Any]] = audit_events + compliance_events
    demisto.debug(
        f"[Command openai-get-events] Returning {len(all_events)} event(s) "
        f"(audit={len(audit_events)}, compliance={len(compliance_events)}, push={should_push_events})."
    )
    if should_push_events:
        # Each stream goes to its own dataset.
        if audit_events:
            client.send_events(audit_events, product=Config.PRODUCT_AUDIT)
        if compliance_events:
            client.send_events(compliance_events, product=Config.PRODUCT_COMPLIANCE)

    readable_output = tableToMarkdown(
        "OpenAI GPT Events",
        all_events,
        headers=["id", "_event_type", "source_log_type", "_time"],
        removeNull=True,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="OpenAI.Event",
        outputs_key_field="id",
        outputs=all_events,
    )


# endregion


# region Main
# =================================
# Main entry point
# =================================

# Maps command name -> handler with a uniform (client, args, params) signature.
COMMAND_MAP: dict[str, Callable[["OpenAiClient", dict[str, Any], dict[str, Any]], Any]] = {
    "test-module": lambda client, args, params: test_module(client=client, params=params),
    "gpt-send-message": lambda client, args, params: send_message_command(client=client, args=args)[0],
    "gpt-check-email-header": lambda client, args, params: check_email_headers_command(client=client, args=args),
    "gpt-check-email-body": lambda client, args, params: check_email_body_command(client=client, args=args),
    "gpt-create-soc-email-template": lambda client, args, params: create_soc_email_template_command(client=client, args=args),
    "fetch-events": lambda client, args, params: fetch_events_command(client=client, params=params),
    "openai-get-events": lambda client, args, params: get_events_command(client=client, args=args, params=params),
}


def main() -> None:  # pragma: no cover
    """Main entry point.

    Parses integration params (via `parse_integration_params`), validates the requested
    command against the `COMMAND_MAP`, builds the `OpenAiClient`, and dispatches.
    Errors are logged with a full traceback and surfaced via `return_error`.
    """
    demisto.debug(f"{INTEGRATION_NAME} integration started")

    try:
        params = demisto.params()
        args = demisto.args()
        command = demisto.command()

        handler = COMMAND_MAP.get(command)
        if handler is None:
            raise NotImplementedError(
                f"Command '{command}' is not implemented in the OpenAI GPT integration. "
                f"Available commands: {sorted(COMMAND_MAP.keys())}"
            )
        demisto.debug(f"[Main] Resolved handler for command '{command}'.")

        # Backfill GPT chat args from instance params when missing.
        setup_args(args, params)

        config = parse_integration_params(params)

        client = OpenAiClient(
            url=config["base_url"],
            api_key=config["api_key"],
            model=config["model"],
            verify=config["verify"],
            proxy=config["proxy"],
            admin_api_key=config["admin_api_key"],
            compliance_api_key=config["compliance_api_key"],
            compliance_base_url=config["compliance_base_url"],
        )
        demisto.debug("[Main] Client built. Dispatching command...")

        result = handler(client, args, params)
        if result is not None:
            return_results(result)

        demisto.debug(f"[Main] Command '{command}' completed successfully.")

    except Exception as error:
        error_msg = str(error)
        demisto.error(f"[Main] Command '{command}' failed: {error_msg}")
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute '{command}' command. Error: {error_msg}")

    demisto.debug(f"{INTEGRATION_NAME} integration finished")


# endregion


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

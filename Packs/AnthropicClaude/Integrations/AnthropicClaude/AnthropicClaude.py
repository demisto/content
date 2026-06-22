import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import urllib3
import parse_emails

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
ANTHROPIC_VERSION = "2023-06-01"
EML_FILE_SUFFIX = ".eml"


class Config:
    """Global static configuration for the Anthropic Compliance API event collector."""

    # send_events_to_xsiam identifiers (dataset: anthropic_claude_raw).
    VENDOR = "anthropic"
    PRODUCT = "claude"

    # Activity Feed pagination / fetch budget.
    ACTIVITIES_PAGE_SIZE = 5000  # API max page size for the Activity Feed.
    MAX_FETCH_CALLS = 10  # API call budget per fetch cycle (5000 x 10 = 50,000 events).
    DEFAULT_MAX_EVENTS_PER_FETCH = 50000
    DEFAULT_FETCH_LOOKBACK = "1 minute"  # On the first fetch (no last_run), look back this far.

    # Rate-limit / transient-error handling for the Compliance API.
    # urllib3 retries with exponential back-off and honors the Retry-After header on 429.
    MAX_RETRIES = 3
    BACKOFF_FACTOR = 2  # Sleep ~ BACKOFF_FACTOR * (2 ** (retry - 1)) seconds between attempts.
    RETRY_STATUS_CODES = (429, 500, 502, 503, 504)

    # Read-only compliance commands.
    DEFAULT_LIST_LIMIT = 50

    # Documentation links surfaced in user-facing error messages.
    COMPLIANCE_KEY_DOCS = "https://platform.claude.com/docs/en/manage-claude/compliance-api-access"
    API_KEY_DOCS = "https://console.anthropic.com/keys"


class ApiPaths:
    """Centralized Anthropic Compliance API endpoint paths (relative to the base URL)."""

    ACTIVITIES = "v1/compliance/activities"
    ORGANIZATIONS = "v1/compliance/organizations"
    GROUPS = "v1/compliance/groups"
    CHATS = "v1/compliance/apps/chats"
    PROJECTS = "v1/compliance/apps/projects"

    @classmethod
    def organization_users(cls, org_uuid: str) -> str:
        return f"{cls.ORGANIZATIONS}/{org_uuid}/users"

    @classmethod
    def roles(cls, org_uuid: str) -> str:
        return f"{cls.ORGANIZATIONS}/{org_uuid}/roles"

    @classmethod
    def role(cls, org_uuid: str, role_id: str) -> str:
        return f"{cls.ORGANIZATIONS}/{org_uuid}/roles/{role_id}"

    @classmethod
    def role_permissions(cls, org_uuid: str, role_id: str) -> str:
        return f"{cls.ORGANIZATIONS}/{org_uuid}/roles/{role_id}/permissions"

    @classmethod
    def group(cls, group_id: str) -> str:
        return f"{cls.GROUPS}/{group_id}"

    @classmethod
    def group_members(cls, group_id: str) -> str:
        return f"{cls.GROUPS}/{group_id}/members"

    @classmethod
    def chat_messages(cls, chat_id: str) -> str:
        return f"{cls.CHATS}/{chat_id}/messages"

    @classmethod
    def project(cls, project_id: str) -> str:
        return f"{cls.PROJECTS}/{project_id}"

    @classmethod
    def project_attachments(cls, project_id: str) -> str:
        return f"{cls.PROJECTS}/{project_id}/attachments"

    @classmethod
    def project_document(cls, project_id: str, document_id: str) -> str:
        return f"{cls.PROJECTS}/{project_id}/documents/{document_id}"


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


class AnthropicClient(BaseClient):
    MESSAGES_ENDPOINT = "v1/messages"

    def __init__(self, url: str, api_key: str, model: str, proxy: bool, verify: bool):
        super().__init__(base_url=url, proxy=proxy, verify=verify)

        self.api_key = api_key
        self.model = model
        self.headers = {"x-api-key": self.api_key, "anthropic-version": ANTHROPIC_VERSION, "Content-Type": "application/json"}

    def get_messages(self, chat_context: List[dict[str, str]], completion_params: dict[str, str | None]) -> dict[str, Any]:
        """Gets the response to a messages request using the Anthropic API."""

        # Convert chat context to Anthropic format
        messages = []
        for msg in chat_context:
            if msg["role"] in [Roles.USER, Roles.ASSISTANT]:
                messages.append({"role": msg["role"], "content": msg["content"]})

        options: Dict[str, Any] = {
            ArgAndParamNames.MODEL: self.model,
            "messages": messages,
            # Anthropic API requires max_tokens to be specified, default to 1024 if not provided
            ArgAndParamNames.MAX_TOKENS: 1024,
        }

        max_tokens = completion_params.get(ArgAndParamNames.MAX_TOKENS, None)
        if max_tokens:
            try:
                # Ensure max_tokens is a valid integer
                options[ArgAndParamNames.MAX_TOKENS] = int(max_tokens)
            except (ValueError, TypeError):
                # Use default if conversion fails
                demisto.debug(f"Could not convert max_tokens value '{max_tokens}' to integer, using default value 1024")
                options[ArgAndParamNames.MAX_TOKENS] = 1024

        temperature = completion_params.get(ArgAndParamNames.TEMPERATURE, None)
        if temperature:
            options[ArgAndParamNames.TEMPERATURE] = float(temperature)

        top_p = completion_params.get(ArgAndParamNames.TOP_P, None)
        if top_p:
            options[ArgAndParamNames.TOP_P] = float(top_p)

        demisto.debug(f"anthropic-claude Using options for message: {options=}")
        return self._http_request(
            method="POST", url_suffix=AnthropicClient.MESSAGES_ENDPOINT, json_data=options, headers=self.headers
        )


class ComplianceClient(BaseClient):
    """Client for the Anthropic Compliance API (Activity Feed + read-only directory/content endpoints).

    Authenticates with the Compliance Access Key (``sk-ant-api01-...``) via the ``x-api-key`` header.
    """

    def __init__(self, url: str, api_key: str, proxy: bool, verify: bool):
        super().__init__(base_url=url, proxy=proxy, verify=verify)
        self.api_key = api_key
        self.headers = {"accept": "application/json", "x-api-key": self.api_key}

    def http_get(self, url_suffix: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Performs an authenticated GET request against a Compliance API endpoint.

        Retries on rate-limit (429) and transient 5xx responses using exponential back-off; the
        underlying urllib3 Retry honors the server's ``Retry-After`` header when present.
        """
        return self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params,
            headers=self.headers,
            retries=Config.MAX_RETRIES,
            backoff_factor=Config.BACKOFF_FACTOR,
            status_list_to_retry=list(Config.RETRY_STATUS_CODES),
        )

    def get_activities(
        self,
        limit: int,
        created_at_gte: str | None = None,
        created_at_gt: str | None = None,
        created_at_lt: str | None = None,
        after_id: str | None = None,
        activity_types: list[str] | None = None,
    ) -> dict[str, Any]:
        """Fetches a single page of the Activity Feed (``GET /v1/compliance/activities``)."""
        params: dict[str, Any] = {"limit": limit}
        if after_id:
            params["after_id"] = after_id
        else:
            # Time-window bounds only apply to the first call of a cycle (cursor takes over afterwards).
            if created_at_gte:
                params["created_at.gte"] = created_at_gte
            if created_at_gt:
                params["created_at.gt"] = created_at_gt
            if created_at_lt:
                params["created_at.lt"] = created_at_lt
        if activity_types:
            params["activity_types[]"] = activity_types
        return self.http_get(ApiPaths.ACTIVITIES, params=params)


""" HELPER FUNCTIONS """


def conversation_to_chat_context(conversation: List[dict[str, str]]) -> List[dict[str, str]]:
    """A 'Conversation' list that was retrieved from 'demisto.context()' is formatted to be more intuitive for XSOAR users
    and is formatted as: [
                            {'user': '<USER_MESSAGE_0>', 'assistant': '<ASSISTANT_MESSAGE_0>'},
                            {'user': '<USER_MESSAGE_1>', 'assistant': '<ASSISTANT_MESSAGE_1>'},
                             ...
                        ].

    The conversational format that is supported by the Anthropic Messages API is a sequence of messages,
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
        demisto.debug(f"anthropic-claude conversation_to_chat_context reading {element=} from conversation")
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
    conversation = demisto.context().get("AnthropicClaude", {}).get("Conversation")

    if reset_conversation_history or not conversation:
        conversation = []
        demisto.debug("anthropic-claude get_chat_context conversation history reset or initialized as empty.")
    else:
        demisto.debug(
            f"anthropic-claude get_chat_context using conversation history from context:"
            f" [type(conversation)={type(conversation)}]{conversation=}"
        )

    # Create the chat context which is suitable with the required format for a 'messages' request.
    chat_context = conversation_to_chat_context(conversation)
    chat_context.append({"role": Roles.USER, "content": message})
    demisto.debug(f"anthropic-claude get_chat_context updated chat_context with new message: {chat_context=}")
    return chat_context


def extract_assistant_message(response: dict[str, Any]) -> str:
    """
    Extracts the assistant message from a response.
    Returns:
    The assistant message as a string.
    """
    if not response:
        return_error("Could not retrieve message from response.")

    content = response.get("content", [])
    if not content:
        return_error("Could not retrieve content from response.")

    message_content = ""
    for item in content:
        if item.get("type") == "text":
            message_content += item.get("text", "")

    if not message_content:
        return_error("Could not retrieve text from response content.")

    return message_content


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
        - file_name (str | None): The name of the .eml file in the war room.
    """
    if not entry_id:
        DemistoException("Provide an entryId of an uploaded '.eml' file.")

    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res["path"]
    file_name = get_file_path_res["name"]

    if not file_name.endswith(EML_FILE_SUFFIX):
        DemistoException("Provided 'entry_id' does not point to a valid '.eml' file.")

    email_parser = parse_emails.EmailParser(file_path=file_path)
    email_parser.parse()

    headers, text_body, html_body = (
        email_parser.parsed_email.get("Headers", None),
        email_parser.parsed_email.get("Text", None),
        email_parser.parsed_email.get("HTML", None),
    )
    return headers, text_body, html_body, file_name


def check_email_part(email_part: str, client: AnthropicClient, args: dict[str, Any]) -> CommandResults:
    """
    Checks email parts (headers/body) for potential security issues using predefined prompts
    ('CHECK_EMAIL_HEADERS_PROMPT', 'CHECK_EMAIL_BODY_PROMPT') that are sent to the Claude model.
    """
    entry_id: str = args.get(ArgAndParamNames.ENTRY_ID, "")
    email_headers, email_text_body, email_html_body, file_name = get_email_parts(entry_id)
    additional_instructions = (
        (f"anthropic-claude check_email_part " f"Additional instructions: {ArgAndParamNames.ADDITIONAL_INSTRUCTIONS}\n")
        if args.get(ArgAndParamNames.ADDITIONAL_INSTRUCTIONS, "")
        else ""
    )

    if email_part == EmailParts.HEADERS:
        demisto.debug(f"anthropic-claude checking email headers: {email_headers=}")
        if email_headers:
            email_headers_formatted = {
                header["name"]: header["value"] for header in email_headers if "name" in header and "value" in header
            }
            readable_input = tableToMarkdown(name=f"{file_name} headers:", t=email_headers_formatted, sort_headers=False)
            check_email_part_message = CHECK_EMAIL_HEADERS_PROMPT.format(additional_instructions, readable_input)

        else:
            raise DemistoException("'parse_emails' did not extract any email headers from the provided file..")
    elif email_part == EmailParts.BODY:
        demisto.debug(f"anthropic-claude checking email body: {email_text_body=} {email_html_body=}")

        if not email_text_body and not email_html_body:
            raise DemistoException("'email_parser' did not extract any email body from the provided file.")

        email_text_body = email_text_body if email_text_body else ""
        email_html_body = email_html_body if email_html_body else ""

        email_body = {"Body/Text": email_text_body, "HTML/Text": email_html_body}

        readable_input = tableToMarkdown(name=f"{file_name} body:", t=email_body, sort_headers=False)
        check_email_part_message = CHECK_EMAIL_BODY_PROMPT.format(additional_instructions, readable_input)
    else:
        raise DemistoException("Invalid email part to check provided.")

    demisto.debug(f"anthropic-claude check_email_part {check_email_part_message=}")

    # Starting a new conversation as of a new topic discussed.
    args.update({ArgAndParamNames.RESET_CONVERSATION_HISTORY: "yes", ArgAndParamNames.MESSAGE: check_email_part_message})
    send_message_command_results, response = send_message_command(client, args)

    # Displaying the analyzed email part to the war room and setting the context for the email checking response
    # prior to returning the 'send-message-command' results and the entire conversation to the context.
    return_results(
        CommandResults(
            readable_output=readable_input,
            outputs_prefix="AnthropicClaude.Email" + email_part.capitalize(),
            outputs={"Email" + email_part.capitalize(): readable_input, "Response": response},
            replace_existing=True,
        )
    )
    return send_message_command_results


""" COMMAND FUNCTIONS """


def test_module(client: AnthropicClient, params: dict) -> str:
    """Tests API connectivity and authentication along with model compatability with 'Messages' endpoint.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``AnthropicClient``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    message = ""
    try:
        chat_message = {"role": "user", "content": "test"}
        completion_params = {
            ArgAndParamNames.MAX_TOKENS: int(params.get(ArgAndParamNames.MAX_TOKENS, "").replace(",", "") or 1024),
            ArgAndParamNames.TEMPERATURE: params.get(ArgAndParamNames.TEMPERATURE, None),
            ArgAndParamNames.TOP_P: params.get(ArgAndParamNames.TOP_P, None),
        }
        client.get_messages(chat_context=[chat_message], completion_params=completion_params)
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return message


def send_message_command(client: AnthropicClient, args: dict[str, Any]) -> tuple[CommandResults, dict[str, Any]]:
    """
    Sending a message with conversation context to an Anthropic Claude model and retrieving the generated response.
    """
    message = args.get(ArgAndParamNames.MESSAGE, "")
    if not message:
        raise ValueError("Message not provided")

    completion_params = {
        ArgAndParamNames.MAX_TOKENS: int(args.get(ArgAndParamNames.MAX_TOKENS, "").replace(",", "") or 1024),
        ArgAndParamNames.TEMPERATURE: args.get(ArgAndParamNames.TEMPERATURE, None),
        ArgAndParamNames.TOP_P: args.get(ArgAndParamNames.TOP_P, None),
    }

    reset_conversation_history = args.get(ArgAndParamNames.RESET_CONVERSATION_HISTORY, "") == "yes"
    chat_context = get_chat_context(reset_conversation_history, message)
    demisto.debug(f"anthropic-claude send_message_command {chat_context=}, {completion_params=}")

    response = client.get_messages(chat_context=chat_context, completion_params=completion_params)
    demisto.debug(f"anthropic-claude send_message_command {response=}")

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
                "Input tokens": usage.get("input_tokens", ""),
                "Output tokens": usage.get("output_tokens", ""),
                "Context messages": str(len(chat_context)),
            },
        )
    )
    return CommandResults(
        outputs_prefix="AnthropicClaude.Conversation",
        outputs=conversation_step,
        replace_existing=reset_conversation_history,
        readable_output=readable_output,
    ), response


def check_email_headers_command(client: AnthropicClient, args: dict[str, Any]) -> CommandResults:
    return check_email_part(EmailParts.HEADERS, client, args)


def check_email_body_command(client: AnthropicClient, args: dict[str, Any]) -> CommandResults:
    return check_email_part(EmailParts.BODY, client, args)


def create_soc_email_template_command(client: AnthropicClient, args: dict[str, Any]) -> CommandResults:
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
        CommandResults(outputs_prefix="AnthropicClaude.SocEmailTemplate", outputs={"Response": response}, replace_existing=True)
    )
    return send_message_command_results


""" EVENT COLLECTOR FUNCTIONS """


def add_time_to_events(events: list[dict[str, Any]]) -> None:
    """Sets the ``_time`` field on each event from the documented ``created_at`` timestamp."""
    for event in events:
        created_at = event.get("created_at")
        if created_at:
            event["_time"] = created_at


def deduplicate_events(events: list[dict[str, Any]], last_fetched_ids: list[str]) -> list[dict[str, Any]]:
    """Remove already-processed events based on previously fetched IDs.

    The Activity Feed is queried with a half-open time window (``created_at.gt``), but events that
    share the exact boundary timestamp may reappear across consecutive runs. We dedup them using the
    IDs persisted in the previous ``last_run``.
    """
    if not events or not last_fetched_ids:
        return events

    fetched_ids = set(last_fetched_ids)
    new_events = [event for event in events if event.get("id") not in fetched_ids]
    skipped = len(events) - len(new_events)
    if skipped:
        demisto.debug(f"[Dedup] Skipped {skipped} duplicate events; {len(new_events)} new events remain.")
    return new_events


def fetch_events_with_pagination(
    client: ComplianceClient,
    last_run: dict[str, Any],
    max_events: int,
    activity_types: list[str] | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch Activity Feed events incrementally using cursor pagination.

    The first call of a cycle uses ``created_at.gt`` against the newest timestamp seen in the
    previous run. On the very first run (no ``last_run``) it looks back a fixed one-minute window.
    Subsequent pages within the same cycle advance using the opaque ``after_id`` cursor, until
    ``has_more`` is ``False``, the per-fetch event cap is reached, or the API-call budget is exhausted.

    To guarantee no events are lost across runs, the persisted cursor (``newest_created_at`` and the
    boundary ``last_fetched_ids``) is derived only from the events actually returned to the caller —
    never from events that were dropped by the per-fetch cap. This keeps the cursor from advancing
    past undelivered events.

    Returns the collected events and the next ``last_run`` state.
    """
    previous_newest = last_run.get("newest_created_at")
    previous_ids = last_run.get("last_fetched_ids", [])
    if previous_newest:
        created_at_gt: str | None = previous_newest
        created_at_gte: str | None = None
    else:
        # No stored state: default to a one-minute lookback and let next_run advance the cursor.
        lookback_dt = arg_to_datetime(Config.DEFAULT_FETCH_LOOKBACK)
        created_at_gte = lookback_dt.strftime(DATE_FORMAT) if lookback_dt else None
        created_at_gt = None

    collected: list[dict[str, Any]] = []
    after_id: str | None = None

    for call_num in range(Config.MAX_FETCH_CALLS):
        if len(collected) >= max_events:
            break
        page_limit = min(Config.ACTIVITIES_PAGE_SIZE, max_events - len(collected))
        response = client.get_activities(
            limit=page_limit,
            created_at_gte=created_at_gte,
            # Apply the time bound only on the first call; the cursor (after_id) drives the rest.
            created_at_gt=created_at_gt if call_num == 0 else None,
            after_id=after_id,
            activity_types=activity_types,
        )
        activities = response.get("data", []) or []
        demisto.debug(f"[Fetch] Call {call_num}: fetched {len(activities)} activities.")

        collected.extend(activities)

        after_id = response.get("last_id")
        if not response.get("has_more") or not after_id:
            break

    # Drop events already pushed in a prior run (boundary-timestamp duplicates), then cap to the budget.
    deduped = deduplicate_events(collected, previous_ids)[:max_events]

    # Derive the cursor from the DELIVERED events only, so capping never advances past undelivered ones.
    newest_created_at = previous_newest
    for event in deduped:
        created_at = event.get("created_at")
        if created_at and (not newest_created_at or created_at > newest_created_at):
            newest_created_at = created_at

    # Persist the IDs sharing the newest delivered timestamp so the next run can dedup boundary events.
    # When nothing new was delivered, carry the previous boundary IDs forward to keep dedup intact.
    boundary_ids = [e["id"] for e in deduped if e.get("id") and e.get("created_at") == newest_created_at]
    next_run = {
        "newest_created_at": newest_created_at,
        "last_fetched_ids": boundary_ids or previous_ids,
    }
    return deduped, next_run


def fetch_events_command(client: ComplianceClient, params: dict[str, Any]) -> None:
    """Fetch-events entry point: pull Activity Feed events and push them to XSIAM."""
    last_run = demisto.getLastRun() or {}
    max_events = arg_to_number(params.get("max_events_per_fetch")) or Config.DEFAULT_MAX_EVENTS_PER_FETCH
    activity_types = argToList(params.get("activity_types")) or None

    events, next_run = fetch_events_with_pagination(client, last_run, max_events, activity_types)

    if events:
        add_time_to_events(events)
        send_events_to_xsiam(events, vendor=Config.VENDOR, product=Config.PRODUCT)
    else:
        demisto.debug("[Fetch] No new events to send to XSIAM this cycle.")

    # Persist the cursor regardless of whether events were found, so the next run advances correctly.
    demisto.setLastRun(next_run)
    demisto.info(f"[Fetch] Completed fetch cycle: sent {len(events)} events to XSIAM. {next_run=}")


def get_events_command(client: ComplianceClient, args: dict[str, Any]) -> tuple[list[dict[str, Any]], CommandResults]:
    """Manually retrieve Activity Feed events for testing/troubleshooting.

    Supports optional ``start_time``/``end_time`` arguments to bound the Activity Feed query by
    creation time (RFC 3339, e.g. ``2025-06-07T08:09:10Z``).
    """
    limit = arg_to_number(args.get("limit")) or Config.DEFAULT_LIST_LIMIT
    activity_types = argToList(args.get("activity_types")) or None

    start_dt = arg_to_datetime(args.get("start_time"))
    end_dt = arg_to_datetime(args.get("end_time"))
    created_at_gte = start_dt.strftime(DATE_FORMAT) if start_dt else None
    created_at_lt = end_dt.strftime(DATE_FORMAT) if end_dt else None

    response = client.get_activities(
        limit=min(limit, Config.ACTIVITIES_PAGE_SIZE),
        created_at_gte=created_at_gte,
        created_at_lt=created_at_lt,
        activity_types=activity_types,
    )
    events = (response.get("data", []) or [])[:limit]
    add_time_to_events(events)

    readable = tableToMarkdown(
        name="Anthropic Claude Activity Feed events",
        t=events,
        headers=["id", "created_at", "activity_type"],
        removeNull=True,
    )
    results = CommandResults(
        outputs_prefix="AnthropicClaude.Event",
        outputs_key_field="id",
        outputs=events,
        readable_output=readable,
        raw_response=response,
    )
    return events, results


""" COMPLIANCE COMMAND FUNCTIONS """


def _paginate_args(args: dict[str, Any]) -> dict[str, Any]:
    """Builds common list query params (limit + XSOAR page-token convention)."""
    params: dict[str, Any] = {}
    if limit := arg_to_number(args.get("limit")):
        params["limit"] = limit
    if next_token := args.get("next_token"):
        params["page"] = next_token
    return params


def resolve_org_uuid(args: dict[str, Any], params: dict[str, Any]) -> str:
    """Resolve the organization UUID, preferring the command argument over the instance parameter."""
    org_uuid = args.get("org_uuid") or params.get("organization_uuid")
    if not org_uuid:
        raise DemistoException(
            "An Organization UUID is required for this command. Provide the 'org_uuid' argument or set the "
            "'Organization UUID' integration parameter. Run 'claude-list-organizations' to find available UUIDs."
        )
    return org_uuid


def _list_command(
    client: ComplianceClient,
    url_suffix: str,
    outputs_prefix: str,
    args: dict[str, Any],
    headers: list[str],
    table_name: str,
    use_pagination: bool = True,
) -> CommandResults:
    """Generic GET-and-tabulate helper for the read-only compliance list endpoints."""
    params = _paginate_args(args) if use_pagination else {}
    response = client.http_get(url_suffix, params=params or None)
    data = response.get("data", response)
    readable = tableToMarkdown(name=table_name, t=data, headers=headers, removeNull=True)
    if next_page := response.get("next_page"):
        readable += f"\n**Next page token:** `{next_page}`"
    return CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field="id",
        outputs=data,
        readable_output=readable,
        raw_response=response,
    )


def list_organizations_command(client: ComplianceClient, args: dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get("limit")) or Config.DEFAULT_LIST_LIMIT
    response = client.http_get(ApiPaths.ORGANIZATIONS, params={"limit": limit})
    data = (response.get("data", []) or [])[:limit]
    readable = tableToMarkdown("Organizations", data, headers=["uuid", "name", "created_at"], removeNull=True)
    return CommandResults(
        outputs_prefix="AnthropicClaude.Organization",
        outputs_key_field="uuid",
        outputs=data,
        readable_output=readable,
        raw_response=response,
    )


def list_organization_users_command(client: ComplianceClient, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    org_uuid = resolve_org_uuid(args, params)
    return _list_command(
        client,
        ApiPaths.organization_users(org_uuid),
        "AnthropicClaude.Organization.User",
        args,
        headers=["id", "full_name", "email", "organization_role", "created_at"],
        table_name="Organization Users",
    )


def list_roles_command(client: ComplianceClient, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    org_uuid = resolve_org_uuid(args, params)
    role_id = args.get("role_id")
    headers = ["id", "name", "description", "created_at", "updated_at"]
    if role_id:
        response = client.http_get(ApiPaths.role(org_uuid, role_id))
        readable = tableToMarkdown("Role", response, headers=headers, removeNull=True)
        return CommandResults(
            outputs_prefix="AnthropicClaude.Organization.Role",
            outputs_key_field="id",
            outputs=response,
            readable_output=readable,
            raw_response=response,
        )
    return _list_command(
        client,
        ApiPaths.roles(org_uuid),
        "AnthropicClaude.Organization.Role",
        args,
        headers=headers,
        table_name="Roles",
    )


def list_role_permissions_command(client: ComplianceClient, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    org_uuid = resolve_org_uuid(args, params)
    role_id = args["role_id"]
    return _list_command(
        client,
        ApiPaths.role_permissions(org_uuid, role_id),
        "AnthropicClaude.Organization.Role.Permission",
        args,
        headers=["resource_type", "resource_id", "action"],
        table_name="Role Permissions",
    )


def list_groups_command(client: ComplianceClient, args: dict[str, Any]) -> CommandResults:
    group_id = args.get("group_id")
    headers = ["id", "name", "description", "source_type", "roles", "created_at", "updated_at"]
    if group_id:
        response = client.http_get(ApiPaths.group(group_id))
        readable = tableToMarkdown("Group", response, headers=headers, removeNull=True)
        return CommandResults(
            outputs_prefix="AnthropicClaude.Group",
            outputs_key_field="id",
            outputs=response,
            readable_output=readable,
            raw_response=response,
        )
    return _list_command(
        client,
        ApiPaths.GROUPS,
        "AnthropicClaude.Group",
        args,
        headers=headers,
        table_name="Groups",
    )


def list_group_members_command(client: ComplianceClient, args: dict[str, Any]) -> CommandResults:
    group_id = args["group_id"]
    params = _paginate_args(args)
    response = client.http_get(ApiPaths.group_members(group_id), params=params or None)
    members = response.get("data", [])
    readable = tableToMarkdown(
        f"Group {group_id} Members", members, headers=["user_id", "email", "created_at", "updated_at"], removeNull=True
    )
    if next_page := response.get("next_page"):
        readable += f"\n**Next page token:** `{next_page}`"
    # Merge the members into the matching Group context entry via DT, keyed on the group ID.
    return CommandResults(
        outputs_prefix=f"AnthropicClaude.Group(val.id == '{group_id}').Member",
        outputs_key_field="user_id",
        outputs=members,
        readable_output=readable,
        raw_response=response,
    )


def list_chats_command(client: ComplianceClient, args: dict[str, Any]) -> CommandResults:
    params: dict[str, Any] = {}
    if user_ids := argToList(args.get("user_ids")):
        params["user_ids[]"] = user_ids
    if organization_ids := argToList(args.get("organization_ids")):
        params["organization_ids[]"] = organization_ids
    if project_ids := argToList(args.get("project_ids")):
        params["project_ids[]"] = project_ids
    for arg_name in ("created_at_gte", "created_at_lte", "updated_at_gte", "updated_at_lte", "after_id", "before_id"):
        if value := args.get(arg_name):
            params[arg_name.replace("_gte", ".gte").replace("_lte", ".lte") if "_at_" in arg_name else arg_name] = value
    if limit := arg_to_number(args.get("limit")):
        params["limit"] = limit
    response = client.http_get(ApiPaths.CHATS, params=params)
    data = response.get("data", [])
    headers = ["id", "name", "created_at", "updated_at", "deleted_at", "href", "model", "organization_uuid", "project_id"]
    readable = tableToMarkdown("Chats", data, headers=headers, removeNull=True)
    return CommandResults(
        outputs_prefix="AnthropicClaude.Chat",
        outputs_key_field="id",
        outputs=data,
        readable_output=readable,
        raw_response=response,
    )


def list_chat_messages_command(client: ComplianceClient, args: dict[str, Any]) -> CommandResults:
    chat_id = args["chat_id"]
    params: dict[str, Any] = {}
    if limit := arg_to_number(args.get("limit")):
        params["limit"] = limit
    for arg_name in ("after_id", "before_id", "order"):
        if value := args.get(arg_name):
            params[arg_name] = value
    for arg_name in ("created_at_gte", "created_at_lte", "updated_at_gte", "updated_at_lte"):
        if value := args.get(arg_name):
            params[arg_name.replace("_gte", ".gte").replace("_lte", ".lte")] = value
    response = client.http_get(ApiPaths.chat_messages(chat_id), params=params or None)
    data = response.get("chat_messages", [])
    readable = tableToMarkdown(f"Chat {chat_id} Messages", data, headers=["id", "role", "created_at"], removeNull=True)
    # Merge the messages into the matching Chat context entry via DT, keyed on the chat ID.
    return CommandResults(
        outputs_prefix=f"AnthropicClaude.Chat(val.id == '{chat_id}').Message",
        outputs_key_field="id",
        outputs=data,
        readable_output=readable,
        raw_response=response,
    )


def list_projects_command(client: ComplianceClient, args: dict[str, Any]) -> CommandResults:
    project_id = args.get("project_id")
    headers = [
        "id",
        "name",
        "is_private",
        "organization_uuid",
        "created_at",
        "updated_at",
        "deleted_at",
    ]
    if project_id:
        response = client.http_get(ApiPaths.project(project_id))
        readable = tableToMarkdown("Project", response, headers=headers, removeNull=True)
        return CommandResults(
            outputs_prefix="AnthropicClaude.Project",
            outputs_key_field="id",
            outputs=response,
            readable_output=readable,
            raw_response=response,
        )
    return _list_command(
        client,
        ApiPaths.PROJECTS,
        "AnthropicClaude.Project",
        args,
        headers=headers,
        table_name="Projects",
    )


def list_project_attachments_command(client: ComplianceClient, args: dict[str, Any]) -> CommandResults:
    project_id = args["project_id"]
    params = _paginate_args(args)
    response = client.http_get(ApiPaths.project_attachments(project_id), params=params or None)
    attachments = response.get("data", [])
    readable = tableToMarkdown(
        f"Project {project_id} Attachments",
        attachments,
        headers=["id", "filename", "mime_type", "type", "created_at"],
        removeNull=True,
    )
    if next_page := response.get("next_page"):
        readable += f"\n**Next page token:** `{next_page}`"
    # Merge the attachments into the matching Project context entry via DT, keyed on the project ID.
    return CommandResults(
        outputs_prefix=f"AnthropicClaude.Project(val.id == '{project_id}').Attachment",
        outputs_key_field="id",
        outputs=attachments,
        readable_output=readable,
        raw_response=response,
    )


def get_project_document_command(client: ComplianceClient, args: dict[str, Any]) -> CommandResults:
    project_id = args["project_id"]
    document_id = args["document_id"]
    response = client.http_get(ApiPaths.project_document(project_id, document_id))
    readable = tableToMarkdown(
        "Project Document",
        response,
        headers=["id", "filename", "mime_type", "created_at"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="AnthropicClaude.ProjectDocument",
        outputs_key_field="id",
        outputs=response,
        readable_output=readable,
        raw_response=response,
    )


def module_test_compliance(client: ComplianceClient) -> str:
    """Validates the Compliance Access Key by hitting the Activity Feed with a minimal request."""
    try:
        client.get_activities(limit=1)
    except DemistoException as e:
        if "401" in str(e) or "403" in str(e) or "Forbidden" in str(e) or "Authorization" in str(e):
            return "Authorization Error: make sure the Compliance Access Key is correct and has the required scopes."
        raise
    return "ok"


def ensure_compliance_key(compliance_api_key: str | None) -> None:
    """Fail fast with a helpful error if the Compliance Access Key is not configured."""
    if not compliance_api_key:
        raise DemistoException(
            "This command requires the Anthropic Compliance Access Key (sk-ant-api01-...), which is not configured. "
            "Set the 'Compliance Access Key' integration parameter. "
            f"See how to obtain one here: {Config.COMPLIANCE_KEY_DOCS}"
        )


def ensure_api_key(api_key: str | None) -> None:
    """Fail fast with a helpful error if the Anthropic API Key is not configured."""
    if not api_key:
        raise DemistoException(
            "This command requires the Anthropic API Key, which is not configured. "
            "Set the 'API Key' integration parameter. "
            f"Generate one here: {Config.API_KEY_DOCS}"
        )


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get("apikey", {}).get("password")
    # If a model name was provided within the free text box, it will override the selected one from the model selection box.
    # The provided model will be tested for compatability within the test module.
    model = params.get("model-freetext") if params.get("model-freetext") else params.get("model-select")
    compliance_api_key = params.get("compliance_apikey", {}).get("password")

    url = params.get("url")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # Compliance commands whose org_uuid argument falls back to the instance Organization UUID parameter.
    org_scoped_commands = {
        "claude-list-organization-users": list_organization_users_command,
        "claude-list-roles": list_roles_command,
        "claude-list-role-permissions": list_role_permissions_command,
    }
    # Remaining read-only Compliance API commands.
    compliance_commands = {
        "claude-list-organizations": list_organizations_command,
        "claude-list-groups": list_groups_command,
        "claude-list-group-members": list_group_members_command,
        "claude-list-chats": list_chats_command,
        "claude-list-chat-messages": list_chat_messages_command,
        "claude-list-projects": list_projects_command,
        "claude-list-project-attachments": list_project_attachments_command,
        "claude-get-project-document": get_project_document_command,
    }
    # LLM (Messages API) commands that require the Anthropic API Key.
    llm_commands: dict[str, Any] = {
        "claude-send-message": lambda c, a: send_message_command(c, a)[0],
        "claude-check-email-header": check_email_headers_command,
        "claude-check-email-body": check_email_body_command,
        "claude-create-soc-email-template": create_soc_email_template_command,
    }

    demisto.debug(f"anthropic-claude Command being called is {command}")
    try:
        if command == "test-module":
            # Validate whichever credentials are configured (a customer may configure either or both).
            results: list[str] = []
            if api_key:
                llm_client = AnthropicClient(url=url, api_key=api_key, model=model, verify=verify, proxy=proxy)
                results.append(test_module(client=llm_client, params=params))
            if compliance_api_key:
                compliance_client = ComplianceClient(url=url, api_key=compliance_api_key, verify=verify, proxy=proxy)
                results.append(module_test_compliance(client=compliance_client))
            if not results:
                raise DemistoException(
                    "No credentials configured. Set the 'API Key' for LLM commands and/or the "
                    "'Compliance Access Key' for event collection and compliance commands."
                )
            # Surface the first failing credential's message; only report "ok" when every check passed.
            failure = next((result for result in results if result != "ok"), None)
            return_results(failure or "ok")

        elif command == "fetch-events":
            ensure_compliance_key(compliance_api_key)
            compliance_client = ComplianceClient(url=url, api_key=compliance_api_key, verify=verify, proxy=proxy)
            fetch_events_command(client=compliance_client, params=params)

        elif command == "claude-get-events":
            ensure_compliance_key(compliance_api_key)
            compliance_client = ComplianceClient(url=url, api_key=compliance_api_key, verify=verify, proxy=proxy)
            events, results_obj = get_events_command(client=compliance_client, args=args)
            # get_events_command already set _time on each event, so just push when requested.
            if events and argToBoolean(args.get("should_push_events", "false")):
                send_events_to_xsiam(events, vendor=Config.VENDOR, product=Config.PRODUCT)
            return_results(results_obj)

        elif command in org_scoped_commands:
            ensure_compliance_key(compliance_api_key)
            compliance_client = ComplianceClient(url=url, api_key=compliance_api_key, verify=verify, proxy=proxy)
            return_results(org_scoped_commands[command](compliance_client, args, params))

        elif command in compliance_commands:
            ensure_compliance_key(compliance_api_key)
            compliance_client = ComplianceClient(url=url, api_key=compliance_api_key, verify=verify, proxy=proxy)
            return_results(compliance_commands[command](compliance_client, args))

        elif command in llm_commands:
            ensure_api_key(api_key)
            llm_args = dict(args)
            llm_args.update({key: value for key, value in params.items() if key not in llm_args and value is not None})
            llm_client = AnthropicClient(url=url, api_key=api_key, model=model, verify=verify, proxy=proxy)
            return_results(llm_commands[command](llm_client, llm_args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

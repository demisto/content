"""
Slack API Module

This module provides Slack-specific utilities for Cortex Assistant integration.
It handles Slack Block Kit formatting, message parsing, and UI element creation.

Functions:
    - parse_to_rich_text_elements: Converts markdown to Slack rich text elements
    - parse_md_table_to_slack_table: Converts markdown tables to Slack table blocks
    - process_text_part: Processes text with headers, lists, and paragraphs
    - prepare_slack_message: Main function to convert messages to Slack blocks
    - create_agent_selection_blocks: Creates agent selection dropdown UI
    - get_feedback_buttons_block: Creates feedback buttons
    - get_approval_buttons_block: Creates approval buttons
    - is_bot_mention: Checks if bot is mentioned in message
    - is_agentix_interactive_response: Checks if action is agentix-related
    - is_agentix_modal_submission: Checks if event is agentix modal submission
"""

import re
import json
from typing import Tuple, List, Dict, Optional, Any
from slack_sdk.models.blocks import (
    SectionBlock,
    ActionsBlock,
    HeaderBlock,
    DividerBlock,
    StaticSelectElement,
    Option,
    ConfirmObject,
    ButtonElement,
    PlainTextObject,
    MarkdownTextObject,
    ContextBlock,
    RichTextBlock,
    RichTextListElement,
    RichTextSectionElement,
    InputBlock,
    CheckboxesElement,
    PlainTextInputElement,
)
from slack_sdk.models.views import View
from slack_sdk.web.slack_response import SlackResponse
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CortexAssistantApiModule import *


class SlackAgentixMessages(AgentixMessages):
    """
    Slack-specific messages and UI elements for Agentix.
    Extends the base AgentixMessages with Slack-specific formatting.
    """

    # Step/Plan display (Slack-specific with emoji)
    PLAN_LABEL = "*Plan*"
    PLAN_LABEL_UPDATING = "*Plan (updating...)*"
    PLAN_ICON = ":clipboard:"

    @classmethod
    def format_message(cls, message_template: str, bot_id: str = "", locked_user: str = "") -> str:
        """
        Formats a message template with Slack-specific bot and user tags.

        Args:
            message_template: The message template
            bot_id: The bot user ID
            locked_user: The locked user ID

        Returns:
            Formatted message with proper Slack tags
        """
        message = message_template
        if "{bot_tag}" in message and bot_id:
            message = message.replace("{bot_tag}", f"<@{bot_id}>")
        if "{locked_user_tag}" in message and locked_user:
            message = message.replace("{locked_user_tag}", f"<@{locked_user}>")
        return message


def parse_to_rich_text_elements(text: str) -> List[Dict]:
    """
    Parses a string and returns a list of Slack rich_text element objects.
    Supports bold (**), italics (_), strikethrough (~~), inline code (`),
    links ([text](url)), and URLs (https://...).

    Args:
        text: The text to parse

    Returns:
        List of Slack rich text element dictionaries
    """
    if not text:
        return [{"type": "text", "text": " "}]

    # Pattern for Links, URLs, Bold, Inline Code, Strike, and Italics
    pattern = r'(\[.*?\]\(.*?\))|(https?://[^\s<>"]+)|(\*\*.*?\*\*)|(`[^`]+`)|((?<!\w)~~.*?~~(?!\w))|((?<!\w)__.*?__(?!\w))|((?<!\w)_.*?_(?!\w))'
    parts = re.split(pattern, text)

    elements: List[Dict] = []
    for part in parts:
        if not part:
            continue

        # Link: [text](url)
        link_match = re.match(r"\[(.*?)\]\((.*?)\)", part)
        if link_match:
            elements.append({"type": "link", "text": link_match.group(1), "url": link_match.group(2)})
            continue

        # URL match
        url_match = re.match(r'(https?://[^\s<>"]+)', part)
        if url_match:
            url = url_match.group(1)
            elements.append({"type": "link", "text": url, "url": url})
            continue

        style = {}
        content = part

        # Bold: **text**
        if part.startswith("**") and part.endswith("**"):
            content = part[2:-2]
            style["bold"] = True
        # Inline Code: `text`
        elif part.startswith("`") and part.endswith("`"):
            content = part[1:-1]
            style["code"] = True
        # Strikethrough: ~~text~~
        elif part.startswith("~~") and part.endswith("~~"):
            content = part[2:-2]
            style["strike"] = True
        # Italics: __text__ or _text_
        elif (part.startswith("__") and part.endswith("__")) or (part.startswith("_") and part.endswith("_")):
            content = part[2:-2] if part.startswith("__") else part[1:-1]
            style["italic"] = True

        element = {"type": "text", "text": content}
        if style:
            element["style"] = style

        elements.append(element)

    return elements if elements else [{"type": "text", "text": " "}]


def create_rich_cell(text: str) -> Dict:
    """
    Helper to wrap rich elements into the cell structure for tables.

    Args:
        text: The cell text

    Returns:
        Slack table cell dictionary
    """
    elements = parse_to_rich_text_elements(text)
    has_rich_features = any(e.get("style") or e.get("type") == "link" for e in elements)

    if not has_rich_features:
        return {"type": "raw_text", "text": text if text else " "}

    return RichTextSectionElement(elements=elements).to_dict()  # type: ignore[arg-type]


def parse_md_table_to_slack_table(md_text: str) -> Optional[Dict]:
    """
    Converts Markdown table to Slack 'table' block.

    Args:
        md_text: Markdown table text

    Returns:
        Slack table block dictionary or None
    """
    lines = [line.strip() for line in md_text.strip().split("\n")]
    if not lines:
        return None

    rows = []
    for line in lines:
        # Skip separator lines like |---|
        if re.match(r"^[\s|:-]+$", line):
            continue

        raw_cells = [cell.strip() for cell in line.split("|")]
        if line.startswith("|"):
            raw_cells.pop(0)
        if line.endswith("|"):
            raw_cells.pop()

        if not raw_cells:
            continue

        slack_row = [create_rich_cell(c) for c in raw_cells]
        rows.append(slack_row)

    if not rows:
        return None

    return {
        "type": "table",
        "column_settings": [{"is_wrapped": True}],
        "rows": rows,
    }


def process_text_part(text: str) -> List[Dict]:
    """
    Processes non-table text.
    Handles headers (#), lists (- or * or numbered), and paragraphs.

    Args:
        text: The text to process

    Returns:
        List of Slack block dictionaries
    """
    sub_blocks = []
    lines = text.split("\n")
    current_paragraph: List[str] = []
    current_list_items: List[str] = []
    current_list_style = "bullet"  # Can be "bullet" or "ordered"

    def flush_list():
        if current_list_items:
            sub_blocks.append(
                RichTextBlock(
                    elements=[
                        RichTextListElement(
                            style=current_list_style,  # type: ignore[arg-type]
                            elements=[
                                RichTextSectionElement(elements=parse_to_rich_text_elements(item))  # type: ignore[arg-type]
                                for item in current_list_items
                            ],
                        )
                    ]
                ).to_dict()
            )
            current_list_items.clear()

    def flush_paragraph():
        if current_paragraph:
            para_text = "\n".join(current_paragraph).strip()
            if para_text:
                sub_blocks.append(
                    RichTextBlock(
                        elements=[
                            RichTextSectionElement(elements=parse_to_rich_text_elements(para_text))  # type: ignore[arg-type]
                        ]
                    ).to_dict()
                )
            current_paragraph.clear()

    for line in lines:
        stripped_line = line.strip()

        if not stripped_line:
            flush_paragraph()
            flush_list()
            continue

        header_match = re.match(r"^(#{1,6})\s+(.+)", stripped_line)
        bullet_list_match = re.match(r"^[-*]\s+(.+)", stripped_line)
        numbered_list_match = re.match(r"^(\d+)\.\s+(.+)", stripped_line)

        if header_match:
            flush_paragraph()
            flush_list()
            header_content = header_match.group(2)
            sub_blocks.append({"type": "header", "text": {"type": "plain_text", "text": header_content, "emoji": True}})
        elif bullet_list_match:
            flush_paragraph()
            # Switch to bullet list if needed
            if current_list_items and current_list_style != "bullet":
                flush_list()
            current_list_style = "bullet"
            current_list_items.append(bullet_list_match.group(1))
        elif numbered_list_match:
            flush_paragraph()
            # Switch to ordered list if needed
            if current_list_items and current_list_style != "ordered":
                flush_list()
            current_list_style = "ordered"
            current_list_items.append(numbered_list_match.group(2))
        else:
            if current_list_items:
                flush_list()
            current_paragraph.append(line)

    flush_paragraph()
    flush_list()
    return sub_blocks


def prepare_slack_message(message: str, message_type: str, is_update: bool = False) -> Tuple[List, List]:
    """
    Main processing function for the input message.
    Converts markdown tables and text into Slack Block Kit components.

    Uses AgentixMessageType constants for message type handling.

    Args:
        message: The message text (markdown format)
        message_type: The type of message (from AgentixMessageType)
        is_update: Whether this is an update to existing message (True) or new message (False)

    Returns:
        Tuple of (blocks, attachments) for Slack message

    Raises:
        ValueError: If message_type is not valid
    """
    # Validate message_type
    if not AgentixMessageType.is_valid(message_type):
        error_msg = (
            f"Invalid message_type: '{message_type}'. " f"Must be one of: {', '.join(sorted(AgentixMessageType.VALID_TYPES))}"
        )
        demisto.error(error_msg)
        raise ValueError(error_msg)

    if not message:
        return [], []

    blocks = []
    attachments = []

    if message_type in AgentixMessageType.VALID_TYPES:
        # Standard processing for all new types
        table_regex = r"(\|[^\n]+\|\r?\n\|[\s|:-]+\|\r?\n(?:\|[^\n]+\|\r?\n?)+)"
        parts = re.split(table_regex, message)

        for part in parts:
            if not part:
                continue

            if re.match(table_regex, part):
                table_block = parse_md_table_to_slack_table(part)
                if table_block:
                    blocks.append(table_block)
            else:
                clean_text = part.replace("</content>", "")
                if clean_text.strip():
                    blocks.extend(process_text_part(clean_text))

        # Note: Approval buttons are added in send_agent_response() via get_approval_buttons_block()
        # to avoid duplication and allow for better styling

        # For step types (step/thought), wrap everything in an attachment structure for a subtle appearance.
        if AgentixMessageType.is_step_type(message_type):
            # Add divider before new content if this is an update
            if is_update:
                blocks.insert(0, DividerBlock().to_dict())
                # Don't add Plan header for updates
                attachment_blocks = blocks
            else:
                # Add Plan header with "updating..." indicator for first message
                attachment_blocks = [
                    ContextBlock(
                        elements=[
                            MarkdownTextObject(
                                text=f"{SlackAgentixMessages.PLAN_ICON} {SlackAgentixMessages.PLAN_LABEL_UPDATING}"
                            )
                        ]
                    ).to_dict()
                ] + blocks

            attachments = [
                {
                    "color": "#D1D2D3",  # Light gray border for a subtle look
                    "blocks": attachment_blocks,
                }
            ]
            return [], attachments

        # For error types, use red color
        if AgentixMessageType.is_error_type(message_type):
            attachments = [
                {
                    "color": "#FF0000",  # Red border for errors
                    "blocks": [ContextBlock(elements=[MarkdownTextObject(text=":x: *Error*")]).to_dict()] + blocks,
                }
            ]
            return [], attachments

    return blocks, attachments


def create_agent_selection_blocks(message: str) -> List:
    """
    Creates Slack blocks for agent selection dropdown with confirmation dialog.

    Args:
        message: JSON string containing agent list

    Returns:
        List of Slack blocks with agent dropdown and confirmation
    """
    try:
        agent_data = json.loads(message)
        agent_options = agent_data.get("agents", [])
    except json.JSONDecodeError:
        demisto.error(f"Failed to parse agent list from message: {message}")
        agent_options = []

    dropdown_options = [
        Option(
            text=PlainTextObject(text=agent.get("name", agent.get("id", ""))),
            value=f"{AgentixActionIds.AGENT_SELECTION_VALUE_PREFIX}{agent.get('id', '')}",
        )
        for agent in agent_options
    ]

    if not dropdown_options:
        demisto.debug("No agents found for selection, returning empty list of blocks")
        return []

    return [
        SectionBlock(text=MarkdownTextObject(text=AgentixMessages.AGENT_SELECTION_PROMPT)).to_dict(),
        ActionsBlock(
            elements=[
                StaticSelectElement(
                    placeholder=PlainTextObject(text=AgentixMessages.AGENT_SELECTION_PLACEHOLDER),
                    action_id=AgentixActionIds.AGENT_SELECTION,
                    options=dropdown_options,
                    confirm=ConfirmObject(
                        title=PlainTextObject(text=AgentixMessages.AGENT_SELECTION_CONFIRM_TITLE),
                        text=MarkdownTextObject(text=AgentixMessages.AGENT_SELECTION_CONFIRM_TEXT),
                        confirm=PlainTextObject(text=AgentixMessages.AGENT_SELECTION_CONFIRM_BUTTON),
                        deny=PlainTextObject(text=AgentixMessages.AGENT_SELECTION_DENY_BUTTON),
                    ),
                )
            ],
        ).to_dict(),
    ]


def get_feedback_buttons_block(message_id: str) -> Dict:
    """
    Creates a feedback buttons block for AI responses.

    Args:
        message_id: The message ID for tracking feedback

    Returns:
        Slack block with Good/Bad feedback buttons
        Value format: "positive-message_id" or "negative-message_id"
    """
    return {
        "type": "context_actions",
        "elements": [
            {
                "type": "feedback_buttons",
                "action_id": AgentixActionIds.FEEDBACK,
                "positive_button": {
                    "text": {"type": "plain_text", "text": AgentixMessages.FEEDBACK_GOOD_BUTTON},
                    "value": f"positive-{message_id}",
                    "accessibility_label": AgentixMessages.FEEDBACK_GOOD_ACCESSIBILITY,
                },
                "negative_button": {
                    "text": {"type": "plain_text", "text": AgentixMessages.FEEDBACK_BAD_BUTTON},
                    "value": f"negative-{message_id}",
                    "accessibility_label": AgentixMessages.FEEDBACK_BAD_ACCESSIBILITY,
                },
            }
        ],
    }


def get_approval_buttons_block() -> List[dict]:
    """
    Creates approval UI blocks for sensitive actions with warning header and Proceed/Cancel buttons.
    Includes confirmation dialog for extra safety.

    Returns:
        List of Slack blocks with warning header and approval buttons with confirmation
    """
    return [
        HeaderBlock(
            text=PlainTextObject(text=AgentixMessages.APPROVAL_HEADER, emoji=True),
        ).to_dict(),
        DividerBlock().to_dict(),
        SectionBlock(text=MarkdownTextObject(text=AgentixMessages.APPROVAL_PROMPT)).to_dict(),
        ActionsBlock(
            elements=[
                ButtonElement(
                    text=PlainTextObject(text=AgentixMessages.APPROVAL_PROCEED_BUTTON),
                    style="primary",
                    action_id=AgentixActionIds.APPROVAL_YES,
                    value="agentix-sensitive-action-btn-yes",
                    confirm=ConfirmObject(
                        title=PlainTextObject(text=AgentixMessages.APPROVAL_CONFIRM_TITLE),
                        text=MarkdownTextObject(text=AgentixMessages.APPROVAL_CONFIRM_TEXT),
                        confirm=PlainTextObject(text=AgentixMessages.APPROVAL_CONFIRM_BUTTON),
                        deny=PlainTextObject(text=AgentixMessages.APPROVAL_DENY_BUTTON),
                    ),
                ),
                ButtonElement(
                    text=PlainTextObject(text=AgentixMessages.APPROVAL_CANCEL_BUTTON),
                    style="danger",
                    action_id=AgentixActionIds.APPROVAL_NO,
                    value="agentix-sensitive-action-btn-no",
                ),
            ],
        ).to_dict(),
    ]


def get_feedback_modal(message_id: str, channel_id: str, thread_ts: str) -> View:
    """
    Creates a Slack feedback modal view using SDK classes.

    Args:
        message_id: The message ID for tracking
        channel_id: The channel ID
        thread_ts: The thread timestamp

    Returns:
        Slack View object for the feedback modal
    """
    return View(
        type="modal",
        callback_id=AgentixActionIds.FEEDBACK_MODAL_CALLBACK_ID,
        title=PlainTextObject(text=AgentixMessages.FEEDBACK_MODAL_TITLE),
        submit=PlainTextObject(text=AgentixMessages.FEEDBACK_MODAL_SUBMIT),
        close=PlainTextObject(text=AgentixMessages.FEEDBACK_MODAL_CANCEL),
        blocks=[
            InputBlock(
                block_id=AgentixActionIds.FEEDBACK_MODAL_QUICK_BLOCK_ID,
                label=PlainTextObject(text=AgentixMessages.FEEDBACK_MODAL_QUICK_LABEL),
                element=CheckboxesElement(
                    action_id=AgentixActionIds.FEEDBACK_MODAL_CHECKBOXES_ACTION_ID,
                    options=[
                        Option(
                            text=PlainTextObject(text=AgentixMessages.FEEDBACK_OPTION_NO_ANSWER),
                            value=AgentixMessages.FEEDBACK_OPTION_NO_ANSWER,
                        ),
                        Option(
                            text=PlainTextObject(text=AgentixMessages.FEEDBACK_OPTION_FACTUALLY_INCORRECT),
                            value=AgentixMessages.FEEDBACK_OPTION_FACTUALLY_INCORRECT,
                        ),
                        Option(
                            text=PlainTextObject(text=AgentixMessages.FEEDBACK_OPTION_ANSWERED_ANOTHER),
                            value=AgentixMessages.FEEDBACK_OPTION_ANSWERED_ANOTHER,
                        ),
                        Option(
                            text=PlainTextObject(text=AgentixMessages.FEEDBACK_OPTION_PARTIALLY_HELPFUL),
                            value=AgentixMessages.FEEDBACK_OPTION_PARTIALLY_HELPFUL,
                        ),
                        Option(
                            text=PlainTextObject(text=AgentixMessages.FEEDBACK_OPTION_UNHELPFUL),
                            value=AgentixMessages.FEEDBACK_OPTION_UNHELPFUL,
                        ),
                    ],
                ),
                optional=False,
            ),
            InputBlock(
                block_id=AgentixActionIds.FEEDBACK_MODAL_TEXT_BLOCK_ID,
                label=PlainTextObject(text=AgentixMessages.FEEDBACK_MODAL_ADDITIONAL_LABEL),
                element=PlainTextInputElement(
                    action_id=AgentixActionIds.FEEDBACK_MODAL_TEXT_INPUT_ACTION_ID,
                    multiline=True,
                    placeholder=PlainTextObject(text=AgentixMessages.FEEDBACK_MODAL_ADDITIONAL_PLACEHOLDER),
                ),
                optional=False,
            ),
        ],
        private_metadata=json.dumps(
            {
                "message_id": message_id,
                "channel_id": channel_id,
                "thread_ts": thread_ts,
            }
        ),
    )


def is_bot_mention(text: str, bot_id: str, event: dict[str, Any]) -> bool:
    """
    Checks if the message directly mentions the bot

    Args:
        text: The text content of the message
        bot_id: The bot user ID

    Returns:
        bool: Indicates if bot was directly mentioned
    """
    return f"<@{bot_id}>" in text and event.get("subtype", "") != "channel_join"


def is_agentix_interactive_response(actions: list) -> bool:
    """
    Check if received action is an agentix interactive response that requires special handling
    (agent selection, sensitive action approval, or feedback)
    """
    if actions:
        action = actions[0]
        demisto.debug(f"Checking Agentix interactive response for action: {action}")

        # Check action_id using centralized constants
        action_id = action.get("action_id", "")
        if AgentixActionIds.is_valid(action_id):
            return True

    return False


def is_agentix_modal_submission(data_type: str, view: dict) -> bool:
    """
    Check if received event is an agentix modal submission (e.g., feedback modal)

    Args:
        data_type: The type of the Slack event
        view: The view payload from Slack

    Returns:
        True if this is an agentix modal submission, False otherwise
    """
    if data_type == "interactive":
        callback_id = view.get("callback_id", "")
        return callback_id == AgentixActionIds.FEEDBACK_MODAL_CALLBACK_ID
    return False


def merge_attachment_blocks(history_response: SlackResponse, new_attachments: List[Dict]) -> List[Dict]:
    """
    Intelligently merges attachment blocks by appending new blocks to existing attachment.

    This function handles the case where we want to update a message with new content
    without creating duplicate attachments. It extracts existing attachments from the
    history response and appends the blocks from new_attachments to the blocks array
    of the first existing attachment.

    Args:
        history_response: The Slack API response from conversations.replies
        new_attachments: List of new attachment dictionaries to merge

    Returns:
        List of merged attachments with combined blocks

    Example:
        history_response = {"messages": [{"attachments": [{"color": "#D1D2D3", "blocks": [block1, block2]}]}]}
        new_attachments = [{"color": "#D1D2D3", "blocks": [block3]}]
        result = [{"color": "#D1D2D3", "blocks": [block1, block2, block3]}]
    """
    # Extract existing attachments from history response
    existing_attachments = []
    messages: list[dict[str, Any]] = history_response.get("messages", [])
    if messages:
        existing_attachments = messages[-1].get("attachments", [])

    if not existing_attachments:
        return new_attachments

    if not new_attachments:
        return existing_attachments

    # Append new blocks to the first existing attachment
    for new_attachment in new_attachments:
        new_blocks = new_attachment.get("blocks", [])
        if new_blocks:
            existing_attachments[0].setdefault("blocks", []).extend(new_blocks)

    return existing_attachments


# Note: get_conversation_context is now implemented in SlackV3.py
# It requires access to ASYNC_CLIENT and get_user_details which are defined there


# Note: handle_agentix_bot_mention is now implemented in SlackV3.py
# It requires access to send_message_to_destinations and get_conversation_context which need global variables


# Note: handle_agentix_action is now implemented in SlackV3.py
# It requires access to ASYNC_CLIENT and send_message_to_destinations which are defined there


# Note: handle_agentix_modal_submission is now implemented in SlackV3.py
# It requires access to send_message_to_destinations which is defined there


# Note: send_or_update_agent_message is now implemented in SlackV3.py
# It requires access to CLIENT and send_message_to_destinations which are defined there


# Note: send_agent_response() is now implemented as a method in SlackAgentixHandler
# in SlackV3.py and called via a wrapper function there

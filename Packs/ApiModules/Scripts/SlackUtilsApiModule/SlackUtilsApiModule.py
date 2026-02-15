import re
import json
from typing import Tuple, List, Dict, Any
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


class SlackAssistantMessages(AssistantMessages):
    """
    Slack-specific messages and UI elements for Assistant.
    Extends the base AssistantMessages with Slack-specific formatting.
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
    Parses markdown-formatted text and converts it to Slack rich_text elements.

    Supported markdown syntax:
    - Bold: **text** → {"type": "text", "text": "text", "style": {"bold": True}}
    - Italic: _text_ or __text__ → {"type": "text", "text": "text", "style": {"italic": True}}
    - Strikethrough: ~~text~~ → {"type": "text", "text": "text", "style": {"strike": True}}
    - Inline code: `text` → {"type": "text", "text": "text", "style": {"code": True}}
    - Links: [text](url) → {"type": "link", "text": "text", "url": "url"}
    - URLs: https://example.com → {"type": "link", "text": "url", "url": "url"}

    Algorithm:
    1. Build regex pattern that matches all supported markdown syntax
    2. Split text by pattern to get alternating plain text and formatted parts
    3. For each part, determine its type and create appropriate Slack element
    4. Return list of elements (or single space element if empty)

    Args:
        text: Markdown-formatted text to parse

    Returns:
        List of Slack rich_text element dictionaries

    Example:
        >>> parse_to_rich_text_elements("Hello **world** and `code`")
        [
            {"type": "text", "text": "Hello "},
            {"type": "text", "text": "world", "style": {"bold": True}},
            {"type": "text", "text": " and "},
            {"type": "text", "text": "code", "style": {"code": True}}
        ]
    """
    if not text:
        return [{"type": "text", "text": " "}]

    # Define regex patterns for each markdown syntax
    # Order matters: more specific patterns first
    LINK_PATTERN = r"\[.*?\]\(.*?\)"  # [text](url)
    URL_PATTERN = r'https?://[^\s<>"]+'  # https://example.com
    BOLD_PATTERN = r"\*\*.*?\*\*"  # **text**
    CODE_PATTERN = r"`[^`]+`"  # `text`
    STRIKE_PATTERN = r"~~.*?~~"  # ~~text~~
    ITALIC_DOUBLE_PATTERN = r"__.*?__"  # __text__
    ITALIC_SINGLE_PATTERN = r"_.*?_"  # _text_

    # Combine all patterns with alternation (|) - each in its own capture group
    # This allows us to identify which pattern matched
    combined_pattern = (
        f"({LINK_PATTERN})|({URL_PATTERN})|({BOLD_PATTERN})|({CODE_PATTERN})|"
        f"({STRIKE_PATTERN})|({ITALIC_DOUBLE_PATTERN})|({ITALIC_SINGLE_PATTERN})"
    )

    # Split text by pattern - results in alternating plain text and matched patterns
    parts = re.split(combined_pattern, text)

    elements: list[dict] = []
    for part in parts:
        if not part:
            continue

        # Check if this part matches a specific pattern and create appropriate element

        # Markdown link: [text](url)
        if link_match := re.match(r"\[(.*?)\]\((.*?)\)", part):
            elements.append({"type": "link", "text": link_match.group(1), "url": link_match.group(2)})
            continue

        # Plain URL: https://example.com
        if url_match := re.match(URL_PATTERN, part):
            url = url_match.group(0)
            elements.append({"type": "link", "text": url, "url": url})
            continue

        # For styled text, extract content and determine style
        style = {}
        content = part

        if re.match(BOLD_PATTERN, part):
            content = part[2:-2]  # Remove ** from both sides
            style["bold"] = True
        elif re.match(CODE_PATTERN, part):
            content = part[1:-1]  # Remove ` from both sides
            style["code"] = True
        elif re.match(STRIKE_PATTERN, part):
            content = part[2:-2]  # Remove ~~ from both sides
            style["strike"] = True
        elif re.match(ITALIC_DOUBLE_PATTERN, part):
            content = part[2:-2]  # Remove __ from both sides
            style["italic"] = True
        elif re.match(ITALIC_SINGLE_PATTERN, part):
            content = part[1:-1]  # Remove _ from both sides
            style["italic"] = True

        # Create text element with optional style
        element = {"type": "text", "text": content}
        if style:
            element["style"] = style

        elements.append(element)

    return elements if elements else [{"type": "text", "text": " "}]


def create_rich_cell(text: str) -> dict:
    """
    Creates a Slack table cell with rich text formatting support.

    Determines whether to use raw_text (for plain text) or rich_text_section
    (for formatted text with bold, italic, links, etc.).

    Args:
        text: Cell content (may contain markdown formatting)

    Returns:
        Slack table cell dictionary:
        - {"type": "raw_text", "text": "..."} for plain text
        - {"type": "rich_text_section", "elements": [...]} for formatted text

    Example:
        >>> create_rich_cell("Plain text")
        {"type": "raw_text", "text": "Plain text"}

        >>> create_rich_cell("**Bold** text")
        {"type": "rich_text_section", "elements": [...]}
    """
    elements = parse_to_rich_text_elements(text)

    # Check if any element has styling or is a link
    has_rich_features = any(e.get("style") or e.get("type") == "link" for e in elements)

    if not has_rich_features:
        # Use raw_text for better performance with plain text
        return {"type": "raw_text", "text": text if text else " "}

    # Use rich_text_section for formatted content
    return RichTextSectionElement(elements=elements).to_dict()


def parse_md_table_to_slack_table(md_text: str) -> dict | None:
    """
    Converts markdown table to Slack table block.

    Markdown table format:
    ```
    | Header 1 | Header 2 |
    |----------|----------|
    | Cell 1   | Cell 2   |
    ```

    Algorithm:
    1. Split table into lines
    2. Skip separator lines (|---|---|)
    3. For each data line:
       - Split by | delimiter
       - Remove leading/trailing | if present
       - Create rich cell for each column
    4. Return Slack table block with all rows

    Args:
        md_text: Markdown table text (must include header separator line)

    Returns:
        Slack table block dictionary, or None if table is empty/invalid

    Example:
        >>> parse_md_table_to_slack_table("|A|B|\\n|---|---|\\n|1|2|")
        {
            "type": "table",
            "column_settings": [{"is_wrapped": True}],
            "rows": [[{"type": "raw_text", "text": "A"}, ...], ...]
        }
    """
    lines = [line.strip() for line in md_text.strip().split("\n")]
    if not lines:
        return None

    rows = []
    SEPARATOR_PATTERN = r"^[\s|:-]+$"  # Matches lines like |---|---| or | --- | --- |

    for line in lines:
        # Skip separator lines (|---|---|)
        if re.match(SEPARATOR_PATTERN, line):
            continue

        # Split line by | delimiter
        raw_cells = [cell.strip() for cell in line.split("|")]

        # Remove empty cells from leading/trailing |
        if line.startswith("|"):
            raw_cells.pop(0)
        if line.endswith("|"):
            raw_cells.pop()

        if not raw_cells:
            continue

        # Convert each cell to Slack table cell format
        slack_row = [create_rich_cell(cell) for cell in raw_cells]
        rows.append(slack_row)

    if not rows:
        return None

    return {
        "type": "table",
        "column_settings": [{"is_wrapped": True}],  # Allow text wrapping in cells
        "rows": rows,
    }


def process_text_part(text: str) -> List[Dict]:
    """
    Processes markdown text and converts it to Slack Block Kit blocks.

    Supported markdown elements:
    - Code blocks: ```python\\ncode\\n``` → rich_text_preformatted block
    - Headers: # Header → header block
    - Bullet lists: - item or * item → rich_text list (bullet style)
    - Numbered lists: 1. item → rich_text list (ordered style)
    - Paragraphs: Plain text → rich_text section

    Algorithm:
    1. Extract code blocks (```...```) and replace with placeholders
    2. Process line by line:
       - Headers (# text) → create header block
       - List items (- or * or 1.) → accumulate into list
       - Empty lines → flush current paragraph/list
       - Code block placeholders → create preformatted block
       - Other lines → accumulate into paragraph
    3. Flush any remaining paragraph/list at end

    Args:
        text: Markdown-formatted text to process

    Returns:
        List of Slack block dictionaries (header, rich_text, etc.)

    Example:
        >>> process_text_part("# Title\\n\\n- Item 1\\n- Item 2\\n\\nParagraph")
        [
            {"type": "header", "text": {"type": "plain_text", "text": "Title"}},
            {"type": "rich_text", "elements": [{"type": "rich_text_list", ...}]},
            {"type": "rich_text", "elements": [{"type": "rich_text_section", ...}]}
        ]
    """
    sub_blocks = []

    # Step 1: Extract code blocks and replace with placeholders
    # This prevents code content from being parsed as markdown
    CODE_BLOCK_PATTERN = r"```(\w+)?\n(.*?)\n```"
    code_blocks: list[dict[str, Any]] = []

    def save_code_block(match):
        """Saves code block and returns placeholder"""
        language = match.group(1) or ""
        code_content = match.group(2)
        placeholder = f"__CODE_BLOCK_{len(code_blocks)}__"
        code_blocks.append({"language": language, "content": code_content})
        return placeholder

    text = re.sub(CODE_BLOCK_PATTERN, save_code_block, text, flags=re.DOTALL)

    # Step 2: Process text line by line
    lines = text.split("\n")
    current_paragraph: list[str] = []
    current_list_items: list[str] = []
    current_list_style = "bullet"  # "bullet" or "ordered"

    def flush_list():
        """Converts accumulated list items to Slack rich_text list block"""
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
        """Converts accumulated paragraph lines to Slack rich_text section block"""
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

    # Regex patterns for line types
    CODE_BLOCK_PLACEHOLDER_PATTERN = r"__CODE_BLOCK_(\d+)__"
    HEADER_PATTERN = r"^(#{1,6})\s+(.+)"  # # Header or ## Header, etc.
    BULLET_LIST_PATTERN = r"^[-*]\s+(.+)"  # - item or * item
    NUMBERED_LIST_PATTERN = r"^(\d+)\.\s+(.+)"  # 1. item

    for line in lines:
        stripped_line = line.strip()

        # Check for code block placeholder
        if code_block_match := re.match(CODE_BLOCK_PLACEHOLDER_PATTERN, stripped_line):
            flush_paragraph()
            flush_list()
            block_index = int(code_block_match.group(1))
            if block_index < len(code_blocks):
                code_block = code_blocks[block_index]
                # Create preformatted block for code (inline display)
                sub_blocks.append(
                    {
                        "type": "rich_text",
                        "elements": [
                            {
                                "type": "rich_text_preformatted",
                                "elements": [{"type": "text", "text": code_block["content"]}],
                            }
                        ],
                    }
                )
            continue

        # Empty line - flush current paragraph/list
        if not stripped_line:
            flush_paragraph()
            flush_list()
            continue

        # Check line type and process accordingly
        if header_match := re.match(HEADER_PATTERN, stripped_line):
            # Header line (# text)
            flush_paragraph()
            flush_list()
            header_content = header_match.group(2)
            sub_blocks.append({"type": "header", "text": {"type": "plain_text", "text": header_content, "emoji": True}})

        elif bullet_list_match := re.match(BULLET_LIST_PATTERN, stripped_line):
            # Bullet list item (- item or * item)
            flush_paragraph()
            # Switch to bullet list if currently in ordered list
            if current_list_items and current_list_style != "bullet":
                flush_list()
            current_list_style = "bullet"
            current_list_items.append(bullet_list_match.group(1))

        elif numbered_list_match := re.match(NUMBERED_LIST_PATTERN, stripped_line):
            # Numbered list item (1. item)
            flush_paragraph()
            # Switch to ordered list if currently in bullet list
            if current_list_items and current_list_style != "ordered":
                flush_list()
            current_list_style = "ordered"
            current_list_items.append(numbered_list_match.group(2))

        else:
            # Regular paragraph line
            if current_list_items:
                flush_list()
            current_paragraph.append(line)

    # Flush any remaining content
    flush_paragraph()
    flush_list()

    return sub_blocks


def prepare_slack_message(message: str, message_type: str, is_update: bool = False) -> Tuple[List, List]:
    """
    Converts markdown-formatted message to Slack Block Kit format.

    This is the main entry point for converting Assistant responses to Slack messages.
    Handles different message types with appropriate styling:
    - Step/Thought: Gray attachment with "Plan" header
    - Error: Red attachment with error icon
    - Model/Final: Standard blocks with no attachment

    Processing flow:
    1. Validate message_type using AssistantMessageType enum
    2. Split message into tables and text parts
    3. Convert tables to Slack table blocks
    4. Convert text to Slack rich_text blocks (headers, lists, paragraphs, code)
    5. Wrap in attachments if needed (step/error types)

    Args:
        message: Markdown-formatted message text
        message_type: Message type from AssistantMessageType enum
        is_update: True if updating existing step message, False for new message

    Returns:
        Tuple of (blocks, attachments):
        - blocks: List of Slack block dictionaries (empty for step/error types)
        - attachments: List of attachment dictionaries (used for step/error types)

    Raises:
        ValueError: If message_type is not a valid AssistantMessageType value

    Example:
        >>> prepare_slack_message("# Title\\n\\n- Item 1", "model", False)
        ([{"type": "header", ...}, {"type": "rich_text", ...}], [])

        >>> prepare_slack_message("Step 1", "step", False)
        ([], [{"color": "#D1D2D3", "blocks": [...]}])
    """
    # Validate message_type using enum
    try:
        AssistantMessageType(message_type)
    except ValueError:
        error_msg = (
            f"Invalid message_type: '{message_type}'. " f"Must be one of: {', '.join([t.value for t in AssistantMessageType])}"
        )
        demisto.error(error_msg)
        raise ValueError(error_msg)

    if not message:
        return [], []

    blocks = []
    attachments = []

    # Step 1: Split message into tables and text parts
    # Tables are identified by markdown table syntax: |col1|col2|\n|---|---|\n|val1|val2|
    TABLE_REGEX = r"(\|[^\n]+\|\r?\n\|[\s|:-]+\|\r?\n(?:\|[^\n]+\|\r?\n?)+)"
    parts = re.split(TABLE_REGEX, message)

    # Step 2: Process each part
    for part in parts:
        if not part:
            continue

        if re.match(TABLE_REGEX, part):
            # This part is a markdown table
            table_block = parse_md_table_to_slack_table(part)
            if table_block:
                blocks.append(table_block)
        else:
            # This part is regular text (may contain headers, lists, code blocks, etc.)
            if part.strip():
                blocks.extend(process_text_part(part))

    # Step 3: Wrap blocks in attachments based on message type

    if AssistantMessageType.is_step_type(message_type):
        # Step/Thought messages: wrap in gray attachment for subtle appearance
        if is_update:
            # For updates, add divider before new content
            blocks.insert(0, DividerBlock().to_dict())
            attachment_blocks = blocks
        else:
            # For first message, add "Plan (updating...)" header
            attachment_blocks = [
                ContextBlock(
                    elements=[
                        MarkdownTextObject(
                            text=f"{SlackAssistantMessages.PLAN_ICON} {SlackAssistantMessages.PLAN_LABEL_UPDATING}"
                        )
                    ]
                ).to_dict()
            ] + blocks

        attachments = [
            {
                "color": "#D1D2D3",  # Light gray border
                "blocks": attachment_blocks,
            }
        ]
        return [], attachments

    if AssistantMessageType.is_error_type(message_type):
        # Error messages: wrap in red attachment with error icon
        attachments = [
            {
                "color": "#FF0000",  # Red border
                "blocks": [ContextBlock(elements=[MarkdownTextObject(text=":x: *Error*")]).to_dict()] + blocks,
            }
        ]
        return [], attachments

    # Model/Final responses: return blocks directly (no attachment)
    return blocks, attachments


def create_agent_selection_blocks(agents: list[dict]) -> list:
    """
    Creates Slack blocks for agent selection dropdown with confirmation dialog.

    Args:
        agents: List of agent dictionaries containing 'id' and 'name' fields

    Returns:
        List of Slack blocks with agent dropdown and confirmation
    """
    dropdown_options = [
        Option(
            text=PlainTextObject(text=agent.get("name", agent.get("id", ""))),
            value=f"{AssistantActionIds.AGENT_SELECTION_VALUE_PREFIX.value}{agent.get('id', '')}",
        )
        for agent in agents
    ]

    if not dropdown_options:
        return []

    return [
        SectionBlock(text=MarkdownTextObject(text=AssistantMessages.AGENT_SELECTION_PROMPT)).to_dict(),
        ActionsBlock(
            elements=[
                StaticSelectElement(
                    placeholder=PlainTextObject(text=AssistantMessages.AGENT_SELECTION_PLACEHOLDER),
                    action_id=AssistantActionIds.AGENT_SELECTION.value,
                    options=dropdown_options,
                    confirm=ConfirmObject(
                        title=PlainTextObject(text=AssistantMessages.AGENT_SELECTION_CONFIRM_TITLE),
                        text=MarkdownTextObject(text=AssistantMessages.AGENT_SELECTION_CONFIRM_TEXT),
                        confirm=PlainTextObject(text=AssistantMessages.AGENT_SELECTION_CONFIRM_BUTTON),
                        deny=PlainTextObject(text=AssistantMessages.AGENT_SELECTION_DENY_BUTTON),
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
                "action_id": AssistantActionIds.FEEDBACK.value,
                "positive_button": {
                    "text": {"type": "plain_text", "text": AssistantMessages.FEEDBACK_GOOD_BUTTON},
                    "value": f"positive-{message_id}",
                    "accessibility_label": AssistantMessages.FEEDBACK_GOOD_ACCESSIBILITY,
                },
                "negative_button": {
                    "text": {"type": "plain_text", "text": AssistantMessages.FEEDBACK_BAD_BUTTON},
                    "value": f"negative-{message_id}",
                    "accessibility_label": AssistantMessages.FEEDBACK_BAD_ACCESSIBILITY,
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
            text=PlainTextObject(text=AssistantMessages.APPROVAL_HEADER, emoji=True),
        ).to_dict(),
        DividerBlock().to_dict(),
        SectionBlock(text=MarkdownTextObject(text=AssistantMessages.APPROVAL_PROMPT)).to_dict(),
        ActionsBlock(
            elements=[
                ButtonElement(
                    text=PlainTextObject(text=AssistantMessages.APPROVAL_PROCEED_BUTTON),
                    style="primary",
                    action_id=AssistantActionIds.APPROVAL_YES.value,
                    value="assistant-sensitive-action-btn-yes",
                    confirm=ConfirmObject(
                        title=PlainTextObject(text=AssistantMessages.APPROVAL_CONFIRM_TITLE),
                        text=MarkdownTextObject(text=AssistantMessages.APPROVAL_CONFIRM_TEXT),
                        confirm=PlainTextObject(text=AssistantMessages.APPROVAL_CONFIRM_BUTTON),
                        deny=PlainTextObject(text=AssistantMessages.APPROVAL_DENY_BUTTON),
                    ),
                ),
                ButtonElement(
                    text=PlainTextObject(text=AssistantMessages.APPROVAL_CANCEL_BUTTON),
                    style="danger",
                    action_id=AssistantActionIds.APPROVAL_NO.value,
                    value="assistant-sensitive-action-btn-no",
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
        callback_id=AssistantActionIds.FEEDBACK_MODAL_CALLBACK_ID.value,
        title=PlainTextObject(text=AssistantMessages.FEEDBACK_MODAL_TITLE),
        submit=PlainTextObject(text=AssistantMessages.FEEDBACK_MODAL_SUBMIT),
        close=PlainTextObject(text=AssistantMessages.FEEDBACK_MODAL_CANCEL),
        blocks=[
            InputBlock(
                block_id=AssistantActionIds.FEEDBACK_MODAL_QUICK_BLOCK_ID.value,
                label=PlainTextObject(text=AssistantMessages.FEEDBACK_MODAL_QUICK_LABEL),
                element=CheckboxesElement(
                    action_id=AssistantActionIds.FEEDBACK_MODAL_CHECKBOXES_ACTION_ID.value,
                    options=[
                        Option(
                            text=PlainTextObject(text=AssistantMessages.FEEDBACK_OPTION_NO_ANSWER),
                            value=AssistantMessages.FEEDBACK_OPTION_NO_ANSWER,
                        ),
                        Option(
                            text=PlainTextObject(text=AssistantMessages.FEEDBACK_OPTION_FACTUALLY_INCORRECT),
                            value=AssistantMessages.FEEDBACK_OPTION_FACTUALLY_INCORRECT,
                        ),
                        Option(
                            text=PlainTextObject(text=AssistantMessages.FEEDBACK_OPTION_ANSWERED_ANOTHER),
                            value=AssistantMessages.FEEDBACK_OPTION_ANSWERED_ANOTHER,
                        ),
                        Option(
                            text=PlainTextObject(text=AssistantMessages.FEEDBACK_OPTION_PARTIALLY_HELPFUL),
                            value=AssistantMessages.FEEDBACK_OPTION_PARTIALLY_HELPFUL,
                        ),
                        Option(
                            text=PlainTextObject(text=AssistantMessages.FEEDBACK_OPTION_UNHELPFUL),
                            value=AssistantMessages.FEEDBACK_OPTION_UNHELPFUL,
                        ),
                    ],
                ),
                optional=False,
            ),
            InputBlock(
                block_id=AssistantActionIds.FEEDBACK_MODAL_TEXT_BLOCK_ID.value,
                label=PlainTextObject(text=AssistantMessages.FEEDBACK_MODAL_ADDITIONAL_LABEL),
                element=PlainTextInputElement(
                    action_id=AssistantActionIds.FEEDBACK_MODAL_TEXT_INPUT_ACTION_ID.value,
                    multiline=True,
                    placeholder=PlainTextObject(text=AssistantMessages.FEEDBACK_MODAL_ADDITIONAL_PLACEHOLDER),
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
        event: The event dictionary

    Returns:
        bool: Indicates if bot was directly mentioned
    """
    return f"<@{bot_id}>" in text and event.get("subtype", "") != "channel_join"


def is_assistant_interactive_response(actions: list) -> bool:
    """
    Check if received action is an assistant interactive response that requires special handling
    (agent selection, sensitive action approval, or feedback)
    """
    if actions:
        action = actions[0]
        # Check action_id using enum values
        action_id = action.get("action_id", "")
        valid_action_ids = {e.value for e in AssistantActionIds}
        if action_id in valid_action_ids:
            return True

    return False


def is_assistant_modal_submission(data_type: str, view: dict) -> bool:
    """
    Check if received event is an assistant modal submission (e.g., feedback modal)

    Args:
        data_type: The type of the Slack event
        view: The view payload from Slack

    Returns:
        True if this is an assistant modal submission, False otherwise
    """
    if data_type == "interactive":
        callback_id = view.get("callback_id", "")
        return callback_id == AssistantActionIds.FEEDBACK_MODAL_CALLBACK_ID
    return False


def merge_attachment_blocks(history_response: SlackResponse, new_attachments: list[dict]) -> list[dict]:
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


def normalize_slack_message_from_user(text: str) -> str:
    """
    Normalizes Slack message from user for backend processing.
    Decodes HTML entities but preserves Slack-specific syntax like user mentions and channel references.

    Decodes:
    - All HTML entities using html.unescape() (e.g., > -> >, < -> <, & -> &, " -> ", etc.)

    Preserves:
    - User mentions: <@U12345>
    - Channel references: <#C12345>
    - Slack links: <url|text> or <url>
    - Bullet points (- or * at start of line)
    - Numbered lists (1. 2. etc.)
    - Plain text structure

    Args:
        text: The Slack message text with Slack formatting

    Returns:
        Normalized text suitable for backend processing
    """
    if not text:
        return text

    # Decode all HTML entities (Slack uses these for special characters)
    import html

    text = html.unescape(text)

    # Note: We preserve Slack syntax like <@U12345>, <#C12345>, and <url|text>
    # The backend should handle these appropriately

    return text


async def handle_assistant_modal_submission(view: dict, user_id: str, user_email: str, handler: AssistantMessagingHandler):
    """
    Handles Assistant modal submissions (e.g., negative feedback with checkboxes and text).
    Extracts Slack-specific data and delegates to the handler.
    Uses AssistantActionIds enum for block and action IDs.

    Args:
        view: The view payload from Slack
        user_id: The Slack user ID
        user_email: The user's email
        handler: The AssistantMessagingHandler instance to delegate to
    """
    private_metadata = json.loads(view.get("private_metadata", "{}"))
    message_id = private_metadata.get("message_id", "")
    channel_id = private_metadata.get("channel_id", "")
    thread_ts = private_metadata.get("thread_ts", "")

    # Extract feedback from modal
    values = view.get("state", {}).get("values", {})

    # Extract selected checkboxes (quick feedback) - using enum constants
    issues = []
    if AssistantActionIds.FEEDBACK_MODAL_QUICK_BLOCK_ID in values:
        checkboxes_data = values[AssistantActionIds.FEEDBACK_MODAL_QUICK_BLOCK_ID].get(
            AssistantActionIds.FEEDBACK_MODAL_CHECKBOXES_ACTION_ID, {}
        )
        selected_options = checkboxes_data.get("selected_options", [])
        issues = [option.get("value", "") for option in selected_options]

    # Extract additional text feedback - using enum constants
    feedback_text = ""
    if AssistantActionIds.FEEDBACK_MODAL_TEXT_BLOCK_ID in values:
        text_input_data = values[AssistantActionIds.FEEDBACK_MODAL_TEXT_BLOCK_ID].get(
            AssistantActionIds.FEEDBACK_MODAL_TEXT_INPUT_ACTION_ID, {}
        )
        feedback_text = text_input_data.get("value", "") or ""

    # Delegate to handler with extracted data
    await handler.handle_modal_submission(
        message_id=message_id,
        channel_id=channel_id,
        thread_id=thread_ts,
        user_id=user_id,
        user_email=user_email,
        issues=issues,
        feedback_text=feedback_text,
    )

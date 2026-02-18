import pytest
import json
import demistomock as demisto
from SlackUtilsApiModule import (
    SlackAssistantMessages,
    parse_to_rich_text_elements,
    create_rich_cell,
    parse_md_table_to_slack_table,
    process_text_part,
    prepare_slack_message,
    create_agent_selection_blocks,
    get_feedback_buttons_block,
    get_approval_buttons_block,
    get_feedback_modal,
    is_bot_mention,
    is_assistant_interactive_response,
    is_assistant_modal_submission,
    normalize_slack_message_from_user,
)
from CortexAssistantApiModule import AssistantActionIds, AssistantMessageType


# ============================================================================
# Test SlackAssistantMessages
# ============================================================================


def test_slack_assistant_messages_format_message_with_bot_tag():
    """
    Given:
        Message template with bot_tag placeholder and bot_id.
    When:
        Formatting message.
    Then:
        Replaces bot_tag with Slack mention format.
    """
    result = SlackAssistantMessages.format_message("Please contact {bot_tag} for help", bot_id="BOT123")
    assert result == "Please contact <@BOT123> for help"


def test_slack_assistant_messages_format_message_with_user_tag():
    """
    Given:
        Message template with locked_user_tag placeholder and user ID.
    When:
        Formatting message.
    Then:
        Replaces locked_user_tag with Slack mention format.
    """
    result = SlackAssistantMessages.format_message("Only {locked_user_tag} can respond", locked_user="USER123")
    assert result == "Only <@USER123> can respond"


def test_slack_assistant_messages_format_message_both_tags():
    """
    Given:
        Message template with both bot_tag and locked_user_tag.
    When:
        Formatting message.
    Then:
        Replaces both placeholders with Slack mentions.
    """
    result = SlackAssistantMessages.format_message(
        "{bot_tag} is locked to {locked_user_tag}", bot_id="BOT123", locked_user="USER123"
    )
    assert result == "<@BOT123> is locked to <@USER123>"


# ============================================================================
# Test parse_to_rich_text_elements
# ============================================================================


def test_parse_to_rich_text_elements_plain_text():
    """
    Given:
        Plain text without formatting.
    When:
        Parsing to rich text elements.
    Then:
        Returns single text element.
    """
    result = parse_to_rich_text_elements("Hello world")
    assert len(result) == 1
    assert result[0]["type"] == "text"
    assert result[0]["text"] == "Hello world"


def test_parse_to_rich_text_elements_bold():
    """
    Given:
        Text with bold markdown.
    When:
        Parsing to rich text elements.
    Then:
        Returns text element with bold style.
    """
    result = parse_to_rich_text_elements("**bold text**")
    assert len(result) == 1
    assert result[0]["type"] == "text"
    assert result[0]["text"] == "bold text"
    assert result[0]["style"]["bold"] is True


def test_parse_to_rich_text_elements_code():
    """
    Given:
        Text with inline code markdown.
    When:
        Parsing to rich text elements.
    Then:
        Returns text element with code style.
    """
    result = parse_to_rich_text_elements("`code here`")
    assert len(result) == 1
    assert result[0]["type"] == "text"
    assert result[0]["text"] == "code here"
    assert result[0]["style"]["code"] is True


def test_parse_to_rich_text_elements_link():
    """
    Given:
        Markdown link.
    When:
        Parsing to rich text elements.
    Then:
        Returns link element with text and url.
    """
    result = parse_to_rich_text_elements("[Click here](https://example.com)")
    assert len(result) == 1
    assert result[0]["type"] == "link"
    assert result[0]["text"] == "Click here"
    assert result[0]["url"] == "https://example.com"


def test_parse_to_rich_text_elements_url():
    """
    Given:
        Plain URL.
    When:
        Parsing to rich text elements.
    Then:
        Returns link element with URL as both text and url.
    """
    result = parse_to_rich_text_elements("https://example.com")
    assert len(result) == 1
    assert result[0]["type"] == "link"
    assert result[0]["url"] == "https://example.com"


def test_parse_to_rich_text_elements_mixed():
    """
    Given:
        Text with multiple formatting types.
    When:
        Parsing to rich text elements.
    Then:
        Returns multiple elements with correct styles.
    """
    result = parse_to_rich_text_elements("Hello **bold** and `code`")
    assert len(result) == 4
    assert result[0]["text"] == "Hello "
    assert result[1]["text"] == "bold"
    assert result[1]["style"]["bold"] is True
    assert result[2]["text"] == " and "
    assert result[3]["text"] == "code"
    assert result[3]["style"]["code"] is True


def test_parse_to_rich_text_elements_empty():
    """
    Given:
        Empty string.
    When:
        Parsing to rich text elements.
    Then:
        Returns single space element.
    """
    result = parse_to_rich_text_elements("")
    assert len(result) == 1
    assert result[0]["text"] == " "


# ============================================================================
# Test create_rich_cell
# ============================================================================


def test_create_rich_cell_plain_text():
    """
    Given:
        Plain text without formatting.
    When:
        Creating rich cell.
    Then:
        Returns raw_text type cell.
    """
    result = create_rich_cell("Plain text")
    assert result["type"] == "raw_text"
    assert result["text"] == "Plain text"


def test_create_rich_cell_formatted_text():
    """
    Given:
        Text with bold formatting.
    When:
        Creating rich cell.
    Then:
        Returns rich_text_section type cell.
    """
    result = create_rich_cell("**Bold text**")
    assert result["type"] == "rich_text_section"
    assert "elements" in result


def test_create_rich_cell_with_url_falls_back_to_raw_text():
    """
    Given:
        Cell text containing a URL.
    When:
        Creating rich cell.
    Then:
        Returns raw_text type (Slack table cells don't support link elements).
    """
    result = create_rich_cell("https://example.com/incident-view?caseId=1")
    assert result["type"] == "raw_text"
    assert result["text"] == "https://example.com/incident-view?caseId=1"


def test_create_rich_cell_with_markdown_link_falls_back_to_raw_text():
    """
    Given:
        Cell text containing a markdown link.
    When:
        Creating rich cell.
    Then:
        Returns raw_text type (Slack table cells don't support link elements).
    """
    result = create_rich_cell("[Click here](https://example.com)")
    assert result["type"] == "raw_text"
    assert result["text"] == "[Click here](https://example.com)"


def test_create_rich_cell_empty():
    """
    Given:
        Empty string.
    When:
        Creating rich cell.
    Then:
        Returns raw_text with single space.
    """
    result = create_rich_cell("")
    assert result["type"] == "raw_text"
    assert result["text"] == " "


# ============================================================================
# Test parse_md_table_to_slack_table
# ============================================================================


def test_parse_md_table_to_slack_table_simple():
    """
    Given:
        Simple markdown table with header and one row.
    When:
        Parsing to Slack table.
    Then:
        Returns table block with correct rows.
    """
    md_table = "|Header1|Header2|\n|---|---|\n|Cell1|Cell2|"
    result = parse_md_table_to_slack_table(md_table)

    assert result is not None
    assert result["type"] == "table"
    assert len(result["rows"]) == 2
    assert result["rows"][0][0]["text"] == "Header1"
    assert result["rows"][1][0]["text"] == "Cell1"


def test_parse_md_table_to_slack_table_multiple_rows():
    """
    Given:
        Markdown table with multiple data rows.
    When:
        Parsing to Slack table.
    Then:
        Returns table with all rows.
    """
    md_table = "|A|B|\n|---|---|\n|1|2|\n|3|4|"
    result = parse_md_table_to_slack_table(md_table)

    assert result is not None
    assert len(result["rows"]) == 3
    assert result["rows"][0][0]["text"] == "A"
    assert result["rows"][1][0]["text"] == "1"
    assert result["rows"][2][0]["text"] == "3"


def test_parse_md_table_to_slack_table_empty():
    """
    Given:
        Empty string.
    When:
        Parsing to Slack table.
    Then:
        Returns None.
    """
    result = parse_md_table_to_slack_table("")
    assert result is None


# ============================================================================
# Test process_text_part
# ============================================================================


def test_process_text_part_header():
    """
    Given:
        Text with markdown header.
    When:
        Processing text part.
    Then:
        Returns header block.
    """
    result = process_text_part("# My Header")
    assert len(result) == 1
    assert result[0]["type"] == "header"
    assert result[0]["text"]["text"] == "My Header"


def test_process_text_part_bullet_list():
    """
    Given:
        Text with bullet list items.
    When:
        Processing text part.
    Then:
        Returns rich_text block with bullet list.
    """
    result = process_text_part("- Item 1\n- Item 2")
    assert len(result) == 1
    assert result[0]["type"] == "rich_text"
    assert result[0]["elements"][0]["type"] == "rich_text_list"
    assert result[0]["elements"][0]["style"] == "bullet"


def test_process_text_part_numbered_list():
    """
    Given:
        Text with numbered list items.
    When:
        Processing text part.
    Then:
        Returns rich_text block with ordered list.
    """
    result = process_text_part("1. First\n2. Second")
    assert len(result) == 1
    assert result[0]["type"] == "rich_text"
    assert result[0]["elements"][0]["style"] == "ordered"


def test_process_text_part_code_block():
    """
    Given:
        Text with code block.
    When:
        Processing text part.
    Then:
        Returns rich_text block with preformatted element.
    """
    result = process_text_part("```python\nprint('hello')\n```")
    assert len(result) == 1
    assert result[0]["type"] == "rich_text"
    assert result[0]["elements"][0]["type"] == "rich_text_preformatted"


def test_process_text_part_paragraph():
    """
    Given:
        Plain paragraph text.
    When:
        Processing text part.
    Then:
        Returns rich_text block with section element.
    """
    result = process_text_part("This is a paragraph")
    assert len(result) == 1
    assert result[0]["type"] == "rich_text"
    assert result[0]["elements"][0]["type"] == "rich_text_section"


# ============================================================================
# Test prepare_slack_message
# ============================================================================


def test_prepare_slack_message_model_type(mocker):
    """
    Given:
        Model message type.
    When:
        Preparing Slack message.
    Then:
        Returns blocks without attachments.
    """
    blocks, attachments = prepare_slack_message("Hello", AssistantMessageType.MODEL.value)
    assert len(blocks) > 0
    assert len(attachments) == 0


def test_prepare_slack_message_step_type(mocker):
    """
    Given:
        Step message type.
    When:
        Preparing Slack message.
    Then:
        Returns empty blocks with gray attachment.
    """
    blocks, attachments = prepare_slack_message("Step 1", AssistantMessageType.STEP.value)
    assert len(blocks) == 0
    assert len(attachments) == 1
    assert attachments[0]["color"] == "#D1D2D3"


def test_prepare_slack_message_error_type(mocker):
    """
    Given:
        Error message type.
    When:
        Preparing Slack message.
    Then:
        Returns empty blocks with red attachment.
    """
    blocks, attachments = prepare_slack_message("Error", AssistantMessageType.ERROR.value)
    assert len(blocks) == 0
    assert len(attachments) == 1
    assert attachments[0]["color"] == "#FF0000"


def test_prepare_slack_message_invalid_type(mocker):
    """
    Given:
        Invalid message type.
    When:
        Preparing Slack message.
    Then:
        Raises ValueError.
    """
    mocker.patch.object(demisto, "error")
    with pytest.raises(ValueError) as exc_info:
        prepare_slack_message("Test", "invalid_type")
    assert "Invalid message_type" in str(exc_info.value)


def test_prepare_slack_message_empty():
    """
    Given:
        Empty message.
    When:
        Preparing Slack message.
    Then:
        Returns empty blocks and attachments.
    """
    blocks, attachments = prepare_slack_message("", AssistantMessageType.MODEL.value)
    assert blocks == []
    assert attachments == []


# ============================================================================
# Test create_agent_selection_blocks
# ============================================================================


def test_create_agent_selection_blocks_with_agents():
    """
    Given:
        List of agents with id and name.
    When:
        Creating agent selection blocks.
    Then:
        Returns blocks with dropdown and options.
    """
    agents = [{"id": "agent1", "name": "Security Analyst"}, {"id": "agent2", "name": "Incident Responder"}]
    result = create_agent_selection_blocks(agents)

    assert len(result) == 2
    assert result[0]["type"] == "section"
    assert result[1]["type"] == "actions"


def test_create_agent_selection_blocks_empty():
    """
    Given:
        Empty agents list.
    When:
        Creating agent selection blocks.
    Then:
        Returns empty list.
    """
    result = create_agent_selection_blocks([])
    assert result == []


# ============================================================================
# Test get_feedback_buttons_block
# ============================================================================


def test_get_feedback_buttons_block():
    """
    Given:
        Message ID.
    When:
        Creating feedback buttons block.
    Then:
        Returns block with positive and negative buttons.
    """
    result = get_feedback_buttons_block("msg123")

    assert result["type"] == "context_actions"
    assert result["elements"][0]["type"] == "feedback_buttons"
    assert result["elements"][0]["positive_button"]["value"] == "positive-msg123"
    assert result["elements"][0]["negative_button"]["value"] == "negative-msg123"


# ============================================================================
# Test get_approval_buttons_block
# ============================================================================


def test_get_approval_buttons_block():
    """
    Given:
        No parameters.
    When:
        Creating approval buttons block.
    Then:
        Returns blocks with header, divider, and action buttons.
    """
    result = get_approval_buttons_block()

    assert len(result) == 4
    assert result[0]["type"] == "header"
    assert result[1]["type"] == "divider"
    assert result[2]["type"] == "section"
    assert result[3]["type"] == "actions"


# ============================================================================
# Test get_feedback_modal
# ============================================================================


def test_get_feedback_modal():
    """
    Given:
        Message ID, channel ID, and thread timestamp.
    When:
        Creating feedback modal.
    Then:
        Returns View with checkboxes and text input.
    """
    result = get_feedback_modal("msg123", "channel123", "thread123")

    assert result.type == "modal"
    assert result.callback_id == AssistantActionIds.FEEDBACK_MODAL_CALLBACK_ID
    assert len(result.blocks) == 2

    assert result.private_metadata is not None
    metadata = json.loads(result.private_metadata)
    assert metadata["message_id"] == "msg123"
    assert metadata["channel_id"] == "channel123"


# ============================================================================
# Test is_bot_mention
# ============================================================================


def test_is_bot_mention_true():
    """
    Given:
        Text with bot mention and normal event.
    When:
        Checking if bot is mentioned.
    Then:
        Returns True.
    """
    result = is_bot_mention("<@BOT123> help", "BOT123", {})
    assert result is True


def test_is_bot_mention_false_no_mention():
    """
    Given:
        Text without bot mention.
    When:
        Checking if bot is mentioned.
    Then:
        Returns False.
    """
    result = is_bot_mention("Hello everyone", "BOT123", {})
    assert result is False


def test_is_bot_mention_false_channel_join():
    """
    Given:
        Text with bot mention but channel_join subtype.
    When:
        Checking if bot is mentioned.
    Then:
        Returns False.
    """
    result = is_bot_mention("<@BOT123> joined", "BOT123", {"subtype": "channel_join"})
    assert result is False


# ============================================================================
# Test is_assistant_interactive_response
# ============================================================================


def test_is_assistant_interactive_response_true():
    """
    Given:
        Actions with valid assistant action_id.
    When:
        Checking if assistant interactive response.
    Then:
        Returns True.
    """
    actions = [{"action_id": AssistantActionIds.FEEDBACK.value}]
    result = is_assistant_interactive_response(actions)
    assert result is True


def test_is_assistant_interactive_response_false():
    """
    Given:
        Actions with non-assistant action_id.
    When:
        Checking if assistant interactive response.
    Then:
        Returns False.
    """
    actions = [{"action_id": "some_other_action"}]
    result = is_assistant_interactive_response(actions)
    assert result is False


def test_is_assistant_interactive_response_empty():
    """
    Given:
        Empty actions list.
    When:
        Checking if assistant interactive response.
    Then:
        Returns False.
    """
    result = is_assistant_interactive_response([])
    assert result is False


# ============================================================================
# Test is_assistant_modal_submission
# ============================================================================


def test_is_assistant_modal_submission_true():
    """
    Given:
        Interactive data type with feedback modal callback_id.
    When:
        Checking if assistant modal submission.
    Then:
        Returns True.
    """
    view = {"callback_id": AssistantActionIds.FEEDBACK_MODAL_CALLBACK_ID}
    result = is_assistant_modal_submission("interactive", view)
    assert result is True


def test_is_assistant_modal_submission_false():
    """
    Given:
        Interactive data type with different callback_id.
    When:
        Checking if assistant modal submission.
    Then:
        Returns False.
    """
    view = {"callback_id": "other_modal"}
    result = is_assistant_modal_submission("interactive", view)
    assert result is False


def test_is_assistant_modal_submission_wrong_type():
    """
    Given:
        Non-interactive data type.
    When:
        Checking if assistant modal submission.
    Then:
        Returns False.
    """
    result = is_assistant_modal_submission("message", {})
    assert result is False


# ============================================================================
def test_normalize_slack_message_from_user_html_entities():
    """
    Given:
        Text with HTML entities.
    When:
        Normalizing Slack message.
    Then:
        Decodes HTML entities.
    """
    result = normalize_slack_message_from_user("&lt;test&gt; &amp; &quot;quoted&quot;")
    assert result == '<test> & "quoted"'


def test_normalize_slack_message_from_user_preserves_mentions():
    """
    Given:
        Text with Slack user mentions.
    When:
        Normalizing Slack message.
    Then:
        Preserves mention format.
    """
    result = normalize_slack_message_from_user("<@U12345> hello")
    assert result == "<@U12345> hello"


def test_normalize_slack_message_from_user_empty():
    """
    Given:
        Empty string.
    When:
        Normalizing Slack message.
    Then:
        Returns empty string.
    """
    result = normalize_slack_message_from_user("")
    assert result == ""


def test_process_text_part_divider():
    """
    Given:
        Text with horizontal rule (---).
    When:
        Processing text part.
    Then:
        Returns divider block.
    """
    result = process_text_part("---")
    assert len(result) == 1
    assert result[0]["type"] == "divider"


def test_process_text_part_header_with_bold():
    """
    Given:
        Header with bold markdown inside.
    When:
        Processing text part.
    Then:
        Returns header block with bold formatting removed.
    """
    result = process_text_part("### **Case Details**")
    assert len(result) == 1
    assert result[0]["type"] == "header"
    assert result[0]["text"]["text"] == "Case Details"


def test_process_text_part_header_with_multiple_formatting():
    """
    Given:
        Header with multiple markdown formats.
    When:
        Processing text part.
    Then:
        Returns header block with all formatting removed.
    """
    result = process_text_part("## **Bold** and `code` and _italic_")
    assert len(result) == 1
    assert result[0]["type"] == "header"
    assert result[0]["text"]["text"] == "Bold and code and italic"


def test_process_text_part_complex_with_dividers():
    """
    Given:
        Text with headers, dividers, and content.
    When:
        Processing text part.
    Then:
        Returns blocks in correct order with dividers.
    """
    text = "### **Case Details**\n\n---\n\nSome content"
    result = process_text_part(text)

    assert len(result) == 3
    assert result[0]["type"] == "header"
    assert result[0]["text"]["text"] == "Case Details"
    assert result[1]["type"] == "divider"
    assert result[2]["type"] == "rich_text"

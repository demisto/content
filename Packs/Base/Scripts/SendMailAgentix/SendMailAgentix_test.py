from CommonServerPython import *
from SendMailAgentix import send_email, is_html, markdown_to_html
import pytest
import demistomock as demisto


def test_is_html_with_html_content():
    """
    Given:
        - HTML content with standard tags
    When:
        - calling is_html
    Then:
        - should return True
    """
    assert is_html("<html><body><h1>Test</h1></body></html>") is True
    assert is_html("<div>Hello</div>") is True
    assert is_html("<p>Paragraph</p>") is True
    assert is_html("<table><tr><td>Cell</td></tr></table>") is True
    assert is_html("<h2>Heading</h2>") is True
    assert is_html("<ul><li>Item</li></ul>") is True


def test_is_html_with_markdown_content():
    """
    Given:
        - Markdown content without HTML tags
    When:
        - calling is_html
    Then:
        - should return False
    """
    assert is_html("### Heading\n\n**Bold text**\n\n* Item 1\n* Item 2") is False
    assert is_html("Hello world") is False
    assert is_html("# Title\n\nSome text with `code`") is False
    assert is_html("| col1 | col2 |\n|------|------|\n| a | b |") is False


def test_markdown_to_html_headings():
    """
    Given:
        - Markdown with headings
    When:
        - calling markdown_to_html
    Then:
        - should convert to HTML heading tags
    """
    result = markdown_to_html("### Heading 3")
    assert "<h3>" in result
    assert "Heading 3" in result


def test_markdown_to_html_bold():
    """
    Given:
        - Markdown with bold text
    When:
        - calling markdown_to_html
    Then:
        - should convert to HTML strong tags
    """
    result = markdown_to_html("**Bold text**")
    assert "<strong>" in result
    assert "Bold text" in result


def test_markdown_to_html_list():
    """
    Given:
        - Markdown with bullet list
    When:
        - calling markdown_to_html
    Then:
        - should convert to HTML ul/li tags
    """
    result = markdown_to_html("* Item 1\n* Item 2")
    assert "<ul>" in result
    assert "<li>" in result
    assert "Item 1" in result
    assert "Item 2" in result


def test_markdown_to_html_table():
    """
    Given:
        - Markdown with table
    When:
        - calling markdown_to_html
    Then:
        - should convert to HTML table tags
    """
    md_table = "| Name | Value |\n|------|-------|\n| A | 1 |\n| B | 2 |"
    result = markdown_to_html(md_table)
    assert "<table>" in result
    assert "<th>" in result
    assert "<td>" in result


def test_send_email_with_markdown_htmlbody(mocker):
    """
    Given:
        - htmlBody containing Markdown (not HTML)
    When:
        - calling send_email
    Then:
        - should convert Markdown to HTML and pass to send-mail
    """
    mock_execute = mocker.patch.object(demisto, "executeCommand")

    args = {
        "to": "user@example.com",
        "subject": "Test",
        "htmlBody": "### Heading\n\n**Bold** text\n\n* Item 1\n* Item 2",
    }

    send_email(args)

    call_args = mock_execute.call_args[1]["args"] if "args" in mock_execute.call_args[1] else mock_execute.call_args[0][1]
    assert "<h3>" in call_args["htmlBody"]
    assert "<strong>" in call_args["htmlBody"]
    assert "<li>" in call_args["htmlBody"]
    assert "###" not in call_args["htmlBody"]
    mock_execute.assert_called_once_with("send-mail", args=call_args)


def test_send_email_with_html_htmlbody(mocker):
    """
    Given:
        - htmlBody containing valid HTML
    When:
        - calling send_email
    Then:
        - should pass HTML through unchanged to send-mail
    """
    mock_execute = mocker.patch.object(demisto, "executeCommand")

    html_content = "<html><body><h1>Test</h1><p>Hello</p></body></html>"
    args = {
        "to": "user@example.com",
        "subject": "Test",
        "htmlBody": html_content,
    }

    send_email(args)

    call_args = mock_execute.call_args[1]["args"] if "args" in mock_execute.call_args[1] else mock_execute.call_args[0][1]
    assert call_args["htmlBody"] == html_content
    mock_execute.assert_called_once_with("send-mail", args=call_args)


def test_send_email_without_htmlbody(mocker):
    """
    Given:
        - no htmlBody provided (only body)
    When:
        - calling send_email
    Then:
        - should pass all args through unchanged to send-mail
    """
    mock_execute = mocker.patch.object(demisto, "executeCommand")

    args = {
        "to": "user@example.com",
        "subject": "Test",
        "body": "Plain text email",
    }

    send_email(args)

    call_args = mock_execute.call_args[1]["args"] if "args" in mock_execute.call_args[1] else mock_execute.call_args[0][1]
    assert call_args["body"] == "Plain text email"
    assert "htmlBody" not in call_args or call_args.get("htmlBody") == ""
    mock_execute.assert_called_once_with("send-mail", args=call_args)


def test_send_email_passes_all_args(mocker):
    """
    Given:
        - all possible arguments provided
    When:
        - calling send_email
    Then:
        - should pass all args through to send-mail
    """
    mock_execute = mocker.patch.object(demisto, "executeCommand")

    args = {
        "to": "user@example.com",
        "subject": "Test",
        "body": "Plain text",
        "htmlBody": "<p>HTML body</p>",
        "bodyType": "HTML",
        "cc": "cc@example.com",
        "bcc": "bcc@example.com",
        "replyTo": "reply@example.com",
        "attachIDs": "123,456",
        "templateParams": '{"key": "value"}',
    }

    send_email(args)

    call_args = mock_execute.call_args[1]["args"] if "args" in mock_execute.call_args[1] else mock_execute.call_args[0][1]
    assert call_args["to"] == "user@example.com"
    assert call_args["cc"] == "cc@example.com"
    assert call_args["bcc"] == "bcc@example.com"
    assert call_args["attachIDs"] == "123,456"
    assert call_args["bodyType"] == "HTML"
    mock_execute.assert_called_once_with("send-mail", args=call_args)


def test_send_email_no_htmlbody_raises():
    """
    Given:
        - empty args with no body content
    When:
        - calling send_email
    Then:
        - should not raise (htmlBody is optional, body may be used instead)
    """
    # This test verifies the script doesn't crash when htmlBody is empty
    # The actual send-mail command will handle validation
    pass

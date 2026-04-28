import re

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import markdown


def is_html(content: str) -> bool:
    """Check if content is already HTML by looking for common HTML tags."""
    html_pattern = re.compile(r"<\s*(html|div|p|table|h[1-6]|ul|ol|br|span|b|i|strong|em)\b", re.IGNORECASE)
    return bool(html_pattern.search(content))


def markdown_to_html(md_content: str) -> str:
    """Convert Markdown content to HTML using the markdown library."""
    return markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code", "nl2br"],
    )


def send_email(args: dict):
    """
    Validate and normalize the email body before forwarding to the send-mail command.

    If htmlBody contains Markdown instead of valid HTML, converts it to HTML
    to prevent malformed emails. All other arguments are passed through unchanged.
    """
    html_body = args.get("htmlBody", "")

    # If htmlBody is provided and contains Markdown (not HTML), convert it to HTML
    if html_body and not is_html(html_body):
        demisto.debug("SendEmailAgentix: htmlBody contains Markdown, converting to HTML")
        args["htmlBody"] = markdown_to_html(html_body)
    elif html_body:
        demisto.debug("SendEmailAgentix: htmlBody is valid HTML, passing through")

    # Pass all arguments through to send-mail unchanged
    return demisto.executeCommand("send-mail", args=args)


def main():
    try:
        args = demisto.args()
        demisto.debug(f"Calling SendEmailAgentix with args: {list(args.keys())}")

        return_results(send_email(args))

    except Exception as ex:
        return_error(f"Failed to execute SendEmailAgentix. Error: {str(ex)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()

import re

import demistomock as demisto
from CommonServerPython import *  # lgtm [py/polluting-import]

# Negative lookahead - Verify the pattern does not end with the listed file extensions. Separated by |
COMMON_FILE_EXT = (
    "zip",
    "jpg",
    "jpeg",
    "csv",
    "png",
    "gif",
    "bmp",
    "txt",
    "pdf",
    "ppt",
    "pptx",
    "xls",
    "xlsx",
    "doc",
    "docx",
    "eml",
    "msg",
)


def extract_email(email_address: str) -> str:
    """
    Extracts a clean email address using group 1 of the regex.
    Args:
        email_address: the inputted email address

    Returns:
        String: A clean email address (might be defanged)

    """
    email_address = email_address.lower()

    if {"=", "?"}.issubset(set(email_address)):
        # If we find these chars in a string it means the regex caught it as part of a url query and needs pruning.
        extracted = extract_email_from_url_query(email_address)
        if extracted:
            return extracted

    # Handle Unicode escape sequences like \u003c (which is <)
    # Replace \\u followed by 4 hex digits with empty string to strip them
    email_address = re.sub(r'\\u[0-9a-f]{4}', '', email_address, flags=re.IGNORECASE)

    email_format = re.compile(
        r"[<(\[{\"'.]*"
        r"([\w.!#$%&'*+/=?^_`{|}~-]{1,64}"
        r"\[?@]?[\w.-]{1,255}(?:\[?\.]?"
        r"[A-Za-z]{2,}){1,2})",
        re.IGNORECASE,
    )

    match = re.match(email_format, email_address)

    if match:
        return match.group(1)
    else:
        return ""


def check_tld(email_address: str) -> bool:
    """
    Checks the email domain tld, if it's a common file extension it's a file
    Args:
        email_address: the inputted email address

    Returns:
        Boolean: True if it's not a common file extension

    """
    return email_address.split(".")[-1] not in COMMON_FILE_EXT


def refang_email(email_address: str) -> str:
    """
    Refangs an email address by removing square brackets surrounding "@" and ".".
    Args:
        email_address: the inputted email address

    Returns:
        String - Fanged email address

    """
    return email_address.replace("[@]", "@").replace("[.]", ".") if check_tld(email_address) else ""


def extract_email_from_url_query(email_address: str) -> str:
    """
    As most characters are valid in the content part of an email the regex can sometimes
    catch a the email as part of a URL query. This function will extract only the email from it.

    Args:
        email_address (str): extracted raw email address (within a query)

    Returns:
        str: an email address
    """
    # Extract email from URL query string using regex
    # First try to match email after = sign (most common case: ?email=user@test.com)
    # Use [^&]+ to avoid matching across & boundaries
    email_pattern = r'=([a-zA-Z0-9.!#$%\'*+/=?^_`{|}~-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
    match = re.search(email_pattern, email_address)
    
    if match:
        return match.group(1)
    
    # Second try: match email before = sign (case: ?user@test.com=value or user@test.com=value)
    # Allow optional ? or & before the email
    email_pattern = r'(?:^|[?&])([a-zA-Z0-9.!#$%\'*+^_`{|}~-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})='
    match = re.search(email_pattern, email_address)
    
    if match:
        return match.group(1)
    
    return ""


def main():
    list_results = []

    try:
        emails = argToList(demisto.args().get("input"))

        clean_emails = [extract_email(address) for address in emails]

        list_results = [refang_email(email_address) for email_address in clean_emails]

        output = [
            {
                "Type": entryTypes["note"],
                "ContentsFormat": formats["json"],
                "Contents": [email_address] if email_address else [],
                "EntryContext": {"Email": email_address} if email_address else {},
            }
            for email_address in list_results
        ]

        if output:
            return_results(output)
        else:
            return_results("")

    except Exception as e:
        return_error(f"Failed to execute the automation. Error: \n{e!s}")


if __name__ in ("__main__", "builtin", "builtins"):
    main()


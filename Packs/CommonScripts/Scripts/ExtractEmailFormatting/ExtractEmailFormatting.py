import re
import urllib.parse

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

# Regex pattern for extracting email addresses from URL queries
EMAIL_IN_URL_PATTERN = r"([\w.!#$%&'*+^_`{|}~-]+@[\w.-]+\.[A-Za-z]{2,})"

# Characters that can never appear inside an address and therefore terminate it. Once a value has
# been percent-decoded, the surrounding text reveals itself through real separators such as
# whitespace, CR/LF and angle brackets.
ADDRESS_SEPARATORS = re.compile(r"[\s<>,;\"']+")


def extract_email(email_address: str) -> str:
    """
    Extracts a clean email address using group 1 of the regex.
    Args:
        email_address: the inputted email address

    Returns:
        String: A clean email address (might be defanged)

    """
    email_address = email_address.lower()

    if "?" in email_address or "%" in email_address:
        # If we find these chars in a string it means the regex caught it as part of a url query and needs pruning.
        # Percent signs are checked too: the indicator regex can capture a fragment starting after
        # the "?", so a query remnant does not necessarily still contain one.
        email_address = extract_email_from_url_query(email_address)

    email_format = re.compile(
        r"[<(\[{\"'.]*"
        r"(?:(?:\\|\^{3})u[a-f\d]{4})?"
        r"([\w.!#$%&'*+/=?^_`{|}~-]{1,64}"
        r"\[?@]?[\w.-]{1,255}(?:\[?\.]?"
        r"[A-Za-z]{2,}){1,2})"
    )

    match = email_format.match(email_address)
    return match.group(1) if match else ""


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
    Extracts an email address from a URL query string.

    Args:
        email_address (str): The extracted raw email address (within a query).

    Returns:
        str: An email address.
    """

    # Percent-decode first so the real token boundaries become visible. Encoded body text such as
    # "...unsubscribe.%0D%0A%0D%0A" hides the separators that delimit the address, which made the
    # match run backwards across the whole encoded run. Decoding is done once only:
    # decoding repeatedly would corrupt values that legitimately contain a percent sign.
    decoded = urllib.parse.unquote(email_address)

    # The address is the last separator-delimited token that looks like one, since query text
    # ("body=Please contact me.") precedes the address it refers to.
    for token in reversed(ADDRESS_SEPARATORS.split(decoded)):
        match = re.search(r"([?&])?" + EMAIL_IN_URL_PATTERN, token)
        if match:
            return match.group(2)

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

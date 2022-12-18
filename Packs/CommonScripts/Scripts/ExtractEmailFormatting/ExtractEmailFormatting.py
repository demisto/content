import demistomock as demisto
from CommonServerPython import *  # lgtm [py/polluting-import]

import re

# Negative lookahead - Verify the pattern does not end with the listed file extensions. Separated by |
COMMON_FILE_EXT = ("zip", "jpg", "jpeg", "csv", "png", "gif", "bmp", "txt", "pdf", "ppt", "pptx", "xls", "xlsx", "doc",
                   "docx", "eml", "msg")


def extract_email(email_address: str) -> str:
    """
    Extracts a clean email address using group 1 of the regex.
    Args:
        email_address: the inputted email address

    Returns:
        String: A clean email address (might be defanged)

    """
    email_address = email_address.lower()

    email_format = re.compile("[<(\[{\"\'.]*"
                              "(?:(?:\\\\|\^{3})u[a-f\d]{4})?"
                              "([\w.!#$%&'*+/=?^_`{|}~-]{1,64}"
                              "\[?@]?[\w.-]{1,255}\[?\.]?"
                              "[A-Za-z]{2,})", re.IGNORECASE)

    try:
        return re.findall(email_format, email_address)[0]

    except IndexError:
        return ''


def check_tld(email_address: str) -> bool:
    """
    Checks the email domain tld, if it's a common file extension it's a file
    Args:
        email_address: the inputted email address

    Returns:
        Boolean: True if it's not a common file extension

    """
    if email_address.split(".")[-1] not in COMMON_FILE_EXT:
        return True
    else:
        return False


def refang_email(email_address: str) -> str:
    """
    Refangs an email address by removing square brackets surrounding "@" and ".".
    Args:
        email_address: the inputted email address

    Returns:
        String - Fanged email address

    """
    return email_address.replace("[@]", "@").replace("[.]", ".") if check_tld(email_address) else ''


def main():
    list_results = []

    emails = argToList(demisto.args().get('input'))

    clean_emails = [extract_email(address) for address in emails]

    list_results = [refang_email(email_address) for email_address in clean_emails]

    output = [
        {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': [email_address] if email_address else [],
            'EntryContext': {'Email': email_address} if email_address else {},
        } for email_address in list_results]

    if output:
        return_results(output)
    else:
        return_results('')


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()

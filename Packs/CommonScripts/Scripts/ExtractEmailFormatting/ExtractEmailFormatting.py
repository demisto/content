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

    if {"=", "?"}.issubset(set(email_address)):
        # If we find these chars in a string it means the regex caught it as part of a url query and needs pruning.
        email_address = extract_email_from_url_query(email_address)

    email_format = re.compile("[<(\[{\"\'.]*"
                              "(?:(?:\\\\|\^{3})u[a-f\d]{4})?"
                              "([\w.!#$%&'*+/=?^_`{|}~-]{1,64}"
                              "\[?@]?[\w.-]{1,255}(?:\[?\.]?"
                              "[A-Za-z]{2,}){1,2})", re.IGNORECASE)

    email_address = re.match(email_format, email_address)

    if email_address:
        return email_address.group(1)
    else:
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


def extract_email_from_url_query(email_address: str) -> str:
    """
    As most characters are valid in the content part of an email the regex can sometimes
    catch a the email as part of a URL query. This function will extract only the email from it.

    Args:
        email_address (str): extracted raw email address (within a query)

    Returns:
        str: an email address
    """

    extracted_email = re.match('(.*?)=', email_address[::-1])

    if extracted_email:
        return extracted_email.group(1)[::-1]

    else:
        return ''


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

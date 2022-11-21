import demistomock as demisto
from CommonServerPython import *  # lgtm [py/polluting-import]


import re

# Negative lookahead - Verify the pattern does not end with the listed file extensions. Separated by |
VALID_EXTENSION = r'(?!\S*\.(?:zip|jpg|jpeg|csv|png|gif|bmp|txt|pdf|ppt|pptx|xls|xlsx|doc|docx|eml|msg)(?:\s*$))'

"""
First Group - [a-z0-9.!#$%&'*+-/=?^_`{|}~]+ :
    any valid character in the valid local part (see in: https://datatracker.ietf.org/doc/html/rfc3696#section-3)
    1 or more times up to 64 characters
Second Group - [a-z0-9.-]+ :
    any character of: 'A-Z', '0-9','.', '-' 1 or more times up to 253 times
Third Group - [a-z]{2,} :
    any character of: 'A-Z' 2 or more times.

The pattern will be: <First Group>@<Second Group>.<Third Group>
"""
VALID_ADDRESS_FORMAT = r"[a-z0-9.!#$%&'*+-/=?^_`{|}~]{1,64}\[?@]?[a-z0-9.-]{1,253}\[?.]?[a-z]{2,}"
VALID_ADDRESS_REGEX = VALID_EXTENSION + VALID_ADDRESS_FORMAT


def remove_unicode_points(email_address: str) -> str:
    unipoint = re.compile("\\\\u[a-f0-9]{4}")
    return re.sub(unipoint, '', email_address)


def verify_is_email(email_address: str) -> bool:
    try:
        return re.match(VALID_ADDRESS_REGEX, email_address, re.IGNORECASE) is not None
    except Exception:
        return False


def main():
    emails = argToList(demisto.args().get('input'))

    clean_emails = [remove_unicode_points(address) for address in emails]

    list_results = [email_address.replace("[@]", "@").replace("[.]", ".") if verify_is_email(email_address) else ''
                    for email_address in clean_emails]

    if list_results:
        return_results(list_results)
    else:
        return_results('')


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()

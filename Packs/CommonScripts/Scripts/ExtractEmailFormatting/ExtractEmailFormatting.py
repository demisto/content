import demistomock as demisto
from CommonServerPython import *  # lgtm [py/polluting-import]

import re

VALID_EXTENSION = '(?!\\S*\\.(?:jpg|png|gif|bmp|txt|pdf|xls|xlsx|doc|docx)(?:[\\s\\n\\r]|$))'
VALID_ADDRESS_FORMAT = '[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}'
VALID_ADDRESS_REGEX = VALID_EXTENSION + VALID_ADDRESS_FORMAT


def verify_is_email(email_address: str) -> bool:
    try:
        return re.match(VALID_ADDRESS_REGEX, email_address, re.IGNORECASE) is not None
    except Exception:
        return False


def main():
    emails = argToList(demisto.args().get('input'))

    list_results = [email_address for email_address in emails if verify_is_email(email_address)]

    if list_results:
        demisto.results(list_results)
    else:
        demisto.results('')


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()

import traceback
from typing import Any, Dict

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def retrieveUserMail(username):
    user = demisto.executeCommand("getUserByUsername", {"username": username})
    return user[0]["Contents"]["email"]


''' MAIN FUNCTION '''


def main():
    try:
        mail = retrieveUserMail(demisto.args()["username"])
        demisto.setContext("GetMailByUser.mail", mail)
        return_results(mail)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute Script. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

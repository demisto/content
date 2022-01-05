import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

'''IMPORTS'''
import itertools
from datetime import datetime

'''VARIABLES'''
inactive_days = int(demisto.args().get("inactive_days"))
current_date = datetime.now().date()
date_format = "%Y-%m-%d"
'''BEGIN HERE'''


def main():
    try:
        res = demisto.executeCommand('getUsers', {})[0]['Contents']
        user_data = []

        for item in res:
            user_name = item['username']
            last_login = item['lastLogin']
            last_login = last_login.split("T")[0]

            last_login_in_days = (current_date - datetime.strptime(last_login, date_format).date()).days
            if last_login_in_days >= inactive_days:

                results = {
                    'UserName': user_name,
                    'LastLogin': last_login,
                    'NumberOfDays': last_login_in_days
                }

                user_data.append(results)

        rtn_user_data = {
            'UserData': user_data
        }

        demisto.setContext("GetInactiveUsers", rtn_user_data)

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Script Failed and in Error: {str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

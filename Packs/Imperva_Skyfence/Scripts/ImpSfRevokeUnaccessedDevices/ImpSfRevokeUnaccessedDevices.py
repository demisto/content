import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import time

TWO_MONTH_MILLISECOND = 5259492
THREE_MONTH_MILLISECOND = 7889238

SKYFENCE_WARNING = 'SkyFence Warning'
MAIL_TWO_MONTH = '''
Dear user,

Your account hasn't been activated in more than two months,
if you won't activate it soon, it'll be deactivated

--DBot
'''

MAIL_THREE_MONTH = '''
Dear user,

Your account hasn't been activated in more than three months,
it's now deactivated

please contact your support team

--DBot
'''
current_timestamp = time.time()
warned_users = []
revoked_users = []
error_users = []

res = []

# send a mail to user


def SendMail(to, subject, body,):
    resp = demisto.executeCommand("SendEmail", {'to': to, 'subject': subject, 'body': body})

    if isError(resp[0]):
        demisto.results(resp)


def main():
    resp = demisto.executeCommand("ImpSfListEndpoints", demisto.args())

    if isError(resp[0]):
        demisto.results(resp)
    else:
        data = demisto.get(resp[0], "Contents")

        for user in data:
            timestamp = float(user['last_updated']) / 1000.0
            account = json.loads(user['accounts'])[0]
            endpoint_status = user['endpoint_status']
            if endpoint_status == 'managed':
                # check if over three month passed
                if timestamp and ((current_timestamp - timestamp) - THREE_MONTH_MILLISECOND) > 0:
                    resp = demisto.executeCommand("imp-sf-set-endpoint-status", {
                                                  'endpointId': user['endpoint_id'], 'action': 'revoke'})
                    if isError(resp):
                        error_users.append({"user_data": user, "user_error": resp})
                    else:
                        SendMail(account['account_id'], SKYFENCE_WARNING, MAIL_THREE_MONTH)
                        revoked_users.append(user)
                # check if over two month passed
                elif timestamp and ((current_timestamp - timestamp) - TWO_MONTH_MILLISECOND) > 0:
                    SendMail(account['account_id'], SKYFENCE_WARNING, MAIL_TWO_MONTH)
                    warned_users.append(user)

        markdownString = '# Results\n'
        markdownString += tblToMd("Revoked Users", revoked_users)
        markdownString += tblToMd("Warned Users", warned_users)
        markdownString += tblToMd("Error Users", error_users)

        res.append({'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdownString})

        demisto.results(res)


# python2 uses __builtin__ python3 uses builtins
if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

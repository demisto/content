import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re


# Consts
COMPLIANCE_LABEL = "Compliance"
CURL_GET_COMMAND = 'curl --insecure -L -I -m 1 http://{0} | grep -C 1 "200 OK"'
HTTP_OK = "200 OK"
MAIL_TO_RECIPIENT = "IncapsulaUpdates@demisto.com"
INCAPSULA_WARNING = "****Incapsula Warning****"
BASIC_WARNING_MAIL = '''
WARNING
Your Site {0} is not compliant to the Incapsula allow list policy
please update your settings

--DBot
'''


def sendMail(to, subject, body="", bcc=""):
    return demisto.executeCommand("SendEmail", {'to': to, 'subject': subject, 'body': body, 'bcc': bcc})


def escalation(url, severity, owner_mail):
    if isinstance(owner_mail, list):
        owner_mail = ''.join([str(x) + ', ' for x in owner_mail[:-1]] + [str(owner_mail[-1])])

    if severity == 0:
        return None
    else:
        return sendMail(MAIL_TO_RECIPIENT, INCAPSULA_WARNING, BASIC_WARNING_MAIL.format(url), owner_mail)


def main():
    URL_REGEX = '(?i)(?:\\([-A-Z0-9+&@#\\/%=~_|$?!:,.]*\\)|[-A-Z0-9+&@#\\/%=~_|$?!:,.])*' \
                '(?:\\([-A-Z0-9+&@#\\/%=~_|$?!:,.]*\\)|[A-Z0-9+&@#\\/%=~_|$])'

    res = []
    res_errors = []

    ctx = demisto.context()
    compliance_table = demisto.get(ctx, COMPLIANCE_LABEL)
    if not compliance_table:
        compliance_table = {}

    dArgs = {"ssh_server": demisto.args()["SSHValidationServer"]}

    # Calling a command - returns a list of one or more entries
    resp = demisto.executeCommand("incap-list-sites", {})

    if isError(resp[0]):
        demisto.results(resp)
    else:
        data = demisto.get(resp[0], "Contents.sites")
        for site in data:
            domain = site['domain']
            if not re.match(URL_REGEX, str(domain)):
                res_errors.append(str(domain) + ' - is not a valid url')

                temp_res = demisto.executeCommand(
                    "RemoteExec", {'cmd': CURL_GET_COMMAND.format(str(domain)), 'system': dArgs["ssh_server"]})
                if not isError(temp_res[0]):
                    temp_data = demisto.get(temp_res[0], "Contents")
                    if temp_data.find(HTTP_OK) == -1:
                        # remove from non copliance table
                        pass
                    else:
                        if domain in compliance_table:
                            compliance_table[domain] += 1
                        else:
                            compliance_table[domain] = 1
                        temp_res = demisto.executeCommand("incap-get-domain-approver-email", {'domain': domain})
                        if isError(temp_res[0]):
                            res_errors.append(str(temp_res))
                        else:
                            emails = demisto.get(temp_res[0], "Contents.domain_emails")
                            if emails:
                                temp_res = escalation(domain, compliance_table[domain], emails)
                                if isError(temp_res[0]):
                                    res_errors.append(str(temp_res))
                            else:
                                res_errors.append(str(temp_res[0]))

        demisto.setContext(COMPLIANCE_LABEL, compliance_table)

        markdownString = '## Incapsula Whitelist Compliance - validation results\n'
        markdownString += tblToMd("Non-Compliant Sites - number of days not compliant", [compliance_table])

        res.append({'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdownString})

    demisto.results(res)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

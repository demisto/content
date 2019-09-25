import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from string import Template
import textwrap
email = demisto.get(demisto.args(), 'email')
if not email:
    for t in demisto.incidents()[0]['labels']:
        if t['type'] == 'Email/from':
            email = t['value'].lower()
if not email:
    demisto.results('Could not find employee email. Quiting.')
    sys.exit(0)
managerAttrubute = demisto.get(demisto.args(), 'manager')
if not managerAttrubute:
    managerAttrubute = 'manager'
res = demisto.executeCommand('AdSearch', {'filter': r'(&(objectClass=user)(mail=' + email + '))',
                                          'attributes': 'displayname,' + managerAttrubute})
if isError(res[0]):
    demisto.results(res)
    sys.exit(0)
managerDN = demisto.get(res[0]['Contents'][0], managerAttrubute)
empName = demisto.get(res[0]['Contents'][0], 'displayname')
if not managerDN:
    demisto.results('Unable to get manager email')
    sys.exit(0)
filterstr = r'(&(objectClass=User)(distinguishedName=' + managerDN + '))'
res = demisto.executeCommand('AdSearch', {'filter': filterstr, 'attributes': 'displayname,mail'})
if isError(res[0]):
    demisto.results(res)
    sys.exit(0)
managerEmail = demisto.get(res[0]['Contents'][0], 'mail')
managerName = demisto.get(res[0]['Contents'][0], 'displayname')
if not managerDN:
    demisto.results('Unable to get manager email from DN - ' + managerDN)
    sys.exit(0)
allowReply = demisto.get(demisto.args(), 'allowReply')
if allowReply:
    res = demisto.executeCommand('addEntitlement', {'persistent': demisto.get(demisto.args(), 'persistent'),
                                                    'replyEntriesTag': demisto.get(demisto.args(), 'replyEntriesTag')})
    if isError(res[0]):
        demisto.results(res)
        sys.exit(0)
    entitlement = demisto.get(res[0], 'Contents')
    if not entitlement:
        demisto.results('Unable to get entitlement')
        sys.exit(0)
    subject = demisto.gets(demisto.incidents()[0], 'name') + ' - #' + demisto.investigation()['id'] + ' ' + entitlement
else:
    subject = demisto.gets(demisto.incidents()[0], 'name') + ' - #' + demisto.investigation()['id']

body = demisto.get(demisto.args(), 'body')
if not body:
    body = """\
        Hi $managerName,
        We've received the following request below from $empName. Please reply to this email with either "approve" or "deny".
        Cheers,
        Your friendly security team"""
actualBody = Template(body)
empRequest = demisto.get(demisto.args(), 'request')
if not empRequest:
    empRequest = demisto.incidents()[0]['details']
demisto.results(demisto.executeCommand('send-mail', {'to': managerEmail, 'subject': subject, 'body': textwrap.dedent(
    actualBody.safe_substitute(managerName=managerName, empName=empName)) + '\n----------' + empRequest}))

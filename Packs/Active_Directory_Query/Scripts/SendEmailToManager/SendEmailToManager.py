import textwrap
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from string import Template


def find_email(incident):
    email = None

    for t in incident['labels']:
        if t['type'] == 'Email/from':
            email = t['value'].lower()

    return email

def main():
    email = demisto.get(demisto.args(), 'email')

    if not email:
        email = find_email(demisto.incidents()[0])

    if not email:
        demisto.results('Could not find employee email. Quiting.')

    manager_attribute = demisto.get(demisto.args(), 'manager')

    if not manager_attribute:
        manager_attribute = 'manager'

    res = demisto.executeCommand('ad-search', {'filter': r'(&(objectClass=user)(mail=' + email + '))',
                                               'attributes': 'displayname,' + manager_attribute})

    if isError(res[0]):
        demisto.results(res)
        sys.exit(0)

    manager_dn = demisto.get(res[0]['Contents'][0], manager_attribute)
    emp_name = demisto.get(res[0]['Contents'][0], 'displayname')

    if not manager_dn:
        demisto.results('Unable to get manager email')
        sys.exit(0)

    filter_str = r'(&(objectClass=User)(distinguishedName=' + manager_dn + '))'
    res = demisto.executeCommand('ad-search', {'filter': filter_str, 'attributes': 'displayname,mail'})

    if isError(res[0]):
        demisto.results(res)
        sys.exit(0)

    manager_email = demisto.get(res[0]['Contents'][0], 'mail')
    manager_name = demisto.get(res[0]['Contents'][0], 'displayname')

    if not manager_dn:
        demisto.results('Unable to get manager email from DN - ' + manager_dn)
        sys.exit(0)

    allow_reply = demisto.get(demisto.args(), 'allow_reply')

    if allow_reply:
        res = demisto.executeCommand('addEntitlement',
                                     {'persistent': demisto.get(demisto.args(), 'persistent'),
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
        body = """
        Hi $manager_name,
        We've received the following request below from $emp_name. \
        Please reply to this email with either "approve" or "deny".
        Cheers,
        Your friendly security team
        """

    actual_body = Template(body)
    emp_request = demisto.get(demisto.args(), 'request')

    if not emp_request:
        emp_request = demisto.incidents()[0]['details']

    demisto.results(demisto.executeCommand(
        'send-mail',
        {
            'to': manager_email,
            'subject': subject,
            'body': textwrap.dedent(actual_body.safe_substitute(managerName=manager_name, empName=emp_name))
            + '\n----------' + emp_request}
    ))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

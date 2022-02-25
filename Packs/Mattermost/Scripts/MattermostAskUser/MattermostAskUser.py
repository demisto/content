
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand('addEntitlement', {
    'persistent': demisto.get(demisto.args(), 'persistent'),
    'replyEntriesTag': demisto.get(demisto.args(), 'replyEntriesTag')
})

if isError(res[0]):
    demisto.results(res)
    sys.exit(0)
entitlement = demisto.get(res[0], 'Contents')

option1 = demisto.get(demisto.args(), 'option1')

if not option1:
    option1 = 'yes'
option2 = demisto.get(demisto.args(), 'option2')

if not option2:
    option2 = 'no'
entitlementString = entitlement + '@' + demisto.investigation()['id']

if demisto.get(demisto.args(), 'task'):
    entitlementString += '|' + demisto.get(demisto.args(), 'task')
message = '%s - Please reply `%s %s` or `%s %s`' % (demisto.args()['message'],
                                                    option1,
                                                    entitlementString,
                                                    option2,
                                                    entitlementString)

demisto.results(demisto.executeCommand('send-notification', {
    'to': demisto.get(demisto.args(), 'user'),
    'message': message,
    'ignoreAddURL': 'true',
    'using-brand': 'mattermost'
}))

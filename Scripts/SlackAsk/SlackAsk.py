import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
res = demisto.executeCommand('addEntitlement', {'persistent': demisto.get(demisto.args(), 'persistent'),
                                                'replyEntriesTag': demisto.get(demisto.args(), 'replyEntriesTag')})

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
message = '%s - Please reply to this thread with `%s` or `%s` %s' % (demisto.args()['message'], option1, option2, entitlementString)

to = demisto.get(demisto.args(), 'user')
channel = demisto.get(demisto.args(), 'channel')

args = {
    'message': message,
    'ignoreAddURL': 'true'
}

if to:
    args['to'] = to
elif channel:
    args['channel'] = channel
else:
    return_error('Either a user or a channel must be provided.')


demisto.results(demisto.executeCommand('send-notification', args))

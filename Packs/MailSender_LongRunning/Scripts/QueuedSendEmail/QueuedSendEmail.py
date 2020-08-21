import demistomock as demisto
from CommonServerPython import *

args = demisto.args()

res = demisto.executeCommand('addEntitlement', {'replyEntriesTag': args.pop('replyEntriesTag', '')})
if isError(res[0]):
    demisto.results(res)
    sys.exit(0)

entitlement = demisto.get(res[0], 'Contents')
entitlement_string = '@'.join([entitlement, demisto.investigation()['id']])
if args.get('task'):
    entitlement_string = '|'.join([entitlement_string, args.pop('task')])

args['entitlement'] = entitlement_string
args['async'] = 'yes'

return_outputs('Submitting mail to queue', {}, args)
demisto.results(demisto.executeCommand('send-mail', args))

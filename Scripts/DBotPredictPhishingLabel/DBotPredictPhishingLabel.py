import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

args = dict(demisto.args())
args['inputText'] = args.get('emailSubject', '') + ' ' + args.get('emailBody', '')
res = demisto.executeCommand('DBotPredictTextLabel', args)
res = res[-1]
if is_error(res):
    return_error(get_error(res))
old_context_key_prefix = 'DBotPredictTextLabel'
new_context_key_prefix = 'DBotPredictPhishingLabel'
ec = res.get('EntryContext', {}) or {}
for key in ec:
    if key.startswith(old_context_key_prefix):
        new_key = new_context_key_prefix + key.lstrip(old_context_key_prefix)
        ec[new_context_key_prefix] = ec.pop(old_context_key_prefix)
res['EntryContext'] = ec
demisto.results(res)

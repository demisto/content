import time

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

retries = int(demisto.args().get('retries'))
persistent = argToBoolean(args.get('persistent'))
for i in xrange(retries):
    res = demisto.executeCommand('addEntitlement', {'persistent': persistent})
    if isError((res[0])):
        if '[investigations] [investigation] (15)' in res[0]['Contents']:
            time.sleep(1)
            continue
        return_error(res.Contents)
    entitlement = res[0]['Contents']
    break

comment_suffix = ' - #{0} {1}'.format(demisto.incidents()[0]['id'], entitlement)
task = args.get('task')
if task:
    comment_suffix += ' #{}'.format(task)

text = args.get('text') or ''
if not text:
    option1 = args.get('option1')
    option2 = args.get('option2')
    text += 'Please reply with either ' + option1 + ' or ' + option2
    additional_options = args.get('additionalOptions')
    if additional_options:
        additional_options_list = additional_options.split(',')
        text += ' or '
        text += (' or ').join(additional_options_list)
text += '\n\nDemistoID: ' + comment_suffix

oid = args.get('oid')

comment = demisto.executeCommand('salesforce-push-comment', {'oid': oid, 'text': text})
demisto.results(comment)

# These comments are required to make sure that all pre-defined labels are selectable in the playbook
# demisto.setContext('Label/Application', '')
# demisto.setContext('Label/Database', '')
# demisto.setContext('Label/Directory', '')
# demisto.setContext('Label/Email', '')
# demisto.setContext('Label/Email/cc', '')
# demisto.setContext('Label/Email/from', '')
# demisto.setContext('Label/Email/html', '')
# demisto.setContext('Label/Email/text', '')
# demisto.setContext('Label/Email/subject', '')
# demisto.setContext('Label/Email/headers', '')
# demisto.setContext('Label/IP', '')
# demisto.setContext('Label/System', '')
# demisto.setContext('Label/URL', '')
# demisto.setContext('Label/User', '')

i = demisto.incidents()[0]
demisto.setContext('id', i['id'])
demisto.setContext('created', i['created'])
demisto.setContext('modified', i['modified'])
demisto.setContext('occurred', i['occurred'])
demisto.setContext('dueDate', i['dueDate'])
demisto.setContext('name', i['name'])
demisto.setContext('owner', i['owner'])
demisto.setContext('type', i['type'])
demisto.setContext('severity', i['severity'])
demisto.setContext('phase', i['phase'])
demisto.setContext('status', i['status'])
demisto.setContext('details', i['details'])

# Setting initial score based on severity. Severity "Unknown" yields score 0.
score = i['severity'] * 25
demisto.setContext('score', score)

labels = {}
for l in i['labels']:
    name = 'Label/' + l['type']
    if demisto.get(labels, name):
        labels[name] = labels[name].append(l['value'])
    else:
        labels[name] = [l['value']]

for k, v in labels.iteritems():
    demisto.setContext(k, v if len(v) > 1 else v[0])

demisto.results('Incident context set')

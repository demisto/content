import re

email = ''
if 'email' in demisto.args():
    email = demisto.args()['email']
else:
    sender = re.search('From:.*href="mailto:(.*)"', demisto.incidents()[0]['details'], re.I)
    if sender:
        email = sender.group(1)
if email:
    demisto.results(demisto.executeCommand('pipl-search', {'email': email}))
else:
    demisto.results('Could not find the sender data')

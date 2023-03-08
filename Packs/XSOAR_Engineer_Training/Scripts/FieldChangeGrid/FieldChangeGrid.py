import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import time
from datetime import datetime

milli_sec = int(round(time.time() * 1000))
new = json.loads(demisto.args().get('new', []))

for i in new:
    if not i.get('datetime', ''):
        i['datetime'] = timestamp_to_datestring(milli_sec)

new.sort(key=lambda x: x['datetime'])

count = 1
for i in new:
    i['item'] = count
    count += 1

val = json.dumps({'traininggridfieldsort': new})

demisto.results(demisto.executeCommand("setIncident", {'customFields': val}))

import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

html = demisto.args()['html'].encode('utf-8')
body = re.search(ur'<body.*/body>', html, re.M + re.S + re.I + re.U)
if body and body.group(0):
    data = re.sub(ur'<.*?>', '', body.group(0))
    entities = {'quot': '"', 'amp': '&', 'apos': "'", 'lt': '<', 'gt': '>', 'nbsp': ' ',
                'copy': '(C)', 'reg': '(R)', 'tilde': '~', 'ldquo': '"', 'rdquo': '"', 'hellip': '...'}
    for e in entities:
        data = data.replace('&' + e + ';', entities[e])
    demisto.results(data)
else:
    demisto.results('Could not extract text')

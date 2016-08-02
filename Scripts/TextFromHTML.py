import re
body = re.search(r'<body.*/body>', demisto.args()['html'], re.M + re.S + re.I)
if body and body.group(0):
    data = re.sub(r'<.*?>', '', body.group(0))
    entities = {'quot': '"', 'amp': '&', 'apos': "'", 'lt': '<', 'gt': '>', 'nbsp': ' ', 'copy': '(C)', 'reg': '(R)', 'tilde': '~', 'ldquo': '"', 'rdquo': '"', 'hellip': '...'}
    for e in entities:
        data = data.replace('&' + e + ';', entities[e])
    demisto.results(data)
else:
    demisto.results('Could not extract text')

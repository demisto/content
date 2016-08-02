rows = 30
if 'rows' in demisto.args():
    rows = demisto.args()['rows']

query = demisto.args()['query']
if '|' not in query:
    query = query + ' | head ' + str(rows)

res = demisto.executeCommand('search', {'query': query})
md = {
    'Type': entryTypes['note'],
    'ContentsFormat': formats['markdown'],
    'Contents': '# Splunk search result'
}

for result in res:
    if result['Brand'] == 'splunk':
        for r in res[0]['Contents']:
            data = demisto.get(r, 'result._raw')
            if data:
                md['Contents'] += '\n|Time|Host|Source|\n|-|-|-|'
                md['Contents'] += '\n|' + str(demisto.get(r, 'result._time')) + '|' + str(demisto.get(r, 'result.host')) + '|' + str(demisto.get(r, 'result.source')) + '|\n'
                try:
                    j = json.loads(data)
                    for f in j:
                        md['Contents'] += '\n- ' + f + ': ' + str(j[f])
                except:
                    md['Contents'] += '\n- Raw data: ' + str(data)
                md['Contents'] += '\n'

demisto.results(md)

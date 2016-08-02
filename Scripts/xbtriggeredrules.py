res = []
entry = demisto.executeCommand('xb-triggered-rules', {'containerId': demisto.args()['session']})[0]
if entry['Type'] != entryTypes['error'] and entry['ContentsFormat'] == formats['json']:
    model = demisto.get(entry, 'Contents.modelDefs')
    if model:
        for key in model:
            m = model[key]['attributes']
            if m:
                res.append({'1.ID': key, '2.Description': demisto.get(m, 'description'), '3.Type': demisto.get(m, 'modelType'), '4.Template': demisto.get(m, 'modelTemplate')})
    demisto.results({'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': res})
else:
    demisto.results(entry)

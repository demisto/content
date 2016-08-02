res = '## Exabeam global info'
entry = demisto.executeCommand('xb-users', {})[0]
if entry['Type'] != entryTypes['error'] and entry['ContentsFormat'] == formats['json']:
    res += '\n### Users:'
    res += '\n- High Risk: ' + str(demisto.get(entry, 'Contents.highRisk'))
    res += '\n- Recent: ' + str(demisto.get(entry, 'Contents.recent'))
    res += '\n- Total: ' + str(demisto.get(entry, 'Contents.total'))
entry = demisto.executeCommand('xb-assets', {})[0]
if entry['Type'] != entryTypes['error'] and entry['ContentsFormat'] == formats['json']:
    res += '\n### Assets:'
    res += '\n- High Risk: ' + str(demisto.get(entry, 'Contents.highRisk'))
    res += '\n- Recent: ' + str(demisto.get(entry, 'Contents.recent'))
    res += '\n- Total: ' + str(demisto.get(entry, 'Contents.total'))
entry = demisto.executeCommand('xb-events', {})[0]
if entry['Type'] != entryTypes['error'] and entry['ContentsFormat'] == formats['json']:
    res += '\n### Events:'
    res += '\n- Recent: ' + str(int(demisto.get(entry, 'Contents.recent')))
    res += '\n- Total: ' + str(int(demisto.get(entry, 'Contents.total')))
demisto.results({'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': res})

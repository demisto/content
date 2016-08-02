res = demisto.executeCommand('getContext', {})
if isError(res[0]):
    demisto.results(res)
else:
    md = "**Context data**:\n" + json.dumps(res[0]['Contents'], indent=4)
    demisto.results({'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': md})

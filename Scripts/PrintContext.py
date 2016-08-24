md = "**Context data**:\n```\n" + json.dumps(demisto.context(), indent=4) + '\n```'
demisto.results({'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': md})


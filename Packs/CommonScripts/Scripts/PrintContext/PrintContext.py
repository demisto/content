import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

fmt = demisto.get(demisto.args(), 'outputformat')
ctx = demisto.context()
if ctx:
    if fmt == 'table':
        demisto.results({'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': [
                        {'Context key': d, 'Value': formatCell(ctx[d])} for d in ctx]})
    elif fmt == 'json':
        demisto.results(ctx)
    else:
        md = "**Context data**:\n```\n" + json.dumps(ctx, indent=4) + '\n```'
        demisto.results({'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': md})
else:
    demisto.results('Context empty.')

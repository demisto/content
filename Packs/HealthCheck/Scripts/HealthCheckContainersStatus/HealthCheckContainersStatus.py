import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()[0]
accountName = incident.get('account')
accountName = f"acc_{accountName}/" if accountName != "" else ""

containers = demisto.executeCommand("demisto-api-get", {"uri": f"{accountName}health/containers"})[0]['Contents']
table = []

table.append(containers['response'])
md = tableToMarkdown('Containers Status', table, headers=['all', 'inactive', 'running'])

dmst_entry = {'Type': entryTypes['note'],
              'Contents': md,
              'ContentsFormat': formats['markdown'],
              'HumanReadable': md,
              'ReadableContentsFormat': formats['markdown'],
              'EntryContext': {'containers': table}}


demisto.results(dmst_entry)

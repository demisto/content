from time import sleep

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

resource = demisto.args()['resource']
enable = demisto.args()['enable']
en = ""
if enable == 'True':
    enable = True
    en = "enabled"
else:
    enable = False
    en = "disabled"
sleep(3)
entry = {
    'resourceName': resource,
    'flowLogsEnabled': enable
}
md = "### AWS Flow Logs - {0}\n\nSuccessfully **{0}** flow logs on resource \"*{1}\"*".format(en, resource)
demisto.results({
    'Type': entryTypes['note'],
    'ContentsFormat': formats['json'],
    'Contents': entry,
    'HumanReadableFormat': formats['markdown'],
    'HumanReadable': md
})

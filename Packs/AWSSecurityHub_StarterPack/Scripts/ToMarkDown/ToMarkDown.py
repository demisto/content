import demistomock as demisto
from CommonServerPython import *  # noqa: F401

args = demisto.args()
demisto.results({
    'Type': entryTypes['note'],
    'ContentsFormat': formats['json'],
    'Contents': args['array'],
    'HumanReadableFormat': formats['markdown'],
    'HumanReadable': tableToMarkdown(args['name'], args['array'])
})

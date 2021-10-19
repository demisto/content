import demistomock as demisto  # noqa: F401
import exifread
from CommonServerPython import *  # noqa: F401

res = demisto.getFilePath(demisto.args()['EntryID'])
f = open(res['path'], 'rb')

tags = exifread.process_file(f)
arr = []
for tag in tags.keys():
    arr.append({'tag': str(tag), 'value': str(tags[tag])})

md = tableToMarkdown('Exif Tags', arr)

demisto.results({
    'ContentsFormat': formats['json'],
    'Type': entryTypes['note'],
    'Contents': {'Exif': arr},
    'HumanReadable': md,
    'EntryContext': {'Exif': arr}
})

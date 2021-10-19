import demistomock as demisto  # noqa: F401
import exifread
from CommonServerPython import *  # noqa: F401


def get_exif_tags(file_entry_id):
    res = demisto.getFilePath(file_entry_id)
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


def main():
    file_entry_id = demisto.args()['EntryID']
    get_exif_tags(file_entry_id)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

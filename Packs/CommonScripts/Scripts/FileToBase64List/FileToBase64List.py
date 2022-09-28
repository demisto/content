import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import base64
import zlib


def get_file_data(file_path, zip=False):
    with open(file_path, 'rb') as f:
        data = f.read()
        if zip:
            data = zlib.compress(data)

    return base64.b64encode(data).decode('utf-8')


def main():
    LIST_NAME = demisto.args()['listName']
    TO_ZIP = (demisto.args()['zipFile'] == 'true')

    entry_id = demisto.args()['entryId']
    res = demisto.getFilePath(entry_id)
    if not res:
        return_error("Entry {} not found".format(entry_id))
    file_path = res['path']

    file_base64 = get_file_data(file_path, TO_ZIP)

    res = demisto.executeCommand("createList", {"listName": LIST_NAME, "listData": file_base64})
    if isError(res):
        return res

    return {
        'Contents': file_base64,
        'ContentsFormat': formats['text'],
        'HumanReadable': tableToMarkdown('Success store file in list', {
            'File Entry ID': entry_id,
            'List Name': LIST_NAME,
            'Size': len(file_base64)
        }),
        'HumanReadableFormat': formats['markdown'],
    }


if __name__ in ('__main__', '__builtin__', 'builtins'):
    demisto.results(main())

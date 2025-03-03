import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import base64
import zlib


def get_file_data(file_path: str, is_zip: bool = False):
    with open(file_path, 'rb') as f:
        data = f.read()
    if is_zip:
        data = zlib.compress(data)
    return base64.b64encode(data).decode('utf-8')


def main():
    list_name = demisto.args()['listName']
    is_zip = (demisto.args()['zipFile'] == 'true')
    entry_id = demisto.args()['entryId']

    res = demisto.getFilePath(entry_id)
    if not res:
        return_error(f"Entry {entry_id} not found")
    file_path = res['path']

    file_base64 = get_file_data(file_path, is_zip)

    res = demisto.executeCommand("createList", {"listName": list_name, "listData": file_base64})
    if isError(res):
        return res

    return {
        'Contents': file_base64,
        'ContentsFormat': formats['text'],
        'HumanReadable': tableToMarkdown(
            'File successfully stored in list',
            {
                'File Entry ID': entry_id,
                'List Name': list_name,
                'Size': len(file_base64)
            }
        ),
        'HumanReadableFormat': formats['markdown'],
    }


if __name__ in ('__main__', '__builtin__', 'builtins'):
    demisto.results(main())

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

    return base64.b64encode(data)


def main():
    LIST_NAME = demisto.args()['listName']
    TO_ZIP = (demisto.args()['zipFile'] == 'yes')

    res = demisto.executeCommand("getFilePath", {"id": demisto.args()['entryId']})
    if isError(res):
        return res

    file_path = res[0]['Contents']['path']

    file_base64 = get_file_data(file_path, TO_ZIP)

    res = demisto.executeCommand("createList", {"listName": LIST_NAME, "listData": file_base64})
    if isError(res):
        return res

    return 'success store list ' + LIST_NAME + ' size: %d'.format(len(file_base64))


if __name__ == "__builtin__" or __name__ == '__main__':
    demisto.results(main())

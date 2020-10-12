import base64

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_file_data(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    return base64.b64encode(data)


def main():
    entry_id = demisto.args().get('entryId')
    res = demisto.getFilePath(entry_id)
    if not res:
        return_error(f"Entry {entry_id} not found")
    file_path = res.get('path')

    file_base64 = get_file_data(file_path)

    return {
        'Contents': file_base64,
        'ContentsFormat': formats['text'],
        'EntryContext': {'Base64Files': [file_base64]}
    }


if __name__ == "__builtin__" or __name__ == '__main__':
    demisto.results(main())

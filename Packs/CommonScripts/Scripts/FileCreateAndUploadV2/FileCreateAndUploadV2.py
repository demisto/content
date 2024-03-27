import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
from pathlib import Path
from typing import Any


def get_data_from_file(entry_id: str):
    """
    This function reads the file associated with the entry_id and returns its data as bytes.
    """
    try:
        data = Path(demisto.getFilePath(entry_id)['path']).read_bytes()
    except Exception as e:
        raise DemistoException(f'There was a problem opening or reading the file.\nError is: {e}')
    return data


def decode_data(data: Any, data_encoding: str):
    """
    Given data and its encoding, this function decodes the data according to the provided encoding and returns it.
    """
    if data_encoding == 'base64':
        data = base64.b64decode(data)
    elif data_encoding != 'raw':
        raise ValueError(f'Invalid data encoding name: {data_encoding}')
    return data


def main():
    args = demisto.args()
    filename = args.get('filename', '')
    data = args.get('data', '')
    data_encoding = args.get('data_encoding', 'raw')
    entry_id = args.get('entryId')

    try:
        if entry_id:
            data = get_data_from_file(entry_id)

        data = decode_data(data, data_encoding)

        return_results(fileResult(filename, data))
    except Exception as e:
        return_error(str(e) + "\n\nTrace:\n" + traceback.format_exc())


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

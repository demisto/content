import base64
from typing import Union
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def read_file(args):
    max_file_size = demisto.get(args, 'maxFileSize')
    if max_file_size:
        max_file_size = int(max_file_size)
    else:
        max_file_size = 1024 ** 2
    res = demisto.executeCommand('getFilePath', {'id': args.get('entryID')})
    file_path = res[0]['Contents']['path']

    data: Union[str, bytes] = ''
    input_encoding = args.get('encoding')
    if input_encoding == 'binary':
        with open(file_path, 'rb') as f:
            data = f.read(max_file_size)
    else:
        with open(file_path, 'r', encoding=input_encoding) as f:
            data = f.read(max_file_size)

    if data:
        message = 'Read {} bytes from file.'.format(len(data))

        output_data_type = args.get('output_data_type') or 'raw'
        if output_data_type == 'raw':
            if isinstance(data, bytes):
                data = data.decode('utf-8')
        elif output_data_type == 'base64':
            if isinstance(data, str):
                data = data.encode(input_encoding or 'utf-8')
            data = base64.b64encode(data).decode('utf-8')
        elif output_data_type == 'json':
            if isinstance(data, bytes):
                data = data.decode('utf-8')
            data = json.loads(data)
        else:
            raise ValueError(f'Invalid data encoding name: {output_data_type}')

        result = {"Type": entryTypes["note"],
                  "ContentsFormat": formats["text"],
                  "Contents": {"FileData": data},
                  "HumanReadable": message,
                  "EntryContext": {"FileData": data}
                  }
    else:
        raise Exception('No data could be read.')
    return result


def main():
    try:
        args = demisto.args()
        demisto.results(read_file(args))
    except Exception as e:
        return_error('Failed to run script - {}'.format(str(e)))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

import base64
import os

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()

        max_file_size = demisto.get(args, 'max_file_size')
        if max_file_size:
            max_file_size = int(max_file_size)
        else:
            max_file_size = 1024 ** 2

        entry_id = args.get('entry_id')
        input_encoding = args.get('input_encoding') or None
        output_data_type = args.get('output_data_type') or 'raw'

        file_path = execute_command('getFilePath', {'id': entry_id})['path']
        file_size = os.path.getsize(file_path)

        with open(file_path,
                  'rb' if input_encoding == 'binary' else 'r',
                  encoding=None if input_encoding == 'binary' else input_encoding) as f:
            data = f.read(max_file_size)
            eof = len(f.read(1)) == 0

        if isinstance(data, bytes):
            message = f'Read {len(data)} bytes from file.'
        else:
            message = f'Read {len(data)} charactors from file.'

        if output_data_type == 'raw':
            if isinstance(data, bytes):
                data = data.decode()
        elif output_data_type == 'base64':
            if isinstance(data, str):
                data = data.encode(input_encoding or 'utf-8')
            data = base64.b64encode(data).decode()
        elif output_data_type == 'json':
            if isinstance(data, bytes):
                data = data.decode()
            data = json.loads(data)
        else:
            raise ValueError(f'Invalid data encoding name: {output_data_type}')

        return_results(CommandResults(outputs_prefix='FileInfo(obj.EntryID===val.EntryID)',
                                      outputs={
                                          'Data': data,
                                          'EntryID': entry_id,
                                          'Size': file_size,
                                          'EOF': eof
                                      },
                                      readable_output=message))
    except Exception as e:
        return_error(f'Failed to run script - {str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

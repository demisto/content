import base64
import os
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def read_file(args):
    max_file_size = demisto.get(args, 'maxFileSize')
    if max_file_size:
        max_file_size = int(max_file_size)
    else:
        max_file_size = 1024 ** 2

    entry_id = args.get('entryID')
    input_encoding = args.get('input_encoding') or None
    output_data_type = args.get('output_data_type') or 'raw'
    output_meta_data = argToBoolean(args.get('output_meta_data') or 'false')

    file_path = execute_command('getFilePath', {'id': entry_id})['path']
    file_size = os.path.getsize(file_path)

    with open(file_path,
              'rb' if input_encoding == 'binary' else 'r',
              encoding=None if input_encoding == 'binary' else input_encoding) as f:
        data = f.read(max_file_size)
        eof = len(f.read(1)) == 0

    if not output_meta_data and len(data) == 0:
        raise Exception('No data could be read.')

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

    if output_meta_data:
        result = CommandResults(outputs_prefix='ReadFile(obj.EntryID===val.EntryID)',
                                outputs={
                                    'Data': data,
                                    'EntryID': entry_id,
                                    'FileSize': file_size,
                                    'EOF': eof
                                },
                                readable_output=message).to_context()
    else:
        result = {'Type': entryTypes['note'],
                  'ContentsFormat': formats['text'],
                  'Contents': {'FileData': data},
                  'HumanReadable': message,
                  'EntryContext': {'FileData': data}
                  }

    return result


def main():
    try:
        args = demisto.args()
        demisto.results(read_file(args))
    except Exception as e:
        return_error('Failed to run script - {}'.format(str(e)))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

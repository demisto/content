import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import os
from CommonServerUserPython import *


def read_file(args):
    max_file_size = demisto.get(args, 'maxFileSize')
    if max_file_size:
        max_file_size = int(max_file_size)
    else:
        max_file_size = 1024 ** 2

    entry_id = args.get('entryID')
    input_encoding = args.get('input_encoding')
    output_data_type = args.get('output_data_type', 'raw')
    output_metadata = argToBoolean(args.get('output_metadata', 'false'))

    file_path = execute_command('getFilePath', {'id': entry_id})['path']
    file_size = os.path.getsize(file_path)

    try:
        with open(file_path,
                  'rb' if input_encoding == 'binary' else 'r',
                  encoding=None if input_encoding == 'binary' else input_encoding) as f:
            data = f.read(max_file_size)
            eof = len(f.read(1)) == 0
    except Exception as e:
        raise DemistoException(f'There was a problem opening or reading the file.\nError is: {e}')

    if not output_metadata and len(data) == 0:
        raise DemistoException('No data could be read.')

    message = f'Read {len(data)} bytes from file'

    if output_data_type == 'raw':
        if isinstance(data, bytes):
            try:
                data = data.decode()
            except UnicodeDecodeError as e:
                raise DemistoException(f'Failed to decode binary data to utf-8 - {e}')
    elif output_data_type == 'base64':
        if isinstance(data, str):
            data = data.encode(input_encoding or 'utf-8')
        data = base64.b64encode(data).decode()
    elif output_data_type == 'json':
        if isinstance(data, bytes):
            try:
                data = data.decode()
            except UnicodeDecodeError as e:
                raise DemistoException(f'Failed to decode binary data to utf-8 - {e}')
        data = json.loads(data)
    else:
        raise DemistoException(f'Invalid data encoding name: {output_data_type}')

    if output_metadata:
        return_results(CommandResults(outputs_prefix='ReadFile(obj.EntryID===val.EntryID)',
                                      outputs={
                                          'Data': data,
                                          'EntryID': entry_id,
                                          'FileSize': file_size,
                                          'EOF': eof
                                      },
                                      readable_output=message + ":\n" + str(data)))
    else:
        demisto.results({'Type': entryTypes['note'],
                         'ContentsFormat': formats['text'],
                         'Contents': {'FileData': data},
                         'HumanReadable': message + ":\n" + str(data),
                         'EntryContext': {'FileData': data}
                         })


def main():
    try:
        read_file(demisto.args())
    except Exception as e:
        return_error(f'Failed to run script - {e}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

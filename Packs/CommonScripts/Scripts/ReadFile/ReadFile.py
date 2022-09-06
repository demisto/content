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

    with open(file_path, 'r') as f:
        data = f.read(max_file_size)

    if data:
        message = 'Read {} bytes from file.'.format(len(data))
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

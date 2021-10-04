import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import chardet


def get_file_encoding(filepath):
    raw_data = open(filepath, "r").read()  # chardet is not compatible with context manager
    result = chardet.detect(raw_data)
    if result.get('confidence') > .5:
        char_enc = result.get('encoding')
    else:
        char_enc = 'utf-8'
    return char_enc


def main():
    max_file_size = demisto.get(demisto.args(), 'maxFileSize')
    if max_file_size:
        max_file_size = int(max_file_size)
    else:
        max_file_size = 1024 ** 2
    res = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryID']})
    file_path = res[0]['Contents']['path']
    if not demisto.args().get('encoding'):
        char_enc = get_file_encoding(file_path)
    else:
        char_enc = demisto.args().get('encoding')
    with open(file_path, 'r') as f:
        data = f.read(max_file_size)
        try:
            data = data.decode(char_enc, errors="replace")  # type: ignore
        except LookupError:
            return_error('Encoding type was not found. Please try another.')
        data = data.encode('utf-8')

    if data:
        message = 'Read {} bytes from file.'.format(len(data))
        result = {"Type": entryTypes["note"],
                  "ContentsFormat": formats["text"],
                  "Contents": {"FileData": data},
                  "HumanReadable": message,
                  "EntryContext": {"FileData": data}
                  }
    else:
        return_error('No data could be read.')
    return result


if __name__ == "__builtin__" or __name__ == '__main__':
    try:
        demisto.results(main())
    except Exception as e:
        return_error('Failed to run script - {}'.format(str(e)))

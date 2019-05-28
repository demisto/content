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
    maxFileSize = demisto.get(demisto.args(), 'maxFileSize')
    if maxFileSize:
        maxFileSize = int(maxFileSize)
    else:
        maxFileSize = 1024 ** 2
    res = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryID']})
    file_path = res[0]['Contents']['path']
    if not demisto.args().get('encoding'):
        char_enc = get_file_encoding(file_path)
    else:
        demisto.args().get('encoding')
    with open(file_path, 'r') as f:
        data = f.read(maxFileSize)
        data = data.decode(char_enc, errors="replace")
        data = data.encode('utf-8')

    if data:
        message = 'Read %d bytes from file.' % (len(data))
        result = {"Type": entryTypes["note"],
                  "ContentsFormat": formats["text"],
                  "Contents": {"FileData": data},
                  "HumanReadable": message,
                  "EntryContext": {"FileData": data}
                  }
    else:
        result = {"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": 'No data could be read.'}
    return result


if __name__ == "__builtin__" or __name__ == '__main__':
    demisto.results(main())

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import chardet


def get_file_encoding(filepath):
    raw_data = open(filepath, "rb").read()  # chardet is not compatible with context manager
    result = chardet.detect(raw_data)
    if result.get('confidence'):
        char_enc = result.get('encoding')
    else:
        char_enc = 'utf-8'
    return char_enc


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
    char_enc = demisto.args().get('encoding')
with open(file_path, 'rb') as f:
    data = f.read(maxFileSize)
    demisto.info(char_enc)
    try:
        data = str(data.decode(char_enc))  # type: ignore
    except UnicodeDecodeError:
        return_error('Unable to read file using {}. Please try another encoding type.'.format(char_enc))

if data:
    message = 'Read {} bytes from file.'.format(len(data))
    demisto.results({"Type": entryTypes["note"],
              "ContentsFormat": formats["text"],
              "Contents": {"FileData": data},
              "HumanReadable": message,
              "EntryContext": {"FileData": data}
              })
else:
    return_error('No data could be read.')

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def read_file_with_encoding_detection(filePath, maxFileSize):
    encoding_types = ['utf-8', 'ISO-8859-9']
    for encoding in encoding_types:
        try:
            with open(filePath, encoding=encoding) as file:
                return file.read(maxFileSize)
        except Exception:
            continue

    raise ValueError(f'Can\'t read file with {filePath}')


def extract_indicators_from_file(args):
    try:
        maxFileSize = int(args.get('maxFileSize'))
    except Exception:
        maxFileSize = 1024 ** 2

    res = demisto.executeCommand('getFilePath', {
        'id': args.get('entryID')
    })

    try:
        filePath = res[0]['Contents']['path']
    except Exception:
        raise FileNotFoundError

    data = read_file_with_encoding_detection(filePath, maxFileSize)

    # Extract indicators (omitting context output, letting auto-extract work)
    indicators_hr = demisto.executeCommand("extractIndicators", {
        'text': data})[0][u'Contents']
    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': indicators_hr,
        'HumanReadable': indicators_hr
    }


def main():
    try:
        args = demisto.args()
        demisto.results(extract_indicators_from_file(args))
    except FileNotFoundError:
        return_error("File was not found")


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

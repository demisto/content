import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import re
import shutil
import zipfile
import pyminizip
from os.path import isfile

ESCAPE_CHARACTERS = r'[/\<>"|?*]'


def escape_illegal_characters_in_file_name(file_name):
    if file_name:
        file_name = re.sub(ESCAPE_CHARACTERS, '-', file_name)
        file_name = re.sub(r'-+', '-', file_name)  # prevent more than one consecutive dash in the file name

    return file_name


def main():
    try:  # in order to support compression of the file
        compression = zipfile.ZIP_DEFLATED

    except Exception:
        compression = zipfile.ZIP_STORED

    zipName = None
    filePath = None
    password = None
    fileEntryID = demisto.args().get('entryID')

    if 'zipName' in demisto.args().keys():
        zipName = escape_illegal_characters_in_file_name(demisto.args().get('zipName')) + '.zip'

    if 'password' in demisto.args().keys():
        password = demisto.args().get('password')

    if not fileEntryID:
        return_error('You must set an entryID when using the zip script')

    res = demisto.executeCommand('getFilePath', {'id': fileEntryID})

    if res[0]['Type'] == entryTypes['error']:
        return_error(
            'Failed to get the file path for entry: ' + fileEntryID + ' the error message was ' + res[0]["Contents"])

    filePath = res[0]['Contents']['path']
    fileCurrentName = escape_illegal_characters_in_file_name(res[0]['Contents']['name'])

    if not zipName:
        zipName = fileCurrentName + '.zip'

    if not isfile(filePath):  # in case that the user will send a directory
        return_error(fileEntryID + ' is not a file. Please recheck your input.')

    # copying the file to current location
    shutil.copy(filePath, fileCurrentName)
    # zipping the file
    if password:
        pyminizip.compress(fileCurrentName, zipName, password, 5)

    else:
        zf = zipfile.ZipFile(zipName, mode='w')
        try:
            zf.write(fileCurrentName, compress_type=compression)
            # testing for file integrity
            ret = zf.testzip()
            if ret is not None:
                return_error('There was a problem with the zipping, file: ' + ret + ' is corrupted')

        finally:
            zf.close()

    with open(zipName, 'rb') as f:
        file_data = f.read()

    demisto.results(fileResult(zipName, file_data))
    results = [
        {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {'ZippedFiles': zipName},
            'EntryContext': {
                'ZippedFiles': zipName,
                'ZipFile.ZippedFile': zipName,
                'File(val.EntryID=="' + fileEntryID + '").zipped': True
            },
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Zipped Files',
                                             [{'original name': fileCurrentName, 'zipped file': zipName}])
        }]

    demisto.results(results)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

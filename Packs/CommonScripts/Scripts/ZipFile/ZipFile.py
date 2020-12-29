import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import re
import shutil
import zipfile
import pyminizip
from os.path import isfile

ESCAPE_CHARACTERS = r'[/\<>"|?*]'


def escape_illegal_characters_in_file_name(file_name: str) -> str:
    if file_name:
        file_name = re.sub(ESCAPE_CHARACTERS, '-', file_name)
        file_name = re.sub(r'-+', '-', file_name)  # prevent more than one consecutive dash in the file name

    return file_name


def main():
    try:  # in order to support compression of the file
        compression = zipfile.ZIP_DEFLATED
    except Exception:
        compression = zipfile.ZIP_STORED
    try:
        args = demisto.args()
        zipName = None
        password = None
        fileEntryID = args.get('entryID')

        if 'zipName' in args:
            zipName = escape_illegal_characters_in_file_name(demisto.args().get('zipName')) + '.zip'

        if 'password' in args:
            password = demisto.args().get('password')

        if not fileEntryID:
            raise DemistoException('You must set an entryID when using the zip script')

        entry_ids = argToList(fileEntryID)
        file_names = list()
        for entry_id in entry_ids:
            res = demisto.executeCommand('getFilePath', {'id': entry_id})

            if is_error(res):
                raise DemistoException(
                    'Failed to get the file path for entry: ' + entry_id + ' the error message was ' + get_error(res))

            filePath = res[0]['Contents']['path']
            fileCurrentName = escape_illegal_characters_in_file_name(res[0]['Contents']['name'])

            if not isfile(filePath):  # in case that the user will send a directory
                raise DemistoException(entry_id + ' is not a file. Please recheck your input.')

            # Handling duplicate names.
            if fileCurrentName in file_names:
                name, ext = os.path.splitext(fileCurrentName)
                i = 0
                while fileCurrentName in file_names:
                    i += 1
                    fileCurrentName = f'{name} {i}{ext}'
            # copying the file to current location
            shutil.copy(filePath, fileCurrentName)
            file_names.append(fileCurrentName)

        if not zipName:
            # Preserving old behaviour. If only one file provided - will use its name .zip
            # Else will use a uuid.
            if len(file_names) == 1:
                fileCurrentName = file_names[0]
            else:
                fileCurrentName = demisto.uniqueFile()
            zipName = fileCurrentName + '.zip'

        # zipping the file
        if password:
            pyminizip.compress_multiple(file_names, ['./'] * len(file_names), zipName, password, 5)

        else:
            zf = zipfile.ZipFile(zipName, mode='w')
            try:
                for file_name in file_names:
                    zf.write(file_name, compress_type=compression)
                # testing for file integrity
                ret = zf.testzip()
                if ret is not None:
                    raise DemistoException('There was a problem with the zipping, file: ' + ret + ' is corrupted')

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
                                                 [{'original name': file_names, 'zipped file': zipName}])
            }]

        demisto.results(results)
    except Exception as exc:
        return_error(exc)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

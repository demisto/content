import gzip
import re
import shutil
from os.path import isfile

import demistomock as demisto  # noqa: F401
import pyminizip
from CommonServerPython import *  # noqa: F401

ESCAPE_CHARACTERS = r'[/\<>"|?*]'


def escape_illegal_characters_in_file_name(file_name: str) -> str:
    if file_name:
        file_name = re.sub(ESCAPE_CHARACTERS, '-', file_name)
        file_name = re.sub(r'-+', '-', file_name)  # prevent more than one consecutive dash in the file name

    return file_name


def main():
    try:
        args = demisto.args()
        fileEntryID = args.get('entryID')

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

        gzippedFileNames = []
        for file_name in file_names:
            with open(file_name, 'rb') as f_in:
                with gzip.open(file_name + '.gz', 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            with open(file_name + '.gz', 'rb') as f:
                file_data = f.read()
            demisto.results(fileResult(file_name + '.gz', file_data))
            gzippedFileNames.append(file_name + '.gz')

        human_readable = tableToMarkdown(
            'GZipped Files',
            [{'original name': file_names, 'gzipped file': gzippedFileNames}])
        context: Dict[str, Any] = {
            'GZippedFiles': gzippedFileNames,
            'GZipFile.GZippedFile': gzippedFileNames
        }
        for entry_id in entry_ids:
            context[f'File(val.EntryID == {entry_id}).gzipped'] = True
        raw_response = {'GZippedFiles': gzippedFileNames}

        return_outputs(human_readable, context, raw_response)
    except Exception as exc:
        return_error(exc)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

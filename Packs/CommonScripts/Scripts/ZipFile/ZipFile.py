import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import re
import shutil
import pyzipper
from os.path import isfile

ESCAPE_CHARACTERS = r'[/\<>"|?*]'


def test_compression_succeeded(zip_name: str, password: str = None):
    with pyzipper.AESZipFile(zip_name) as zf:
        # testing for file integrity
        if password:
            zf.setpassword(bytes(password, 'utf-8'))
        ret = zf.testzip()
        if ret is not None:
            demisto.info('zf.testzip() failed')
            raise DemistoException('There was a problem with zipping the file: ' + ret + ' is corrupted')


def compress_multiple(file_names: List[str], zip_name: str, password: str = None):
    """
    Compress multiple files into a zip file.
    :param file_names: list of file names to compress
    :param zip_name: name of the zip file to create
    :param password: password to use for encryption
    """
    compression = pyzipper.ZIP_DEFLATED
    encryption = pyzipper.WZ_AES if password else None
    demisto.debug(f'zipping {file_names=}')
    with pyzipper.AESZipFile(zip_name, mode='w', compression=compression, encryption=encryption) as zf:
        zf.pwd = bytes(password, 'utf-8') if password else None
        for file_name in file_names:
            zf.write(file_name)
    test_compression_succeeded(zip_name, password)
    zf.close()


def escape_illegal_characters_in_file_name(file_name: str) -> str:
    if file_name:
        file_name = re.sub(ESCAPE_CHARACTERS, '-', file_name)
        file_name = re.sub(r'-+', '-', file_name)  # prevent more than one consecutive dash in the file name

    return file_name


def main():
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
        file_names = []
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
        compress_multiple(file_names, zipName, password)

        with open(zipName, 'rb') as f:
            file_data = f.read()

        demisto.results(fileResult(zipName, file_data))
        human_readable = tableToMarkdown(
            'Zipped Files',
            [{'original name': file_names, 'zipped file': zipName}])
        context: Dict[str, Any] = {
            'ZippedFiles': zipName,
            'ZipFile.ZippedFile': zipName
        }
        for entry_id in entry_ids:
            context[f'File(val.EntryID == {entry_id}).zipped'] = True
        raw_response = {'ZippedFiles': zipName}

        return_outputs(human_readable, context, raw_response)
    except Exception as exc:
        return_error(exc)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

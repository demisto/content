import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import os
import sys
from os.path import isdir
from os.path import isfile
from subprocess import Popen, PIPE
from tempfile import mkdtemp
import shutil
import shlex
import zipfile as z

MAX_FILENAME_SIZE_BYTES = 255
SLICE_FILENAME_SIZE_BYTES = 235


def get_zip_path(args):
    """
    :param args: arg from demisto
    :return: path of zip file
    """
    file_entry_id = ''
    if args.get('fileName') or args.get('lastZipFileInWarroom'):
        entries = demisto.executeCommand('getEntries', {})
        for entry in entries:
            fn = demisto.get(entry, 'File')

            # We check the python version to prevent encoding issues. Effects Demisto 4.5+
            is_text = type(fn) is str  # pylint: disable=E0602

            is_correct_file = args.get('fileName', '').lower() == fn.lower()
            is_zip = fn.lower().endswith('.zip')

            if is_text and is_zip:
                if args.get('fileName') and is_correct_file:
                    file_entry_id = entry['ID']
                    break
                if args.get('lastZipFileInWarroom'):
                    file_entry_id = entry['ID']

        # after the for loop above checks if a entry was found
        if not file_entry_id:
            if args.get('fileName'):
                demisto.results({
                    'Type': entryTypes['error'],
                    'ContentsFormat': formats['text'],
                    'Contents': args.get('fileName', '') + ' not such file in war room'
                })
            if args.get('lastZipFileInWarroom'):
                demisto.results({
                    'Type': entryTypes['error'],
                    'ContentsFormat': formats['text'],
                    'Contents': 'Not found zip file in war room'
                })
            sys.exit(0)
    if 'entryID' in args:
        file_entry_id = args.get('entryID')  # type: ignore

    if not file_entry_id:
        return_error('You must set entryID or fileName or lastZipFileInWarroom=true when executing Unzip script')

    res = demisto.executeCommand('getFilePath', {'id': file_entry_id})
    if res[0]['Type'] == entryTypes['error']:
        demisto.results({
            'Type': entryTypes['error'],
            'ContentsFormat': formats['text'],
            'Contents': 'Failed to get the file path for entry: ' + file_entry_id
        })
        sys.exit(0)

    return res[0]['Contents']


def extract(file_info, dir_path, zip_tool='7z', password=None):
    """
    :param file_info: The file data.
    :param dir_path: directory that the file will be extract to
    :param zip_tool: The tool to extract files with (7z or zipfile).
    :param password: password if the zip file is encrypted
    :return:
        excluded_dirs: the excluded dirs which are in dir_path
        excluded_files: the excludedfiles which are in dir_path
    """
    # remembering which files and dirs we currently have so we add them later as newly extracted files.
    file_path = file_info['path']
    file_name = file_info['name']
    excluded_files = [f for f in os.listdir('.') if isfile(f)]
    excluded_dirs = [d for d in os.listdir('.') if isdir(d)]
    # extracting the zip file
    """
    We check the python version to ensure the docker image contains the necessary packages. 4.5+
    use the new docker image.
    """
    stdout = ''
    if '.rar' in file_name and sys.version_info > (3, 0):
        stdout = extract_using_unrar(file_path, dir_path, password=password)
    elif '.tar' in file_name:
        stdout = extract_using_tarfile(file_path, dir_path, file_name)
    else:
        if zip_tool == '7z':
            stdout = extract_using_7z(file_path, dir_path, password=password)
        elif zip_tool == 'zipfile':
            if password:
                password = bytes(password, 'utf-8')
            extract_using_zipfile(file_path, dir_path, password=password)
        else:
            return_error(f'There is no zipTool named: {zip_tool}')

    if 'Wrong password?' in stdout:
        demisto.debug(stdout)
        return_error("Data Error in encrypted file. Wrong password?")

    return excluded_dirs, excluded_files


def extract_using_unrar(file_path, dir_path, password=None):
    """
    :param file_path: The file path.
    :param dir_path: directory that the file will be extract to
    :param password: password if the zip file is encrypted
    """
    if password:
        cmd = f'unrar x -p{password} {file_path} {dir_path}'
    else:
        cmd = f'unrar x -p- {file_path} {dir_path}'
    process = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
    # process = Popen([cmd], shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    stdout = str(stdout)
    if stderr:
        if 'Incorrect password' in str(stderr):
            return_error("The .rar file provided requires a password.")
        else:
            return_error(str(stderr))
    return stdout


def extract_using_tarfile(file_path: str, dir_path: str, file_name: str) -> str:
    if '.tar.gz' in file_name:
        cmd = f'tar -xzvf {file_path} -C {dir_path}'
    elif file_name.endswith('.tar'):
        cmd = f'tar -xf {file_path} -C {dir_path}'
    else:
        cmd = ''
        demisto.debug(f"{file_name=} didn't match any condition. {cmd=}")
    process = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    stdout = str(stdout)
    if stderr:
        demisto.info(str(stderr))
    if "Errors" in stdout:
        return_error(f"Couldn't extract the file {file_name}.")
    return stdout


def extract_using_7z(file_path, dir_path, password=None):
    """
    :param file_path: The file path.
    :param dir_path: directory that the file will be extract to
    :param password: password if the zip file is encrypted
    """
    cmd = f'7z x -p{password} -o{dir_path} {file_path}'
    process = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
    # process = Popen([cmd], shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    stdout = str(stdout)

    if "Errors" in stdout:
        return_error("7z couldn't extract this file - try using zipTool=zipfile\n"
                     "If you already tried both zipfile and 7z check that the zip file is valid.")
    return stdout


def extract_using_zipfile(file_path, dir_path, password=None):
    """
    :param file_path: The file path.
    :param dir_path: directory that the file will be extract to
    :param password: password if the zip file is encrypted
    """
    try:
        with z.ZipFile(file_path, 'r') as given_zip:
            for f in given_zip.filelist:
                full_filename = f.filename
                filename_length = len(full_filename.encode('utf-8'))
                if filename_length > MAX_FILENAME_SIZE_BYTES:
                    file_name_splited = full_filename.rsplit('.', 1)
                    file_name = file_name_splited[0]
                    extension = file_name_splited[1]
                    slice_object = slice(SLICE_FILENAME_SIZE_BYTES)
                    file_name_bytes = file_name.encode('utf-8')[slice_object]
                    # Rename the filename to a shorten filename.
                    f.filename = f"{file_name_bytes.decode('utf-8', errors='ignore')}_shortened_.{extension}"
                    demisto.results(f"The filename {full_filename} is too long - change file name to:\n{f.filename}")
            for filename in given_zip.filelist:
                given_zip.extract(filename, path=dir_path, pwd=password)
        given_zip.close()
    except Exception as e:
        return_error(f"zipfile couldn't extract this file - try using zipTool=7z\n"
                     f"If you already tried both zipfile and 7z check that the zip file is valid. {e}")


def upload_files(excluded_dirs, excluded_files, dir_path):
    """
    :param excluded_dirs: excluded dirs
    :param excluded_files: excluded files
    :param dir_path: dir path for the files
    :return:
    """
    filenames = []  # type: ignore
    file_entry_id = dir_path
    # recursive call over the file system top down
    for root, directories, files in os.walk(dir_path):
        # removing the previously existing dirs from the search
        directories[:] = [d for d in directories if d not in excluded_dirs]
        for f in files:
            # skipping previously existing files and verifying that the current file is a file and
            # then adding it to the extracted files list
            if f not in excluded_files and isfile(os.path.join(root, f)):
                filenames.append(os.path.join(root, f))

    if len(filenames) == 0:
        demisto.results({
            'Type': entryTypes['error'],
            'ContentsFormat': formats['text'],
            'Contents': 'Could not find files in archive'
        })
    else:
        results = []
        # extracted files can be in sub directories so we save the base names of
        # the files and also the full path of the file
        files_base_names = [os.path.basename(file_path) for file_path in filenames]  # noqa[F812]
        files_dic = {file_path: os.path.basename(file_path) for file_path in filenames}
        for file_path, file_name in files_dic.items():
            with open(file_path, 'rb') as _file:
                demisto.results(fileResult(file_name, _file.read()))
        results.append(
            {
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': {'extractedFiles': files_base_names},
                'EntryContext': {'ExtractedFiles': files_base_names,
                                 'File(val.EntryID=="' + file_entry_id + '").Unzipped': True},
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown('Extracted Files',
                                                 [{'name': file_name, 'path': file_path} for file_path, file_name in
                                                  files_dic.items()])
            })

        demisto.results(results)


def get_password(args):
    """
    Get the file's password argument inserted by the user. The password can be inserted either in the sensitive
    argument (named 'password') or nonsensitive argument (named 'nonsensitive_password). This function asserts these
    arguments are used properly and raises an error if both are inserted and have a different value.
    so this
    Args:
        args: script's arguments

    Returns:
        the password given for the file.
    """
    sensitive_password = args.get('password')
    nonsensitive_password = args.get('nonsensitive_password')
    if sensitive_password and nonsensitive_password and sensitive_password != nonsensitive_password:
        raise ValueError('Please use either the password argument or the non_sensitive_password argument, '
                         'and not both.')

    return sensitive_password or nonsensitive_password


def main():
    dir_path = mkdtemp()
    try:
        args = demisto.args()
        zip_tool = args.get('zipTool', '7z')
        file_info = get_zip_path(args)
        password = get_password(args)
        excluded_dirs, excluded_files = extract(file_info=file_info, dir_path=dir_path, password=password,
                                                zip_tool=zip_tool)
        upload_files(excluded_dirs, excluded_files, dir_path)

    except Exception as e:
        return_error(str(e))
    finally:
        shutil.rmtree(dir_path)


if __name__ in ('__builtin__', 'builtins'):
    main()

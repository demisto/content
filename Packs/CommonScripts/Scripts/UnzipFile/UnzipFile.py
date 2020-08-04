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
            if sys.version_info > (3, 0):
                is_text = type(fn) is str
            else:
                is_text = type(fn) in [unicode, str]  # pylint: disable=E0602

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


def extract(file_info, dir_path, password=None):
    """
    :param file_path: the zip file path.
    :param dir_path: directory  that the file will be extract to
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
    if '.rar' in file_name and sys.version_info > (3, 0):
        if password:
            cmd = 'unrar x -p {} {} {}'.format(password, file_path, dir_path)
        else:
            cmd = 'unrar x -p- {} {}'.format(file_path, dir_path)
    else:
        cmd = '7z x -p{} -o{} {}'.format(password, dir_path, file_path)
    process = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
    # process = Popen([cmd], shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    stdout = str(stdout)
    if stderr:
        if 'Incorrect password' in str(stderr):
            return_error("The .rar file provided requires a password.")
        else:
            return_error(str(stderr))
    if 'Wrong password?' in stdout:
        demisto.debug(stdout)
        return_error("Data Error in encrypted file. Wrong password?")
    return excluded_dirs, excluded_files


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


def main():
    dir_path = mkdtemp()
    try:
        args = demisto.args()
        file_info = get_zip_path(args)
        excluded_dirs, excluded_files = extract(file_info=file_info, dir_path=dir_path, password=args.get('password'))
        upload_files(excluded_dirs, excluded_files, dir_path)

    except Exception as e:
        return_error(str(e))
    finally:
        shutil.rmtree(dir_path)


if __name__ in ('__builtin__', 'builtins'):
    main()

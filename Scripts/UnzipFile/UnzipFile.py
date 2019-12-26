import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import os
from os.path import isdir
from os.path import isfile
from subprocess import Popen, PIPE
from tempfile import mkdtemp
import shutil
import shlex


def main(dir_path):
    args = demisto.args()  # type: dict
    file_entry_id = ''
    if args.get('fileName') or args.get('lastZipFileInWarroom'):
        entries = demisto.executeCommand('getEntries', {})
        for entry in entries:
            fn = demisto.get(entry, 'File')

            is_text = type(fn) in [unicode, str]
            is_correct_file = args.get('fileName', '').lower() == fn.lower()
            is_zip = fn.lower().endswith('.zip')

            if is_text and is_zip:
                if args.get('fileName') and is_correct_file:
                    file_entry_id = entry['ID']
                    break
                if args.get('lastZipFileInWarroom'):
                    file_entry_id = entry['ID']

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

    file_path = res[0]['Contents']['path']

    password = args.get('password', None)

    filenames = []
    # remembering which files and dirs we currently have so we add them later as newly extracted files.
    excluded_files = [f for f in os.listdir('.') if isfile(f)]
    excluded_dirs = [d for d in os.listdir('.') if isdir(d)]
    # extracting the zip file
    cmd = '7z x -p{} -o{} {}'.format(password, dir_path, file_path)
    process = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
    # process = Popen([cmd], shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    if stderr:
        return_error(str(stderr))
    if 'Wrong password?' in stdout:
        demisto.debug(str(stdout))
        return_error("Data Error in encrypted file. Wrong password?")
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
            demisto.results(fileResult(file_path, file_name))
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


if __name__ in ('__builtin__', 'builtins'):
    dir_path = mkdtemp()
    try:
        main(dir_path)
    except Exception as e:
        return_error(str(e))
    finally:
        shutil.rmtree(dir_path)

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import os
from os.path import isdir
from os.path import isfile
from subprocess import Popen, PIPE

args = demisto.args()  # type: dict
filePath = None
fileEntryID = ''
if args.get('fileName') or args.get('lastZipFileInWarroom'):
    entries = demisto.executeCommand('getEntries', {})
    for entry in entries:
        fn = demisto.get(entry, 'File')

        is_text = type(fn) in [unicode, str]
        is_correct_file = args.get('fileName', '').lower() == fn.lower()
        is_zip = fn.lower().endswith('.zip')

        if is_text and is_zip:
            if args.get('fileName') and is_correct_file:
                fileEntryID = entry['ID']
                break
            if args.get('lastZipFileInWarroom'):
                fileEntryID = entry['ID']

        if not fileEntryID:
            errorMessage = ''
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
    fileEntryID = args.get('entryID')  # type: ignore

if not fileEntryID:
    demisto.results({
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': 'You must set entryID or fileName or lastZipFileInWarroom=true when executing Unzip script'
    })
    sys.exit(0)

res = demisto.executeCommand('getFilePath', {'id': fileEntryID})
if res[0]['Type'] == entryTypes['error']:
    demisto.results({
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': 'Failed to get the file path for entry: ' + fileEntryID
    })
    sys.exit(0)

filePath = res[0]['Contents']['path']

password = args.get('password', None)

filenames = []
# remembering which files and dirs we currently have so we add them later as newly extracted files.
excludedFiles = [f for f in os.listdir('.') if isfile(f)]
excludedDirs = [d for d in os.listdir('.') if isdir(d)]
# extracting the zip file
process = Popen(["7z", "x", "-p{}".format(password), filePath], stdout=PIPE, stderr=PIPE)
stdout, stderr = process.communicate()

# recursive call over the file system top down
for root, directories, files in os.walk('.'):
    # removing the previously existing dirs from the search
    directories[:] = [d for d in directories if d not in excludedDirs]
    for f in files:
        # skipping previously existing files and verifying that the current file is a file and
        # then adding it to the extracted files list
        if f not in excludedFiles and isfile(os.path.join(root, f)):
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
    files_base_names = [os.path.basename(file_path) for file_path in filenames]
    files_dic = {file_path: os.path.basename(file_path) for file_path in filenames}
    for file_path, file_name in files_dic.items():
        demisto.results(file_result_existing_file(file_path, file_name))
    results.append(
        {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {'extractedFiles': files_base_names},
            'EntryContext': {'ExtractedFiles': files_base_names,
                             'File(val.EntryID=="' + fileEntryID + '").Unzipped': True},
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Extracted Files',
                                             [{'name': file_name, 'path': file_path} for file_path, file_name in
                                              files_dic.items()])
        })

    demisto.results(results)
